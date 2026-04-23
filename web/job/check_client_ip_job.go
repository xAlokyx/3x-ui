package job

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/web/service"
)

var clientIPRegex = regexp.MustCompile(`[ \t](\d+\.\d+\.\d+\.\d+):\d+ tcp:(\S+)`)

const ipLimitLogPath = "/var/log/x-ui/3xipl.log"

type ipSeen struct {
	IP   string
	Seen int64
}

type clientIPBucket struct {
	mu    sync.Mutex
	items map[string]int64
}

func newClientIPBucket() *clientIPBucket {
	return &clientIPBucket{items: make(map[string]int64)}
}

func (b *clientIPBucket) add(ip string, seen int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if old, ok := b.items[ip]; !ok || seen > old {
		b.items[ip] = seen
	}
}

func (b *clientIPBucket) trimToLimit(limit int) []string {
	b.mu.Lock()
	defer b.mu.Unlock()

	if limit <= 0 || len(b.items) <= limit {
		return nil
	}

	all := make([]ipSeen, 0, len(b.items))
	for ip, seen := range b.items {
		all = append(all, ipSeen{IP: ip, Seen: seen})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].Seen == all[j].Seen {
			return all[i].IP < all[j].IP
		}
		return all[i].Seen > all[j].Seen // newest first
	})

	removed := make([]string, 0, len(all)-limit)
	kept := make(map[string]int64, limit)
	for i, row := range all {
		if i < limit {
			kept[row.IP] = row.Seen
			continue
		}
		removed = append(removed, row.IP)
	}
	b.items = kept
	return removed
}

// CheckClientIpJob monitors access.log incrementally and enforces per-client IP limits.
type CheckClientIpJob struct {
	runMu sync.Mutex

	lastOffset int64
	lastPath   string
	eventSeq   int64

	clientIPs sync.Map // map[email]*clientIPBucket
}

var job *CheckClientIpJob

// NewCheckClientIpJob creates a new client IP monitoring job instance.
func NewCheckClientIpJob() *CheckClientIpJob {
	job = &CheckClientIpJob{}
	return job
}

func (j *CheckClientIpJob) Run() {
	j.runMu.Lock()
	defer j.runMu.Unlock()

	limitedClients, hasLimit := j.getLimitedClients()
	if !hasLimit {
		return
	}

	if runtime.GOOS != "windows" && !j.checkFail2BanInstalled() {
		logger.Warning("[LimitIP] Fail2Ban is not installed, Please install Fail2Ban from the x-ui bash menu.")
		return
	}

	accessLogPath := j.resolveAccessLogPath()
	if accessLogPath == "" {
		logger.Warning("[LimitIP] Access log path is not set, Please configure the access log path in Xray configs.")
		return
	}

	entries, err := j.readNewEntries(accessLogPath)
	if err != nil {
		logger.Warning("client ip job err:", err)
		return
	}

	for _, e := range entries {
		if e.ip == "127.0.0.1" || e.ip == "::1" || e.email == "" {
			continue
		}
		bucket := j.getOrCreateBucket(e.email)
		bucket.add(e.ip, e.seq)
	}

	j.cleanupUnknownClients(limitedClients)
	j.enforceLimits(limitedClients)
}

type logEntry struct {
	ip    string
	email string
	seq   int64
}

func parseAccessLogLine(line string) (string, string, bool) {
	matches := clientIPRegex.FindStringSubmatch(line)
	if len(matches) != 3 {
		return "", "", false
	}
	ip := strings.TrimSpace(matches[1])
	email := strings.TrimSpace(matches[2])
	if ip == "" || email == "" {
		return "", "", false
	}
	return ip, email, true
}

func (j *CheckClientIpJob) readNewEntries(accessLogPath string) ([]logEntry, error) {
	file, err := os.Open(accessLogPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}

	if j.lastPath != accessLogPath {
		j.lastPath = accessLogPath
		j.lastOffset = 0
	}
	if stat.Size() < j.lastOffset {
		j.lastOffset = 0
	}

	if _, err = file.Seek(j.lastOffset, io.SeekStart); err != nil {
		return nil, err
	}

	reader := bufio.NewReader(file)
	offset := j.lastOffset
	entries := make([]logEntry, 0, 64)

	for {
		line, readErr := reader.ReadString('\n')
		if len(line) > 0 {
			offset += int64(len(line))
			trimmed := strings.TrimRight(line, "\r\n")
			if ip, email, ok := parseAccessLogLine(trimmed); ok {
				j.eventSeq++
				entries = append(entries, logEntry{ip: ip, email: email, seq: j.eventSeq})
			}
		}

		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, readErr
		}
	}

	j.lastOffset = offset
	return entries, nil
}

type limitedClient struct {
	inbound model.Inbound
	client  model.Client
}

func (j *CheckClientIpJob) getLimitedClients() (map[string]limitedClient, bool) {
	db := database.GetDB()
	var inbounds []model.Inbound
	if err := db.Model(model.Inbound{}).Find(&inbounds).Error; err != nil {
		return nil, false
	}

	clients := make(map[string]limitedClient)
	hasLimit := false

	for _, inbound := range inbounds {
		if inbound.Settings == "" {
			continue
		}

		settings := map[string][]model.Client{}
		if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
			continue
		}

		for _, client := range settings["clients"] {
			if client.Email == "" || client.LimitIP <= 0 {
				continue
			}
			hasLimit = true
			clients[client.Email] = limitedClient{inbound: inbound, client: client}
		}
	}

	return clients, hasLimit
}

func (j *CheckClientIpJob) getOrCreateBucket(email string) *clientIPBucket {
	if v, ok := j.clientIPs.Load(email); ok {
		return v.(*clientIPBucket)
	}

	bucket := newClientIPBucket()
	actual, _ := j.clientIPs.LoadOrStore(email, bucket)
	return actual.(*clientIPBucket)
}

func (j *CheckClientIpJob) cleanupUnknownClients(limitedClients map[string]limitedClient) {
	j.clientIPs.Range(func(key, _ any) bool {
		email, ok := key.(string)
		if !ok {
			return true
		}
		if _, exists := limitedClients[email]; !exists {
			j.clientIPs.Delete(email)
		}
		return true
	})
}

func (j *CheckClientIpJob) enforceLimits(limitedClients map[string]limitedClient) {
	if len(limitedClients) == 0 {
		return
	}

	if err := os.MkdirAll("/var/log/x-ui", 0o755); err != nil {
		logger.Warning("[LIMIT_IP] Failed to create log directory:", err)
		return
	}

	f, err := os.OpenFile(ipLimitLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		logger.Warning("[LIMIT_IP] Failed to open IP limit log file:", err)
		return
	}
	defer f.Close()

	inboundService := service.InboundService{}

	for email, info := range limitedClients {
		if !info.inbound.Enable {
			continue
		}

		v, ok := j.clientIPs.Load(email)
		if !ok {
			continue
		}

		removed := v.(*clientIPBucket).trimToLimit(info.client.LimitIP)
		if len(removed) == 0 {
			continue
		}

		for _, oldIP := range removed {
			_, _ = fmt.Fprintf(f, "[LIMIT_IP] Email=%s Disconnecting OLD IP=%s\n", email, oldIP)
		}

		if err := inboundService.CycleClientSessions(&info.inbound, info.client); err != nil {
			logger.Warning("[LIMIT_IP] Failed to cycle user sessions for", email, ":", err)
		}
	}
}

func (j *CheckClientIpJob) checkFail2BanInstalled() bool {
	cmd := "fail2ban-client"
	args := []string{"-h"}
	return exec.Command(cmd, args...).Run() == nil
}

func (j *CheckClientIpJob) resolveAccessLogPath() string {
	if path, err := os.Stat(config.GetBinFolderPath() + "/access.log"); err == nil && !path.IsDir() {
		return config.GetBinFolderPath() + "/access.log"
	}
	return config.GetBinFolderPath() + "/access.log"
}
