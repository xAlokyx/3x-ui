package service

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
)

const (
	tcMaxRate      = "10gbit"
	tcMaxBurst     = "100m"
	tcRootHandle   = "1:"
	tcRootClass    = "1:1"
	tcDefaultClass = "1:65535"
	tcDefaultPrio  = "65535"
)

// SpeedLimitService manages per-inbound bandwidth limiting using Linux tc (traffic control).
// Download limits are enforced via HTB egress classes; upload limits via ingress police filters.
// The service is stateless – all state lives in the kernel's tc tables.
type SpeedLimitService struct{}

// getDefaultInterface returns the name of the primary network interface used for the default route.
func (s *SpeedLimitService) getDefaultInterface() (string, error) {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err == nil && len(out) > 0 {
		fields := strings.Fields(string(out))
		for i, f := range fields {
			if f == "dev" && i+1 < len(fields) {
				return fields[i+1], nil
			}
		}
	}
	return "", fmt.Errorf("cannot determine default network interface")
}

func runTC(args ...string) error {
	cmd := exec.Command("tc", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Debugf("tc %v: %v: %s", args, err, string(output))
	}
	return err
}

// ensureHTBRoot ensures the root HTB qdisc and required parent classes exist on the interface.
// It is safe to call multiple times (idempotent via add-then-change fallback).
func (s *SpeedLimitService) ensureHTBRoot(iface string) {
	// Try to add; if it fails the qdisc already exists – try change in case it is already HTB.
	if err := runTC("qdisc", "add", "dev", iface, "root",
		"handle", tcRootHandle, "htb", "default", tcDefaultPrio); err != nil {
		runTC("qdisc", "change", "dev", iface, "root",
			"handle", tcRootHandle, "htb", "default", tcDefaultPrio)
	}
	// Root class (1:1) — full speed ceiling for all children.
	if err := runTC("class", "add", "dev", iface, "parent", tcRootHandle,
		"classid", tcRootClass, "htb", "rate", tcMaxRate, "burst", tcMaxBurst); err != nil {
		runTC("class", "change", "dev", iface, "parent", tcRootHandle,
			"classid", tcRootClass, "htb", "rate", tcMaxRate, "burst", tcMaxBurst)
	}
	// Default leaf class (1:65535) — unlimited, used by unmatched traffic.
	if err := runTC("class", "add", "dev", iface, "parent", tcRootClass,
		"classid", tcDefaultClass, "htb", "rate", tcMaxRate, "burst", tcMaxBurst); err != nil {
		runTC("class", "change", "dev", iface, "parent", tcRootClass,
			"classid", tcDefaultClass, "htb", "rate", tcMaxRate, "burst", tcMaxBurst)
	}
}

// ensureIngress ensures an ingress qdisc exists on the interface.
func (s *SpeedLimitService) ensureIngress(iface string) {
	// Ignore error – qdisc may already be present.
	runTC("qdisc", "add", "dev", iface, "handle", "ffff:", "ingress")
}

// classID returns the HTB class identifier string for the given inbound.
func classID(inbound *model.Inbound) string {
	return fmt.Sprintf("1:%d", inbound.Id)
}

// prioStr returns the tc filter priority string for the given inbound.
// Using the inbound ID keeps it unique and stable across service restarts.
func prioStr(inbound *model.Inbound) string {
	return fmt.Sprintf("%d", inbound.Id)
}

// kbitRate converts a KB/s value to a kbit/s string suitable for tc rate arguments.
func kbitRate(kbps int64) string {
	return fmt.Sprintf("%dkbit", kbps*8)
}

// burstValue returns a sensible burst size string for the given KB/s rate.
func burstValue(kbps int64) string {
	burst := kbps / 8
	if burst < 1 {
		burst = 1
	}
	return fmt.Sprintf("%dk", burst)
}

// ApplySpeedLimit configures tc rules to enforce download/upload limits for the inbound.
// Calling with SpeedLimitDown == 0 && SpeedLimitUp == 0 removes any existing rules.
func (s *SpeedLimitService) ApplySpeedLimit(inbound *model.Inbound) error {
	if inbound.SpeedLimitDown == 0 && inbound.SpeedLimitUp == 0 {
		s.RemoveSpeedLimit(inbound)
		return nil
	}

	iface, err := s.getDefaultInterface()
	if err != nil {
		return fmt.Errorf("speed limit: %v", err)
	}

	// Remove existing rules for this inbound first (idempotent).
	s.RemoveSpeedLimit(inbound)

	port := fmt.Sprintf("%d", inbound.Port)
	prio := prioStr(inbound)

	if inbound.SpeedLimitDown > 0 {
		// Egress: limit traffic leaving the server (= client download).
		s.ensureHTBRoot(iface)

		rate := kbitRate(inbound.SpeedLimitDown)
		burst := burstValue(inbound.SpeedLimitDown)

		if err := runTC("class", "add", "dev", iface, "parent", tcRootClass,
			"classid", classID(inbound), "htb", "rate", rate, "burst", burst); err != nil {
			logger.Warningf("speed limit: failed to add egress class for inbound %d: %v", inbound.Id, err)
		}

		if err := runTC("filter", "add", "dev", iface, "parent", tcRootHandle,
			"protocol", "ip", "prio", prio,
			"u32", "match", "ip", "sport", port, "0xffff",
			"flowid", classID(inbound)); err != nil {
			logger.Warningf("speed limit: failed to add egress filter for inbound %d: %v", inbound.Id, err)
		}
	}

	if inbound.SpeedLimitUp > 0 {
		// Ingress: police traffic arriving at the server (= client upload).
		s.ensureIngress(iface)

		rate := kbitRate(inbound.SpeedLimitUp)
		burst := burstValue(inbound.SpeedLimitUp)

		if err := runTC("filter", "add", "dev", iface, "parent", "ffff:",
			"protocol", "ip", "prio", prio,
			"u32", "match", "ip", "dport", port, "0xffff",
			"police", "rate", rate, "burst", burst, "drop"); err != nil {
			logger.Warningf("speed limit: failed to add ingress filter for inbound %d: %v", inbound.Id, err)
		}
	}

	return nil
}

// RemoveSpeedLimit deletes any tc rules previously applied for the inbound.
func (s *SpeedLimitService) RemoveSpeedLimit(inbound *model.Inbound) {
	iface, err := s.getDefaultInterface()
	if err != nil {
		logger.Debugf("speed limit cleanup: %v", err)
		return
	}

	prio := prioStr(inbound)

	// Delete egress filter and class (errors are expected when rules don't exist).
	runTC("filter", "del", "dev", iface, "parent", tcRootHandle, "prio", prio)
	runTC("class", "del", "dev", iface, "classid", classID(inbound))

	// Delete ingress filter.
	runTC("filter", "del", "dev", iface, "parent", "ffff:", "prio", prio)
}

// RestoreAllLimits re-applies tc rules for every enabled inbound that has a speed limit set.
// This should be called once on server startup since tc rules do not survive reboots.
func (s *SpeedLimitService) RestoreAllLimits(inbounds []*model.Inbound) {
	for _, inbound := range inbounds {
		if !inbound.Enable {
			continue
		}
		if inbound.SpeedLimitDown > 0 || inbound.SpeedLimitUp > 0 {
			if err := s.ApplySpeedLimit(inbound); err != nil {
				logger.Errorf("speed limit restore: inbound %d: %v", inbound.Id, err)
			}
		}
	}
}

