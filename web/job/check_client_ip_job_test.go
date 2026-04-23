package job

import (
	"reflect"
	"testing"
)

func TestParseAccessLogLine_UsesRequiredRegex(t *testing.T) {
	line := "2026/04/23 17:00:00 1.2.3.4:51234 tcp:user@example.com accepted"
	ip, email, ok := parseAccessLogLine(line)
	if !ok {
		t.Fatalf("expected regex to match line")
	}
	if ip != "1.2.3.4" {
		t.Fatalf("unexpected ip: %s", ip)
	}
	if email != "user@example.com" {
		t.Fatalf("unexpected email: %s", email)
	}
}

func TestParseAccessLogLine_NonMatchingLine(t *testing.T) {
	_, _, ok := parseAccessLogLine("invalid line")
	if ok {
		t.Fatalf("expected non-matching line to be ignored")
	}
}

func TestClientIPBucket_TrimToLimit_KeepsMostRecent(t *testing.T) {
	b := newClientIPBucket()
	b.add("1.1.1.1", 1)
	b.add("2.2.2.2", 2)
	b.add("3.3.3.3", 3)

	removed := b.trimToLimit(1)
	wantRemoved := []string{"2.2.2.2", "1.1.1.1"}
	if !reflect.DeepEqual(removed, wantRemoved) {
		t.Fatalf("unexpected removed IPs, got=%v want=%v", removed, wantRemoved)
	}

	if got := len(b.items); got != 1 {
		t.Fatalf("expected one kept IP, got=%d", got)
	}
	if _, ok := b.items["3.3.3.3"]; !ok {
		t.Fatalf("expected newest IP to be kept")
	}
}
