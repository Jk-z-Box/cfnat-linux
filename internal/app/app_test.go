package app

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cfnat-linux/cfnat-linux/internal/config"
)

func TestPrintStatusIncludesOperationalDetails(t *testing.T) {
	cfg := config.Defaults()
	cfg.StateFile = filepath.Join(t.TempDir(), "state.json")
	cfg.DNS.Enabled = true
	cfg.DNS.ZoneID = "0123456789abcdef0123456789abcdef"
	cfg.DNS.RecordName = "best.example.com"
	now := time.Now().UTC()
	state := RuntimeState{
		Status: "running", Listen: cfg.Listen, MaxLatency: cfg.MaxLatency.Value().String(), PrimaryIP: "192.0.2.1",
		Scan:    ScanState{Completed: true, CompletedAt: &now},
		Targets: []TargetState{{IP: netip.MustParseAddr("192.0.2.1"), LatencyMS: 88, Status: "healthy", CheckedAt: now}},
		DNS:     DNSState{Enabled: true, RecordName: cfg.DNS.RecordName, Synced: true, SyncedIPs: []string{"192.0.2.1"}, LastSyncedAt: &now},
	}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeState(cfg.StateFile, data); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	PrintStatus(&output, cfg)
	for _, wanted := range []string{"0.0.0.0:1234", "扫描状态        : 已完成", "192.0.2.1", "健康", "已同步", "best.example.com"} {
		if !strings.Contains(output.String(), wanted) {
			t.Fatalf("status output missing %q:\n%s", wanted, output.String())
		}
	}
}
