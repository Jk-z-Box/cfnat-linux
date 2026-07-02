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
		DailyScan: DailyScanState{Date: "2026-07-02", Count: 3},
		Scan:      ScanState{Completed: true, CompletedAt: &now},
		Targets:   []TargetState{{IP: netip.MustParseAddr("192.0.2.1"), LatencyMS: 88, Status: "healthy", CheckedAt: now}},
		DNS:       DNSState{Enabled: true, RecordName: cfg.DNS.RecordName, Synced: true, SyncedIPs: []string{"192.0.2.1"}, LastSyncedAt: &now},
		Update:    UpdateState{CheckEnabled: true, CurrentVersion: "v0.9.0", LatestVersion: "v0.10.0", UpdateAvailable: true, ReleaseURL: "https://github.com/Jk-z-Box/cfnat-linux/releases/tag/v0.10.0", LastCheckedAt: &now},
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
	for _, wanted := range []string{"0.0.0.0:1234", "今日扫描        : 2026-07-02 已触发 3 次", "发现新版本 v0.10.0", "扫描状态        : 已完成", "192.0.2.1", "健康", "已同步", "best.example.com"} {
		if !strings.Contains(output.String(), wanted) {
			t.Fatalf("status output missing %q:\n%s", wanted, output.String())
		}
	}
}

func TestDNSLatencySyncPolicy(t *testing.T) {
	cfg := config.Defaults()
	cfg.DNS.Enabled = true
	cfg.DNS.RecordType = "A"
	cfg.DNS.SyncCount = 1
	cfg.DNS.LatencySyncEnabled = false
	app := New(cfg, nil, nil, "v0.9.0", "")
	now := time.Now().UTC()
	app.state.DNS.Synced = true
	app.state.DNS.LastSyncedAt = &now
	app.state.DNS.SyncedIPs = []string{"192.0.2.1"}
	desired := []string{"192.0.2.2"}
	if app.shouldSyncDNSAfterPoolChangeLocked(app.state.DNS.SyncedIPs, desired, map[netip.Addr]struct{}{}, now.Add(time.Hour)) {
		t.Fatal("latency-only DNS sync should be disabled by default")
	}
	cfg.DNS.LatencySyncEnabled = true
	cfg.DNS.LatencySyncInterval = config.Duration(5 * time.Minute)
	app.cfg = cfg
	if app.shouldSyncDNSAfterPoolChangeLocked(app.state.DNS.SyncedIPs, desired, map[netip.Addr]struct{}{}, now.Add(time.Minute)) {
		t.Fatal("latency-only DNS sync should respect cooldown")
	}
	if !app.shouldSyncDNSAfterPoolChangeLocked(app.state.DNS.SyncedIPs, desired, map[netip.Addr]struct{}{}, now.Add(6*time.Minute)) {
		t.Fatal("latency-only DNS sync should run after cooldown")
	}
	removed := map[netip.Addr]struct{}{netip.MustParseAddr("192.0.2.1"): {}}
	if !app.shouldSyncDNSAfterPoolChangeLocked(app.state.DNS.SyncedIPs, desired, removed, now.Add(time.Minute)) {
		t.Fatal("removed synced IP should sync immediately")
	}
}
