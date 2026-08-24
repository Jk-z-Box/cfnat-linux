package app

import (
	"bytes"
	"encoding/json"
	"html/template"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cfnat-linux/cfnat-linux/internal/config"
	"github.com/cfnat-linux/cfnat-linux/internal/scanner"
	"github.com/cfnat-linux/cfnat-linux/internal/shodan"
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

func TestPrintStatusHidesSyntheticLatency(t *testing.T) {
	cfg := config.Defaults()
	cfg.StateFile = filepath.Join(t.TempDir(), "state.json")
	now := time.Now().UTC()
	state := RuntimeState{
		Status:     "running",
		Listen:     cfg.Listen,
		MaxLatency: cfg.MaxLatency.Value().String(),
		Scan:       ScanState{Completed: true, CompletedAt: &now},
		Targets: []TargetState{
			{IP: netip.MustParseAddr("192.0.2.1"), LatencyMS: 1 << 62, Status: "checking", CheckedAt: now},
		},
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
	text := output.String()
	if strings.Contains(text, "4611686018427387904") {
		t.Fatalf("status leaked synthetic latency:\n%s", text)
	}
	if !strings.Contains(text, "检测中") || !strings.Contains(text, " - ") {
		t.Fatalf("status did not render checking placeholder:\n%s", text)
	}
}

func TestPanelTemplateParses(t *testing.T) {
	if _, err := template.New("panel").Funcs(template.FuncMap{"join": strings.Join}).Parse(panelHTML); err != nil {
		t.Fatal(err)
	}
}

func TestConfiguredConcurrencySwitch(t *testing.T) {
	if got := configuredConcurrency(false, 20, 100); got != 1 {
		t.Fatalf("disabled concurrency = %d, want 1", got)
	}
	if got := configuredConcurrency(true, 20, 100); got != 20 {
		t.Fatalf("enabled concurrency = %d, want 20", got)
	}
	if got := configuredConcurrency(true, 20, 3); got != 3 {
		t.Fatalf("bounded concurrency = %d, want 3", got)
	}
	if got := configuredConcurrency(false, 20, 0); got != 0 {
		t.Fatalf("empty concurrency = %d, want 0", got)
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

func TestFinalScanSkipsDuplicateDNSSync(t *testing.T) {
	cfg := config.Defaults()
	cfg.DNS.Enabled = true
	cfg.DNS.RecordType = "A"
	cfg.DNS.SyncCount = 1
	app := New(cfg, nil, nil, "v0.17.5", "")
	app.pool = []scanner.Result{result("192.0.2.1", 100)}
	app.state.DNS.Synced = true
	app.state.DNS.SyncedIPs = []string{"192.0.2.1"}
	if app.shouldSyncDNSAfterFinalScanLocked() {
		t.Fatal("final scan should not sync DNS when desired IP is already synced")
	}
	app.pool = []scanner.Result{result("192.0.2.2", 90)}
	if !app.shouldSyncDNSAfterFinalScanLocked() {
		t.Fatal("final scan should sync DNS when desired IP changed")
	}
}

func TestSyncedIPRemovedRequiresImmediateDNSSync(t *testing.T) {
	removed := map[netip.Addr]struct{}{netip.MustParseAddr("192.0.2.1"): {}}
	if !syncedIPRemoved([]string{"192.0.2.1"}, removed) {
		t.Fatal("removed synced IP should require immediate DNS sync")
	}
	if syncedIPRemoved([]string{"192.0.2.2"}, removed) {
		t.Fatal("unrelated removed IP should not require immediate DNS sync")
	}
}

func TestSelectPoolAfterHealthScanReplacesWhenScanIsFaster(t *testing.T) {
	current := []scanner.Result{
		result("192.0.2.1", 120),
		result("192.0.2.2", 130),
	}
	scanned := []scanner.Result{
		result("192.0.2.10", 80),
		result("192.0.2.11", 90),
		result("192.0.2.12", 100),
	}
	pool, strategy := selectPoolAfterScan("health", current, scanned, 3)
	if strategy != "replace_better_scan" {
		t.Fatalf("strategy = %q, want replace_better_scan", strategy)
	}
	assertIPs(t, pool, "192.0.2.10", "192.0.2.11", "192.0.2.12")
}

func TestSelectPoolAfterHealthScanKeepsHealthyAndFillsWhenScanIsSlower(t *testing.T) {
	current := []scanner.Result{
		result("192.0.2.1", 80),
		result("192.0.2.2", 90),
		result("192.0.2.3", 100),
	}
	scanned := []scanner.Result{
		result("192.0.2.20", 120),
		result("192.0.2.21", 130),
		result("192.0.2.22", 140),
		result("192.0.2.23", 150),
	}
	pool, strategy := selectPoolAfterScan("health", current, scanned, 5)
	if strategy != "keep_healthy_fill" {
		t.Fatalf("strategy = %q, want keep_healthy_fill", strategy)
	}
	assertIPs(t, pool, "192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.20", "192.0.2.21")
}

func TestSelectPoolAfterNonHealthScanReplaces(t *testing.T) {
	current := []scanner.Result{result("192.0.2.1", 80)}
	scanned := []scanner.Result{result("192.0.2.20", 120), result("192.0.2.21", 130)}
	pool, strategy := selectPoolAfterScan("scheduled", current, scanned, 2)
	if strategy != "replace" {
		t.Fatalf("strategy = %q, want replace", strategy)
	}
	assertIPs(t, pool, "192.0.2.20", "192.0.2.21")
}

func TestSelectProgressPoolMergesNewValidWithCurrentHealthy(t *testing.T) {
	current := []scanner.Result{
		result("192.0.2.1", 80),
		result("192.0.2.2", 150),
		result("192.0.2.3", 160),
	}
	scanned := []scanner.Result{
		result("192.0.2.20", 70),
		result("192.0.2.21", 120),
	}
	pool := selectProgressPool(current, scanned, 4)
	assertIPs(t, pool, "192.0.2.20", "192.0.2.1", "192.0.2.21", "192.0.2.2")
}

func TestRecoveryPoolSwapKeepsFastestTargets(t *testing.T) {
	current := []scanner.Result{
		result("192.0.2.1", 80),
		result("192.0.2.2", 90),
		result("192.0.2.3", 200),
	}
	recovered := result("192.0.2.9", 70)
	pool, recovery := swapRecoveredForWorst(current, []scanner.Result{recovered}, 3)
	assertIPs(t, pool, "192.0.2.9", "192.0.2.1", "192.0.2.2")
	assertIPs(t, recovery, "192.0.2.3")
}

func TestFilterRecoveryResultsExcludesCoolingIPs(t *testing.T) {
	cfg := config.Defaults()
	app := New(cfg, nil, nil, "v0.17.11", "")
	app.recovery = []scanner.Result{result("192.0.2.2", 90)}
	filtered := app.filterRecoveryResults([]scanner.Result{
		result("192.0.2.1", 80),
		result("192.0.2.2", 90),
		result("192.0.2.3", 100),
	})
	assertIPs(t, filtered, "192.0.2.1", "192.0.2.3")
}

func TestPinnedExemptIPsDoNotCountTowardDynamicPoolSize(t *testing.T) {
	cfg := config.Defaults()
	cfg.PoolSize = 2
	cfg.ValidIPCount = 3
	cfg.PostPoolSpeedTest.ExemptDirectPoolEnabled = true
	cfg.PostPoolSpeedTest.ExemptLatencyFilterEnabled = false
	cfg.PostPoolSpeedTest.ExemptList = []string{"192.0.2.100", "192.0.2.101", "192.0.2.0/24"}
	app := New(cfg, nil, nil, "v0.18.0", "")
	app.pool = []scanner.Result{result("192.0.2.100", 10), result("192.0.2.101", 11)}
	app.mu.Lock()
	pool := app.composeForwardPoolLocked([]scanner.Result{result("192.0.2.1", 20), result("192.0.2.2", 30)})
	app.mu.Unlock()
	assertIPs(t, pool, "192.0.2.100", "192.0.2.101", "192.0.2.1", "192.0.2.2")
	if app.state.PinnedPool.Total != 2 || app.state.PinnedPool.Active != 2 || app.state.PinnedPool.DynamicLimit != 2 {
		t.Fatalf("pinned state = %+v", app.state.PinnedPool)
	}
}

func TestPinnedExemptIPsNeedLatencyEligibilityWhenEnabled(t *testing.T) {
	cfg := config.Defaults()
	cfg.PoolSize = 2
	cfg.ValidIPCount = 3
	cfg.PostPoolSpeedTest.ExemptDirectPoolEnabled = true
	cfg.PostPoolSpeedTest.ExemptLatencyFilterEnabled = true
	cfg.PostPoolSpeedTest.ExemptList = []string{"192.0.2.100", "192.0.2.101"}
	app := New(cfg, nil, nil, "v0.18.0", "")
	app.pinnedEligible[netip.MustParseAddr("192.0.2.100")] = result("192.0.2.100", 10)
	app.mu.Lock()
	pool := app.composeForwardPoolLocked([]scanner.Result{result("192.0.2.1", 20), result("192.0.2.2", 30)})
	app.mu.Unlock()
	assertIPs(t, pool, "192.0.2.100", "192.0.2.1", "192.0.2.2")
	if app.state.PinnedPool.Total != 2 || app.state.PinnedPool.DynamicLimit != 2 {
		t.Fatalf("pinned state = %+v", app.state.PinnedPool)
	}
}

func TestFilterPinnedResultsExcludesDirectPoolIPsFromScanResults(t *testing.T) {
	cfg := config.Defaults()
	cfg.PostPoolSpeedTest.ExemptDirectPoolEnabled = true
	cfg.PostPoolSpeedTest.ExemptList = []string{"192.0.2.100"}
	app := New(cfg, nil, nil, "v0.18.0", "")
	filtered := app.filterPinnedResults([]scanner.Result{
		result("192.0.2.1", 80),
		result("192.0.2.100", 90),
	})
	assertIPs(t, filtered, "192.0.2.1")
}

func TestTargetStatesSanitizeSyntheticLatency(t *testing.T) {
	targets := targetStatesFromResults([]scanner.Result{result("192.0.2.1", 1<<62)}, "healthy")
	if len(targets) != 1 {
		t.Fatalf("targets = %#v", targets)
	}
	if targets[0].LatencyMS != 0 || targets[0].Status != "checking" {
		t.Fatalf("target = %+v", targets[0])
	}
	merged := mergeTargetStates([]scanner.Result{result("192.0.2.2", 1<<62)}, []TargetState{{IP: netip.MustParseAddr("192.0.2.2"), LatencyMS: 88, Status: "healthy"}})
	if merged[0].LatencyMS != 0 || merged[0].Status != "checking" {
		t.Fatalf("merged target = %+v", merged[0])
	}
}

func TestApplyBlacklistNowPrunesPoolAndRecovery(t *testing.T) {
	cfg := config.Defaults()
	cfg.IPBlacklist = []string{"192.0.2.2", "198.51.100.0/24"}
	app := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, "v0.17.12", "")
	app.pool = []scanner.Result{result("192.0.2.1", 80), result("192.0.2.2", 90)}
	app.recovery = []scanner.Result{result("198.51.100.9", 100)}
	app.recoveryAt[netip.MustParseAddr("198.51.100.9")] = time.Now()
	app.recoveryOK[netip.MustParseAddr("198.51.100.9")] = 1
	removed, dns := app.applyBlacklistNow()
	if removed != 2 {
		t.Fatalf("removed = %d", removed)
	}
	if dns {
		t.Fatal("unexpected dns sync")
	}
	assertIPs(t, app.pool, "192.0.2.1")
	if len(app.recovery) != 0 {
		t.Fatalf("recovery = %#v", app.recovery)
	}
}

func TestShodanSummaryUsesActiveProfileState(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.StateFile = filepath.Join(dir, "state.json")
	cfg.Shodan.Enabled = true
	cfg.Shodan.DataDir = filepath.Join(dir, "shodan")
	app := New(cfg, nil, nil, "v0.14.0", "")
	manager := shodan.New(cfg.Shodan)
	ws := &webServer{app: app, shodan: manager}
	store := shodan.StoreConfig{
		ActiveProfile: "JP",
		Profiles: map[string]shodan.Profile{
			"SG": {Name: "SG", LastSuccessAt: "2026-07-02T21:32:59+08:00", UniqueIPsWritten: 400},
			"JP": {Name: "JP", APIKey: "test-key", Ports: "443", Countries: "JP", FetchCount: 200},
		},
	}
	if err := manager.SaveConfig(store); err != nil {
		t.Fatal(err)
	}
	statusPath := filepath.Join(cfg.Shodan.DataDir, "status.json")
	statusData, _ := json.Marshal(shodan.Status{State: "idle", ActiveProfile: "SG", LastSuccessAt: "2026-07-02T21:32:59+08:00", UniqueIPsWritten: 400})
	if err := writeState(statusPath, statusData); err != nil {
		t.Fatal(err)
	}
	payload := ws.statusPayload()
	got := payload["shodan"].(map[string]string)
	if got["profile"] != "JP" {
		t.Fatalf("profile = %q", got["profile"])
	}
	if got["ips"] != "0" {
		t.Fatalf("ips = %q, want 0", got["ips"])
	}
	if got["last_success"] != "" {
		t.Fatalf("last_success = %q, want empty", got["last_success"])
	}
}

func result(ip string, latency int64) scanner.Result {
	return scanner.Result{IP: netip.MustParseAddr(ip), LatencyMS: latency, CheckedAt: time.Unix(0, 0).UTC()}
}

func assertIPs(t *testing.T, results []scanner.Result, want ...string) {
	t.Helper()
	if len(results) != len(want) {
		t.Fatalf("len(results) = %d, want %d: %#v", len(results), len(want), results)
	}
	for i, result := range results {
		if result.IP.String() != want[i] {
			t.Fatalf("results[%d] = %s, want %s", i, result.IP, want[i])
		}
	}
}
