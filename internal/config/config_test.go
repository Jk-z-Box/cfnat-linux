package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const testZoneID = "0123456789abcdef0123456789abcdef"

func TestMigrateBrokenDefaultEndpoint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	raw := map[string]any{
		"check_url":       "https://cloudflaremirrors.com/debian/",
		"tls_server_name": "cloudflaremirrors.com",
	}
	data, _ := json.Marshal(raw)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	changed, err := Migrate(path)
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	data, _ = os.ReadFile(path)
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got["check_url"] != "https://cloudflare.com/cdn-cgi/trace" {
		t.Fatalf("url=%v", got["check_url"])
	}
	if got["tls_server_name"] != "" {
		t.Fatalf("sni=%v", got["tls_server_name"])
	}
}

func TestMigrateOversizedDefaultSpeedTestURL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	raw := map[string]any{
		"speed_test": map[string]any{
			"enabled": false, "url": "https://speed.cloudflare.com/__down?bytes=200000000",
			"min_mbps": 5, "timeout": "10s", "max_candidates": 50,
		},
	}
	data, _ := json.Marshal(raw)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	changed, err := Migrate(path)
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SpeedTest.URL != "https://speed.cloudflare.com/__down?bytes=50000000" {
		t.Fatalf("speed url = %q", cfg.SpeedTest.URL)
	}
	if cfg.SpeedTest.Concurrency != 3 {
		t.Fatalf("speed concurrency = %d", cfg.SpeedTest.Concurrency)
	}
	if cfg.PostPoolSpeedTest.Enabled {
		t.Fatal("expected post-pool speed test to be disabled after migration")
	}
	if cfg.PostPoolSpeedTest.MinMBps != 1 {
		t.Fatalf("post-pool min speed = %f", cfg.PostPoolSpeedTest.MinMBps)
	}
	if cfg.PostPoolSpeedTest.Timeout.Value() == 0 {
		t.Fatal("expected post-pool speed timeout after migration")
	}
	if len(cfg.PostPoolSpeedTest.ExemptList) != 0 {
		t.Fatalf("post-pool exempt list = %+v", cfg.PostPoolSpeedTest.ExemptList)
	}
	if len(cfg.PostPoolSpeedTest.ForceTestList) != 0 {
		t.Fatalf("post-pool force-test list = %+v", cfg.PostPoolSpeedTest.ForceTestList)
	}
	if cfg.BlacklistSpeedTest.Enabled {
		t.Fatal("expected blacklist speed test to be disabled after migration")
	}
	if cfg.BlacklistSpeedTest.Interval.Value() != 24*time.Hour || cfg.BlacklistSpeedTest.Timeout.Value() == 0 || cfg.BlacklistSpeedTest.Concurrency != 3 {
		t.Fatalf("blacklist speed config = %+v", cfg.BlacklistSpeedTest)
	}
	if !cfg.ScanIntervalEnabled {
		t.Fatal("expected scan interval to be enabled after migration")
	}
	if cfg.Management.PasswordEnabled {
		t.Fatal("expected management password to be disabled after migration")
	}
	if !cfg.Update.CheckEnabled {
		t.Fatal("expected update check to be enabled after migration")
	}
	if cfg.Update.AutoUpdateEnabled {
		t.Fatal("expected auto update to be disabled after migration")
	}
	if cfg.Update.Repository != "Jk-z-Box/cfnat-linux" {
		t.Fatalf("update repository = %q", cfg.Update.Repository)
	}
	if !cfg.Web.Enabled {
		t.Fatal("expected web panel to be enabled after migration")
	}
	if cfg.Web.Listen != "0.0.0.0:8787" {
		t.Fatalf("web listen = %q", cfg.Web.Listen)
	}
	if cfg.Web.Username != "admin" || cfg.Web.PasswordSHA256 == "" {
		t.Fatal("expected default web auth after migration")
	}
	if cfg.Shodan.Enabled {
		t.Fatal("expected shodan panel to be disabled after migration")
	}
	if cfg.RecoveryCooldown.Value() == 0 {
		t.Fatal("expected recovery cooldown after migration")
	}
	if cfg.RecoverySuccesses != 2 {
		t.Fatalf("recovery successes = %d", cfg.RecoverySuccesses)
	}
	if cfg.ProbeMode != "http" {
		t.Fatalf("probe mode = %q", cfg.ProbeMode)
	}
	if cfg.ScanProbeMode != "http" || cfg.HealthProbeMode != "http" || cfg.RecoveryProbeMode != "http" {
		t.Fatalf("probe modes = scan:%q health:%q recovery:%q", cfg.ScanProbeMode, cfg.HealthProbeMode, cfg.RecoveryProbeMode)
	}
}

func TestDNSRecordTypeAuto(t *testing.T) {
	cfg := Defaults()
	cfg.DNS.Enabled = true
	cfg.DNS.ZoneID = testZoneID
	cfg.DNS.RecordName = "best.example.com"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.DNS.RecordType != "A" {
		t.Fatalf("record type = %q", cfg.DNS.RecordType)
	}
}

func TestRejectProxied(t *testing.T) {
	cfg := Defaults()
	cfg.DNS.Enabled = true
	cfg.DNS.ZoneID = testZoneID
	cfg.DNS.RecordName = "best.example.com"
	cfg.DNS.Proxied = true
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected proxied validation error")
	}
}

func TestRejectEmptyDNSMarker(t *testing.T) {
	cfg := Defaults()
	cfg.DNS.Enabled = true
	cfg.DNS.ZoneID = testZoneID
	cfg.DNS.RecordName = "best.example.com"
	cfg.DNS.Marker = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected empty marker validation error")
	}
}

func TestRejectInvalidListenAddress(t *testing.T) {
	cfg := Defaults()
	cfg.Listen = "0.0.0.0:not-a-port"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected invalid listen address error")
	}
}

func TestRejectMinHealthyCountLargerThanPool(t *testing.T) {
	cfg := Defaults()
	cfg.PoolSize = 3
	cfg.MinHealthyCount = 4
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected min healthy count validation error")
	}
}

func TestRejectInvalidDNSLatencySyncInterval(t *testing.T) {
	cfg := Defaults()
	cfg.DNS.LatencySyncInterval = Duration(0)
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected latency sync interval validation error")
	}
}

func TestRejectInvalidRecoverySettings(t *testing.T) {
	cfg := Defaults()
	cfg.RecoveryCooldown = Duration(0)
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected recovery cooldown validation error")
	}
	cfg = Defaults()
	cfg.RecoverySuccesses = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected recovery successes validation error")
	}
}

func TestProbeModeAliasesAndValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	cfg := Defaults()
	data, _ := json.Marshal(cfg)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := Set(path, "probe_mode", "tcping"); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.ProbeMode != "tcp" || got.ScanProbeMode != "tcp" || got.HealthProbeMode != "tcp" || got.RecoveryProbeMode != "tcp" {
		t.Fatalf("probe modes = %q/%q/%q/%q", got.ProbeMode, got.ScanProbeMode, got.HealthProbeMode, got.RecoveryProbeMode)
	}
	if err := Set(path, "scan_probe_mode", "http"); err != nil {
		t.Fatal(err)
	}
	if err := Set(path, "health_probe_mode", "ping"); err != nil {
		t.Fatal(err)
	}
	if err := Set(path, "recovery_probe_mode", "tcping"); err != nil {
		t.Fatal(err)
	}
	got, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.ScanProbeMode != "http" || got.HealthProbeMode != "icmp" || got.RecoveryProbeMode != "tcp" {
		t.Fatalf("independent probe modes = scan:%q health:%q recovery:%q", got.ScanProbeMode, got.HealthProbeMode, got.RecoveryProbeMode)
	}
	if err := Set(path, "probe_mode", "bad"); err == nil {
		t.Fatal("expected invalid probe mode error")
	}
	if err := Set(path, "health_probe_mode", "bad"); err == nil {
		t.Fatal("expected invalid health probe mode error")
	}
}

func TestRejectInvalidSpeedTestThreshold(t *testing.T) {
	cfg := Defaults()
	cfg.SpeedTest.Enabled = true
	cfg.SpeedTest.MinMBps = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected speed threshold validation error")
	}
}

func TestRejectInvalidSpeedTestConcurrency(t *testing.T) {
	cfg := Defaults()
	cfg.SpeedTest.Enabled = true
	cfg.SpeedTest.Concurrency = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected speed concurrency validation error")
	}
}

func TestPostPoolSpeedTestSetAndValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	cfg := Defaults()
	data, _ := json.Marshal(cfg)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := Set(path, "post_pool_speed_test_enabled", "true"); err != nil {
		t.Fatal(err)
	}
	if err := Set(path, "post_pool_speed_test_min_mbps", "0.5"); err != nil {
		t.Fatal(err)
	}
	if err := Set(path, "post_pool_speed_test_timeout", "3s"); err != nil {
		t.Fatal(err)
	}
	if err := Set(path, "post_pool_speed_test_auto_blacklist", "true"); err != nil {
		t.Fatal(err)
	}
	if err := Set(path, "post_pool_speed_test_exempt_list", "192.0.2.1\n198.51.100.0/24"); err != nil {
		t.Fatal(err)
	}
	if err := Set(path, "post_pool_speed_test_force_test_list", "203.0.113.1"); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !got.PostPoolSpeedTest.Enabled || got.PostPoolSpeedTest.MinMBps != 0.5 || got.PostPoolSpeedTest.Timeout.Value() == 0 || !got.PostPoolSpeedTest.AutoBlacklist || len(got.PostPoolSpeedTest.ExemptList) != 2 || len(got.PostPoolSpeedTest.ForceTestList) != 1 {
		t.Fatalf("post pool speed config = %+v", got.PostPoolSpeedTest)
	}
	if err := Set(path, "post_pool_speed_test_min_mbps", "0"); err == nil {
		t.Fatal("expected invalid post-pool speed threshold")
	}
}

func TestBlacklistSpeedTestSetAndValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	cfg := Defaults()
	data, _ := json.Marshal(cfg)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := Set(path, "blacklist_speed_test_enabled", "true"); err != nil {
		t.Fatal(err)
	}
	if err := Set(path, "blacklist_speed_test_interval", "10h"); err != nil {
		t.Fatal(err)
	}
	if err := Set(path, "blacklist_speed_test_timeout", "4s"); err != nil {
		t.Fatal(err)
	}
	if err := Set(path, "blacklist_speed_test_concurrency", "6"); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !got.BlacklistSpeedTest.Enabled || got.BlacklistSpeedTest.Interval.Value() != 10*time.Hour || got.BlacklistSpeedTest.Timeout.Value() != 4*time.Second || got.BlacklistSpeedTest.Concurrency != 6 {
		t.Fatalf("blacklist speed config = %+v", got.BlacklistSpeedTest)
	}
	if err := Set(path, "blacklist_speed_test_interval", "30m"); err == nil {
		t.Fatal("expected invalid non-hour blacklist speed interval")
	}
	if err := Set(path, "blacklist_speed_test_concurrency", "0"); err == nil {
		t.Fatal("expected invalid blacklist speed concurrency")
	}
}

func TestRejectInvalidManagementPasswordHash(t *testing.T) {
	cfg := Defaults()
	cfg.Management.PasswordEnabled = true
	cfg.Management.PasswordSHA256 = "not-a-sha256"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected management password hash validation error")
	}
}

func TestRejectInvalidUpdateRepository(t *testing.T) {
	cfg := Defaults()
	cfg.Update.Repository = "not-owner-repo"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected invalid update repository validation error")
	}
}

func TestRejectInvalidWebListen(t *testing.T) {
	cfg := Defaults()
	cfg.Web.Enabled = true
	cfg.Web.Listen = "bad-listen"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected invalid web listen validation error")
	}
}

func TestRejectInvalidWebAuth(t *testing.T) {
	cfg := Defaults()
	cfg.Web.Enabled = true
	cfg.Web.Username = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected empty web username validation error")
	}
	cfg = Defaults()
	cfg.Web.Enabled = true
	cfg.Web.PasswordSHA256 = "bad"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected invalid web password hash validation error")
	}
}

func TestAcceptIPv6ListenAddress(t *testing.T) {
	cfg := Defaults()
	cfg.Listen = "[::]:1234"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestSetValidatedConfigValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	data, err := json.Marshal(Defaults())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0640); err != nil {
		t.Fatal(err)
	}
	if err := Set(path, "max_latency", "450ms"); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxLatency.Value().String() != "450ms" {
		t.Fatalf("max latency = %s", cfg.MaxLatency.Value())
	}
	if err := Set(path, "listen", "bad-address"); err == nil {
		t.Fatal("expected invalid listen update to fail")
	}
}
