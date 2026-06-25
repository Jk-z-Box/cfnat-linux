package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
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
