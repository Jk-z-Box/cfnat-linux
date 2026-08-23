package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Duration time.Duration

func (d Duration) Value() time.Duration { return time.Duration(d) }

func (d *Duration) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return errors.New("持续时间必须是字符串，例如 300ms、60s、6h")
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

type DNSConfig struct {
	Enabled             bool     `json:"enabled"`
	ZoneID              string   `json:"zone_id"`
	RecordName          string   `json:"record_name"`
	RecordType          string   `json:"record_type"`
	SyncCount           int      `json:"sync_count"`
	TTL                 int      `json:"ttl"`
	Proxied             bool     `json:"proxied"`
	TokenEnv            string   `json:"token_env"`
	Marker              string   `json:"marker"`
	LatencySyncEnabled  bool     `json:"latency_sync_enabled"`
	LatencySyncInterval Duration `json:"latency_sync_interval"`
}

type SpeedTestConfig struct {
	Enabled       bool     `json:"enabled"`
	URL           string   `json:"url"`
	MinMBps       float64  `json:"min_mbps"`
	Timeout       Duration `json:"timeout"`
	MaxCandidates int      `json:"max_candidates"`
	Concurrency   int      `json:"concurrency"`
}

type PostPoolSpeedTestConfig struct {
	Enabled                    bool     `json:"enabled"`
	MinMBps                    float64  `json:"min_mbps"`
	Timeout                    Duration `json:"timeout"`
	AutoBlacklist              bool     `json:"auto_blacklist"`
	ExemptList                 []string `json:"exempt_list"`
	ForceTestList              []string `json:"force_test_list"`
	ExemptDirectPoolEnabled    bool     `json:"exempt_direct_pool_enabled"`
	ExemptLatencyFilterEnabled bool     `json:"exempt_latency_filter_enabled"`
	ExemptMaxLatency           Duration `json:"exempt_max_latency"`
	ExemptProbeMode            string   `json:"exempt_probe_mode"`
	ExemptLatencyConcurrency   int      `json:"exempt_latency_concurrency"`
	ExemptRecoveryEvictEnabled bool     `json:"exempt_recovery_evict_enabled"`
	ExemptRecoveryWindow       Duration `json:"exempt_recovery_window"`
	ExemptRecoveryMaxRatio     float64  `json:"exempt_recovery_max_ratio"`
	ExemptRecoveryMinSamples   int      `json:"exempt_recovery_min_samples"`
}

type BlacklistSpeedTestConfig struct {
	Enabled     bool     `json:"enabled"`
	Interval    Duration `json:"interval"`
	Timeout     Duration `json:"timeout"`
	Concurrency int      `json:"concurrency"`
}

type ManagementConfig struct {
	PasswordEnabled bool   `json:"password_enabled"`
	PasswordSHA256  string `json:"password_sha256"`
}

type UpdateConfig struct {
	CheckEnabled      bool     `json:"check_enabled"`
	CheckInterval     Duration `json:"check_interval"`
	AutoUpdateEnabled bool     `json:"auto_update_enabled"`
	Repository        string   `json:"repository"`
}

type WebConfig struct {
	Enabled        bool   `json:"enabled"`
	Listen         string `json:"listen"`
	Username       string `json:"username"`
	PasswordSHA256 string `json:"password_sha256"`
}

type ShodanConfig struct {
	Enabled bool   `json:"enabled"`
	DataDir string `json:"data_dir"`
}

type Config struct {
	ConfigVersion          int                      `json:"config_version"`
	Listen                 string                   `json:"listen"`
	IPVersion              int                      `json:"ip_version"`
	IPSources              []string                 `json:"ip_sources"`
	IPBlacklist            []string                 `json:"ip_blacklist"`
	RandomIPs              bool                     `json:"random_ips"`
	MaxCandidates          int                      `json:"max_candidates"`
	ValidIPCount           int                      `json:"valid_ip_count"`
	PoolSize               int                      `json:"pool_size"`
	MinHealthyCount        int                      `json:"min_healthy_count"`
	Concurrency            int                      `json:"concurrency"`
	TargetPort             int                      `json:"target_port"`
	TLS                    bool                     `json:"tls"`
	TLSServerName          string                   `json:"tls_server_name"`
	InsecureSkipVerify     bool                     `json:"insecure_skip_verify"`
	CheckURL               string                   `json:"check_url"`
	ExpectedStatus         int                      `json:"expected_status"`
	ProbeMode              string                   `json:"probe_mode"`
	ScanProbeMode          string                   `json:"scan_probe_mode"`
	HealthProbeMode        string                   `json:"health_probe_mode"`
	RecoveryProbeMode      string                   `json:"recovery_probe_mode"`
	MaxLatency             Duration                 `json:"max_latency"`
	DialTimeout            Duration                 `json:"dial_timeout"`
	Colos                  []string                 `json:"colos"`
	ScanIntervalEnabled    bool                     `json:"scan_interval_enabled"`
	ScanInterval           Duration                 `json:"scan_interval"`
	LatencyMonitorInterval Duration                 `json:"latency_monitor_interval"`
	HealthInterval         Duration                 `json:"health_interval"`
	HealthFailures         int                      `json:"health_failures"`
	RecoveryCooldown       Duration                 `json:"recovery_cooldown"`
	RecoverySuccesses      int                      `json:"recovery_successes"`
	StateFile              string                   `json:"state_file"`
	SourceCacheDir         string                   `json:"source_cache_dir"`
	LogLevel               string                   `json:"log_level"`
	DNS                    DNSConfig                `json:"cloudflare_dns"`
	SpeedTest              SpeedTestConfig          `json:"speed_test"`
	PostPoolSpeedTest      PostPoolSpeedTestConfig  `json:"post_pool_speed_test"`
	BlacklistSpeedTest     BlacklistSpeedTestConfig `json:"blacklist_speed_test"`
	Management             ManagementConfig         `json:"management"`
	Update                 UpdateConfig             `json:"update"`
	Web                    WebConfig                `json:"web"`
	Shodan                 ShodanConfig             `json:"shodan"`
}

func Defaults() Config {
	return Config{
		ConfigVersion:          22,
		Listen:                 "0.0.0.0:1234",
		IPVersion:              4,
		IPSources:              []string{"https://www.cloudflare.com/ips-v4"},
		IPBlacklist:            []string{},
		RandomIPs:              true,
		MaxCandidates:          2000,
		ValidIPCount:           20,
		PoolSize:               10,
		MinHealthyCount:        5,
		Concurrency:            100,
		TargetPort:             443,
		TLS:                    true,
		CheckURL:               "https://cloudflare.com/cdn-cgi/trace",
		ExpectedStatus:         200,
		ProbeMode:              "http",
		ScanProbeMode:          "http",
		HealthProbeMode:        "http",
		RecoveryProbeMode:      "http",
		MaxLatency:             Duration(800 * time.Millisecond),
		DialTimeout:            Duration(3 * time.Second),
		ScanIntervalEnabled:    true,
		ScanInterval:           Duration(6 * time.Hour),
		LatencyMonitorInterval: Duration(2 * time.Second),
		HealthInterval:         Duration(60 * time.Second),
		HealthFailures:         3,
		RecoveryCooldown:       Duration(5 * time.Minute),
		RecoverySuccesses:      2,
		StateFile:              "/var/lib/cfnat/state.json",
		SourceCacheDir:         "/var/lib/cfnat/ip-cache",
		LogLevel:               "info",
		DNS: DNSConfig{
			RecordType: "auto", SyncCount: 1, TTL: 1, TokenEnv: "CF_API_TOKEN",
			Marker: "managed-by:cfnat-linux", LatencySyncEnabled: false, LatencySyncInterval: Duration(5 * time.Minute),
		},
		SpeedTest: SpeedTestConfig{
			Enabled: false, URL: "https://speed.cloudflare.com/__down?bytes=50000000",
			MinMBps: 5, Timeout: Duration(10 * time.Second), MaxCandidates: 50, Concurrency: 3,
		},
		PostPoolSpeedTest: PostPoolSpeedTestConfig{
			Enabled: false, MinMBps: 1, Timeout: Duration(5 * time.Second), AutoBlacklist: false, ExemptList: []string{}, ForceTestList: []string{},
			ExemptDirectPoolEnabled: true, ExemptLatencyFilterEnabled: true, ExemptMaxLatency: Duration(800 * time.Millisecond),
			ExemptProbeMode: "tcp", ExemptLatencyConcurrency: 20,
			ExemptRecoveryEvictEnabled: true, ExemptRecoveryWindow: Duration(24 * time.Hour),
			ExemptRecoveryMaxRatio: 0.6, ExemptRecoveryMinSamples: 20,
		},
		BlacklistSpeedTest: BlacklistSpeedTestConfig{
			Enabled: false, Interval: Duration(24 * time.Hour), Timeout: Duration(5 * time.Second), Concurrency: 3,
		},
		Management: ManagementConfig{PasswordEnabled: false},
		Update: UpdateConfig{
			CheckEnabled: true, CheckInterval: Duration(6 * time.Hour), AutoUpdateEnabled: false,
			Repository: "Jk-z-Box/cfnat-linux",
		},
		Web:    WebConfig{Enabled: true, Listen: "0.0.0.0:8787", Username: "admin", PasswordSHA256: "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"},
		Shodan: ShodanConfig{Enabled: false, DataDir: "/var/lib/cfnat/shodan"},
	}
}

func Load(path string) (Config, error) {
	cfg := Defaults()
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	dec := json.NewDecoder(strings.NewReader(os.ExpandEnv(string(data))))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, err
	}
	cfg.normalizeExclusiveLists()
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	cfg.normalizeProbeModes()
	return cfg, nil
}

// Migrate upgrades only defaults known to be broken. User-selected endpoints are preserved.
func Migrate(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return false, err
	}
	changed := false
	if raw["check_url"] == "https://cloudflaremirrors.com/debian/" {
		raw["check_url"] = "https://cloudflare.com/cdn-cgi/trace"
		changed = true
		if raw["tls_server_name"] == "cloudflaremirrors.com" {
			raw["tls_server_name"] = ""
		}
	}
	if _, ok := raw["source_cache_dir"]; !ok {
		raw["source_cache_dir"] = "/var/lib/cfnat/ip-cache"
		changed = true
	}
	if _, ok := raw["ip_blacklist"]; !ok {
		raw["ip_blacklist"] = []any{}
		changed = true
	}
	if _, ok := raw["min_healthy_count"]; !ok {
		raw["min_healthy_count"] = 5
		changed = true
	}
	if _, ok := raw["latency_monitor_interval"]; !ok {
		raw["latency_monitor_interval"] = "2s"
		changed = true
	}
	if _, ok := raw["probe_mode"]; !ok {
		raw["probe_mode"] = "http"
		changed = true
	}
	probeMode := "http"
	if value, ok := raw["probe_mode"].(string); ok && strings.TrimSpace(value) != "" {
		probeMode = value
	}
	if _, ok := raw["scan_probe_mode"]; !ok {
		raw["scan_probe_mode"] = probeMode
		changed = true
	}
	if _, ok := raw["health_probe_mode"]; !ok {
		raw["health_probe_mode"] = probeMode
		changed = true
	}
	if _, ok := raw["recovery_probe_mode"]; !ok {
		raw["recovery_probe_mode"] = probeMode
		changed = true
	}
	if _, ok := raw["recovery_cooldown"]; !ok {
		raw["recovery_cooldown"] = "5m"
		changed = true
	}
	if _, ok := raw["recovery_successes"]; !ok {
		raw["recovery_successes"] = 2
		changed = true
	}
	if dns, ok := raw["cloudflare_dns"].(map[string]any); ok {
		if _, ok := dns["latency_sync_enabled"]; !ok {
			dns["latency_sync_enabled"] = false
			changed = true
		}
		if _, ok := dns["latency_sync_interval"]; !ok {
			dns["latency_sync_interval"] = "5m"
			changed = true
		}
	}
	if _, ok := raw["speed_test"]; !ok {
		raw["speed_test"] = map[string]any{
			"enabled": false, "url": "https://speed.cloudflare.com/__down?bytes=50000000",
			"min_mbps": 5, "timeout": "10s", "max_candidates": 50, "concurrency": 3,
		}
		changed = true
	} else if speed, ok := raw["speed_test"].(map[string]any); ok {
		if speed["url"] == "https://speed.cloudflare.com/__down?bytes=200000000" {
			speed["url"] = "https://speed.cloudflare.com/__down?bytes=50000000"
			changed = true
		}
		if _, ok := speed["concurrency"]; !ok {
			speed["concurrency"] = 3
			changed = true
		}
	}
	if _, ok := raw["post_pool_speed_test"]; !ok {
		raw["post_pool_speed_test"] = map[string]any{
			"enabled": false, "min_mbps": 1, "timeout": "5s", "auto_blacklist": false, "exempt_list": []any{}, "force_test_list": []any{},
			"exempt_direct_pool_enabled": true, "exempt_latency_filter_enabled": true, "exempt_max_latency": "800ms",
			"exempt_probe_mode": "tcp", "exempt_latency_concurrency": 20,
			"exempt_recovery_evict_enabled": true, "exempt_recovery_window": "24h",
			"exempt_recovery_max_ratio": 0.6, "exempt_recovery_min_samples": 20,
		}
		changed = true
	} else if post, ok := raw["post_pool_speed_test"].(map[string]any); ok {
		if _, ok := post["enabled"]; !ok {
			post["enabled"] = false
			changed = true
		}
		if _, ok := post["min_mbps"]; !ok {
			post["min_mbps"] = 1
			changed = true
		}
		if _, ok := post["timeout"]; !ok {
			post["timeout"] = "5s"
			changed = true
		}
		if _, ok := post["auto_blacklist"]; !ok {
			post["auto_blacklist"] = false
			changed = true
		}
		if _, ok := post["exempt_list"]; !ok {
			post["exempt_list"] = []any{}
			changed = true
		}
		if _, ok := post["force_test_list"]; !ok {
			post["force_test_list"] = []any{}
			changed = true
		}
		if _, ok := post["exempt_direct_pool_enabled"]; !ok {
			post["exempt_direct_pool_enabled"] = true
			changed = true
		}
		if _, ok := post["exempt_latency_filter_enabled"]; !ok {
			post["exempt_latency_filter_enabled"] = true
			changed = true
		}
		if _, ok := post["exempt_max_latency"]; !ok {
			if value, ok := raw["max_latency"].(string); ok && strings.TrimSpace(value) != "" {
				post["exempt_max_latency"] = value
			} else {
				post["exempt_max_latency"] = "800ms"
			}
			changed = true
		}
		if _, ok := post["exempt_probe_mode"]; !ok {
			post["exempt_probe_mode"] = "tcp"
			changed = true
		}
		if _, ok := post["exempt_latency_concurrency"]; !ok {
			post["exempt_latency_concurrency"] = 20
			changed = true
		}
		if _, ok := post["exempt_recovery_evict_enabled"]; !ok {
			post["exempt_recovery_evict_enabled"] = true
			changed = true
		}
		if _, ok := post["exempt_recovery_window"]; !ok {
			post["exempt_recovery_window"] = "24h"
			changed = true
		}
		if _, ok := post["exempt_recovery_max_ratio"]; !ok {
			post["exempt_recovery_max_ratio"] = 0.6
			changed = true
		}
		if _, ok := post["exempt_recovery_min_samples"]; !ok {
			post["exempt_recovery_min_samples"] = 20
			changed = true
		}
	}
	if _, ok := raw["blacklist_speed_test"]; !ok {
		raw["blacklist_speed_test"] = map[string]any{
			"enabled": false, "interval": "24h", "timeout": "5s", "concurrency": 3,
		}
		changed = true
	} else if black, ok := raw["blacklist_speed_test"].(map[string]any); ok {
		if _, ok := black["enabled"]; !ok {
			black["enabled"] = false
			changed = true
		}
		if _, ok := black["interval"]; !ok {
			black["interval"] = "24h"
			changed = true
		} else if interval, ok := black["interval"].(string); ok {
			parsed, err := time.ParseDuration(interval)
			if err != nil || parsed%time.Hour != 0 {
				black["interval"] = "24h"
				changed = true
			}
		}
		if _, ok := black["timeout"]; !ok {
			black["timeout"] = "5s"
			changed = true
		}
		if _, ok := black["concurrency"]; !ok {
			black["concurrency"] = 3
			changed = true
		}
	}
	if _, ok := raw["scan_interval_enabled"]; !ok {
		raw["scan_interval_enabled"] = true
		changed = true
	}
	if _, ok := raw["management"]; !ok {
		raw["management"] = map[string]any{"password_enabled": false, "password_sha256": ""}
		changed = true
	}
	if _, ok := raw["update"]; !ok {
		raw["update"] = map[string]any{
			"check_enabled": true, "check_interval": "6h", "auto_update_enabled": false, "repository": "Jk-z-Box/cfnat-linux",
		}
		changed = true
	} else if update, ok := raw["update"].(map[string]any); ok {
		if _, ok := update["check_enabled"]; !ok {
			update["check_enabled"] = true
			changed = true
		}
		if _, ok := update["check_interval"]; !ok {
			update["check_interval"] = "6h"
			changed = true
		}
		if _, ok := update["auto_update_enabled"]; !ok {
			update["auto_update_enabled"] = false
			changed = true
		}
		if _, ok := update["repository"]; !ok {
			update["repository"] = "Jk-z-Box/cfnat-linux"
			changed = true
		}
	}
	if _, ok := raw["web"]; !ok {
		raw["web"] = map[string]any{"enabled": true, "listen": "0.0.0.0:8787", "username": "admin", "password_sha256": "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"}
		changed = true
	} else if web, ok := raw["web"].(map[string]any); ok {
		if _, ok := web["username"]; !ok {
			web["username"] = "admin"
			changed = true
		}
		if _, ok := web["password_sha256"]; !ok {
			web["password_sha256"] = "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
			changed = true
		}
	}
	if _, ok := raw["shodan"]; !ok {
		raw["shodan"] = map[string]any{"enabled": false, "data_dir": "/var/lib/cfnat/shodan"}
		changed = true
	}
	if version, _ := raw["config_version"].(float64); int(version) < 22 {
		raw["config_version"] = 22
		changed = true
	}
	if normalizeRawExclusiveLists(raw) {
		changed = true
	}
	if !changed {
		return false, nil
	}
	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return false, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return true, os.WriteFile(path, append(out, '\n'), info.Mode().Perm())
}

func Set(path, key, value string) error {
	cfg, err := Load(path)
	if err != nil {
		return err
	}
	switch key {
	case "listen":
		cfg.Listen = value
	case "ip_sources":
		sources := []string{}
		for _, line := range strings.Split(value, "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				sources = append(sources, line)
			}
		}
		cfg.IPSources = sources
	case "ip_blacklist":
		cfg.IPBlacklist = splitNonEmptyLines(value)
	case "max_candidates":
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return errors.New("max_candidates 必须是整数")
		}
		cfg.MaxCandidates = parsed
	case "max_latency":
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return errors.New("延迟格式无效，请使用 300ms、1s 等格式")
		}
		cfg.MaxLatency = Duration(parsed)
	case "probe_mode":
		cfg.ProbeMode = strings.TrimSpace(value)
		cfg.ScanProbeMode = strings.TrimSpace(value)
		cfg.HealthProbeMode = strings.TrimSpace(value)
		cfg.RecoveryProbeMode = strings.TrimSpace(value)
	case "scan_probe_mode":
		cfg.ScanProbeMode = strings.TrimSpace(value)
	case "health_probe_mode":
		cfg.HealthProbeMode = strings.TrimSpace(value)
	case "recovery_probe_mode":
		cfg.RecoveryProbeMode = strings.TrimSpace(value)
	case "min_healthy_count":
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return errors.New("min_healthy_count 必须是整数")
		}
		cfg.MinHealthyCount = parsed
	case "latency_monitor_interval":
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return errors.New("latency_monitor_interval 格式无效，请使用 2s、500ms 等格式")
		}
		cfg.LatencyMonitorInterval = Duration(parsed)
	case "scan_interval_enabled":
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return errors.New("scan_interval_enabled 只能是 true 或 false")
		}
		cfg.ScanIntervalEnabled = parsed
	case "management_password_enabled":
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return errors.New("management_password_enabled 只能是 true 或 false")
		}
		cfg.Management.PasswordEnabled = parsed
	case "management_password_sha256":
		cfg.Management.PasswordSHA256 = value
	case "update_check_enabled":
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return errors.New("update_check_enabled 只能是 true 或 false")
		}
		cfg.Update.CheckEnabled = parsed
	case "update_auto_update_enabled":
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return errors.New("update_auto_update_enabled 只能是 true 或 false")
		}
		cfg.Update.AutoUpdateEnabled = parsed
	case "update_check_interval":
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return errors.New("update_check_interval 格式无效，请使用 6h、24h 等格式")
		}
		cfg.Update.CheckInterval = Duration(parsed)
	case "web_enabled":
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return errors.New("web_enabled 只能是 true 或 false")
		}
		cfg.Web.Enabled = parsed
	case "web_listen":
		cfg.Web.Listen = value
	case "web_username":
		cfg.Web.Username = strings.TrimSpace(value)
	case "web_password_sha256":
		cfg.Web.PasswordSHA256 = value
	case "shodan_enabled":
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return errors.New("shodan_enabled 只能是 true 或 false")
		}
		cfg.Shodan.Enabled = parsed
	case "zone_id":
		cfg.DNS.ZoneID = value
	case "record_name":
		cfg.DNS.RecordName = value
	case "dns_enabled":
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return errors.New("dns_enabled 只能是 true 或 false")
		}
		cfg.DNS.Enabled = parsed
	case "dns_latency_sync_enabled":
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return errors.New("dns_latency_sync_enabled 只能是 true 或 false")
		}
		cfg.DNS.LatencySyncEnabled = parsed
	case "dns_latency_sync_interval":
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return errors.New("dns_latency_sync_interval 格式无效，请使用 5m、1h 等格式")
		}
		cfg.DNS.LatencySyncInterval = Duration(parsed)
	case "speed_test_min_mbps":
		parsed, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return errors.New("speed_test_min_mbps 必须是数字")
		}
		cfg.SpeedTest.MinMBps = parsed
	case "speed_test_enabled":
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return errors.New("speed_test_enabled 只能是 true 或 false")
		}
		cfg.SpeedTest.Enabled = parsed
	case "speed_test_concurrency":
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return errors.New("speed_test_concurrency 必须是整数")
		}
		cfg.SpeedTest.Concurrency = parsed
	case "post_pool_speed_test_enabled":
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return errors.New("post_pool_speed_test_enabled 只能是 true 或 false")
		}
		cfg.PostPoolSpeedTest.Enabled = parsed
	case "post_pool_speed_test_min_mbps":
		parsed, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return errors.New("post_pool_speed_test_min_mbps 必须是数字")
		}
		cfg.PostPoolSpeedTest.MinMBps = parsed
	case "post_pool_speed_test_timeout":
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return errors.New("post_pool_speed_test_timeout 格式无效，请使用 5s、10s 等格式")
		}
		cfg.PostPoolSpeedTest.Timeout = Duration(parsed)
	case "post_pool_speed_test_auto_blacklist":
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return errors.New("post_pool_speed_test_auto_blacklist 只能是 true 或 false")
		}
		cfg.PostPoolSpeedTest.AutoBlacklist = parsed
	case "post_pool_speed_test_exempt_list":
		cfg.PostPoolSpeedTest.ExemptList = splitNonEmptyLines(value)
	case "post_pool_speed_test_force_test_list":
		cfg.PostPoolSpeedTest.ForceTestList = splitNonEmptyLines(value)
	case "post_pool_speed_test_exempt_direct_pool_enabled":
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return errors.New("post_pool_speed_test.exempt_direct_pool_enabled 只能是 true 或 false")
		}
		cfg.PostPoolSpeedTest.ExemptDirectPoolEnabled = parsed
	case "post_pool_speed_test_exempt_latency_filter_enabled":
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return errors.New("post_pool_speed_test.exempt_latency_filter_enabled 只能是 true 或 false")
		}
		cfg.PostPoolSpeedTest.ExemptLatencyFilterEnabled = parsed
	case "post_pool_speed_test_exempt_max_latency":
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return errors.New("post_pool_speed_test.exempt_max_latency 格式无效，请使用 300ms、1s 等格式")
		}
		cfg.PostPoolSpeedTest.ExemptMaxLatency = Duration(parsed)
	case "post_pool_speed_test_exempt_probe_mode":
		cfg.PostPoolSpeedTest.ExemptProbeMode = strings.TrimSpace(value)
	case "post_pool_speed_test_exempt_latency_concurrency":
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return errors.New("post_pool_speed_test.exempt_latency_concurrency 必须是整数")
		}
		cfg.PostPoolSpeedTest.ExemptLatencyConcurrency = parsed
	case "post_pool_speed_test_exempt_recovery_evict_enabled":
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return errors.New("post_pool_speed_test.exempt_recovery_evict_enabled 只能是 true 或 false")
		}
		cfg.PostPoolSpeedTest.ExemptRecoveryEvictEnabled = parsed
	case "post_pool_speed_test_exempt_recovery_window":
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return errors.New("post_pool_speed_test.exempt_recovery_window 格式无效，请使用 24h、7d 不支持，请用 168h")
		}
		cfg.PostPoolSpeedTest.ExemptRecoveryWindow = Duration(parsed)
	case "post_pool_speed_test_exempt_recovery_max_ratio":
		parsed, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return errors.New("post_pool_speed_test.exempt_recovery_max_ratio 必须是数字")
		}
		cfg.PostPoolSpeedTest.ExemptRecoveryMaxRatio = parsed
	case "post_pool_speed_test_exempt_recovery_min_samples":
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return errors.New("post_pool_speed_test.exempt_recovery_min_samples 必须是整数")
		}
		cfg.PostPoolSpeedTest.ExemptRecoveryMinSamples = parsed
	case "blacklist_speed_test_enabled":
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return errors.New("blacklist_speed_test_enabled 只能是 true 或 false")
		}
		cfg.BlacklistSpeedTest.Enabled = parsed
	case "blacklist_speed_test_interval":
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return errors.New("blacklist_speed_test.interval 格式无效，请使用 1h、24h 等小时格式")
		}
		cfg.BlacklistSpeedTest.Interval = Duration(parsed)
	case "blacklist_speed_test_timeout":
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return errors.New("blacklist_speed_test.timeout 格式无效，请使用 5s、10s 等格式")
		}
		cfg.BlacklistSpeedTest.Timeout = Duration(parsed)
	case "blacklist_speed_test_concurrency":
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return errors.New("blacklist_speed_test.concurrency 必须是整数")
		}
		cfg.BlacklistSpeedTest.Concurrency = parsed
	default:
		return fmt.Errorf("不允许修改的配置项: %s", key)
	}
	cfg.normalizeExclusiveListsForWinner(key)
	if err := cfg.Validate(); err != nil {
		return err
	}
	cfg.normalizeProbeModes()
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, info.Mode().Perm())
}

func splitNonEmptyLines(value string) []string {
	items := []string{}
	for _, line := range strings.Split(value, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			items = append(items, line)
		}
	}
	return items
}

func normalizeRawExclusiveLists(raw map[string]any) bool {
	cfg := Defaults()
	data, err := json.Marshal(raw)
	if err != nil || json.Unmarshal(data, &cfg) != nil {
		return false
	}
	oldBlacklist := append([]string(nil), cfg.IPBlacklist...)
	oldForce := append([]string(nil), cfg.PostPoolSpeedTest.ForceTestList...)
	oldExempt := append([]string(nil), cfg.PostPoolSpeedTest.ExemptList...)
	cfg.normalizeExclusiveLists()
	changed := !equalStringSlices(oldBlacklist, cfg.IPBlacklist) ||
		!equalStringSlices(oldForce, cfg.PostPoolSpeedTest.ForceTestList) ||
		!equalStringSlices(oldExempt, cfg.PostPoolSpeedTest.ExemptList)
	if !changed {
		return false
	}
	raw["ip_blacklist"] = cfg.IPBlacklist
	post, ok := raw["post_pool_speed_test"].(map[string]any)
	if !ok {
		post = map[string]any{}
		raw["post_pool_speed_test"] = post
	}
	post["exempt_list"] = cfg.PostPoolSpeedTest.ExemptList
	post["force_test_list"] = cfg.PostPoolSpeedTest.ForceTestList
	return true
}

func (c *Config) normalizeExclusiveLists() {
	c.IPBlacklist = normalizeList(c.IPBlacklist)
	c.PostPoolSpeedTest.ForceTestList = filterCoveredEntries(normalizeList(c.PostPoolSpeedTest.ForceTestList), c.IPBlacklist)
	higher := append([]string(nil), c.IPBlacklist...)
	higher = append(higher, c.PostPoolSpeedTest.ForceTestList...)
	c.PostPoolSpeedTest.ExemptList = filterCoveredEntries(normalizeList(c.PostPoolSpeedTest.ExemptList), higher)
}

func (c *Config) normalizeExclusiveListsForWinner(key string) {
	c.IPBlacklist = normalizeList(c.IPBlacklist)
	c.PostPoolSpeedTest.ForceTestList = normalizeList(c.PostPoolSpeedTest.ForceTestList)
	c.PostPoolSpeedTest.ExemptList = normalizeList(c.PostPoolSpeedTest.ExemptList)
	switch key {
	case "ip_blacklist":
		c.PostPoolSpeedTest.ForceTestList = filterCoveredEntries(c.PostPoolSpeedTest.ForceTestList, c.IPBlacklist)
		c.PostPoolSpeedTest.ExemptList = filterCoveredEntries(c.PostPoolSpeedTest.ExemptList, c.IPBlacklist)
	case "post_pool_speed_test_force_test_list":
		c.IPBlacklist = filterCoveredEntries(c.IPBlacklist, c.PostPoolSpeedTest.ForceTestList)
		c.PostPoolSpeedTest.ExemptList = filterCoveredEntries(c.PostPoolSpeedTest.ExemptList, c.PostPoolSpeedTest.ForceTestList)
	case "post_pool_speed_test_exempt_list":
		c.IPBlacklist = filterCoveredEntries(c.IPBlacklist, c.PostPoolSpeedTest.ExemptList)
		c.PostPoolSpeedTest.ForceTestList = filterCoveredEntries(c.PostPoolSpeedTest.ForceTestList, c.PostPoolSpeedTest.ExemptList)
	default:
		c.normalizeExclusiveLists()
	}
}

func normalizeList(items []string) []string {
	normalized := make([]string, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		key := strings.ToLower(item)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, item)
	}
	return normalized
}

func filterCoveredEntries(items, higher []string) []string {
	filtered := make([]string, 0, len(items))
	for _, item := range items {
		if entryCoveredBy(item, higher) {
			continue
		}
		filtered = append(filtered, item)
	}
	return filtered
}

func entryCoveredBy(item string, higher []string) bool {
	for _, high := range higher {
		if entriesOverlapOrCover(strings.TrimSpace(item), strings.TrimSpace(high)) {
			return true
		}
	}
	return false
}

func entriesOverlapOrCover(item, high string) bool {
	if item == "" || high == "" {
		return false
	}
	itemIsPrefix, itemAddr, itemPrefix, itemOK := parseAddrOrPrefix(item)
	highIsPrefix, highAddr, highPrefix, highOK := parseAddrOrPrefix(high)
	if !itemOK || !highOK {
		return strings.EqualFold(item, high)
	}
	if !itemIsPrefix && !highIsPrefix {
		return itemAddr == highAddr
	}
	if !itemIsPrefix && highIsPrefix {
		return highPrefix.Masked().Contains(itemAddr)
	}
	if itemIsPrefix && highIsPrefix {
		hp := highPrefix.Masked()
		ip := itemPrefix.Masked()
		return hp.Bits() <= ip.Bits() && hp.Contains(ip.Addr())
	}
	return false
}

func parseAddrOrPrefix(value string) (bool, netip.Addr, netip.Prefix, bool) {
	if strings.Contains(value, "/") {
		prefix, err := netip.ParsePrefix(value)
		return true, netip.Addr{}, prefix, err == nil
	}
	addr, err := netip.ParseAddr(value)
	return false, addr, netip.Prefix{}, err == nil
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func normalizeProbeMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "http", "https":
		return "http"
	case "tcp", "tcping":
		return "tcp"
	case "icmp", "ping":
		return "icmp"
	default:
		return ""
	}
}

func (c *Config) normalizeProbeModes() {
	c.ProbeMode = normalizeProbeMode(c.ProbeMode)
	if strings.TrimSpace(c.ScanProbeMode) == "" {
		c.ScanProbeMode = c.ProbeMode
	}
	if strings.TrimSpace(c.HealthProbeMode) == "" {
		c.HealthProbeMode = c.ProbeMode
	}
	if strings.TrimSpace(c.RecoveryProbeMode) == "" {
		c.RecoveryProbeMode = c.HealthProbeMode
	}
	c.ScanProbeMode = normalizeProbeMode(c.ScanProbeMode)
	c.HealthProbeMode = normalizeProbeMode(c.HealthProbeMode)
	c.RecoveryProbeMode = normalizeProbeMode(c.RecoveryProbeMode)
	c.PostPoolSpeedTest.ExemptProbeMode = normalizeProbeMode(c.PostPoolSpeedTest.ExemptProbeMode)
}

func validateProbeModeField(name, value string) error {
	raw := strings.TrimSpace(value)
	mode := normalizeProbeMode(raw)
	if mode == "" || raw == "" && value != "" {
		return fmt.Errorf("%s 只能是 http、tcp/tcping 或 icmp/ping", name)
	}
	return nil
}

func (c *Config) Validate() error {
	if c.Listen == "" {
		return errors.New("listen 不能为空")
	}
	_, listenPort, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return fmt.Errorf("listen 格式无效，应类似 0.0.0.0:1234 或 [::]:1234: %w", err)
	}
	port, err := strconv.Atoi(listenPort)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("listen 端口必须在 1-65535 范围内")
	}
	if c.IPVersion != 4 && c.IPVersion != 6 {
		return errors.New("ip_version 只能是 4 或 6")
	}
	if len(c.IPSources) == 0 {
		return errors.New("ip_sources 至少需要一个来源")
	}
	for _, item := range c.IPBlacklist {
		if _, err := netipOrPrefix(item); err != nil {
			return fmt.Errorf("ip_blacklist 包含无效 IP 或 CIDR: %q", item)
		}
	}
	for _, item := range c.PostPoolSpeedTest.ExemptList {
		if _, err := netipOrPrefix(item); err != nil {
			return fmt.Errorf("post_pool_speed_test.exempt_list 包含无效 IP 或 CIDR: %q", item)
		}
	}
	for _, item := range c.PostPoolSpeedTest.ForceTestList {
		if _, err := netipOrPrefix(item); err != nil {
			return fmt.Errorf("post_pool_speed_test.force_test_list 包含无效 IP 或 CIDR: %q", item)
		}
	}
	if c.MaxCandidates < 1 || c.Concurrency < 1 || c.ValidIPCount < 1 || c.PoolSize < 1 || c.MinHealthyCount < 1 {
		return errors.New("候选数、并发数、有效 IP 数、池大小和最小健康 IP 数必须大于 0")
	}
	if c.PoolSize > c.ValidIPCount {
		return errors.New("pool_size 不能大于 valid_ip_count")
	}
	if c.MinHealthyCount > c.PoolSize {
		return errors.New("min_healthy_count 不能大于 pool_size")
	}
	if c.TargetPort < 1 || c.TargetPort > 65535 {
		return errors.New("target_port 超出范围")
	}
	if err := validateProbeModeField("probe_mode", c.ProbeMode); err != nil {
		return err
	}
	if err := validateProbeModeField("scan_probe_mode", c.ScanProbeMode); err != nil {
		return err
	}
	if err := validateProbeModeField("health_probe_mode", c.HealthProbeMode); err != nil {
		return err
	}
	if err := validateProbeModeField("recovery_probe_mode", c.RecoveryProbeMode); err != nil {
		return err
	}
	if err := validateProbeModeField("post_pool_speed_test.exempt_probe_mode", c.PostPoolSpeedTest.ExemptProbeMode); err != nil {
		return err
	}
	if c.RecoverySuccesses < 1 {
		return errors.New("recovery_successes 必须大于 0")
	}
	if c.MaxLatency.Value() <= 0 || c.DialTimeout.Value() <= 0 || c.ScanInterval.Value() <= 0 || c.HealthInterval.Value() <= 0 || c.LatencyMonitorInterval.Value() <= 0 || c.RecoveryCooldown.Value() <= 0 || c.Update.CheckInterval.Value() <= 0 {
		return errors.New("超时时间必须大于 0")
	}
	if strings.TrimSpace(c.Update.Repository) == "" || !regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`).MatchString(c.Update.Repository) {
		return errors.New("update.repository 必须是 owner/repo 格式")
	}
	if c.Web.Enabled {
		if _, _, err := net.SplitHostPort(c.Web.Listen); err != nil {
			return fmt.Errorf("web.listen 格式无效，应类似 0.0.0.0:8787 或 [::]:8787: %w", err)
		}
		if strings.TrimSpace(c.Web.Username) == "" {
			return errors.New("web.username 不能为空")
		}
		if !regexp.MustCompile(`^[a-fA-F0-9]{64}$`).MatchString(c.Web.PasswordSHA256) {
			return errors.New("web.password_sha256 必须是 64 位 SHA-256 十六进制字符串")
		}
	}
	if strings.TrimSpace(c.Shodan.DataDir) == "" {
		return errors.New("shodan.data_dir 不能为空")
	}
	if c.Management.PasswordSHA256 != "" && !regexp.MustCompile(`^[a-fA-F0-9]{64}$`).MatchString(c.Management.PasswordSHA256) {
		return errors.New("management.password_sha256 必须是空值或 64 位 SHA-256 十六进制字符串")
	}
	if c.Management.PasswordEnabled && c.Management.PasswordSHA256 == "" {
		return errors.New("启用管理密码时 management.password_sha256 不能为空")
	}
	if c.SpeedTest.Enabled {
		if c.SpeedTest.MinMBps <= 0 {
			return errors.New("启用测速筛选时 speed_test.min_mbps 必须大于 0")
		}
		if c.SpeedTest.Timeout.Value() <= 0 {
			return errors.New("speed_test.timeout 必须大于 0")
		}
		if c.SpeedTest.MaxCandidates < 1 {
			return errors.New("speed_test.max_candidates 必须大于 0")
		}
		if c.SpeedTest.Concurrency < 1 {
			return errors.New("speed_test.concurrency 必须大于 0")
		}
	}
	if c.PostPoolSpeedTest.Enabled {
		if c.PostPoolSpeedTest.MinMBps <= 0 {
			return errors.New("启用入池后测速筛选时 post_pool_speed_test.min_mbps 必须大于 0")
		}
		if c.PostPoolSpeedTest.Timeout.Value() <= 0 {
			return errors.New("post_pool_speed_test.timeout 必须大于 0")
		}
	}
	if c.PostPoolSpeedTest.ExemptRecoveryWindow.Value() <= 0 {
		return errors.New("post_pool_speed_test.exempt_recovery_window 必须大于 0")
	}
	if c.PostPoolSpeedTest.ExemptMaxLatency.Value() <= 0 {
		return errors.New("post_pool_speed_test.exempt_max_latency 必须大于 0")
	}
	if c.PostPoolSpeedTest.ExemptLatencyConcurrency < 1 {
		return errors.New("post_pool_speed_test.exempt_latency_concurrency 必须大于 0")
	}
	if c.PostPoolSpeedTest.ExemptRecoveryMaxRatio <= 0 || c.PostPoolSpeedTest.ExemptRecoveryMaxRatio > 1 {
		return errors.New("post_pool_speed_test.exempt_recovery_max_ratio 必须大于 0 且小于等于 1")
	}
	if c.PostPoolSpeedTest.ExemptRecoveryMinSamples < 1 {
		return errors.New("post_pool_speed_test.exempt_recovery_min_samples 必须大于 0")
	}
	if c.BlacklistSpeedTest.Enabled {
		if c.BlacklistSpeedTest.Interval.Value() <= 0 {
			return errors.New("blacklist_speed_test.interval 必须大于 0")
		}
		if c.BlacklistSpeedTest.Interval.Value()%time.Hour != 0 {
			return errors.New("blacklist_speed_test.interval 必须以小时为单位，例如 1h、24h")
		}
		if c.BlacklistSpeedTest.Timeout.Value() <= 0 {
			return errors.New("blacklist_speed_test.timeout 必须大于 0")
		}
		if c.BlacklistSpeedTest.Concurrency < 1 {
			return errors.New("blacklist_speed_test.concurrency 必须大于 0")
		}
		if c.PostPoolSpeedTest.MinMBps <= 0 {
			return errors.New("启用黑名单 IP 定时测速时 post_pool_speed_test.min_mbps 必须大于 0")
		}
	}
	if c.SpeedTest.Enabled || c.PostPoolSpeedTest.Enabled || c.BlacklistSpeedTest.Enabled {
		u, err := url.Parse(c.SpeedTest.URL)
		if err != nil || u.Hostname() == "" || (u.Scheme != "https" && u.Scheme != "http") {
			return fmt.Errorf("speed_test.url 无效: %q", c.SpeedTest.URL)
		}
	}
	if c.DNS.LatencySyncInterval.Value() <= 0 {
		return errors.New("cloudflare_dns.latency_sync_interval 必须大于 0")
	}
	u, err := url.Parse(c.CheckURL)
	if err != nil || u.Hostname() == "" {
		return fmt.Errorf("check_url 无效: %q", c.CheckURL)
	}
	if c.TLS && u.Scheme != "https" {
		return errors.New("tls=true 时 check_url 必须使用 https")
	}
	for i := range c.Colos {
		c.Colos[i] = strings.ToUpper(strings.TrimSpace(c.Colos[i]))
	}
	if c.DNS.ZoneID != "" && !regexp.MustCompile(`^[A-Fa-f0-9]{32}$`).MatchString(c.DNS.ZoneID) {
		return errors.New("cloudflare_dns.zone_id 必须是 32 位十六进制字符串")
	}
	if c.DNS.RecordName != "" && !validRecordName(c.DNS.RecordName) {
		return errors.New("cloudflare_dns.record_name 不是有效的完整域名")
	}
	if c.DNS.Enabled {
		if c.DNS.ZoneID == "" || c.DNS.RecordName == "" {
			return errors.New("启用 Cloudflare DNS 时 zone_id 和 record_name 不能为空")
		}
		if c.DNS.SyncCount < 1 || c.DNS.SyncCount > c.PoolSize {
			return errors.New("cloudflare_dns.sync_count 必须在 1 到 pool_size 之间")
		}
		if c.DNS.TTL != 1 && c.DNS.TTL < 60 {
			return errors.New("cloudflare_dns.ttl 必须为 1（自动）或至少 60 秒")
		}
		if c.DNS.Proxied {
			return errors.New("优选 IP 记录必须设置 proxied=false，否则解析结果会被 Cloudflare Anycast 隐藏")
		}
		if strings.TrimSpace(c.DNS.Marker) == "" {
			return errors.New("cloudflare_dns.marker 不能为空，以免误删非托管记录")
		}
		if c.DNS.LatencySyncEnabled && c.DNS.LatencySyncInterval.Value() <= 0 {
			return errors.New("cloudflare_dns.latency_sync_interval 必须大于 0")
		}
		want := map[int]string{4: "A", 6: "AAAA"}[c.IPVersion]
		if c.DNS.RecordType == "auto" {
			c.DNS.RecordType = want
		}
		if strings.ToUpper(c.DNS.RecordType) != want {
			return fmt.Errorf("IP v%d 必须使用 %s 记录", c.IPVersion, want)
		}
		c.DNS.RecordType = want
		if c.DNS.TokenEnv == "" {
			c.DNS.TokenEnv = "CF_API_TOKEN"
		}
	}
	return nil
}

func validRecordName(name string) bool {
	if len(name) > 253 || !strings.Contains(name, ".") || strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") {
		return false
	}
	labelPattern := regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	for _, label := range strings.Split(name, ".") {
		if !labelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

func netipOrPrefix(value string) (bool, error) {
	if strings.Contains(value, "/") {
		_, err := netip.ParsePrefix(value)
		return true, err
	}
	_, err := netip.ParseAddr(value)
	return false, err
}
