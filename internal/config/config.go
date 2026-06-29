package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
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

type Config struct {
	ConfigVersion          int             `json:"config_version"`
	Listen                 string          `json:"listen"`
	IPVersion              int             `json:"ip_version"`
	IPSources              []string        `json:"ip_sources"`
	RandomIPs              bool            `json:"random_ips"`
	MaxCandidates          int             `json:"max_candidates"`
	ValidIPCount           int             `json:"valid_ip_count"`
	PoolSize               int             `json:"pool_size"`
	MinHealthyCount        int             `json:"min_healthy_count"`
	Concurrency            int             `json:"concurrency"`
	TargetPort             int             `json:"target_port"`
	TLS                    bool            `json:"tls"`
	TLSServerName          string          `json:"tls_server_name"`
	InsecureSkipVerify     bool            `json:"insecure_skip_verify"`
	CheckURL               string          `json:"check_url"`
	ExpectedStatus         int             `json:"expected_status"`
	MaxLatency             Duration        `json:"max_latency"`
	DialTimeout            Duration        `json:"dial_timeout"`
	Colos                  []string        `json:"colos"`
	ScanInterval           Duration        `json:"scan_interval"`
	LatencyMonitorInterval Duration        `json:"latency_monitor_interval"`
	HealthInterval         Duration        `json:"health_interval"`
	HealthFailures         int             `json:"health_failures"`
	StateFile              string          `json:"state_file"`
	SourceCacheDir         string          `json:"source_cache_dir"`
	LogLevel               string          `json:"log_level"`
	DNS                    DNSConfig       `json:"cloudflare_dns"`
	SpeedTest              SpeedTestConfig `json:"speed_test"`
}

func Defaults() Config {
	return Config{
		ConfigVersion:          9,
		Listen:                 "0.0.0.0:1234",
		IPVersion:              4,
		IPSources:              []string{"https://www.cloudflare.com/ips-v4"},
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
		MaxLatency:             Duration(800 * time.Millisecond),
		DialTimeout:            Duration(3 * time.Second),
		ScanInterval:           Duration(6 * time.Hour),
		LatencyMonitorInterval: Duration(2 * time.Second),
		HealthInterval:         Duration(60 * time.Second),
		HealthFailures:         3,
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
	return cfg, cfg.Validate()
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
	if _, ok := raw["min_healthy_count"]; !ok {
		raw["min_healthy_count"] = 5
		changed = true
	}
	if _, ok := raw["latency_monitor_interval"]; !ok {
		raw["latency_monitor_interval"] = "2s"
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
	if version, _ := raw["config_version"].(float64); int(version) < 9 {
		raw["config_version"] = 9
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
	case "max_latency":
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return errors.New("延迟格式无效，请使用 300ms、1s 等格式")
		}
		cfg.MaxLatency = Duration(parsed)
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
	default:
		return fmt.Errorf("不允许修改的配置项: %s", key)
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
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
	if c.MaxLatency.Value() <= 0 || c.DialTimeout.Value() <= 0 || c.ScanInterval.Value() <= 0 || c.HealthInterval.Value() <= 0 || c.LatencyMonitorInterval.Value() <= 0 {
		return errors.New("超时时间必须大于 0")
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
