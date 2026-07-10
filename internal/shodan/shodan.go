package shodan

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/cfnat-linux/cfnat-linux/internal/config"
)

type Profile struct {
	Name               string `json:"name"`
	APIKey             string `json:"api_key"`
	Ports              string `json:"ports"`
	Countries          string `json:"countries"`
	ASNs               string `json:"asns"`
	Keywords           string `json:"keywords"`
	ExtraFilters       string `json:"extra_filters"`
	RawQuery           string `json:"raw_query"`
	FetchCount         int    `json:"fetch_count"`
	DownloadEnabled    bool   `json:"download_enabled"`
	AutoFetchEnabled   bool   `json:"auto_fetch_enabled"`
	AutoFetchInterval  string `json:"auto_fetch_interval"`
	LastAutoFetchAt    string `json:"last_auto_fetch_at"`
	NextAutoFetchAt    string `json:"next_auto_fetch_at"`
	LastAutoFetchError string `json:"last_auto_fetch_error"`
	LastSuccessAt      string `json:"last_success_at"`
	ReportedTotal      int    `json:"reported_total"`
	UniqueIPsWritten   int    `json:"unique_ips_written"`
	LastFile           string `json:"last_file"`
	LastQuery          string `json:"last_query"`
}

type StoreConfig struct {
	ActiveProfile string             `json:"active_profile"`
	Profiles      map[string]Profile `json:"profiles"`
}

type Status struct {
	State             string `json:"state"`
	LastRunAt         string `json:"last_run_at"`
	LastSuccessAt     string `json:"last_success_at"`
	ActiveProfile     string `json:"active_profile"`
	LastQuery         string `json:"last_query"`
	ReportedTotal     int    `json:"reported_total"`
	RawMatchesFetched int    `json:"raw_matches_fetched"`
	UniqueIPsWritten  int    `json:"unique_ips_written"`
	LastFile          string `json:"last_file"`
	LastError         string `json:"last_error"`
}

type Manager struct {
	cfg      config.ShodanConfig
	mu       sync.Mutex
	client   *http.Client
	onChange func()
}

func New(cfg config.ShodanConfig) *Manager {
	return &Manager{cfg: cfg, client: &http.Client{Timeout: 60 * time.Second}}
}

func (m *Manager) SetOnChange(fn func()) {
	m.onChange = fn
}

func (m *Manager) Enabled() bool { return m.cfg.Enabled }

func (m *Manager) ensure() error {
	if err := os.MkdirAll(filepath.Join(m.cfg.DataDir, "results"), 0750); err != nil {
		return err
	}
	cfg, err := m.Config()
	if err != nil {
		return err
	}
	if len(cfg.Profiles) == 0 {
		cfg.ActiveProfile = "default"
		cfg.Profiles = map[string]Profile{"default": defaultProfile("default")}
		if err := m.SaveConfig(cfg); err != nil {
			return err
		}
	}
	if _, err := os.Stat(m.statusPath()); os.IsNotExist(err) {
		return m.writeJSON(m.statusPath(), Status{State: "idle"})
	}
	return nil
}

func defaultProfile(name string) Profile {
	return Profile{Name: name, Ports: "443", Countries: "SG", ASNs: "AS16509", Keywords: "cloudflare\nForbidden", FetchCount: 200}
}

func (m *Manager) configPath() string { return filepath.Join(m.cfg.DataDir, "config.json") }
func (m *Manager) statusPath() string { return filepath.Join(m.cfg.DataDir, "status.json") }

func (m *Manager) Config() (StoreConfig, error) {
	var cfg StoreConfig
	if err := readJSON(m.configPath(), &cfg); err != nil {
		if os.IsNotExist(err) {
			return StoreConfig{ActiveProfile: "default", Profiles: map[string]Profile{"default": defaultProfile("default")}}, nil
		}
		return cfg, err
	}
	if cfg.Profiles == nil {
		cfg.Profiles = map[string]Profile{}
	}
	for name, profile := range cfg.Profiles {
		cfg.Profiles[name] = normalizeProfile(name, profile)
	}
	if cfg.ActiveProfile == "" || cfg.Profiles[cfg.ActiveProfile].Name == "" {
		for name := range cfg.Profiles {
			cfg.ActiveProfile = name
			break
		}
	}
	return cfg, nil
}

func (m *Manager) SaveConfig(cfg StoreConfig) error {
	if cfg.Profiles == nil {
		cfg.Profiles = map[string]Profile{}
	}
	for name, profile := range cfg.Profiles {
		cfg.Profiles[name] = normalizeProfile(name, profile)
	}
	if cfg.ActiveProfile == "" {
		for name := range cfg.Profiles {
			cfg.ActiveProfile = name
			break
		}
	}
	return m.writeJSON(m.configPath(), cfg)
}

func (m *Manager) Status() Status {
	var status Status
	if err := readJSON(m.statusPath(), &status); err != nil || status.State == "" {
		return Status{State: "idle"}
	}
	return status
}

func (m *Manager) Active() (StoreConfig, Profile, Status, error) {
	if err := m.ensure(); err != nil {
		return StoreConfig{}, Profile{}, Status{}, err
	}
	cfg, err := m.Config()
	if err != nil {
		return cfg, Profile{}, Status{}, err
	}
	profile := cfg.Profiles[cfg.ActiveProfile]
	return cfg, profile, m.Status(), nil
}

func (m *Manager) UpdateActive(update Profile) error {
	cfg, err := m.Config()
	if err != nil {
		return err
	}
	name := cfg.ActiveProfile
	current := cfg.Profiles[name]
	current.APIKey = strings.TrimSpace(update.APIKey)
	current.Ports = strings.TrimSpace(update.Ports)
	current.Countries = strings.TrimSpace(update.Countries)
	current.ASNs = strings.TrimSpace(update.ASNs)
	current.Keywords = strings.TrimSpace(update.Keywords)
	current.ExtraFilters = strings.TrimSpace(update.ExtraFilters)
	current.RawQuery = strings.TrimSpace(update.RawQuery)
	current.FetchCount = update.FetchCount
	cfg.Profiles[name] = normalizeProfile(name, current)
	return m.SaveConfig(cfg)
}

func (m *Manager) ToggleDownload() error {
	cfg, err := m.Config()
	if err != nil {
		return err
	}
	p := cfg.Profiles[cfg.ActiveProfile]
	p.DownloadEnabled = !p.DownloadEnabled
	cfg.Profiles[cfg.ActiveProfile] = normalizeProfile(cfg.ActiveProfile, p)
	return m.SaveConfig(cfg)
}

func (m *Manager) SwitchProfile(name string) error {
	cfg, err := m.Config()
	if err != nil {
		return err
	}
	if _, ok := cfg.Profiles[name]; !ok {
		return fmt.Errorf("配置不存在")
	}
	cfg.ActiveProfile = name
	return m.SaveConfig(cfg)
}

func (m *Manager) NewProfile(name string) error {
	name = Slug(name)
	if name == "" {
		return fmt.Errorf("配置名不可为空")
	}
	cfg, err := m.Config()
	if err != nil {
		return err
	}
	if _, ok := cfg.Profiles[name]; ok {
		return fmt.Errorf("配置已存在")
	}
	cfg.Profiles[name] = defaultProfile(name)
	cfg.ActiveProfile = name
	return m.SaveConfig(cfg)
}

func (m *Manager) DeleteActive() error {
	cfg, err := m.Config()
	if err != nil {
		return err
	}
	if len(cfg.Profiles) <= 1 {
		return fmt.Errorf("至少保留一个配置")
	}
	delete(cfg.Profiles, cfg.ActiveProfile)
	for name := range cfg.Profiles {
		cfg.ActiveProfile = name
		break
	}
	return m.SaveConfig(cfg)
}

func (m *Manager) FetchAsync(ctx context.Context) {
	go func() { _ = m.Fetch(ctx) }()
}

func (m *Manager) Fetch(ctx context.Context) error {
	cfg, err := m.Config()
	if err != nil {
		return err
	}
	return m.FetchProfile(ctx, cfg.ActiveProfile)
}

func (m *Manager) FetchProfile(ctx context.Context, profileName string) error {
	if !m.mu.TryLock() {
		m.setStatus(Status{State: "running", LastError: "已有 Shodan 获取任务正在运行"})
		return nil
	}
	defer m.mu.Unlock()
	if err := m.ensure(); err != nil {
		return err
	}
	cfg, err := m.Config()
	if err != nil {
		return err
	}
	profileName = Slug(profileName)
	profile, ok := cfg.Profiles[profileName]
	if !ok {
		return fmt.Errorf("Shodan 配置不存在: %s", profileName)
	}
	query := BuildQuery(profile)
	if strings.TrimSpace(profile.APIKey) == "" {
		err = fmt.Errorf("Shodan API Key 为空")
		m.updateError(err)
		return err
	}
	if query == "" {
		err = fmt.Errorf("Shodan 查询语法为空")
		m.updateError(err)
		return err
	}
	start := now()
	m.setStatus(Status{State: "running", LastRunAt: start, ActiveProfile: profileName, LastQuery: query})
	total, raw, unique, err := m.search(ctx, profile.APIKey, query, profile.FetchCount)
	if err != nil {
		m.updateError(err)
		return err
	}
	name := filenameFor(profile, query)
	out := filepath.Join(m.cfg.DataDir, "results", name)
	if err := os.WriteFile(out, []byte(strings.Join(unique, "\n")+"\n"), 0640); err != nil {
		m.updateError(err)
		return err
	}
	copyPath := m.ProfilePath(profileName)
	_ = os.WriteFile(copyPath, []byte(strings.Join(unique, "\n")+"\n"), 0640)
	success := now()
	profile.LastSuccessAt = success
	profile.LastAutoFetchError = ""
	profile.ReportedTotal = total
	profile.UniqueIPsWritten = len(unique)
	profile.LastFile = copyPath
	profile.LastQuery = query
	cfg.Profiles[profileName] = normalizeProfile(profileName, profile)
	_ = m.SaveConfig(cfg)
	m.setStatus(Status{State: "idle", LastRunAt: start, LastSuccessAt: success, ActiveProfile: profileName, LastQuery: query, ReportedTotal: total, RawMatchesFetched: len(raw), UniqueIPsWritten: len(unique), LastFile: copyPath})
	return nil
}

func (m *Manager) UpdateActiveSchedule(enabled bool, interval string) error {
	cfg, err := m.Config()
	if err != nil {
		return err
	}
	name := cfg.ActiveProfile
	p := cfg.Profiles[name]
	parsed, err := parseAutoFetchInterval(interval)
	if err != nil {
		return err
	}
	p.AutoFetchEnabled = enabled
	p.AutoFetchInterval = parsed.String()
	if enabled {
		p.NextAutoFetchAt = time.Now().Add(parsed).Format(time.RFC3339)
	} else {
		p.NextAutoFetchAt = ""
	}
	cfg.Profiles[name] = normalizeProfile(name, p)
	return m.SaveConfig(cfg)
}

func (m *Manager) AutoFetchLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.RunDueAutoFetch(ctx)
		}
	}
}

func (m *Manager) RunDueAutoFetch(ctx context.Context) {
	if !m.cfg.Enabled {
		return
	}
	cfg, err := m.Config()
	if err != nil {
		return
	}
	nowTime := time.Now()
	for name, profile := range cfg.Profiles {
		profile = normalizeProfile(name, profile)
		if !profile.AutoFetchEnabled {
			continue
		}
		interval, err := parseAutoFetchInterval(profile.AutoFetchInterval)
		if err != nil {
			profile.LastAutoFetchError = err.Error()
			cfg.Profiles[name] = profile
			_ = m.SaveConfig(cfg)
			continue
		}
		due := false
		if profile.NextAutoFetchAt == "" {
			due = true
		} else if next, err := time.Parse(time.RFC3339, profile.NextAutoFetchAt); err != nil || !next.After(nowTime) {
			due = true
		}
		if !due {
			continue
		}
		_ = m.markAutoFetchDue(name, nowTime, interval)
		if err := m.FetchProfile(ctx, name); err != nil {
			m.recordAutoFetch(name, err)
		} else {
			m.recordAutoFetch(name, nil)
		}
	}
}

func (m *Manager) markAutoFetchDue(name string, at time.Time, interval time.Duration) error {
	cfg, err := m.Config()
	if err != nil {
		return err
	}
	p := cfg.Profiles[name]
	p.LastAutoFetchAt = at.Format(time.RFC3339)
	p.NextAutoFetchAt = at.Add(interval).Format(time.RFC3339)
	cfg.Profiles[name] = normalizeProfile(name, p)
	return m.SaveConfig(cfg)
}

func (m *Manager) recordAutoFetch(name string, err error) {
	cfg, cfgErr := m.Config()
	if cfgErr != nil {
		return
	}
	p := cfg.Profiles[name]
	interval, intervalErr := parseAutoFetchInterval(p.AutoFetchInterval)
	if intervalErr != nil {
		interval = 6 * time.Hour
	}
	p.LastAutoFetchAt = time.Now().Format(time.RFC3339)
	p.NextAutoFetchAt = time.Now().Add(interval).Format(time.RFC3339)
	if err != nil {
		p.LastAutoFetchError = err.Error()
	} else {
		p.LastAutoFetchError = ""
	}
	cfg.Profiles[name] = normalizeProfile(name, p)
	_ = m.SaveConfig(cfg)
}

func (m *Manager) ProfilePath(name string) string {
	return filepath.Join(m.cfg.DataDir, fmt.Sprintf("%s.txt", Slug(name)))
}

func (m *Manager) LegacyProfilePath(name string) string {
	return filepath.Join(m.cfg.DataDir, fmt.Sprintf("shodan_ips_%s.txt", Slug(name)))
}

func (m *Manager) search(ctx context.Context, apiKey, query string, fetchCount int) (int, []string, []string, error) {
	pages := (fetchCount + 99) / 100
	all := make([]string, 0, fetchCount)
	total := 0
	for page := 1; page <= pages; page++ {
		values := url.Values{"key": {apiKey}, "query": {query}, "page": {fmt.Sprint(page)}}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.shodan.io/shodan/host/search?"+values.Encode(), nil)
		if err != nil {
			return 0, nil, nil, err
		}
		req.Header.Set("User-Agent", "cfnat-linux-shodan-panel/1.0")
		resp, err := m.client.Do(req)
		if err != nil {
			return 0, nil, nil, err
		}
		var payload struct {
			Total   int `json:"total"`
			Matches []struct {
				IP string `json:"ip_str"`
			} `json:"matches"`
			Error string `json:"error"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
			resp.Body.Close()
			return 0, nil, nil, err
		}
		resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			if payload.Error == "" {
				payload.Error = resp.Status
			}
			return 0, nil, nil, fmt.Errorf("Shodan API HTTP %d: %s", resp.StatusCode, payload.Error)
		}
		if page == 1 {
			total = payload.Total
		}
		for _, item := range payload.Matches {
			if item.IP != "" {
				all = append(all, item.IP)
			}
		}
		if len(all) >= fetchCount {
			break
		}
	}
	seen := map[string]struct{}{}
	unique := make([]string, 0, fetchCount)
	for _, ip := range all {
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		unique = append(unique, ip)
		if len(unique) >= fetchCount {
			break
		}
	}
	return total, all, unique, nil
}

func (m *Manager) updateError(err error) {
	s := m.Status()
	s.State = "error"
	s.LastError = err.Error()
	m.setStatus(s)
}

func (m *Manager) setStatus(s Status) {
	if s.State == "" {
		s.State = "idle"
	}
	_ = m.writeJSON(m.statusPath(), s)
	if m.onChange != nil {
		m.onChange()
	}
}

func (m *Manager) writeJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0640)
}

func readJSON(path string, out any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

func normalizeProfile(name string, p Profile) Profile {
	if p.Name == "" {
		p.Name = name
	}
	if strings.TrimSpace(p.AutoFetchInterval) == "" {
		p.AutoFetchInterval = "6h"
	}
	if p.FetchCount < 1 {
		p.FetchCount = 200
	}
	if p.FetchCount > 10000 {
		p.FetchCount = 10000
	}
	return p
}

func parseAutoFetchInterval(value string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		value = "6h"
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("定时获取间隔格式无效，请使用 30m、6h、24h 等格式")
	}
	if parsed < time.Minute {
		return 0, fmt.Errorf("定时获取间隔不能小于 1m")
	}
	return parsed, nil
}

func BuildQuery(p Profile) string {
	if strings.TrimSpace(p.RawQuery) != "" {
		return strings.TrimSpace(p.RawQuery)
	}
	parts := []string{
		orGroup("port", splitValues(p.Ports)),
		orGroup("country", upperValues(splitValues(p.Countries))),
		orGroup("asn", splitValues(p.ASNs)),
	}
	for _, kw := range splitValues(p.Keywords) {
		parts = append(parts, quoteTerm(kw))
	}
	if strings.TrimSpace(p.ExtraFilters) != "" {
		parts = append(parts, strings.TrimSpace(p.ExtraFilters))
	}
	return strings.Join(compact(parts), " ")
}

func splitValues(s string) []string {
	raw := regexp.MustCompile(`[,\n]+`).Split(s, -1)
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func upperValues(values []string) []string {
	for i := range values {
		values[i] = strings.ToUpper(values[i])
	}
	return values
}

func orGroup(field string, values []string) string {
	cleaned := []string{}
	for _, value := range values {
		if field == "asn" {
			value = strings.ToUpper(value)
			if value != "" && !strings.HasPrefix(value, "AS") {
				value = "AS" + value
			}
		}
		if field == "port" {
			value = regexp.MustCompile(`[^0-9]`).ReplaceAllString(value, "")
		}
		if value != "" {
			cleaned = append(cleaned, quoteTerm(value))
		}
	}
	if len(cleaned) == 0 {
		return ""
	}
	return field + ":" + strings.Join(cleaned, ",")
}

func quoteTerm(v string) string {
	v = strings.TrimSpace(v)
	if regexp.MustCompile(`^[A-Za-z0-9_.:/@+-]+$`).MatchString(v) {
		return v
	}
	return `"` + strings.ReplaceAll(v, `"`, `\"`) + `"`
}

func compact(values []string) []string {
	out := []string{}
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, value)
		}
	}
	return out
}

func Slug(name string) string {
	slug := regexp.MustCompile(`[^A-Za-z0-9_.-]+`).ReplaceAllString(strings.TrimSpace(name), "-")
	slug = strings.Trim(slug, "-")
	if len(slug) > 80 {
		slug = slug[:80]
	}
	if slug == "" {
		return "default"
	}
	return slug
}

func filenameFor(p Profile, query string) string {
	base := Slug(strings.ReplaceAll(query, " ", "-"))
	if len(base) > 120 {
		base = base[:120]
	}
	return fmt.Sprintf("%s_N%d.txt", base, p.FetchCount)
}

func MaskKey(v string) string {
	if v == "" {
		return "未设置"
	}
	if len(v) <= 8 {
		return strings.Repeat("*", len(v))
	}
	return v[:4] + strings.Repeat("*", len(v)-8) + v[len(v)-4:]
}

func Esc(v any) string { return html.EscapeString(fmt.Sprint(v)) }

func now() string { return time.Now().Format(time.RFC3339) }
