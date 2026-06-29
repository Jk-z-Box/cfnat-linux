package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/cfnat-linux/cfnat-linux/internal/cloudflare"
	"github.com/cfnat-linux/cfnat-linux/internal/config"
	"github.com/cfnat-linux/cfnat-linux/internal/proxy"
	"github.com/cfnat-linux/cfnat-linux/internal/scanner"
)

type ScanState struct {
	InProgress  bool       `json:"in_progress"`
	Completed   bool       `json:"completed"`
	Reason      string     `json:"reason,omitempty"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
}

type TargetState struct {
	IP        netip.Addr `json:"ip"`
	LatencyMS int64      `json:"latency_ms"`
	SpeedMBps float64    `json:"speed_mbps,omitempty"`
	Colo      string     `json:"colo,omitempty"`
	Status    string     `json:"status"`
	CheckedAt time.Time  `json:"checked_at"`
	LastError string     `json:"last_error,omitempty"`
}

type DNSState struct {
	Enabled      bool       `json:"enabled"`
	RecordName   string     `json:"record_name,omitempty"`
	Synced       bool       `json:"synced"`
	SyncedIPs    []string   `json:"synced_ips,omitempty"`
	LastSyncedAt *time.Time `json:"last_synced_at,omitempty"`
	LastError    string     `json:"last_error,omitempty"`
}

type RuntimeState struct {
	UpdatedAt  time.Time     `json:"updated_at"`
	Status     string        `json:"status"`
	Listen     string        `json:"listen"`
	MaxLatency string        `json:"max_latency"`
	PrimaryIP  string        `json:"primary_ip,omitempty"`
	Scan       ScanState     `json:"scan"`
	Targets    []TargetState `json:"targets,omitempty"`
	DNS        DNSState      `json:"dns"`
}

type App struct {
	cfg      config.Config
	logger   *slog.Logger
	scanner  *scanner.Scanner
	proxy    *proxy.Server
	dns      *cloudflare.Client
	mu       sync.Mutex
	pool     []scanner.Result
	failures map[netip.Addr]int
	state    RuntimeState
}

func New(cfg config.Config, logger *slog.Logger, s *scanner.Scanner) *App {
	return &App{
		cfg: cfg, logger: logger, scanner: s,
		proxy:    proxy.New(cfg.Listen, cfg.TargetPort, cfg.DialTimeout.Value(), logger),
		dns:      cloudflare.New(cfg.DNS),
		failures: make(map[netip.Addr]int),
		state: RuntimeState{
			Status: "starting", Listen: cfg.Listen, MaxLatency: cfg.MaxLatency.Value().String(),
			DNS: DNSState{Enabled: cfg.DNS.Enabled, RecordName: cfg.DNS.RecordName},
		},
	}
}

func (a *App) Run(ctx context.Context) error {
	if err := a.rescan(ctx, "startup"); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		a.logger.Error("初始扫描失败，服务保持运行并将在后台重试", "error", err, "retry_after", a.cfg.HealthInterval.Value())
	}
	errCh := make(chan error, 1)
	go func() { errCh <- a.proxy.Serve(ctx) }()
	go a.maintain(ctx)
	select {
	case <-ctx.Done():
		a.setStatus("stopped")
		return nil
	case err := <-errCh:
		a.setStatus("error")
		return err
	}
}

func (a *App) maintain(ctx context.Context) {
	scanTicker := time.NewTicker(a.cfg.ScanInterval.Value())
	monitorTicker := time.NewTicker(a.cfg.LatencyMonitorInterval.Value())
	retryTicker := time.NewTicker(a.cfg.HealthInterval.Value())
	defer scanTicker.Stop()
	defer monitorTicker.Stop()
	defer retryTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-scanTicker.C:
			if err := a.rescan(ctx, "scheduled"); err != nil {
				a.logger.Error("定时扫描失败，继续使用原池", "error", err)
			}
		case <-retryTicker.C:
			a.mu.Lock()
			empty := len(a.pool) == 0
			a.mu.Unlock()
			if empty {
				if err := a.rescan(ctx, "retry"); err != nil {
					a.logger.Error("后台重试失败", "error", err)
				}
				continue
			}
		case <-monitorTicker.C:
			a.mu.Lock()
			empty := len(a.pool) == 0
			a.mu.Unlock()
			if empty {
				continue
			}
			status := a.checkAndPrunePool(ctx)
			if status.dnsNeedsSync {
				a.syncDNS(ctx)
			}
			if status.healthyCount < a.cfg.MinHealthyCount {
				a.logger.Warn("健康 IP 数低于阈值，触发整池重选", "healthy", status.healthyCount, "min_healthy_count", a.cfg.MinHealthyCount)
				if err := a.rescan(ctx, "health"); err != nil {
					a.logger.Error("故障重选失败，继续使用原池", "error", err)
				}
				continue
			}
			if status.allHealthy {
				continue
			}
			a.logger.Warn("目标池健康检查发现异常 IP，已保留健康 IP 继续转发", "healthy", status.healthyCount, "removed", status.removed)
		}
	}
}

func (a *App) rescan(ctx context.Context, reason string) error {
	a.logger.Info("触发优选", "reason", reason, "max_latency", a.cfg.MaxLatency.Value())
	now := time.Now().UTC()
	a.mu.Lock()
	a.state.Status = "scanning"
	a.state.Scan = ScanState{InProgress: true, Completed: false, Reason: reason, StartedAt: &now}
	a.mu.Unlock()
	a.saveState()

	results, err := a.scanner.Scan(ctx)
	if err != nil {
		a.mu.Lock()
		a.state.Scan.InProgress = false
		a.state.Scan.LastError = err.Error()
		if len(a.pool) > 0 {
			a.state.Status = "degraded"
		} else {
			a.state.Status = "error"
		}
		a.mu.Unlock()
		a.saveState()
		return err
	}
	if len(results) < a.cfg.PoolSize {
		a.logger.Warn("有效 IP 少于目标池大小", "valid", len(results), "wanted", a.cfg.PoolSize)
	}
	size := min(len(results), a.cfg.PoolSize)
	pool := append([]scanner.Result(nil), results[:size]...)
	completed := time.Now().UTC()
	targets := make([]TargetState, 0, len(pool))
	for _, result := range pool {
		targets = append(targets, TargetState{IP: result.IP, LatencyMS: result.LatencyMS, SpeedMBps: result.SpeedMBps, Colo: result.Colo, Status: "healthy", CheckedAt: result.CheckedAt})
	}
	a.mu.Lock()
	a.pool = pool
	a.failures = make(map[netip.Addr]int)
	a.state.Status = "running"
	a.state.PrimaryIP = pool[0].IP.String()
	a.state.Targets = targets
	a.state.Scan.InProgress = false
	a.state.Scan.Completed = true
	a.state.Scan.CompletedAt = &completed
	a.state.Scan.LastError = ""
	if a.cfg.DNS.Enabled {
		a.state.DNS.Synced = false
		a.state.DNS.LastError = "同步中"
	}
	a.mu.Unlock()
	a.proxy.Update(pool)
	a.saveState()

	a.syncDNS(ctx)
	return nil
}

type healthStatus struct {
	allHealthy   bool
	dnsNeedsSync bool
	healthyCount int
	removed      int
	reordered    bool
}

func (a *App) checkAndPrunePool(ctx context.Context) healthStatus {
	a.mu.Lock()
	pool := append([]scanner.Result(nil), a.pool...)
	a.mu.Unlock()
	if len(pool) == 0 {
		return healthStatus{allHealthy: false, healthyCount: 0}
	}
	checkCtx, cancel := context.WithTimeout(ctx, a.cfg.DialTimeout.Value()*time.Duration(len(pool)+1))
	defer cancel()
	allHealthy := true
	removed := make(map[netip.Addr]struct{})
	checkedByIP := make(map[netip.Addr]scanner.Result, len(pool))
	for _, result := range pool {
		checked, err := a.scanner.Probe(checkCtx, result.IP)
		a.mu.Lock()
		targetIndex := -1
		for i := range a.state.Targets {
			if a.state.Targets[i].IP == result.IP {
				targetIndex = i
				break
			}
		}
		if err != nil {
			a.failures[result.IP]++
			allHealthy = false
			if targetIndex >= 0 {
				a.state.Targets[targetIndex].CheckedAt = time.Now().UTC()
				a.state.Targets[targetIndex].Status = "unhealthy"
				a.state.Targets[targetIndex].LastError = err.Error()
			}
			if a.failures[result.IP] >= a.cfg.HealthFailures {
				removed[result.IP] = struct{}{}
			}
		} else {
			a.failures[result.IP] = 0
			checkedByIP[result.IP] = checked
			if targetIndex >= 0 {
				a.state.Targets[targetIndex].Status = "healthy"
				a.state.Targets[targetIndex].LatencyMS = checked.LatencyMS
				a.state.Targets[targetIndex].CheckedAt = checked.CheckedAt
				a.state.Targets[targetIndex].LastError = ""
			}
		}
		a.mu.Unlock()
	}
	dnsNeedsSync := false
	reordered := false
	healthyCount := len(pool)
	a.mu.Lock()
	oldSyncedIPs := append([]string(nil), a.state.DNS.SyncedIPs...)
	newPool := make([]scanner.Result, 0, len(a.pool))
	for _, result := range a.pool {
		if _, drop := removed[result.IP]; drop {
			delete(a.failures, result.IP)
			continue
		}
		if checked, ok := checkedByIP[result.IP]; ok {
			result.LatencyMS = checked.LatencyMS
			result.Colo = checked.Colo
			result.CheckedAt = checked.CheckedAt
		} else if a.failures[result.IP] > 0 {
			result.LatencyMS = 1 << 62
		}
		newPool = append(newPool, result)
	}
	sort.SliceStable(newPool, func(i, j int) bool {
		if newPool[i].LatencyMS == newPool[j].LatencyMS {
			return newPool[i].IP.String() < newPool[j].IP.String()
		}
		return newPool[i].LatencyMS < newPool[j].LatencyMS
	})
	oldOrder := make([]netip.Addr, 0, len(a.pool))
	for _, result := range a.pool {
		oldOrder = append(oldOrder, result.IP)
	}
	for i, result := range newPool {
		if i >= len(oldOrder) || oldOrder[i] != result.IP {
			reordered = true
			break
		}
	}
	a.pool = newPool
	a.state.Targets = mergeTargetStates(newPool, a.state.Targets)
	a.state.PrimaryIP = ""
	if len(newPool) > 0 {
		a.state.PrimaryIP = newPool[0].IP.String()
		a.state.Status = "running"
	} else {
		a.state.Status = "degraded"
	}
	newDNSIPs := a.desiredDNSIPsLocked()
	dnsNeedsSync = a.shouldSyncDNSAfterPoolChangeLocked(oldSyncedIPs, newDNSIPs, removed, time.Now())
	pool = append([]scanner.Result(nil), newPool...)
	healthyCount = len(newPool)
	a.mu.Unlock()

	if len(removed) > 0 || reordered {
		a.proxy.Update(pool)
	}
	if len(removed) > 0 {
		a.logger.Warn("不健康 IP 已从转发池剔除", "removed", len(removed), "remaining", len(pool))
	}
	if reordered {
		a.logger.Info("转发池已按最新延迟重新排序", "primary_ip", valueOr(a.primaryIP(pool), "暂无"))
	}
	a.saveState()
	return healthStatus{allHealthy: allHealthy && len(removed) == 0, dnsNeedsSync: dnsNeedsSync, healthyCount: healthyCount, removed: len(removed), reordered: reordered}
}

func mergeTargetStates(results []scanner.Result, existing []TargetState) []TargetState {
	byIP := make(map[netip.Addr]TargetState, len(existing))
	for _, target := range existing {
		byIP[target.IP] = target
	}
	targets := make([]TargetState, 0, len(results))
	for _, result := range results {
		target := TargetState{IP: result.IP, LatencyMS: result.LatencyMS, SpeedMBps: result.SpeedMBps, Colo: result.Colo, Status: "healthy", CheckedAt: result.CheckedAt}
		if old, ok := byIP[result.IP]; ok {
			target.Status = old.Status
			target.LastError = old.LastError
			target.CheckedAt = old.CheckedAt
			if old.Status == "healthy" {
				target.LatencyMS = result.LatencyMS
				target.SpeedMBps = result.SpeedMBps
				target.Colo = result.Colo
				target.CheckedAt = result.CheckedAt
			}
		}
		targets = append(targets, target)
	}
	return targets
}

func (a *App) desiredDNSIPsLocked() []string {
	if !a.cfg.DNS.Enabled {
		return nil
	}
	ips := make([]string, 0, a.cfg.DNS.SyncCount)
	for _, result := range a.pool {
		ip := result.IP
		if (a.cfg.DNS.RecordType == "A" && ip.Is4()) || (a.cfg.DNS.RecordType == "AAAA" && ip.Is6()) {
			ips = append(ips, ip.String())
		}
		if len(ips) == a.cfg.DNS.SyncCount {
			break
		}
	}
	return ips
}

func (a *App) shouldSyncDNSAfterPoolChangeLocked(oldSyncedIPs, newDesiredIPs []string, removed map[netip.Addr]struct{}, now time.Time) bool {
	if !a.cfg.DNS.Enabled {
		return false
	}
	if len(newDesiredIPs) == 0 {
		return false
	}
	if len(oldSyncedIPs) == 0 || !a.state.DNS.Synced {
		return true
	}
	for _, ip := range oldSyncedIPs {
		parsed, err := netip.ParseAddr(ip)
		if err != nil {
			return true
		}
		if _, drop := removed[parsed]; drop {
			return true
		}
	}
	if sameStrings(oldSyncedIPs, newDesiredIPs) {
		return false
	}
	if !a.cfg.DNS.LatencySyncEnabled {
		return false
	}
	if a.state.DNS.LastSyncedAt == nil {
		return true
	}
	return now.Sub(*a.state.DNS.LastSyncedAt) >= a.cfg.DNS.LatencySyncInterval.Value()
}

func sameStrings(a, b []string) bool {
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

func (a *App) primaryIP(pool []scanner.Result) string {
	if len(pool) == 0 {
		return ""
	}
	return pool[0].IP.String()
}

func (a *App) syncDNS(ctx context.Context) {
	if !a.cfg.DNS.Enabled {
		return
	}
	a.mu.Lock()
	pool := append([]scanner.Result(nil), a.pool...)
	a.state.DNS.Synced = false
	a.state.DNS.LastError = "同步中"
	a.mu.Unlock()
	a.saveState()

	ips := make([]netip.Addr, 0, len(pool))
	for _, result := range pool {
		ips = append(ips, result.IP)
	}
	err := a.dns.Sync(ctx, ips)
	a.mu.Lock()
	if err != nil {
		a.state.DNS.Synced = false
		a.state.DNS.LastError = err.Error()
	} else {
		syncedAt := time.Now().UTC()
		a.state.DNS.Synced = true
		a.state.DNS.LastError = ""
		a.state.DNS.LastSyncedAt = &syncedAt
		a.state.DNS.SyncedIPs = nil
		for i := 0; i < min(a.cfg.DNS.SyncCount, len(ips)); i++ {
			a.state.DNS.SyncedIPs = append(a.state.DNS.SyncedIPs, ips[i].String())
		}
	}
	a.mu.Unlock()
	a.saveState()
	if err != nil {
		a.logger.Error("Cloudflare DNS 同步失败，转发服务继续运行", "error", err)
	} else {
		a.logger.Info("Cloudflare DNS 同步完成", "record", a.cfg.DNS.RecordName, "count", min(a.cfg.DNS.SyncCount, len(ips)))
	}
}

func (a *App) setStatus(status string) {
	a.mu.Lock()
	a.state.Status = status
	a.mu.Unlock()
	a.saveState()
}

func (a *App) saveState() {
	if a.cfg.StateFile == "" {
		return
	}
	a.mu.Lock()
	a.state.UpdatedAt = time.Now().UTC()
	data, err := json.MarshalIndent(a.state, "", "  ")
	a.mu.Unlock()
	if err != nil {
		a.logger.Warn("状态序列化失败", "error", err)
		return
	}
	if err := writeState(a.cfg.StateFile, data); err != nil {
		a.logger.Warn("状态文件保存失败", "error", err)
	}
}

func writeState(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".state-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err = tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Chmod(0640); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func ReadState(path string) (RuntimeState, error) {
	var state RuntimeState
	data, err := os.ReadFile(path)
	if err != nil {
		return state, err
	}
	err = json.Unmarshal(data, &state)
	return state, err
}

func PrintStatus(w io.Writer, cfg config.Config) {
	fmt.Fprintf(w, "监听地址        : %s\n", cfg.Listen)
	fmt.Fprintf(w, "延迟上限        : %s（超过该值不优选）\n", cfg.MaxLatency.Value())
	fmt.Fprintf(w, "延迟监控        : 每 %s 重新排序转发池\n", cfg.LatencyMonitorInterval.Value())
	if cfg.SpeedTest.Enabled {
		fmt.Fprintf(w, "测速筛选        : ≥ %.2f MB/s，最多测试 %d 个候选，并发 %d\n", cfg.SpeedTest.MinMBps, cfg.SpeedTest.MaxCandidates, cfg.SpeedTest.Concurrency)
	} else {
		fmt.Fprintln(w, "测速筛选        : 未启用")
	}
	fmt.Fprintf(w, "重选阈值        : 健康 IP 少于 %d 个时整池重选\n", cfg.MinHealthyCount)
	state, err := ReadState(cfg.StateFile)
	if err != nil {
		fmt.Fprintln(w, "运行状态        : 尚无状态数据")
		fmt.Fprintln(w, "扫描状态        : 尚未完成")
		if cfg.DNS.Enabled {
			fmt.Fprintf(w, "DNS 解析        : 等待同步 → %s\n", cfg.DNS.RecordName)
		} else {
			fmt.Fprintln(w, "DNS 解析        : 未启用")
		}
		return
	}
	fmt.Fprintf(w, "运行状态        : %s\n", statusText(state.Status))
	if state.Scan.InProgress {
		fmt.Fprintln(w, "扫描状态        : 扫描中")
	} else if state.Scan.Completed {
		fmt.Fprintln(w, "扫描状态        : 已完成")
	} else {
		fmt.Fprintln(w, "扫描状态        : 未完成")
	}
	if state.Scan.LastError != "" {
		fmt.Fprintf(w, "扫描错误        : %s\n", state.Scan.LastError)
	}
	fmt.Fprintf(w, "当前最优 IP     : %s\n", valueOr(state.PrimaryIP, "暂无"))
	if len(state.Targets) == 0 {
		fmt.Fprintln(w, "优选 IP 状态    : 暂无")
	} else {
		fmt.Fprintln(w, "优选 IP 状态    :")
		for i, target := range state.Targets {
			fmt.Fprintf(w, "  %2d. %-39s %4dms %8s %-8s %s\n", i+1, target.IP, target.LatencyMS, speedText(target.SpeedMBps), valueOr(target.Colo, "-"), statusText(target.Status))
		}
	}
	if !cfg.DNS.Enabled {
		fmt.Fprintln(w, "DNS 解析        : 未启用")
	} else if state.DNS.Synced {
		fmt.Fprintf(w, "DNS 解析        : 已同步 → %s (%s)\n", cfg.DNS.RecordName, valueOr(join(state.DNS.SyncedIPs), "无 IP"))
		if cfg.DNS.LatencySyncEnabled {
			fmt.Fprintf(w, "DNS 延迟同步    : 已启用，冷却时间 %s\n", cfg.DNS.LatencySyncInterval.Value())
		} else {
			fmt.Fprintln(w, "DNS 延迟同步    : 未启用")
		}
	} else {
		fmt.Fprintf(w, "DNS 解析        : 未同步 → %s\n", cfg.DNS.RecordName)
		if cfg.DNS.LatencySyncEnabled {
			fmt.Fprintf(w, "DNS 延迟同步    : 已启用，冷却时间 %s\n", cfg.DNS.LatencySyncInterval.Value())
		} else {
			fmt.Fprintln(w, "DNS 延迟同步    : 未启用")
		}
		if state.DNS.LastError != "" {
			fmt.Fprintf(w, "DNS 错误        : %s\n", state.DNS.LastError)
		}
	}
}

func statusText(value string) string {
	text := map[string]string{"starting": "启动中", "scanning": "扫描中", "running": "运行中", "degraded": "降级运行", "error": "错误", "stopped": "已停止", "healthy": "健康", "unhealthy": "异常"}[value]
	return valueOr(text, valueOr(value, "未知"))
}

func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func speedText(value float64) string {
	if value <= 0 {
		return "-"
	}
	return fmt.Sprintf("%.2fMB/s", value)
}

func join(values []string) string {
	result := ""
	for _, value := range values {
		if result != "" {
			result += ", "
		}
		result += value
	}
	return result
}
