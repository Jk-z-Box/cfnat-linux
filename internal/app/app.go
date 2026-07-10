package app

import (
	"context"
	"encoding/json"
	"errors"
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
	updatecheck "github.com/cfnat-linux/cfnat-linux/internal/update"
)

var errScanInProgress = errors.New("scan already in progress")

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

type UpdateState struct {
	CheckEnabled      bool       `json:"check_enabled"`
	AutoUpdateEnabled bool       `json:"auto_update_enabled"`
	CurrentVersion    string     `json:"current_version,omitempty"`
	LatestVersion     string     `json:"latest_version,omitempty"`
	UpdateAvailable   bool       `json:"update_available"`
	ReleaseURL        string     `json:"release_url,omitempty"`
	PackageURL        string     `json:"package_url,omitempty"`
	LastCheckedAt     *time.Time `json:"last_checked_at,omitempty"`
	LastError         string     `json:"last_error,omitempty"`
}

type DailyScanState struct {
	Date  string `json:"date"`
	Count int    `json:"count"`
}

type RuntimeState struct {
	UpdatedAt  time.Time      `json:"updated_at"`
	Status     string         `json:"status"`
	Listen     string         `json:"listen"`
	MaxLatency string         `json:"max_latency"`
	PrimaryIP  string         `json:"primary_ip,omitempty"`
	DailyScan  DailyScanState `json:"daily_scan"`
	Scan       ScanState      `json:"scan"`
	Targets    []TargetState  `json:"targets,omitempty"`
	Recovery   []TargetState  `json:"recovery,omitempty"`
	DNS        DNSState       `json:"dns"`
	Update     UpdateState    `json:"update"`
}

type App struct {
	cfg        config.Config
	logger     *slog.Logger
	scanner    *scanner.Scanner
	proxy      *proxy.Server
	dns        *cloudflare.Client
	version    string
	configPath string
	mu         sync.Mutex
	scanMu     sync.Mutex
	eventMu    sync.Mutex
	eventCond  *sync.Cond
	eventSeq   uint64
	pool       []scanner.Result
	recovery   []scanner.Result
	failures   map[netip.Addr]int
	scanPaused bool
	state      RuntimeState
}

var errScanPaused = errors.New("scan paused")

func New(cfg config.Config, logger *slog.Logger, s *scanner.Scanner, version, configPath string) *App {
	state := RuntimeState{
		Status: "starting", Listen: cfg.Listen, MaxLatency: cfg.MaxLatency.Value().String(),
		DNS: DNSState{Enabled: cfg.DNS.Enabled, RecordName: cfg.DNS.RecordName},
		Update: UpdateState{
			CheckEnabled: cfg.Update.CheckEnabled, AutoUpdateEnabled: cfg.Update.AutoUpdateEnabled,
			CurrentVersion: version,
		},
	}
	if previous, err := ReadState(cfg.StateFile); err == nil {
		today := time.Now().Format("2006-01-02")
		if previous.DailyScan.Date == today {
			state.DailyScan = previous.DailyScan
		}
		state.Update = previous.Update
		state.Update.CheckEnabled = cfg.Update.CheckEnabled
		state.Update.AutoUpdateEnabled = cfg.Update.AutoUpdateEnabled
		state.Update.CurrentVersion = version
	}
	app := &App{
		cfg: cfg, logger: logger, scanner: s,
		proxy:      proxy.New(cfg.Listen, cfg.TargetPort, cfg.DialTimeout.Value(), logger),
		dns:        cloudflare.New(cfg.DNS),
		version:    version,
		configPath: configPath,
		failures:   make(map[netip.Addr]int),
		state:      state,
	}
	app.eventCond = sync.NewCond(&app.eventMu)
	return app
}

func (a *App) Run(ctx context.Context) error {
	errCh := make(chan error, 2)
	if a.cfg.Web.Enabled {
		webReady := make(chan error, 1)
		go func() { errCh <- a.serveWeb(ctx, webReady) }()
		if err := <-webReady; err != nil {
			a.setStatus("error")
			return err
		}
	}
	proxyReady := make(chan error, 1)
	go func() { errCh <- a.proxy.Serve(ctx, proxyReady) }()
	if err := <-proxyReady; err != nil {
		a.setStatus("error")
		return err
	}
	go func() {
		if err := a.rescan(ctx, "startup"); err != nil {
			if ctx.Err() != nil {
				return
			}
			if errors.Is(err, errScanInProgress) {
				return
			}
			a.logger.Error("初始扫描失败，服务保持运行并将在后台重试", "error", err, "retry_after", a.cfg.HealthInterval.Value())
		}
	}()
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
	var scanC <-chan time.Time
	if a.cfg.ScanIntervalEnabled {
		scanTicker := time.NewTicker(a.cfg.ScanInterval.Value())
		defer scanTicker.Stop()
		scanC = scanTicker.C
	}
	monitorTicker := time.NewTicker(a.cfg.LatencyMonitorInterval.Value())
	retryTicker := time.NewTicker(a.cfg.HealthInterval.Value())
	var updateC <-chan time.Time
	var updateTicker *time.Ticker
	if a.cfg.Update.CheckEnabled {
		updateTicker = time.NewTicker(a.cfg.Update.CheckInterval.Value())
		updateC = updateTicker.C
		go a.checkUpdate(ctx)
	}
	defer monitorTicker.Stop()
	defer retryTicker.Stop()
	if updateTicker != nil {
		defer updateTicker.Stop()
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-scanC:
			if a.scansPaused() {
				continue
			}
			if err := a.rescan(ctx, "scheduled"); err != nil {
				if !errors.Is(err, errScanInProgress) {
					a.logger.Error("定时扫描失败，继续使用原池", "error", err)
				}
			}
		case <-updateC:
			a.checkUpdate(ctx)
		case <-retryTicker.C:
			a.mu.Lock()
			empty := len(a.pool) == 0
			scanning := a.state.Scan.InProgress
			a.mu.Unlock()
			if scanning {
				continue
			}
			if empty {
				if a.scansPaused() {
					continue
				}
				if err := a.rescan(ctx, "retry"); err != nil {
					if !errors.Is(err, errScanInProgress) {
						a.logger.Error("后台重试失败", "error", err)
					}
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
			recoveryStatus := a.checkRecoveryPool(ctx)
			if recoveryStatus.dnsNeedsSync {
				status.dnsNeedsSync = true
			}
			if status.dnsNeedsSync {
				a.syncDNS(ctx)
			}
			if status.healthyCount < a.cfg.MinHealthyCount {
				if a.scansPaused() {
					continue
				}
				a.logger.Warn("健康 IP 数低于阈值，触发整池重选", "healthy", status.healthyCount, "min_healthy_count", a.cfg.MinHealthyCount)
				if err := a.rescan(ctx, "health"); err != nil {
					if !errors.Is(err, errScanInProgress) {
						a.logger.Error("故障重选失败，继续使用原池", "error", err)
					}
				}
				continue
			}
			if status.allHealthy || status.removed == 0 {
				continue
			}
			a.logger.Warn("目标池健康检查发现异常 IP，已保留健康 IP 继续转发", "healthy", status.healthyCount, "removed", status.removed)
		}
	}
}

func (a *App) checkUpdate(ctx context.Context) {
	checkCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	result, err := updatecheck.Check(checkCtx, updatecheck.Config{Repository: a.cfg.Update.Repository}, a.version)
	a.mu.Lock()
	a.state.Update.CheckEnabled = a.cfg.Update.CheckEnabled
	a.state.Update.AutoUpdateEnabled = a.cfg.Update.AutoUpdateEnabled
	a.state.Update.CurrentVersion = result.CurrentVersion
	if err != nil {
		now := time.Now().UTC()
		a.state.Update.LastCheckedAt = &now
		a.state.Update.LastError = err.Error()
		a.mu.Unlock()
		a.saveState()
		a.logger.Warn("检查更新失败", "error", err)
		return
	}
	a.state.Update.LatestVersion = result.LatestVersion
	a.state.Update.UpdateAvailable = result.UpdateAvailable
	a.state.Update.ReleaseURL = result.ReleaseURL
	a.state.Update.PackageURL = result.PackageURL
	a.state.Update.LastCheckedAt = result.CheckedAt
	a.state.Update.LastError = ""
	a.mu.Unlock()
	a.saveState()
	if result.UpdateAvailable {
		a.logger.Info("发现新版本", "current", result.CurrentVersion, "latest", result.LatestVersion, "auto_update", a.cfg.Update.AutoUpdateEnabled)
	}
}

func (a *App) rescan(ctx context.Context, reason string) error {
	if a.scansPaused() {
		a.logger.Info("跳过优选，扫描已暂停", "reason", reason)
		return errScanPaused
	}
	if !a.scanMu.TryLock() {
		a.logger.Debug("跳过优选，已有扫描正在进行", "reason", reason)
		return errScanInProgress
	}
	defer a.scanMu.Unlock()
	a.logger.Info("触发优选", "reason", reason, "max_latency", a.cfg.MaxLatency.Value())
	now := time.Now().UTC()
	a.mu.Lock()
	if reason == "web" {
		a.recovery = nil
		a.state.Recovery = nil
	}
	a.incrementDailyScanLocked(now)
	a.state.Status = "scanning"
	a.state.Scan = ScanState{InProgress: true, Completed: false, Reason: reason, StartedAt: &now}
	scanBaseHealthy := a.currentHealthyPoolLocked()
	a.mu.Unlock()
	a.saveState()

	results, err := a.scanner.ScanProgress(ctx, func(partial []scanner.Result) {
		a.applyScanProgress(reason, partial)
	})
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
	pool, strategy := selectPoolAfterScan(reason, scanBaseHealthy, results, size)
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
	dnsNeedsSync := a.shouldSyncDNSAfterFinalScanLocked()
	if dnsNeedsSync {
		a.state.DNS.Synced = false
		a.state.DNS.LastError = "同步中"
	}
	a.mu.Unlock()
	a.proxy.Update(pool)
	if strategy == "keep_healthy_fill" {
		a.logger.Info("健康重选完成，保留现有健康 IP 并补齐转发池", "strategy", strategy, "targets", len(pool), "primary_ip", pool[0].IP.String())
	} else {
		a.logger.Info("重选完成，转发池已热替换", "strategy", strategy, "targets", len(pool), "primary_ip", pool[0].IP.String())
	}
	a.saveState()

	if dnsNeedsSync {
		a.syncDNS(ctx)
	}
	return nil
}

func (a *App) applyScanProgress(reason string, results []scanner.Result) {
	if len(results) == 0 {
		return
	}
	a.mu.Lock()
	currentHealthy := a.currentHealthyPoolLocked()
	a.mu.Unlock()
	pool := selectProgressPool(currentHealthy, results, a.cfg.PoolSize)
	if len(pool) == 0 {
		return
	}
	targets := make([]TargetState, 0, len(pool))
	for _, result := range pool {
		targets = append(targets, TargetState{IP: result.IP, LatencyMS: result.LatencyMS, SpeedMBps: result.SpeedMBps, Colo: result.Colo, Status: "healthy", CheckedAt: result.CheckedAt})
	}
	a.mu.Lock()
	a.pool = pool
	for _, result := range results {
		a.failures[result.IP] = 0
	}
	a.state.Status = "running"
	a.state.PrimaryIP = pool[0].IP.String()
	a.state.Targets = targets
	a.state.Scan.InProgress = true
	a.state.Scan.Completed = false
	a.state.Scan.LastError = ""
	a.mu.Unlock()
	a.proxy.Update(pool)
	a.logger.Info("分批扫描已有合格 IP，已热更新转发池", "reason", reason, "valid", len(results), "targets", len(pool), "primary_ip", pool[0].IP.String())
	a.saveState()
}

func (a *App) scansPaused() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.scanPaused
}

func (a *App) ToggleScanPause() bool {
	a.mu.Lock()
	a.scanPaused = !a.scanPaused
	paused := a.scanPaused
	a.mu.Unlock()
	a.saveState()
	return paused
}

func (a *App) currentHealthyPoolLocked() []scanner.Result {
	healthy := make(map[netip.Addr]bool, len(a.state.Targets))
	if len(a.state.Targets) == 0 {
		for _, result := range a.pool {
			healthy[result.IP] = true
		}
	} else {
		for _, target := range a.state.Targets {
			if target.Status == "healthy" {
				healthy[target.IP] = true
			}
		}
	}
	pool := make([]scanner.Result, 0, len(a.pool))
	for _, result := range a.pool {
		if healthy[result.IP] {
			pool = append(pool, result)
		}
	}
	sortResults(pool)
	return pool
}

func selectPoolAfterScan(reason string, currentHealthy, scanned []scanner.Result, size int) ([]scanner.Result, string) {
	if size <= 0 || len(scanned) == 0 {
		return nil, "empty"
	}
	newPool := append([]scanner.Result(nil), scanned...)
	sortResults(newPool)
	if len(newPool) > size {
		newPool = newPool[:size]
	}
	oldHealthy := uniqueResults(currentHealthy)
	sortResults(oldHealthy)
	if reason != "health" || len(oldHealthy) == 0 {
		return newPool, "replace"
	}
	if newPool[0].LatencyMS < oldHealthy[0].LatencyMS {
		return newPool, "replace_better_scan"
	}
	merged := make([]scanner.Result, 0, size)
	seen := make(map[netip.Addr]struct{}, size)
	for _, result := range oldHealthy {
		if len(merged) >= size {
			break
		}
		if _, ok := seen[result.IP]; ok {
			continue
		}
		seen[result.IP] = struct{}{}
		merged = append(merged, result)
	}
	for _, result := range newPool {
		if len(merged) >= size {
			break
		}
		if _, ok := seen[result.IP]; ok {
			continue
		}
		seen[result.IP] = struct{}{}
		merged = append(merged, result)
	}
	sortResults(merged)
	return merged, "keep_healthy_fill"
}

func selectProgressPool(currentHealthy, scanned []scanner.Result, size int) []scanner.Result {
	if size <= 0 {
		return nil
	}
	merged := make([]scanner.Result, 0, size)
	seen := make(map[netip.Addr]struct{}, size)
	add := func(results []scanner.Result) {
		for _, result := range results {
			if len(merged) >= size {
				return
			}
			if _, ok := seen[result.IP]; ok {
				continue
			}
			seen[result.IP] = struct{}{}
			merged = append(merged, result)
		}
	}
	scanned = uniqueResults(scanned)
	currentHealthy = uniqueResults(currentHealthy)
	sortResults(scanned)
	sortResults(currentHealthy)
	add(scanned)
	add(currentHealthy)
	sortResults(merged)
	if len(merged) > size {
		merged = merged[:size]
	}
	return merged
}

func swapRecoveredForWorst(pool, recovered []scanner.Result, size int) ([]scanner.Result, []scanner.Result) {
	pool = uniqueResults(pool)
	recovered = uniqueResults(recovered)
	sortResults(pool)
	sortResults(recovered)
	recovery := []scanner.Result{}
	for _, candidate := range recovered {
		inPool := false
		for i, current := range pool {
			if current.IP == candidate.IP {
				pool[i] = candidate
				inPool = true
				break
			}
		}
		if inPool {
			continue
		}
		if len(pool) < size {
			pool = append(pool, candidate)
			continue
		}
		if len(pool) == 0 {
			recovery = append(recovery, candidate)
			continue
		}
		sortResults(pool)
		worst := pool[len(pool)-1]
		if candidate.LatencyMS < worst.LatencyMS {
			pool[len(pool)-1] = candidate
			recovery = append(recovery, worst)
		} else {
			recovery = append(recovery, candidate)
		}
	}
	sortResults(pool)
	sortResults(recovery)
	return pool, recovery
}

func uniqueResults(results []scanner.Result) []scanner.Result {
	seen := make(map[netip.Addr]struct{}, len(results))
	unique := make([]scanner.Result, 0, len(results))
	for _, result := range results {
		if _, ok := seen[result.IP]; ok {
			continue
		}
		seen[result.IP] = struct{}{}
		unique = append(unique, result)
	}
	return unique
}

func sortResults(results []scanner.Result) {
	sort.SliceStable(results, func(i, j int) bool {
		if results[i].LatencyMS == results[j].LatencyMS {
			return results[i].IP.String() < results[j].IP.String()
		}
		return results[i].LatencyMS < results[j].LatencyMS
	})
}

func (a *App) incrementDailyScanLocked(now time.Time) {
	date := now.Local().Format("2006-01-02")
	if a.state.DailyScan.Date != date {
		a.state.DailyScan = DailyScanState{Date: date}
	}
	a.state.DailyScan.Count++
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
			a.addRecoveryLocked(result)
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
	a.state.Recovery = targetStatesFromResults(a.recovery, "recovering")
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
		a.logger.Warn("不健康 IP 已从转发池剔除并进入冷却恢复池", "removed", len(removed), "remaining", len(pool), "recovery", len(a.recoverySnapshot()))
	}
	if reordered {
		a.logger.Debug("转发池已按最新延迟重新排序", "primary_ip", valueOr(a.primaryIP(pool), "暂无"))
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

func targetStatesFromResults(results []scanner.Result, status string) []TargetState {
	targets := make([]TargetState, 0, len(results))
	for _, result := range results {
		targets = append(targets, TargetState{IP: result.IP, LatencyMS: result.LatencyMS, SpeedMBps: result.SpeedMBps, Colo: result.Colo, Status: status, CheckedAt: result.CheckedAt})
	}
	return targets
}

func (a *App) addRecoveryLocked(result scanner.Result) {
	for i, existing := range a.recovery {
		if existing.IP == result.IP {
			a.recovery[i] = result
			sortResults(a.recovery)
			return
		}
	}
	a.recovery = append(a.recovery, result)
	sortResults(a.recovery)
}

func (a *App) recoverySnapshot() []scanner.Result {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]scanner.Result(nil), a.recovery...)
}

func (a *App) checkRecoveryPool(ctx context.Context) healthStatus {
	a.mu.Lock()
	recovery := append([]scanner.Result(nil), a.recovery...)
	a.mu.Unlock()
	if len(recovery) == 0 {
		return healthStatus{allHealthy: true}
	}
	checkCtx, cancel := context.WithTimeout(ctx, a.cfg.DialTimeout.Value()*time.Duration(len(recovery)+1))
	defer cancel()
	recovered := make([]scanner.Result, 0, len(recovery))
	for _, result := range recovery {
		checked, err := a.scanner.Probe(checkCtx, result.IP)
		if err != nil {
			continue
		}
		recovered = append(recovered, checked)
	}
	if len(recovered) == 0 {
		return healthStatus{allHealthy: false, healthyCount: len(recovery)}
	}
	sortResults(recovered)
	a.mu.Lock()
	oldSyncedIPs := append([]string(nil), a.state.DNS.SyncedIPs...)
	oldDesired := a.desiredDNSIPsLocked()
	changed := false
	for _, candidate := range recovered {
		poolIndex := -1
		for i, current := range a.pool {
			if current.IP == candidate.IP {
				poolIndex = i
				break
			}
		}
		if poolIndex >= 0 {
			a.pool[poolIndex] = candidate
			a.removeRecoveryLocked(candidate.IP)
			changed = true
			continue
		}
		if len(a.pool) < a.cfg.PoolSize {
			a.pool = append(a.pool, candidate)
			a.removeRecoveryLocked(candidate.IP)
			changed = true
			continue
		}
		if len(a.pool) == 0 {
			continue
		}
		sortResults(a.pool)
		worst := a.pool[len(a.pool)-1]
		if candidate.LatencyMS < worst.LatencyMS {
			a.pool[len(a.pool)-1] = candidate
			a.removeRecoveryLocked(candidate.IP)
			a.addRecoveryLocked(worst)
			changed = true
		}
	}
	if changed {
		sortResults(a.pool)
		a.state.Targets = mergeTargetStates(a.pool, a.state.Targets)
		a.state.Recovery = targetStatesFromResults(a.recovery, "recovering")
		a.state.PrimaryIP = valueOr(a.primaryIP(a.pool), "")
		a.state.Status = "running"
	}
	pool := append([]scanner.Result(nil), a.pool...)
	newDesired := a.desiredDNSIPsLocked()
	dnsNeedsSync := changed && !sameStrings(oldDesired, newDesired) && a.shouldSyncDNSAfterPoolChangeLocked(oldSyncedIPs, newDesired, map[netip.Addr]struct{}{}, time.Now())
	a.mu.Unlock()
	if changed {
		a.proxy.Update(pool)
		a.logger.Info("冷却恢复池 IP 恢复健康并参与排序", "recovered", len(recovered), "targets", len(pool), "primary_ip", valueOr(a.primaryIP(pool), "暂无"))
		a.saveState()
	}
	return healthStatus{allHealthy: !changed, dnsNeedsSync: dnsNeedsSync, healthyCount: len(pool), reordered: changed}
}

func (a *App) removeRecoveryLocked(ip netip.Addr) {
	filtered := a.recovery[:0]
	for _, result := range a.recovery {
		if result.IP != ip {
			filtered = append(filtered, result)
		}
	}
	a.recovery = filtered
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

func (a *App) shouldSyncDNSAfterFinalScanLocked() bool {
	if !a.cfg.DNS.Enabled {
		return false
	}
	desired := a.desiredDNSIPsLocked()
	if len(desired) == 0 {
		return false
	}
	if !a.state.DNS.Synced || len(a.state.DNS.SyncedIPs) == 0 {
		return true
	}
	return !sameStrings(a.state.DNS.SyncedIPs, desired)
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
	a.broadcastState()
}

func (a *App) broadcastState() {
	a.eventMu.Lock()
	a.eventSeq++
	a.eventCond.Broadcast()
	a.eventMu.Unlock()
}

func (a *App) waitStateChange(ctx context.Context, last uint64) uint64 {
	a.eventMu.Lock()
	defer a.eventMu.Unlock()
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			a.eventCond.Broadcast()
		case <-done:
		}
	}()
	defer close(done)
	for a.eventSeq == last && ctx.Err() == nil {
		a.eventCond.Wait()
	}
	return a.eventSeq
}

func (a *App) stateSequence() uint64 {
	a.eventMu.Lock()
	defer a.eventMu.Unlock()
	return a.eventSeq
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
	if cfg.ScanIntervalEnabled {
		fmt.Fprintf(w, "定时重选        : 已启用，每 %s\n", cfg.ScanInterval.Value())
	} else {
		fmt.Fprintln(w, "定时重选        : 未启用")
	}
	fmt.Fprintf(w, "延迟监控        : 每 %s 重新排序转发池\n", cfg.LatencyMonitorInterval.Value())
	if cfg.SpeedTest.Enabled {
		fmt.Fprintf(w, "测速筛选        : ≥ %.2f MB/s，最多测试 %d 个候选，并发 %d\n", cfg.SpeedTest.MinMBps, cfg.SpeedTest.MaxCandidates, cfg.SpeedTest.Concurrency)
	} else {
		fmt.Fprintln(w, "测速筛选        : 未启用")
	}
	fmt.Fprintf(w, "重选阈值        : 健康 IP 少于 %d 个时整池重选\n", cfg.MinHealthyCount)
	if cfg.Update.CheckEnabled {
		fmt.Fprintf(w, "更新检查        : 已启用，每 %s\n", cfg.Update.CheckInterval.Value())
	} else {
		fmt.Fprintln(w, "更新检查        : 未启用")
	}
	if cfg.Update.AutoUpdateEnabled {
		fmt.Fprintln(w, "后台自动更新    : 已启用")
	} else {
		fmt.Fprintln(w, "后台自动更新    : 未启用")
	}
	if cfg.Web.Enabled {
		fmt.Fprintf(w, "Web 管理面板    : 已启用，监听 %s\n", cfg.Web.Listen)
	} else {
		fmt.Fprintln(w, "Web 管理面板    : 未启用")
	}
	if cfg.Shodan.Enabled {
		fmt.Fprintln(w, "Shodan IP Panel : 已启用")
	} else {
		fmt.Fprintln(w, "Shodan IP Panel : 未启用")
	}
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
	if state.DailyScan.Date != "" {
		fmt.Fprintf(w, "今日扫描        : %s 已触发 %d 次\n", state.DailyScan.Date, state.DailyScan.Count)
	}
	if state.Update.LastCheckedAt != nil {
		if state.Update.UpdateAvailable {
			fmt.Fprintf(w, "版本更新        : 发现新版本 %s（当前 %s）\n", valueOr(state.Update.LatestVersion, "未知"), valueOr(state.Update.CurrentVersion, "未知"))
			if state.Update.ReleaseURL != "" {
				fmt.Fprintf(w, "更新地址        : %s\n", state.Update.ReleaseURL)
			}
		} else if state.Update.LastError != "" {
			fmt.Fprintf(w, "版本更新        : 检查失败：%s\n", state.Update.LastError)
		} else {
			fmt.Fprintf(w, "版本更新        : 已是最新（%s）\n", valueOr(state.Update.CurrentVersion, "未知"))
		}
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
