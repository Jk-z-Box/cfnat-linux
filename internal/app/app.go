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
	cfg     config.Config
	logger  *slog.Logger
	scanner *scanner.Scanner
	proxy   *proxy.Server
	dns     *cloudflare.Client
	mu      sync.Mutex
	pool    []scanner.Result
	state   RuntimeState
}

func New(cfg config.Config, logger *slog.Logger, s *scanner.Scanner) *App {
	return &App{
		cfg: cfg, logger: logger, scanner: s,
		proxy: proxy.New(cfg.Listen, cfg.TargetPort, cfg.DialTimeout.Value(), logger),
		dns:   cloudflare.New(cfg.DNS),
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
	healthTicker := time.NewTicker(a.cfg.HealthInterval.Value())
	defer scanTicker.Stop()
	defer healthTicker.Stop()
	failures := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-scanTicker.C:
			if err := a.rescan(ctx, "scheduled"); err != nil {
				a.logger.Error("定时扫描失败，继续使用原池", "error", err)
			}
		case <-healthTicker.C:
			a.mu.Lock()
			empty := len(a.pool) == 0
			a.mu.Unlock()
			if empty {
				if err := a.rescan(ctx, "retry"); err != nil {
					a.logger.Error("后台重试失败", "error", err)
				}
				continue
			}
			if a.poolHealthy(ctx) {
				failures = 0
				continue
			}
			failures++
			a.logger.Warn("目标池健康检查失败", "consecutive_failures", failures)
			if failures >= a.cfg.HealthFailures {
				if err := a.rescan(ctx, "health"); err != nil {
					a.logger.Error("故障重选失败，继续使用原池", "error", err)
				} else {
					failures = 0
				}
			}
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
		targets = append(targets, TargetState{IP: result.IP, LatencyMS: result.LatencyMS, Colo: result.Colo, Status: "healthy", CheckedAt: result.CheckedAt})
	}
	a.mu.Lock()
	a.pool = pool
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

	if a.cfg.DNS.Enabled {
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
	return nil
}

func (a *App) poolHealthy(ctx context.Context) bool {
	a.mu.Lock()
	pool := append([]scanner.Result(nil), a.pool...)
	a.mu.Unlock()
	if len(pool) == 0 {
		return false
	}
	checkCtx, cancel := context.WithTimeout(ctx, a.cfg.DialTimeout.Value()*time.Duration(len(pool)+1))
	defer cancel()
	allHealthy := true
	for _, result := range pool {
		checked, err := a.scanner.Probe(checkCtx, result.IP)
		a.mu.Lock()
		for i := range a.state.Targets {
			if a.state.Targets[i].IP != result.IP {
				continue
			}
			a.state.Targets[i].CheckedAt = time.Now().UTC()
			if err != nil {
				a.state.Targets[i].Status = "unhealthy"
				a.state.Targets[i].LastError = err.Error()
				allHealthy = false
			} else {
				a.state.Targets[i].Status = "healthy"
				a.state.Targets[i].LatencyMS = checked.LatencyMS
				a.state.Targets[i].LastError = ""
			}
			break
		}
		a.mu.Unlock()
	}
	a.saveState()
	return allHealthy
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
			fmt.Fprintf(w, "  %2d. %-39s %4dms %-8s %s\n", i+1, target.IP, target.LatencyMS, valueOr(target.Colo, "-"), statusText(target.Status))
		}
	}
	if !cfg.DNS.Enabled {
		fmt.Fprintln(w, "DNS 解析        : 未启用")
	} else if state.DNS.Synced {
		fmt.Fprintf(w, "DNS 解析        : 已同步 → %s (%s)\n", cfg.DNS.RecordName, valueOr(join(state.DNS.SyncedIPs), "无 IP"))
	} else {
		fmt.Fprintf(w, "DNS 解析        : 未同步 → %s\n", cfg.DNS.RecordName)
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
