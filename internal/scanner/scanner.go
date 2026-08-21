package scanner

import (
	"bufio"
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cfnat-linux/cfnat-linux/internal/config"
)

type Result struct {
	IP        netip.Addr `json:"ip"`
	LatencyMS int64      `json:"latency_ms"`
	SpeedMBps float64    `json:"speed_mbps,omitempty"`
	Colo      string     `json:"colo,omitempty"`
	CheckedAt time.Time  `json:"checked_at"`
}

type rankedIP struct {
	IP      netip.Addr
	Latency time.Duration
}

type Scanner struct {
	cfg    config.Config
	logger *slog.Logger
	client *http.Client
}

type ProgressFunc func([]Result)

type ProbeError struct {
	Kind string
	Err  error
}

func (e *ProbeError) Error() string           { return e.Err.Error() }
func (e *ProbeError) Unwrap() error           { return e.Err }
func probeError(kind string, err error) error { return &ProbeError{Kind: kind, Err: err} }

func New(cfg config.Config, logger *slog.Logger) *Scanner {
	return &Scanner{cfg: cfg, logger: logger, client: &http.Client{Timeout: 20 * time.Second}}
}

func (s *Scanner) Scan(ctx context.Context) ([]Result, error) {
	return s.ScanProgress(ctx, nil)
}

func (s *Scanner) ScanProgress(ctx context.Context, onProgress ProgressFunc) ([]Result, error) {
	prefixes, err := s.readPrefixes(ctx)
	if err != nil {
		return nil, err
	}
	candidates, err := generateCandidates(prefixes, s.cfg.RandomIPs, s.cfg.MaxCandidates)
	if err != nil {
		return nil, err
	}
	beforeBlacklist := len(candidates)
	candidates = filterBlacklist(candidates, s.cfg.IPBlacklist)
	blacklisted := beforeBlacklist - len(candidates)
	if len(candidates) == 0 {
		return nil, errors.New("候选 IP 均被 ip_blacklist 排除")
	}
	s.logger.Info("开始扫描", "prefixes", len(prefixes), "candidates", len(candidates), "blacklisted", blacklisted, "tcp_concurrency", s.cfg.Concurrency)
	ranked, tcpFailures := s.rankTCP(ctx, candidates)
	if len(ranked) == 0 {
		return nil, fmt.Errorf("没有可建立 TCP 连接的候选 IP（失败统计: %s）", formatCounts(tcpFailures))
	}
	batchSize := s.scanBatchSize(len(ranked))
	httpConcurrency := min(s.cfg.Concurrency, 20)
	s.logger.Info("TCP 初筛完成", "reachable", len(ranked), "batch_size", batchSize, "http_concurrency", httpConcurrency, "failures", tcpFailures)

	valid := make([]Result, 0, s.cfg.ValidIPCount)
	seenValid := make(map[netip.Addr]struct{}, s.cfg.ValidIPCount)
	probeFailures := map[string]int{}
	speedFailuresTotal := map[string]int{}
	batch := 0
	for start := 0; start < len(ranked) && len(valid) < s.cfg.ValidIPCount; start += batchSize {
		end := min(start+batchSize, len(ranked))
		batch++
		batchCandidates := make([]netip.Addr, 0, end-start)
		for _, item := range ranked[start:end] {
			batchCandidates = append(batchCandidates, item.IP)
		}
		s.logger.Info("开始分批复筛", "batch", batch, "offset", start, "candidates", len(batchCandidates))
		speeds := map[netip.Addr]float64{}
		if s.cfg.SpeedTest.Enabled {
			var speedFailures map[string]int
			batchCandidates, speeds, speedFailures = s.filterByDownloadSpeed(ctx, batchCandidates)
			mergeCounts(speedFailuresTotal, speedFailures)
			if len(batchCandidates) == 0 {
				s.logger.Warn("本批下载测速筛选无通过 IP", "batch", batch, "tested", min(end-start, s.cfg.SpeedTest.MaxCandidates), "min_mbps", s.cfg.SpeedTest.MinMBps, "failures", speedFailures)
				continue
			}
			s.logger.Info("本批下载测速筛选完成", "batch", batch, "passed", len(batchCandidates), "min_mbps", s.cfg.SpeedTest.MinMBps, "failures", speedFailures)
		}
		batchValid, batchFailures := s.probeCandidates(ctx, batchCandidates, speeds)
		mergeCounts(probeFailures, batchFailures)
		newValid := 0
		for _, result := range batchValid {
			if _, ok := seenValid[result.IP]; ok {
				continue
			}
			seenValid[result.IP] = struct{}{}
			valid = append(valid, result)
			newValid++
		}
		sort.Slice(valid, func(i, j int) bool { return valid[i].LatencyMS < valid[j].LatencyMS })
		if len(valid) > s.cfg.ValidIPCount {
			valid = valid[:s.cfg.ValidIPCount]
		}
		if newValid > 0 {
			s.logger.Info("本批复筛通过", "batch", batch, "new_valid", newValid, "total_valid", len(valid), "best_ip", valid[0].IP.String(), "best_latency_ms", valid[0].LatencyMS, "failures", batchFailures)
			if onProgress != nil {
				onProgress(append([]Result(nil), valid...))
			}
		} else {
			s.logger.Warn("本批复筛无通过 IP", "batch", batch, "failures", batchFailures)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(valid) == 0 {
		s.logger.Warn("扫描失败统计", "speed_failures", speedFailuresTotal, "probe_failures", probeFailures)
		if len(speedFailuresTotal) > 0 && len(probeFailures) == 0 {
			return nil, fmt.Errorf("没有找到满足测速条件的 IP（失败统计: %s）", formatCounts(speedFailuresTotal))
		}
		return nil, fmt.Errorf("没有找到符合条件的 IP（测速失败统计: %s，复筛失败统计: %s）", formatCounts(speedFailuresTotal), formatCounts(probeFailures))
	}
	s.logger.Info("扫描完成", "valid", len(valid), "best_ip", valid[0].IP.String(), "best_latency_ms", valid[0].LatencyMS, "best_speed_mbps", valid[0].SpeedMBps, "speed_failures", speedFailuresTotal, "probe_failures", probeFailures)
	return valid, nil
}

func (s *Scanner) scanBatchSize(reachable int) int {
	batchSize := max(s.cfg.ValidIPCount*10, 100)
	if s.cfg.SpeedTest.Enabled {
		batchSize = max(batchSize, s.cfg.SpeedTest.MaxCandidates)
	}
	return min(batchSize, reachable)
}

func (s *Scanner) probeCandidates(ctx context.Context, candidates []netip.Addr, speeds map[netip.Addr]float64) ([]Result, map[string]int) {
	if len(candidates) == 0 {
		return nil, map[string]int{}
	}

	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan netip.Addr)
	results := make(chan Result, max(s.cfg.Concurrency, s.cfg.ValidIPCount))
	failures := make(chan string, len(candidates))
	var wg sync.WaitGroup
	httpConcurrency := min(s.cfg.Concurrency, 20)
	workers := min(httpConcurrency, len(candidates))
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				result, err := s.ProbeWithMode(scanCtx, ip, s.cfg.ScanProbeMode)
				if err == nil {
					results <- result
				} else {
					kind := "other"
					var pe *ProbeError
					if errors.As(err, &pe) {
						kind = pe.Kind
					}
					failures <- kind
					s.logger.Debug("IP 不可用", "ip", ip.String(), "error", err)
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, ip := range candidates {
			select {
			case jobs <- ip:
			case <-scanCtx.Done():
				return
			}
		}
	}()
	go func() { wg.Wait(); close(results); close(failures) }()

	valid := make([]Result, 0, min(len(candidates), s.cfg.ValidIPCount))
	counts := map[string]int{}
	for results != nil || failures != nil {
		select {
		case result, ok := <-results:
			if !ok {
				results = nil
				continue
			}
			if speed, ok := speeds[result.IP]; ok {
				result.SpeedMBps = speed
			}
			valid = append(valid, result)
			if len(valid) >= s.cfg.ValidIPCount {
				cancel()
			}
		case kind, ok := <-failures:
			if !ok {
				failures = nil
				continue
			}
			if kind != "canceled" {
				counts[kind]++
			}
		}
	}
	sort.Slice(valid, func(i, j int) bool { return valid[i].LatencyMS < valid[j].LatencyMS })
	if len(valid) > s.cfg.ValidIPCount {
		valid = valid[:s.cfg.ValidIPCount]
	}
	return valid, counts
}

func (s *Scanner) filterByDownloadSpeed(ctx context.Context, candidates []netip.Addr) ([]netip.Addr, map[netip.Addr]float64, map[string]int) {
	limit := min(len(candidates), s.cfg.SpeedTest.MaxCandidates)
	type speedJob struct {
		index int
		ip    netip.Addr
	}
	type speedResult struct {
		index int
		ip    netip.Addr
		speed float64
		err   error
	}
	testCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan speedJob)
	results := make(chan speedResult, limit)
	workers := min(s.cfg.SpeedTest.Concurrency, limit)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				speed, err := s.downloadSpeed(testCtx, job.ip)
				select {
				case results <- speedResult{index: job.index, ip: job.ip, speed: speed, err: err}:
				case <-testCtx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for i, ip := range candidates[:limit] {
			select {
			case jobs <- speedJob{index: i, ip: ip}:
			case <-testCtx.Done():
				return
			}
		}
	}()
	go func() { wg.Wait(); close(results) }()

	passed := make([]speedResult, 0, s.cfg.ValidIPCount)
	speeds := make(map[netip.Addr]float64)
	failures := map[string]int{}
	for result := range results {
		if result.err != nil {
			if errors.Is(result.err, context.Canceled) {
				continue
			}
			failures[classifySpeedError(result.err)]++
			s.logger.Debug("下载测速失败", "ip", result.ip.String(), "error", result.err)
			continue
		}
		if result.speed <= 0 {
			failures["speed_zero"]++
			continue
		}
		if result.speed < s.cfg.SpeedTest.MinMBps {
			failures["speed_low"]++
			s.logger.Debug("下载速度未达标", "ip", result.ip.String(), "speed_mbps", result.speed, "min_mbps", s.cfg.SpeedTest.MinMBps)
			continue
		}
		passed = append(passed, result)
		speeds[result.ip] = result.speed
		if len(passed) >= s.cfg.ValidIPCount {
			cancel()
		}
	}
	sort.Slice(passed, func(i, j int) bool { return passed[i].index < passed[j].index })
	ips := make([]netip.Addr, 0, len(passed))
	for _, result := range passed {
		ips = append(ips, result.ip)
	}
	return ips, speeds, failures
}

func classifySpeedError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return "speed_timeout"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "speed_timeout"
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		text := strings.ToLower(urlErr.Err.Error())
		switch {
		case strings.Contains(text, "tls") || strings.Contains(text, "certificate") || strings.Contains(text, "handshake"):
			return "speed_tls"
		case strings.Contains(text, "connect") || strings.Contains(text, "connection refused") || strings.Contains(text, "no route"):
			return "speed_connect"
		case strings.Contains(text, "reset"):
			return "speed_reset"
		}
	}
	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "http "):
		fields := strings.Fields(text)
		for _, field := range fields {
			code := strings.Trim(field, ":,;")
			if len(code) == 3 && code[0] >= '1' && code[0] <= '5' && code[1] >= '0' && code[1] <= '9' && code[2] >= '0' && code[2] <= '9' {
				return "speed_status_" + code
			}
		}
		return "speed_status"
	case strings.Contains(text, "no data"):
		return "speed_no_data"
	case strings.Contains(text, "tls") || strings.Contains(text, "certificate") || strings.Contains(text, "handshake"):
		return "speed_tls"
	case strings.Contains(text, "connect") || strings.Contains(text, "connection refused") || strings.Contains(text, "no route"):
		return "speed_connect"
	case strings.Contains(text, "reset"):
		return "speed_reset"
	default:
		return "speed_error"
	}
}

func (s *Scanner) downloadSpeed(ctx context.Context, ip netip.Addr) (float64, error) {
	u, err := url.Parse(s.cfg.SpeedTest.URL)
	if err != nil {
		return 0, err
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	target := net.JoinHostPort(ip.String(), port)
	dialer := &net.Dialer{Timeout: s.cfg.DialTimeout.Value()}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, target)
		},
		TLSHandshakeTimeout: s.cfg.DialTimeout.Value(),
		ForceAttemptHTTP2:   false,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	testCtx, cancel := context.WithTimeout(ctx, s.cfg.SpeedTest.Timeout.Value())
	defer cancel()
	req, err := http.NewRequestWithContext(testCtx, http.MethodGet, s.cfg.SpeedTest.URL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "cfnat-linux speed-test")
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("speed test HTTP %d", resp.StatusCode)
	}
	started := time.Now()
	buf := make([]byte, 64*1024)
	var bytesRead int64
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			bytesRead += int64(n)
		}
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(testCtx.Err(), context.DeadlineExceeded) {
				break
			}
			if errors.Is(err, io.EOF) {
				break
			}
			return 0, err
		}
		if testCtx.Err() != nil {
			break
		}
	}
	elapsed := time.Since(started).Seconds()
	if bytesRead == 0 || elapsed <= 0 {
		return 0, errors.New("speed test returned no data")
	}
	return float64(bytesRead) / 1000 / 1000 / elapsed, nil
}

func (s *Scanner) rankTCP(ctx context.Context, candidates []netip.Addr) ([]rankedIP, map[string]int) {
	jobs := make(chan netip.Addr)
	results := make(chan rankedIP, len(candidates))
	failures := make(chan string, len(candidates))
	workers := min(s.cfg.Concurrency, len(candidates))
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dialer := net.Dialer{Timeout: s.cfg.DialTimeout.Value()}
			for ip := range jobs {
				started := time.Now()
				conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), fmt.Sprint(s.cfg.TargetPort)))
				if err != nil {
					kind := "tcp_connect"
					if ne, ok := err.(net.Error); ok && ne.Timeout() {
						kind = "tcp_timeout"
					}
					failures <- kind
					continue
				}
				_ = conn.Close()
				results <- rankedIP{IP: ip, Latency: time.Since(started)}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, ip := range candidates {
			select {
			case jobs <- ip:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { wg.Wait(); close(results); close(failures) }()
	ranked := make([]rankedIP, 0, len(candidates))
	counts := map[string]int{}
	for results != nil || failures != nil {
		select {
		case item, ok := <-results:
			if !ok {
				results = nil
			} else {
				ranked = append(ranked, item)
			}
		case kind, ok := <-failures:
			if !ok {
				failures = nil
			} else {
				counts[kind]++
			}
		}
	}
	sort.Slice(ranked, func(i, j int) bool { return ranked[i].Latency < ranked[j].Latency })
	return ranked, counts
}

func (s *Scanner) Probe(ctx context.Context, ip netip.Addr) (Result, error) {
	return s.ProbeWithMode(ctx, ip, s.cfg.ProbeMode)
}

func (s *Scanner) ProbeWithMode(ctx context.Context, ip netip.Addr, mode string) (Result, error) {
	switch mode {
	case "tcp":
		return s.probeTCP(ctx, ip)
	case "icmp":
		return s.probeICMP(ctx, ip)
	default:
		return s.probeHTTP(ctx, ip)
	}
}

func (s *Scanner) probeHTTP(ctx context.Context, ip netip.Addr) (Result, error) {
	u, _ := url.Parse(s.cfg.CheckURL)
	start := time.Now()
	needBody := len(s.cfg.Colos) > 0 && u.Path == "/cdn-cgi/trace"
	status, body, err := s.request(ctx, ip, u.RequestURI(), needBody)
	latency := time.Since(start)
	if err != nil {
		return Result{}, err
	}
	if status != s.cfg.ExpectedStatus {
		return Result{}, probeError("status", fmt.Errorf("状态码 %d，期望 %d", status, s.cfg.ExpectedStatus))
	}
	if latency > s.cfg.MaxLatency.Value() {
		return Result{}, probeError("latency", fmt.Errorf("延迟 %s 超过限制 %s", latency, s.cfg.MaxLatency.Value()))
	}
	colo := ""
	if len(s.cfg.Colos) > 0 {
		if !needBody {
			_, body, err = s.request(ctx, ip, "/cdn-cgi/trace", true)
			if err != nil {
				return Result{}, probeError("trace", fmt.Errorf("读取 colo: %w", err))
			}
		}
		colo = traceValue(body, "colo")
		if !contains(s.cfg.Colos, strings.ToUpper(colo)) {
			return Result{}, probeError("colo", fmt.Errorf("数据中心 %q 不在允许列表", colo))
		}
	}
	return Result{IP: ip, LatencyMS: latency.Milliseconds(), Colo: colo, CheckedAt: time.Now().UTC()}, nil
}

func (s *Scanner) probeTCP(ctx context.Context, ip netip.Addr) (Result, error) {
	dialer := net.Dialer{Timeout: s.cfg.DialTimeout.Value()}
	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), fmt.Sprint(s.cfg.TargetPort)))
	latency := time.Since(start)
	if err != nil {
		kind := "tcp_connect"
		if errors.Is(err, context.Canceled) {
			kind = "canceled"
		} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
			kind = "tcp_timeout"
		}
		return Result{}, probeError(kind, err)
	}
	_ = conn.Close()
	if latency > s.cfg.MaxLatency.Value() {
		return Result{}, probeError("latency", fmt.Errorf("延迟 %s 超过限制 %s", latency, s.cfg.MaxLatency.Value()))
	}
	return Result{IP: ip, LatencyMS: latency.Milliseconds(), CheckedAt: time.Now().UTC()}, nil
}

func (s *Scanner) probeICMP(ctx context.Context, ip netip.Addr) (Result, error) {
	timeout := max(1, int(s.cfg.DialTimeout.Value().Round(time.Second)/time.Second))
	args := []string{"-c", "1", "-W", fmt.Sprint(timeout), ip.String()}
	if ip.Is6() {
		args = append([]string{"-6"}, args...)
	}
	start := time.Now()
	out, err := exec.CommandContext(ctx, "ping", args...).CombinedOutput()
	latency := time.Since(start)
	if err != nil {
		kind := "icmp"
		if errors.Is(ctx.Err(), context.Canceled) {
			kind = "canceled"
		}
		return Result{}, probeError(kind, fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out))))
	}
	if parsed, ok := parsePingLatency(string(out)); ok {
		latency = parsed
	}
	if latency > s.cfg.MaxLatency.Value() {
		return Result{}, probeError("latency", fmt.Errorf("延迟 %s 超过限制 %s", latency, s.cfg.MaxLatency.Value()))
	}
	return Result{IP: ip, LatencyMS: latency.Milliseconds(), CheckedAt: time.Now().UTC()}, nil
}

func parsePingLatency(output string) (time.Duration, bool) {
	for _, field := range strings.Fields(output) {
		if strings.HasPrefix(field, "time=") || strings.HasPrefix(field, "time<") {
			value := strings.TrimPrefix(strings.TrimPrefix(field, "time="), "time<")
			value = strings.TrimSuffix(value, "ms")
			ms, err := strconv.ParseFloat(value, 64)
			if err != nil {
				return 0, false
			}
			return time.Duration(ms * float64(time.Millisecond)), true
		}
	}
	return 0, false
}

func (s *Scanner) request(ctx context.Context, ip netip.Addr, path string, readBody bool) (int, string, error) {
	u, _ := url.Parse(s.cfg.CheckURL)
	host := u.Hostname()
	serverName := s.cfg.TLSServerName
	if serverName == "" {
		serverName = host
	}
	dialer := &net.Dialer{Timeout: s.cfg.DialTimeout.Value()}
	address := net.JoinHostPort(ip.String(), fmt.Sprint(s.cfg.TargetPort))
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		kind := "connect"
		if errors.Is(err, context.Canceled) {
			kind = "canceled"
		} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
			kind = "timeout"
		}
		return 0, "", probeError(kind, err)
	}
	defer conn.Close()
	deadline := time.Now().Add(s.cfg.DialTimeout.Value())
	_ = conn.SetDeadline(deadline)
	if s.cfg.TLS {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: serverName, InsecureSkipVerify: s.cfg.InsecureSkipVerify}) // #nosec G402: explicit opt-in configuration
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return 0, "", probeError("tls", err)
		}
		conn = tlsConn
	}
	if path == "" {
		path = "/"
	}
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: cfnat-linux/1\r\nAccept: */*\r\nConnection: close\r\n\r\n", path, u.Host)
	if _, err := io.WriteString(conn, req); err != nil {
		return 0, "", probeError("http", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		return 0, "", probeError("http", err)
	}
	defer resp.Body.Close()
	body := ""
	if readBody {
		data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<10))
		if err != nil {
			return 0, "", probeError("http", err)
		}
		body = string(data)
	}
	return resp.StatusCode, body, nil
}

func (s *Scanner) readPrefixes(ctx context.Context) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	seen := make(map[netip.Prefix]struct{})
	for _, source := range s.cfg.IPSources {
		data, err := s.readSource(ctx, source)
		if err != nil {
			s.logger.Warn("IP 来源读取失败", "source", source, "error", err)
			continue
		}
		parsed, ignored := 0, 0
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
			for _, field := range strings.Fields(line) {
				prefix, parseErr := netip.ParsePrefix(field)
				if parseErr != nil {
					addr, addrErr := netip.ParseAddr(field)
					if addrErr != nil {
						ignored++
						continue
					}
					prefix = netip.PrefixFrom(addr, addr.BitLen())
				}
				if (s.cfg.IPVersion == 4) != prefix.Addr().Is4() {
					ignored++
					continue
				}
				prefix = prefix.Masked()
				if _, ok := seen[prefix]; !ok {
					seen[prefix] = struct{}{}
					prefixes = append(prefixes, prefix)
					parsed++
				}
			}
		}
		s.logger.Info("IP 来源已载入", "source", source, "parsed", parsed, "ignored", ignored)
	}
	if len(prefixes) == 0 {
		return nil, errors.New("所有 IP 来源均不可用或没有匹配的 CIDR")
	}
	return prefixes, nil
}

func (s *Scanner) readSource(ctx context.Context, source string) ([]byte, error) {
	if strings.HasPrefix(source, "https://") || strings.HasPrefix(source, "http://") {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
		if err != nil {
			return nil, err
		}
		resp, err := s.client.Do(req)
		if err != nil {
			if cached, cacheErr := s.readCache(source); cacheErr == nil {
				s.logger.Warn("远程 IP 来源不可用，使用本地缓存", "source", source, "error", err)
				return cached, nil
			}
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			if cached, cacheErr := s.readCache(source); cacheErr == nil {
				s.logger.Warn("远程 IP 来源返回异常，使用本地缓存", "source", source, "status", resp.StatusCode)
				return cached, nil
			}
			return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		if err == nil {
			s.writeCache(source, data)
		}
		return data, err
	}
	return os.ReadFile(source)
}

func (s *Scanner) cachePath(source string) string {
	if s.cfg.SourceCacheDir == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(source))
	return fmt.Sprintf("%s/%x.txt", strings.TrimRight(s.cfg.SourceCacheDir, "/"), sum[:8])
}

func (s *Scanner) readCache(source string) ([]byte, error) {
	path := s.cachePath(source)
	if path == "" {
		return nil, os.ErrNotExist
	}
	return os.ReadFile(path)
}

func (s *Scanner) writeCache(source string, data []byte) {
	path := s.cachePath(source)
	if path == "" {
		return
	}
	if err := os.MkdirAll(s.cfg.SourceCacheDir, 0750); err != nil {
		return
	}
	if err := os.WriteFile(path, data, 0640); err != nil {
		s.logger.Debug("IP 来源缓存写入失败", "error", err)
	}
}

func formatCounts(counts map[string]int) string {
	if len(counts) == 0 {
		return "无响应或扫描被中断"
	}
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", key, counts[key]))
	}
	return strings.Join(parts, ", ")
}

func mergeCounts(dst, src map[string]int) {
	for key, value := range src {
		dst[key] += value
	}
}

func filterBlacklist(candidates []netip.Addr, blacklist []string) []netip.Addr {
	if len(candidates) == 0 || len(blacklist) == 0 {
		return candidates
	}
	blockedIPs := make(map[netip.Addr]struct{})
	blockedPrefixes := []netip.Prefix{}
	for _, item := range blacklist {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if strings.Contains(item, "/") {
			prefix, err := netip.ParsePrefix(item)
			if err == nil {
				blockedPrefixes = append(blockedPrefixes, prefix.Masked())
			}
			continue
		}
		ip, err := netip.ParseAddr(item)
		if err == nil {
			blockedIPs[ip] = struct{}{}
		}
	}
	filtered := candidates[:0]
	for _, ip := range candidates {
		if _, ok := blockedIPs[ip]; ok {
			continue
		}
		blocked := false
		for _, prefix := range blockedPrefixes {
			if prefix.Contains(ip) {
				blocked = true
				break
			}
		}
		if !blocked {
			filtered = append(filtered, ip)
		}
	}
	return filtered
}

func generateCandidates(prefixes []netip.Prefix, random bool, limit int) ([]netip.Addr, error) {
	if len(prefixes) == 0 || limit < 1 {
		return nil, errors.New("无候选网段")
	}
	result := make([]netip.Addr, 0, limit)
	seen := make(map[netip.Addr]struct{}, limit)
	if random {
		attempts := 0
		for len(result) < limit && attempts < limit*20 {
			prefix := prefixes[attempts%len(prefixes)]
			ip, err := randomAddr(prefix)
			if err != nil {
				return nil, err
			}
			if _, ok := seen[ip]; !ok {
				seen[ip] = struct{}{}
				result = append(result, ip)
			}
			attempts++
		}
		return result, nil
	}
	for _, prefix := range prefixes {
		for ip := prefix.Addr(); prefix.Contains(ip) && len(result) < limit; ip = ip.Next() {
			if _, ok := seen[ip]; !ok {
				seen[ip] = struct{}{}
				result = append(result, ip)
			}
		}
		if len(result) == limit {
			break
		}
	}
	return result, nil
}

func randomAddr(prefix netip.Prefix) (netip.Addr, error) {
	bits := 128
	base := prefix.Addr().As16()
	if prefix.Addr().Is4() {
		bits = 32
	}
	hostBits := bits - prefix.Bits()
	var random [16]byte
	if _, err := cryptorand.Read(random[:]); err != nil {
		return netip.Addr{}, err
	}
	if bits == 32 {
		base4 := prefix.Addr().As4()
		baseNum := binary.BigEndian.Uint32(base4[:])
		randomNum := binary.BigEndian.Uint32(random[:4])
		var mask uint32
		if hostBits == 32 {
			mask = ^uint32(0)
		} else if hostBits > 0 {
			mask = (uint32(1) << hostBits) - 1
		}
		var out [4]byte
		binary.BigEndian.PutUint32(out[:], baseNum|(randomNum&mask))
		return netip.AddrFrom4(out), nil
	}
	for bit := prefix.Bits(); bit < 128; bit++ {
		byteIndex, bitIndex := bit/8, uint(7-bit%8)
		if random[byteIndex]&(1<<bitIndex) != 0 {
			base[byteIndex] |= 1 << bitIndex
		}
	}
	return netip.AddrFrom16(base), nil
}

func traceValue(body, key string) string {
	for _, line := range strings.Split(body, "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), "=", 2)
		if len(parts) == 2 && parts[0] == key {
			return parts[1]
		}
	}
	return ""
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
