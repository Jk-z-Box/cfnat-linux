package app

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/cfnat-linux/cfnat-linux/internal/config"
	"github.com/cfnat-linux/cfnat-linux/internal/shodan"
)

type webServer struct {
	app    *App
	shodan *shodan.Manager
	tmpl   *template.Template
}

func (a *App) serveWeb(ctx context.Context, ready chan<- error) error {
	ws := &webServer{app: a, shodan: shodan.New(a.cfg.Shodan)}
	ws.shodan.SetOnChange(a.broadcastState)
	ws.tmpl = template.Must(template.New("panel").Funcs(template.FuncMap{
		"join": strings.Join,
	}).Parse(panelHTML))
	mux := http.NewServeMux()
	mux.HandleFunc("/", ws.handleIndex)
	mux.HandleFunc("/login", ws.handleLogin)
	mux.HandleFunc("/logout", ws.handleLogout)
	mux.HandleFunc("/api/status", ws.requireAuth(ws.handleAPIStatus))
	mux.HandleFunc("/events", ws.requireAuth(ws.handleEvents))
	mux.HandleFunc("/logs/events", ws.requireAuth(ws.handleLogEvents))
	mux.HandleFunc("/cfnat/scan", ws.requireAuth(ws.handleCFNatScan))
	mux.HandleFunc("/cfnat/toggle", ws.requireAuth(ws.handleCFNatToggle))
	mux.HandleFunc("/cfnat/config", ws.requireAuth(ws.handleCFNatConfig))
	mux.HandleFunc("/shodan/save", ws.requireAuth(ws.handleShodanSave))
	mux.HandleFunc("/shodan/fetch", ws.requireAuth(ws.handleShodanFetch))
	mux.HandleFunc("/shodan/download/", ws.requireAuth(ws.handleShodanDownload))
	mux.HandleFunc("/shodan/toggle-download", ws.requireAuth(ws.handleShodanToggleDownload))
	mux.HandleFunc("/shodan/switch", ws.requireAuth(ws.handleShodanSwitch))
	mux.HandleFunc("/shodan/new", ws.requireAuth(ws.handleShodanNew))
	mux.HandleFunc("/shodan/delete", ws.requireAuth(ws.handleShodanDelete))

	lc := net.ListenConfig{}
	listener, err := lc.Listen(ctx, "tcp", a.cfg.Web.Listen)
	if err != nil {
		if ready != nil {
			ready <- err
		}
		return err
	}
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	a.logger.Info("Web 管理面板已启动", "listen", a.cfg.Web.Listen, "shodan_enabled", a.cfg.Shodan.Enabled)
	if ready != nil {
		ready <- nil
	}
	err = server.Serve(listener)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (w *webServer) handleIndex(rw http.ResponseWriter, r *http.Request) {
	if !w.authed(r) {
		w.renderLogin(rw, "")
		return
	}
	w.render(rw, w.consumeFlash(rw, r))
}

func (w *webServer) handleLogin(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.renderLogin(rw, "")
		return
	}
	_ = r.ParseForm()
	username := r.Form.Get("username")
	password := r.Form.Get("password")
	if !w.passwordOK(username, password) {
		w.renderLogin(rw, "用户名或密码错误。")
		return
	}
	http.SetCookie(rw, &http.Cookie{Name: "cfnat_web_session", Value: w.sessionValue(), Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 86400})
	http.Redirect(rw, r, "/", http.StatusSeeOther)
}

func (w *webServer) handleLogout(rw http.ResponseWriter, r *http.Request) {
	http.SetCookie(rw, &http.Cookie{Name: "cfnat_web_session", Value: "", Path: "/", MaxAge: -1})
	http.Redirect(rw, r, "/", http.StatusSeeOther)
}

func (w *webServer) consumeFlash(rw http.ResponseWriter, r *http.Request) string {
	cookie, err := r.Cookie("cfnat_flash")
	if err != nil {
		return ""
	}
	http.SetCookie(rw, &http.Cookie{Name: "cfnat_flash", Value: "", Path: "/", MaxAge: -1, SameSite: http.SameSiteLaxMode})
	msg, err := url.QueryUnescape(cookie.Value)
	if err != nil {
		return cookie.Value
	}
	return msg
}

func (w *webServer) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		if !w.authed(r) {
			w.renderLogin(rw, "请先登录。")
			return
		}
		next(rw, r)
	}
}

func (w *webServer) authed(r *http.Request) bool {
	cookie, err := r.Cookie("cfnat_web_session")
	return err == nil && cookie.Value == w.sessionValue()
}

func (w *webServer) sessionValue() string {
	sum := sha256.Sum256([]byte("cfnat-web:" + w.app.cfg.Web.Username + ":" + w.app.cfg.Web.PasswordSHA256))
	return hex.EncodeToString(sum[:])
}

func (w *webServer) passwordOK(username, password string) bool {
	if username != w.app.cfg.Web.Username {
		return false
	}
	sum := sha256.Sum256([]byte(password))
	return hex.EncodeToString(sum[:]) == strings.ToLower(w.app.cfg.Web.PasswordSHA256)
}

func (w *webServer) handleCFNatScan(rw http.ResponseWriter, r *http.Request) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		if err := w.app.rescan(ctx, "web"); err != nil {
			w.app.logger.Error("Web 触发扫描失败", "error", err)
		}
	}()
	w.redirect(rw, "已触发 cfnat 重新扫描。")
}

func (w *webServer) handleCFNatToggle(rw http.ResponseWriter, r *http.Request) {
	enabled := w.app.proxy.Toggle()
	w.app.broadcastState()
	if enabled {
		w.redirect(rw, "TCP 转发已恢复。")
		return
	}
	w.redirect(rw, "TCP 转发已暂停，Web 面板保持运行。")
}

func (w *webServer) handleAPIStatus(rw http.ResponseWriter, r *http.Request) {
	payload := w.statusPayload()
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(rw).Encode(payload)
}

func (w *webServer) handleEvents(rw http.ResponseWriter, r *http.Request) {
	flusher, ok := rw.(http.Flusher)
	if !ok {
		http.Error(rw, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	rw.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	rw.Header().Set("Cache-Control", "no-cache")
	rw.Header().Set("Connection", "keep-alive")
	send := func() bool {
		data, err := json.Marshal(w.statusPayload())
		if err != nil {
			return false
		}
		if _, err := fmt.Fprintf(rw, "event: status\ndata: %s\n\n", data); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}
	if !send() {
		return
	}
	seq := w.app.stateSequence()
	for r.Context().Err() == nil {
		seq = w.app.waitStateChange(r.Context(), seq)
		if r.Context().Err() != nil {
			return
		}
		if !send() {
			return
		}
	}
}

func (w *webServer) handleLogEvents(rw http.ResponseWriter, r *http.Request) {
	flusher, ok := rw.(http.Flusher)
	if !ok {
		http.Error(rw, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	rw.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	rw.Header().Set("Cache-Control", "no-cache")
	rw.Header().Set("Connection", "keep-alive")
	send := func(line string) bool {
		data, err := json.Marshal(map[string]string{"line": line})
		if err != nil {
			return false
		}
		if _, err := fmt.Fprintf(rw, "event: log\ndata: %s\n\n", data); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}
	if !send("正在连接 journald：journalctl -u cfnat -n 120 -f") {
		return
	}
	cmd := exec.CommandContext(r.Context(), "journalctl", "-u", "cfnat", "-n", "120", "-f", "-o", "short-iso", "--no-pager")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = send("无法读取 journalctl 输出：" + err.Error())
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		_ = send("无法读取 journalctl 错误输出：" + err.Error())
		return
	}
	if err := cmd.Start(); err != nil {
		_ = send("无法启动 journalctl：" + err.Error())
		return
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		scanner := bufio.NewScanner(stdout)
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 1024*1024)
		for scanner.Scan() {
			if !send(scanner.Text()) {
				return
			}
		}
		if err := scanner.Err(); err != nil && r.Context().Err() == nil {
			_ = send("journalctl 读取中断：" + err.Error())
		}
	}()
	errDone := make(chan string, 1)
	go func() {
		var b strings.Builder
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			if b.Len() > 0 {
				b.WriteByte('\n')
			}
			b.WriteString(scanner.Text())
		}
		errDone <- b.String()
	}()
	select {
	case <-r.Context().Done():
	case <-done:
	}
	if err := cmd.Wait(); err != nil && r.Context().Err() == nil {
		msg := strings.TrimSpace(<-errDone)
		if msg != "" {
			_ = send("journalctl 退出：" + msg)
		} else {
			_ = send("journalctl 退出：" + err.Error())
		}
	}
}

func (w *webServer) handleCFNatConfig(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.redirect(rw, "请求方法无效。")
		return
	}
	_ = r.ParseForm()
	updates := map[string]string{
		"max_latency":              r.Form.Get("max_latency") + "ms",
		"min_healthy_count":        r.Form.Get("min_healthy_count"),
		"latency_monitor_interval": r.Form.Get("latency_monitor_interval") + "s",
		"speed_test_enabled":       boolText(r.Form.Get("speed_test_enabled") == "on"),
		"speed_test_min_mbps":      r.Form.Get("speed_test_min_mbps"),
		"speed_test_concurrency":   r.Form.Get("speed_test_concurrency"),
		"dns_enabled":              boolText(r.Form.Get("dns_enabled") == "on"),
		"record_name":              r.Form.Get("record_name"),
		"zone_id":                  r.Form.Get("zone_id"),
		"web_enabled":              boolText(r.Form.Get("web_enabled") == "on"),
		"web_listen":               r.Form.Get("web_listen"),
		"web_username":             r.Form.Get("web_username"),
		"shodan_enabled":           boolText(r.Form.Get("shodan_enabled") == "on"),
	}
	if password := r.Form.Get("web_password"); password != "" {
		sum := sha256.Sum256([]byte(password))
		updates["web_password_sha256"] = hex.EncodeToString(sum[:])
	}
	for key, value := range updates {
		if strings.TrimSpace(value) == "" || value == "ms" || value == "s" {
			continue
		}
		if err := config.Set(w.app.configPath, key, value); err != nil {
			w.render(rw, fmt.Sprintf("配置保存失败：%s = %s，%v", key, value, err))
			return
		}
	}
	if cfg, err := config.Load(w.app.configPath); err == nil {
		w.app.cfg = cfg
	}
	w.app.broadcastState()
	w.redirect(rw, "配置已保存。监听地址、Web 开关、Shodan 开关等项目需要重启 cfnat 服务后完全生效。")
}

func (w *webServer) handleShodanSave(rw http.ResponseWriter, r *http.Request) {
	if !w.app.cfg.Shodan.Enabled {
		w.redirect(rw, "Shodan IP Panel 未启用。")
		return
	}
	_ = r.ParseForm()
	fetchCount, _ := strconv.Atoi(r.Form.Get("fetch_count"))
	err := w.shodan.UpdateActive(shodan.Profile{
		APIKey: r.Form.Get("api_key"), Ports: r.Form.Get("ports"), Countries: r.Form.Get("countries"),
		ASNs: r.Form.Get("asns"), Keywords: r.Form.Get("keywords"), ExtraFilters: r.Form.Get("extra_filters"),
		RawQuery: r.Form.Get("raw_query"), FetchCount: fetchCount,
	})
	if err != nil {
		w.render(rw, "Shodan 配置保存失败："+err.Error())
		return
	}
	w.app.broadcastState()
	w.redirect(rw, "Shodan 当前配置已保存。")
}

func (w *webServer) handleShodanFetch(rw http.ResponseWriter, r *http.Request) {
	if w.app.cfg.Shodan.Enabled {
		w.shodan.FetchAsync(context.Background())
		w.redirect(rw, "已开始获取 Shodan IP，状态会在页面中实时更新。")
		return
	}
	w.redirect(rw, "Shodan IP Panel 未启用。")
}

func (w *webServer) handleShodanToggleDownload(rw http.ResponseWriter, r *http.Request) {
	if err := w.shodan.ToggleDownload(); err != nil {
		w.render(rw, "下载开关切换失败："+err.Error())
		return
	}
	w.app.broadcastState()
	w.redirect(rw, "Shodan 下载链接状态已切换。")
}

func (w *webServer) handleShodanSwitch(rw http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	if err := w.shodan.SwitchProfile(r.Form.Get("profile_name")); err != nil {
		w.render(rw, "切换失败："+err.Error())
		return
	}
	w.app.broadcastState()
	w.redirect(rw, "已切换 Shodan 配置。")
}

func (w *webServer) handleShodanNew(rw http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	if err := w.shodan.NewProfile(r.Form.Get("profile_name")); err != nil {
		w.render(rw, "新增配置失败："+err.Error())
		return
	}
	fetchCount, _ := strconv.Atoi(r.Form.Get("fetch_count"))
	if strings.TrimSpace(r.Form.Get("api_key")+r.Form.Get("ports")+r.Form.Get("countries")+r.Form.Get("asns")+r.Form.Get("keywords")+r.Form.Get("extra_filters")+r.Form.Get("raw_query")) != "" || fetchCount > 0 {
		_ = w.shodan.UpdateActive(shodan.Profile{
			APIKey: r.Form.Get("api_key"), Ports: r.Form.Get("ports"), Countries: r.Form.Get("countries"),
			ASNs: r.Form.Get("asns"), Keywords: r.Form.Get("keywords"), ExtraFilters: r.Form.Get("extra_filters"),
			RawQuery: r.Form.Get("raw_query"), FetchCount: fetchCount,
		})
	}
	w.app.broadcastState()
	w.redirect(rw, "已新增 Shodan 配置。")
}

func (w *webServer) handleShodanDelete(rw http.ResponseWriter, r *http.Request) {
	if err := w.shodan.DeleteActive(); err != nil {
		w.render(rw, "删除配置失败："+err.Error())
		return
	}
	w.app.broadcastState()
	w.redirect(rw, "已删除 Shodan 当前配置。")
}

func (w *webServer) handleShodanDownload(rw http.ResponseWriter, r *http.Request) {
	name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/shodan/download/"), ".txt")
	cfg, err := w.shodan.Config()
	if err != nil {
		http.NotFound(rw, r)
		return
	}
	for profileName, profile := range cfg.Profiles {
		if shodan.Slug(profileName) == name && profile.DownloadEnabled {
			path := w.shodan.ProfilePath(profileName)
			data, err := os.ReadFile(path)
			if err != nil {
				http.NotFound(rw, r)
				return
			}
			rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
			rw.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="shodan_ips_%s.txt"`, name))
			_, _ = rw.Write(data)
			return
		}
	}
	http.NotFound(rw, r)
}

func (w *webServer) renderLogin(rw http.ResponseWriter, msg string) {
	_, _ = rw.Write([]byte(`<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>cfnat Web Login</title><style>` + css + `</style></head><body><main class="login"><h1>cfnat-linux</h1><p>` + template.HTMLEscapeString(msg) + `</p><form method="post" action="/login"><label>Web 用户名</label><input name="username" autocomplete="username" autofocus><label>Web 密码</label><input name="password" type="password" autocomplete="current-password"><button>登入</button></form></main></body></html>`))
}

func (w *webServer) render(rw http.ResponseWriter, msg string) {
	cfg := w.app.cfg
	payload := w.statusPayload()
	var shodanCfg shodan.StoreConfig
	var shodanProfile shodan.Profile
	var shodanStatus shodan.Status
	var shodanErr string
	if cfg.Shodan.Enabled {
		var err error
		shodanCfg, shodanProfile, shodanStatus, err = w.shodan.Active()
		if err != nil {
			shodanErr = err.Error()
		}
	}
	data := map[string]any{
		"CSS":           template.CSS(css),
		"Message":       msg,
		"Payload":       payload,
		"Config":        cfg,
		"MaxLatencyMS":  cfg.MaxLatency.Value().Milliseconds(),
		"LatencySecs":   int(cfg.LatencyMonitorInterval.Value().Seconds()),
		"ShodanConfig":  shodanCfg,
		"ShodanProfile": shodanProfile,
		"ShodanStatus":  shodanStatus,
		"ShodanQuery":   shodan.BuildQuery(shodanProfile),
		"ShodanError":   shodanErr,
		"ShodanMaskKey": shodan.MaskKey(shodanProfile.APIKey),
	}
	if err := w.tmpl.Execute(rw, data); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
	}
}

func (w *webServer) statusPayload() map[string]any {
	cfg := w.app.cfg
	var status bytes.Buffer
	PrintStatus(&status, cfg)
	state, _ := ReadState(cfg.StateFile)
	summary := map[string]string{
		"cfnat":      statusText(state.Status),
		"scan":       scanSummary(state.Scan),
		"primary_ip": valueOr(state.PrimaryIP, "暂无"),
		"dns":        dnsSummary(cfg, state),
		"update":     updateSummary(state),
	}
	shodanSummary := map[string]string{"enabled": boolLabel(cfg.Shodan.Enabled), "state": "未启用", "ips": "0", "error": ""}
	if cfg.Shodan.Enabled {
		st := w.shodan.Status()
		store, profile, _, err := w.shodan.Active()
		if err != nil {
			shodanSummary["state"] = "错误"
			shodanSummary["error"] = err.Error()
		} else {
			shodanSummary["state"] = shodanStateText(st.State)
			shodanSummary["state_raw"] = valueOr(st.State, "idle")
			shodanSummary["ips"] = fmt.Sprint(profile.UniqueIPsWritten)
			shodanSummary["profile"] = store.ActiveProfile
			shodanSummary["last_success"] = profile.LastSuccessAt
			shodanSummary["download_enabled"] = boolLabel(profile.DownloadEnabled)
			if st.ActiveProfile == "" || st.ActiveProfile == store.ActiveProfile || st.State == "running" {
				shodanSummary["error"] = st.LastError
			}
		}
	}
	return map[string]any{
		"summary": summary,
		"cfnat": map[string]any{
			"text":       status.String(),
			"status":     statusText(state.Status),
			"proxy":      proxyStatusText(w.app.proxy.Enabled()),
			"proxy_on":   w.app.proxy.Enabled(),
			"scan":       scanSummary(state.Scan),
			"primary_ip": valueOr(state.PrimaryIP, "暂无"),
			"dns":        dnsSummary(cfg, state),
			"targets":    len(state.Targets),
		},
		"shodan": shodanSummary,
	}
}

func scanSummary(scan ScanState) string {
	if scan.InProgress {
		return "扫描中"
	}
	if scan.Completed {
		return "已完成"
	}
	if scan.LastError != "" {
		return "失败"
	}
	return "未完成"
}

func dnsSummary(cfg config.Config, state RuntimeState) string {
	if !cfg.DNS.Enabled {
		return "未启用"
	}
	if state.DNS.Synced {
		return "已同步"
	}
	return "未同步"
}

func updateSummary(state RuntimeState) string {
	if state.Update.UpdateAvailable {
		return "发现 " + state.Update.LatestVersion
	}
	if state.Update.LastError != "" {
		return "检查失败"
	}
	if state.Update.LastCheckedAt != nil {
		return "已是最新"
	}
	return "未检查"
}

func shodanStateText(state string) string {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "running":
		return "获取中"
	case "error":
		return "错误"
	case "idle", "":
		return "空闲"
	default:
		return state
	}
}

func proxyStatusText(enabled bool) string {
	if enabled {
		return "转发中"
	}
	return "已暂停"
}

func boolLabel(v bool) string {
	if v {
		return "已启用"
	}
	return "未启用"
}

func (w *webServer) redirect(rw http.ResponseWriter, msg string) {
	http.SetCookie(rw, &http.Cookie{Name: "cfnat_flash", Value: url.QueryEscape(msg), Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 30})
	rw.Header().Set("Location", "/")
	rw.WriteHeader(http.StatusSeeOther)
}

func boolText(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

const css = `
:root{--bg:#f4f7fb;--panel:#fff;--line:#dfe7f0;--text:#17202a;--muted:#66758a;--blue:#1769e0;--green:#168047;--red:#c7362f;--amber:#a86b00;--shadow:0 14px 38px rgba(20,35,60,.08)}*{box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:0;background:linear-gradient(180deg,#edf4ff 0,#f7f8fb 280px);color:var(--text)}main{max-width:1220px;margin:0 auto;padding:22px 16px 48px}.login{max-width:430px;margin-top:12vh;background:var(--panel);border:1px solid var(--line);border-radius:20px;box-shadow:var(--shadow);padding:24px}.topbar{display:flex;align-items:center;justify-content:space-between;gap:14px;margin-bottom:18px}.brand h1{margin:0;font-size:28px}.brand p{margin:5px 0 0;color:var(--muted)}.top-actions{display:flex;align-items:center;gap:8px;flex-wrap:wrap}.lang-switch{display:inline-flex;gap:4px;padding:4px;background:#edf3fb;border-radius:999px;border:1px solid #dde8f5}.lang-switch button{background:transparent;color:#31527c;border-radius:999px;padding:7px 10px}.lang-switch button.active{background:#fff;color:var(--blue);box-shadow:0 2px 10px rgba(20,35,60,.12)}a{color:var(--blue)}section,.panel{background:rgba(255,255,255,.95);border:1px solid var(--line);border-radius:20px;box-shadow:var(--shadow);padding:18px;margin:14px 0}.summary-grid{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:12px}.card{background:#f9fbfe;border:1px solid #e6edf5;border-radius:16px;padding:14px;min-width:0}.card b{display:block;color:var(--muted);font-size:12px;margin-bottom:8px;text-transform:uppercase;letter-spacing:.03em}.value,.metric{font-size:20px;font-weight:760;overflow-wrap:anywhere;word-break:break-word}.value{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.ok{color:var(--green)}.warn{color:var(--amber)}.bad{color:var(--red)}.layout{display:grid;grid-template-columns:minmax(0,1fr) minmax(360px,.82fr);gap:14px;align-items:start}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.config-group{border-color:#e6edf5;background:#fff}.config-group summary{display:flex;align-items:center;justify-content:space-between}label{display:block;font-weight:650;margin:10px 0 6px}input,textarea,select{width:100%;border:1px solid #cfd9e5;border-radius:12px;padding:10px;font-size:14px;background:#fff}textarea{min-height:82px}button,.button{border:0;border-radius:12px;background:var(--blue);color:white;padding:10px 14px;cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;justify-content:center;font-size:14px;font-weight:650}.secondary{background:#59697b}.danger{background:var(--red)}.logout{background:#17202a;color:white;border-radius:999px;padding:9px 14px;text-decoration:none}.logout:hover{text-decoration:none;filter:brightness(1.08)}.actions{display:flex;flex-wrap:wrap;gap:10px;margin-top:14px}.msg{background:#edf7ed;border:1px solid #b9dfbc;padding:10px;border-radius:12px;margin:12px 0}.hint,.muted{color:var(--muted);font-size:13px;line-height:1.45}pre{white-space:pre-wrap;background:#0f1724;color:#dce8ff;border-radius:14px;padding:14px;overflow:auto;font-size:13px;line-height:1.5;max-height:420px}details{border:1px solid #e1e8f0;border-radius:16px;padding:12px 14px;margin:12px 0;background:#fbfcfe}summary{cursor:pointer;font-weight:760}.pill{display:inline-flex;align-items:center;gap:6px;border-radius:999px;padding:6px 10px;background:#eef4ff;color:#31527c;font-size:12px}.live-dot{width:8px;height:8px;border-radius:50%;background:#15b76a;box-shadow:0 0 0 5px rgba(21,183,106,.13)}.section-title{display:flex;align-items:center;justify-content:space-between;gap:10px}.title-actions{display:flex;align-items:center;gap:8px;flex-wrap:wrap}.mini-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}.profile-head{display:grid;grid-template-columns:1fr minmax(180px,340px) auto;gap:12px;align-items:center;background:#f7faff;border:1px solid #e4edf8;border-radius:16px;padding:12px;margin:12px 0}.profile-name{font-size:22px;font-weight:780}.profile-switch{display:contents}.profile-switch select{min-width:0}.accordion-list details{margin:10px 0}dialog{border:0;border-radius:20px;box-shadow:0 24px 80px rgba(15,30,55,.28);padding:0;width:min(720px,calc(100vw - 24px));max-height:88vh}dialog::backdrop{background:rgba(9,18,33,.45);backdrop-filter:blur(2px)}.modal-card{padding:18px;background:white;overflow:auto;max-height:88vh}.inline-form{display:inline-flex}@media(max-width:980px){.summary-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.layout{grid-template-columns:1fr}.profile-head{grid-template-columns:1fr}}@media(max-width:620px){main{padding:14px 10px 36px}.topbar{align-items:flex-start;flex-direction:column}.top-actions{width:100%;justify-content:space-between}.brand h1{font-size:24px}.summary-grid,.grid,.mini-grid{grid-template-columns:1fr}.value{font-size:18px}section,.panel{border-radius:16px;padding:14px}.actions{flex-direction:column}.actions button,.actions .button,.inline-form{width:100%}.profile-head{align-items:stretch}.profile-switch{display:flex;flex-direction:column}.section-title{align-items:flex-start;flex-direction:column}.title-actions{width:100%}.title-actions button,.title-actions form{flex:1}}
`

const panelHTML = `<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>cfnat Web 管理面板</title><style>{{.CSS}}</style></head><body><main>
<div class="topbar"><div class="brand"><h1 data-i18n="brandTitle">cfnat-linux 控制台</h1><p data-i18n="brandSub">統一管理 cfnat 與 Shodan IP Panel</p></div><div class="top-actions"><div class="lang-switch"><button type="button" data-lang="zh-Hant" class="active">繁</button><button type="button" data-lang="zh-Hans">简</button><button type="button" data-lang="en">EN</button></div><a class="logout" href="/logout" data-i18n="logout">登出</a></div></div>
{{if .Message}}<div class="msg">{{.Message}}</div>{{end}}
<section><div class="section-title"><h2 data-i18n="overview">即時狀態總覽</h2><span class="pill"><span class="live-dot"></span><span id="live-state" data-i18n="connecting">即時連線中</span></span></div><div class="summary-grid">
<div class="card"><b>CFNAT</b><div class="value" id="sum-cfnat">{{index (index .Payload "summary") "cfnat"}}</div></div><div class="card"><b data-i18n="scan">掃描</b><div class="value" id="sum-scan">{{index (index .Payload "summary") "scan"}}</div></div><div class="card"><b data-i18n="primaryIP">最優 IP</b><div class="value" id="sum-primary">{{index (index .Payload "summary") "primary_ip"}}</div></div><div class="card"><b>DNS</b><div class="value" id="sum-dns">{{index (index .Payload "summary") "dns"}}</div></div><div class="card"><b>SHODAN</b><div class="value" id="sum-shodan-state">{{index (index .Payload "shodan") "state"}}</div><div class="muted">IP: <span id="sum-shodan-ips">{{index (index .Payload "shodan") "ips"}}</span></div></div>
</div><p id="sum-shodan-error" class="hint">{{index (index .Payload "shodan") "error"}}</p><details><summary data-i18n="fullStatus">查看完整運行狀態明細</summary><pre id="cfnat-status">{{index (index .Payload "cfnat") "text"}}</pre></details><details id="log-details"><summary data-i18n="liveLog">查看即時日誌</summary><pre id="realtime-log">正在等待日誌連線...</pre></details></section>
<div class="layout"><div>
<section><div class="section-title"><h2 data-i18n="cfnatActions">cfnat 操作</h2><span class="hint" id="proxy-state">{{index (index .Payload "cfnat") "proxy"}}</span></div><div class="actions"><form method="post" action="/cfnat/toggle"><button class="secondary" id="proxy-toggle">{{if index (index .Payload "cfnat") "proxy_on"}}暫停 TCP 轉發{{else}}恢復 TCP 轉發{{end}}</button></form><form method="post" action="/cfnat/scan"><button data-i18n="rescan">立即重新掃描</button></form></div></section>
<section><h2 data-i18n="commonConfig">cfnat 常用配置</h2><form method="post" action="/cfnat/config"><details class="config-group"><summary data-i18n="optHealth">優選與健康</summary><div class="grid"><div><label data-i18n="maxLatency">最大優選延遲 ms</label><input name="max_latency" type="number" value="{{.MaxLatencyMS}}"></div><div><label data-i18n="minHealthy">最小健康 IP 數</label><input name="min_healthy_count" type="number" value="{{.Config.MinHealthyCount}}"></div><div><label data-i18n="latencyInterval">延遲監控間隔 秒</label><input name="latency_monitor_interval" type="number" value="{{.LatencySecs}}"></div></div></details><details class="config-group"><summary data-i18n="speedFilter">測速篩選</summary><label><input style="width:auto" type="checkbox" name="speed_test_enabled" {{if .Config.SpeedTest.Enabled}}checked{{end}}> <span data-i18n="enableSpeed">啟用下載測速</span></label><div class="grid"><div><label data-i18n="speedMin">下載測速最低 MB/s</label><input name="speed_test_min_mbps" value="{{.Config.SpeedTest.MinMBps}}"></div><div><label data-i18n="speedConc">下載測速並發</label><input name="speed_test_concurrency" type="number" value="{{.Config.SpeedTest.Concurrency}}"></div></div></details><details class="config-group"><summary data-i18n="dnsCf">DNS 與 Cloudflare</summary><label><input style="width:auto" type="checkbox" name="dns_enabled" {{if .Config.DNS.Enabled}}checked{{end}}> <span data-i18n="enableDNS">啟用 Cloudflare DNS 同步</span></label><div class="grid"><div><label>Cloudflare Zone ID</label><input name="zone_id" value="{{.Config.DNS.ZoneID}}"></div><div><label data-i18n="recordName">DNS 解析域名</label><input name="record_name" value="{{.Config.DNS.RecordName}}"></div></div></details><details class="config-group"><summary data-i18n="webSensitive">Web 與敏感設定</summary><div class="grid"><div><label data-i18n="webListen">Web 監聽</label><input name="web_listen" value="{{.Config.Web.Listen}}"></div><div><label data-i18n="webUser">Web 使用者名稱</label><input name="web_username" value="{{.Config.Web.Username}}" autocomplete="username"></div><div><label data-i18n="webNewPass">Web 新密碼</label><input name="web_password" type="password" autocomplete="new-password" placeholder="留空不修改"></div></div><label><input style="width:auto" type="checkbox" name="web_enabled" {{if .Config.Web.Enabled}}checked{{end}}> <span data-i18n="enableWeb">啟用 Web 管理面板</span></label><label><input style="width:auto" type="checkbox" name="shodan_enabled" {{if .Config.Shodan.Enabled}}checked{{end}}> <span data-i18n="enableShodan">啟用 Shodan IP Panel</span></label><p class="hint" data-i18n="webHint">Web 帳密與 SSH 選單管理密碼互不干涉。修改 Web 監聽、Web 開關或 Shodan 開關後需重啟 cfnat 服務。</p></details><div class="actions"><button data-i18n="saveCfnat">儲存 cfnat 配置</button></div></form></section>
</div><div>
<section><div class="section-title"><div><h2>Shodan IP Panel</h2><span class="hint" data-i18n="shodanSub">配置、查詢與結果下載集中管理</span></div>{{if .Config.Shodan.Enabled}}<div class="title-actions"><button type="button" class="secondary" onclick="openModal('new-profile-modal')" data-i18n="newProfile">新增配置</button><form method="post" action="/shodan/delete" class="inline-form" onsubmit="return confirm('確認刪除目前 Shodan 配置？');"><button class="danger" data-i18n="deleteProfile">刪除配置</button></form></div>{{end}}</div>{{if not .Config.Shodan.Enabled}}<p data-i18n="shodanDisabled">Shodan IP Panel 未啟用。可在敏感設定中勾選後儲存，重啟 cfnat 服務生效。</p>{{else}}{{if .ShodanError}}<div class="msg">{{.ShodanError}}</div>{{end}}<div class="profile-head"><div><div class="muted" data-i18n="currentProfile">目前配置</div><div class="profile-name">{{.ShodanConfig.ActiveProfile}}</div></div><form method="post" action="/shodan/switch" class="profile-switch"><select name="profile_name">{{range $name, $_ := .ShodanConfig.Profiles}}<option value="{{$name}}" {{if eq $.ShodanConfig.ActiveProfile $name}}selected{{end}}>{{$name}}</option>{{end}}</select><button class="secondary" data-i18n="switch">切換</button></form></div><div class="accordion-list"><details><summary data-i18n="profileStatus">配置狀態</summary><div class="mini-grid"><div class="card"><b>API Key</b><div class="metric">{{.ShodanMaskKey}}</div></div><div class="card"><b data-i18n="lastSuccess">最近成功</b><div class="metric" id="shodan-success-card">{{if .ShodanProfile.LastSuccessAt}}{{.ShodanProfile.LastSuccessAt}}{{else}}未獲取{{end}}</div></div><div class="card"><b data-i18n="writtenIPs">已寫入 IP</b><div class="metric" id="shodan-ips-card">{{.ShodanProfile.UniqueIPsWritten}}</div></div></div><p data-i18n="querySyntax">目前查詢語法</p><pre>{{.ShodanQuery}}</pre>{{if .ShodanStatus.LastError}}<pre>{{.ShodanStatus.LastError}}</pre>{{end}}</details><details><summary data-i18n="downloadFetch">下載與獲取</summary><div class="actions"><form method="post" action="/shodan/fetch"><button data-i18n="fetchNow">獲取最新資料</button></form><form method="post" action="/shodan/toggle-download"><button class="secondary">{{if .ShodanProfile.DownloadEnabled}}關閉{{else}}開啟{{end}}下載連結</button></form>{{if .ShodanProfile.DownloadEnabled}}<a class="button" href="/shodan/download/{{.ShodanConfig.ActiveProfile}}.txt" data-i18n="downloadCurrent">下載目前配置 IP</a>{{end}}</div><p class="hint" data-i18n="downloadHint">下載開關只影響目前配置的下載入口。</p></details><details><summary data-i18n="editProfile">修改配置</summary><form method="post" action="/shodan/save"><label>Shodan API Key</label><input name="api_key" value="{{.ShodanProfile.APIKey}}" autocomplete="off"><div class="grid"><div><label>Port</label><input name="ports" value="{{.ShodanProfile.Ports}}"></div><div><label>Country</label><input name="countries" value="{{.ShodanProfile.Countries}}"></div><div><label>ASN</label><input name="asns" value="{{.ShodanProfile.ASNs}}"></div><div><label data-i18n="fetchCount">IP 獲取數量</label><input name="fetch_count" type="number" min="1" max="10000" value="{{.ShodanProfile.FetchCount}}"></div></div><label>Keyword</label><textarea name="keywords">{{.ShodanProfile.Keywords}}</textarea><label>Extra filters</label><textarea name="extra_filters">{{.ShodanProfile.ExtraFilters}}</textarea><label>Raw query</label><textarea name="raw_query">{{.ShodanProfile.RawQuery}}</textarea><div class="actions"><button data-i18n="saveShodan">儲存 Shodan 配置</button></div></form></details></div><dialog id="new-profile-modal"><form method="post" action="/shodan/new" class="modal-card"><div class="section-title"><h3 data-i18n="newProfile">新增配置</h3><button type="button" class="secondary" onclick="closeModal('new-profile-modal')" data-i18n="close">關閉</button></div><label data-i18n="profileName">配置名</label><input name="profile_name" required placeholder="sg-aws-cloudflare"><label>Shodan API Key</label><input name="api_key" autocomplete="off" placeholder="可留空稍後填寫"><div class="grid"><div><label>Port</label><input name="ports" value="443"></div><div><label>Country</label><input name="countries" value="SG"></div><div><label>ASN</label><input name="asns" value="AS16509"></div><div><label data-i18n="fetchCount">IP 獲取數量</label><input name="fetch_count" type="number" min="1" max="10000" value="200"></div></div><label>Keyword</label><textarea name="keywords">cloudflare
Forbidden</textarea><label>Extra filters</label><textarea name="extra_filters" placeholder='product:Cloudflare org:"Amazon.com" ssl:true'></textarea><label>Raw query</label><textarea name="raw_query" placeholder="填寫後會覆蓋上方組合條件"></textarea><div class="actions"><button data-i18n="createSwitch">建立並切換</button></div></form></dialog>{{end}}</section>
</div></div>
<script>
const dict={'zh-Hant':{brandTitle:'cfnat-linux 控制台',brandSub:'統一管理 cfnat 與 Shodan IP Panel',logout:'登出',overview:'即時狀態總覽',connecting:'即時連線中',connected:'即時已連線',disconnected:'連線中斷，正在重連',scan:'掃描',primaryIP:'最優 IP',fullStatus:'查看完整運行狀態明細',liveLog:'查看即時日誌',cfnatActions:'cfnat 操作',rescan:'立即重新掃描',commonConfig:'cfnat 常用配置',optHealth:'優選與健康',maxLatency:'最大優選延遲 ms',minHealthy:'最小健康 IP 數',latencyInterval:'延遲監控間隔 秒',speedFilter:'測速篩選',enableSpeed:'啟用下載測速',speedMin:'下載測速最低 MB/s',speedConc:'下載測速並發',dnsCf:'DNS 與 Cloudflare',enableDNS:'啟用 Cloudflare DNS 同步',recordName:'DNS 解析域名',webSensitive:'Web 與敏感設定',webListen:'Web 監聽',webUser:'Web 使用者名稱',webNewPass:'Web 新密碼',enableWeb:'啟用 Web 管理面板',enableShodan:'啟用 Shodan IP Panel',webHint:'Web 帳密與 SSH 選單管理密碼互不干涉。修改 Web 監聽、Web 開關或 Shodan 開關後需重啟 cfnat 服務。',saveCfnat:'儲存 cfnat 配置',shodanSub:'配置、查詢與結果下載集中管理',newProfile:'新增配置',deleteProfile:'刪除配置',shodanDisabled:'Shodan IP Panel 未啟用。可在敏感設定中勾選後儲存，重啟 cfnat 服務生效。',currentProfile:'目前配置',switch:'切換',profileStatus:'配置狀態',lastSuccess:'最近成功',writtenIPs:'已寫入 IP',querySyntax:'目前查詢語法',downloadFetch:'下載與獲取',fetchNow:'獲取最新資料',downloadCurrent:'下載目前配置 IP',downloadHint:'下載開關只影響目前配置的下載入口。',editProfile:'修改配置',fetchCount:'IP 獲取數量',saveShodan:'儲存 Shodan 配置',close:'關閉',profileName:'配置名',createSwitch:'建立並切換',pauseProxy:'暫停 TCP 轉發',resumeProxy:'恢復 TCP 轉發',notFetched:'未獲取'},'zh-Hans':{brandTitle:'cfnat-linux 控制台',brandSub:'统一管理 cfnat 与 Shodan IP Panel',logout:'登出',overview:'实时状态总览',connecting:'实时连接中',connected:'实时已连接',disconnected:'连接中断，正在重连',scan:'扫描',primaryIP:'最优 IP',fullStatus:'查看完整运行状态明细',liveLog:'查看实时日志',cfnatActions:'cfnat 操作',rescan:'立即重新扫描',commonConfig:'cfnat 常用配置',optHealth:'优选与健康',maxLatency:'最大优选延迟 ms',minHealthy:'最小健康 IP 数',latencyInterval:'延迟监控间隔 秒',speedFilter:'测速筛选',enableSpeed:'启用下载测速',speedMin:'下载测速最低 MB/s',speedConc:'下载测速并发',dnsCf:'DNS 与 Cloudflare',enableDNS:'启用 Cloudflare DNS 同步',recordName:'DNS 解析域名',webSensitive:'Web 与敏感设置',webListen:'Web 监听',webUser:'Web 用户名',webNewPass:'Web 新密码',enableWeb:'启用 Web 管理面板',enableShodan:'启用 Shodan IP Panel',webHint:'Web 帐密与 SSH 菜单管理密码互不干涉。修改 Web 监听、Web 开关或 Shodan 开关后需重启 cfnat 服务。',saveCfnat:'保存 cfnat 配置',shodanSub:'配置、查询与结果下载集中管理',newProfile:'新增配置',deleteProfile:'删除配置',shodanDisabled:'Shodan IP Panel 未启用。可在敏感设置中勾选后保存，重启 cfnat 服务生效。',currentProfile:'当前配置',switch:'切换',profileStatus:'配置状态',lastSuccess:'最近成功',writtenIPs:'已写入 IP',querySyntax:'当前查询语法',downloadFetch:'下载与获取',fetchNow:'获取最新数据',downloadCurrent:'下载当前配置 IP',downloadHint:'下载开关只影响当前配置的下载入口。',editProfile:'修改配置',fetchCount:'IP 获取数量',saveShodan:'保存 Shodan 配置',close:'关闭',profileName:'配置名',createSwitch:'创建并切换',pauseProxy:'暂停 TCP 转发',resumeProxy:'恢复 TCP 转发',notFetched:'未获取'},en:{brandTitle:'cfnat-linux Console',brandSub:'Unified cfnat and Shodan IP Panel management',logout:'Logout',overview:'Live Status Overview',connecting:'Connecting live',connected:'Live connected',disconnected:'Disconnected, reconnecting',scan:'Scan',primaryIP:'Best IP',fullStatus:'View full runtime details',liveLog:'View live log',cfnatActions:'cfnat Actions',rescan:'Rescan now',commonConfig:'cfnat Common Config',optHealth:'Optimization & Health',maxLatency:'Max latency ms',minHealthy:'Minimum healthy IPs',latencyInterval:'Latency monitor interval sec',speedFilter:'Speed filter',enableSpeed:'Enable download speed test',speedMin:'Minimum speed MB/s',speedConc:'Speed test concurrency',dnsCf:'DNS & Cloudflare',enableDNS:'Enable Cloudflare DNS sync',recordName:'DNS record name',webSensitive:'Web & Sensitive Settings',webListen:'Web listen',webUser:'Web username',webNewPass:'New Web password',enableWeb:'Enable Web panel',enableShodan:'Enable Shodan IP Panel',webHint:'Web credentials are independent from the SSH menu password. Web listen, Web switch, or Shodan switch changes need service restart.',saveCfnat:'Save cfnat config',shodanSub:'Centralized config, query and result download management',newProfile:'Add profile',deleteProfile:'Delete profile',shodanDisabled:'Shodan IP Panel is disabled. Enable it in sensitive settings, save, then restart cfnat.',currentProfile:'Current profile',switch:'Switch',profileStatus:'Profile status',lastSuccess:'Last success',writtenIPs:'Written IPs',querySyntax:'Current query syntax',downloadFetch:'Download & Fetch',fetchNow:'Fetch latest data',downloadCurrent:'Download current profile IPs',downloadHint:'Download switch only affects the current profile.',editProfile:'Edit profile',fetchCount:'Fetch count',saveShodan:'Save Shodan config',close:'Close',profileName:'Profile name',createSwitch:'Create and switch',pauseProxy:'Pause TCP forwarding',resumeProxy:'Resume TCP forwarding',notFetched:'Not fetched'}};
function lang(){return localStorage.getItem('cfnat_lang')||'zh-Hant'}function t(k){return (dict[lang()]&&dict[lang()][k])||dict['zh-Hant'][k]||k}function setLang(l){localStorage.setItem('cfnat_lang',l);applyLang()}function applyLang(){document.documentElement.lang=lang();document.querySelectorAll('[data-i18n]').forEach(el=>{el.textContent=t(el.dataset.i18n)});document.querySelectorAll('[data-lang]').forEach(b=>b.classList.toggle('active',b.dataset.lang===lang()));const live=document.getElementById('live-state');if(live&&!live.dataset.state)live.textContent=t('connecting')}document.querySelectorAll('[data-lang]').forEach(b=>b.addEventListener('click',()=>setLang(b.dataset.lang)));
function setText(id,v){const el=document.getElementById(id);if(el)el.textContent=v||''}function cls(id,v){const el=document.getElementById(id);if(!el)return;el.classList.remove('ok','warn','bad');const tx=(v||'').toString();if(tx.includes('运行')||tx.includes('運行')||tx.includes('完成')||tx.includes('同步')||tx.includes('空闲')||tx.includes('空閒')||tx.includes('中')||tx.includes('forward'))el.classList.add('ok');else if(tx.includes('错误')||tx.includes('錯誤')||tx.includes('失败')||tx.includes('失敗')||tx.includes('error'))el.classList.add('bad');else el.classList.add('warn')}function appendJournalLine(line){const el=document.getElementById('realtime-log');if(!el)return;if(!el.dataset.ready){el.textContent='';el.dataset.ready='1'}el.textContent=(el.textContent+line+'\n').slice(-30000);el.scrollTop=el.scrollHeight}function applyStatus(d){setText('sum-cfnat',d.summary.cfnat);setText('sum-scan',d.summary.scan);setText('sum-primary',d.summary.primary_ip);setText('sum-dns',d.summary.dns);setText('sum-shodan-state',d.shodan.state);setText('sum-shodan-ips',d.shodan.ips);setText('sum-shodan-error',d.shodan.error);setText('shodan-ips-card',d.shodan.ips);setText('shodan-success-card',d.shodan.last_success||t('notFetched'));setText('cfnat-status',d.cfnat.text);setText('proxy-state',d.cfnat.proxy);setText('proxy-toggle',d.cfnat.proxy_on?t('pauseProxy'):t('resumeProxy'));['sum-cfnat','sum-scan','sum-dns','sum-shodan-state'].forEach(id=>cls(id,document.getElementById(id)?.textContent))}function openModal(id){const el=document.getElementById(id);if(el&&el.showModal)el.showModal()}function closeModal(id){const el=document.getElementById(id);if(el)el.close()}function connectEvents(){const live=document.getElementById('live-state');const es=new EventSource('/events');es.onopen=()=>{if(live){live.dataset.state='connected';live.textContent=t('connected')}};es.onerror=()=>{if(live){live.dataset.state='disconnected';live.textContent=t('disconnected')}};es.addEventListener('status',ev=>{try{applyStatus(JSON.parse(ev.data))}catch(e){}})}function connectLogs(){const log=document.getElementById('realtime-log');if(!log)return;const es=new EventSource('/logs/events');es.onerror=()=>appendJournalLine('日誌連線中斷，正在重連...');es.addEventListener('log',ev=>{try{appendJournalLine(JSON.parse(ev.data).line||'')}catch(e){}})}applyLang();connectEvents();connectLogs();
</script></main></body></html>`
