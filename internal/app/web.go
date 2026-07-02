package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
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

func (a *App) serveWeb(ctx context.Context) error {
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
	mux.HandleFunc("/cfnat/scan", ws.requireAuth(ws.handleCFNatScan))
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
	w.render(rw, r.URL.Query().Get("msg"))
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
			shodanSummary["state"] = "error"
			shodanSummary["error"] = err.Error()
		} else {
			shodanSummary["state"] = valueOr(st.State, "idle")
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

func boolLabel(v bool) string {
	if v {
		return "已启用"
	}
	return "未启用"
}

func (w *webServer) redirect(rw http.ResponseWriter, msg string) {
	rw.Header().Set("Location", "/?msg="+template.URLQueryEscaper(msg))
	rw.WriteHeader(http.StatusSeeOther)
}

func boolText(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

const css = `
:root{--bg:#f4f7fb;--panel:#fff;--line:#dfe7f0;--text:#17202a;--muted:#66758a;--blue:#1769e0;--green:#168047;--red:#c7362f;--amber:#a86b00;--shadow:0 10px 28px rgba(20,35,60,.08)}*{box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:0;background:linear-gradient(180deg,#edf4ff 0,#f7f8fb 260px);color:var(--text)}main{max-width:1180px;margin:0 auto;padding:22px 16px 48px}.login{max-width:430px;margin-top:12vh;background:var(--panel);border:1px solid var(--line);border-radius:18px;box-shadow:var(--shadow);padding:24px}.topbar{display:flex;align-items:center;justify-content:space-between;gap:14px;margin-bottom:18px}.brand h1{margin:0;font-size:26px}.brand p{margin:5px 0 0;color:var(--muted)}a{color:var(--blue)}section,.panel{background:rgba(255,255,255,.94);border:1px solid var(--line);border-radius:18px;box-shadow:var(--shadow);padding:18px;margin:14px 0}.summary-grid{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:12px}.card{background:#f9fbfe;border:1px solid #e6edf5;border-radius:14px;padding:14px;min-width:0}.card b{display:block;color:var(--muted);font-size:12px;margin-bottom:8px;text-transform:uppercase;letter-spacing:.03em}.value{font-size:20px;font-weight:760;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.ok{color:var(--green)}.warn{color:var(--amber)}.bad{color:var(--red)}.layout{display:grid;grid-template-columns:minmax(0,1fr) minmax(320px,.82fr);gap:14px;align-items:start}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}label{display:block;font-weight:650;margin:10px 0 6px}input,textarea,select{width:100%;border:1px solid #cfd9e5;border-radius:10px;padding:10px;font-size:14px;background:#fff}textarea{min-height:82px}button,.button{border:0;border-radius:10px;background:var(--blue);color:white;padding:10px 14px;cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;justify-content:center;font-size:14px}.secondary{background:#59697b}.danger{background:var(--red)}.actions{display:flex;flex-wrap:wrap;gap:10px;margin-top:14px}.msg{background:#edf7ed;border:1px solid #b9dfbc;padding:10px;border-radius:10px;margin:12px 0}.hint,.muted{color:var(--muted);font-size:13px;line-height:1.45}pre{white-space:pre-wrap;background:#0f1724;color:#dce8ff;border-radius:14px;padding:14px;overflow:auto;font-size:13px;line-height:1.5}details{border:1px solid #e1e8f0;border-radius:14px;padding:11px 13px;margin:12px 0;background:#fbfcfe}summary{cursor:pointer;font-weight:760}.danger-zone{border-color:#f0c6c3;background:#fff8f7}.pill{display:inline-flex;align-items:center;gap:6px;border-radius:999px;padding:5px 9px;background:#eef4ff;color:#31527c;font-size:12px}.live-dot{width:8px;height:8px;border-radius:50%;background:#15b76a;box-shadow:0 0 0 5px rgba(21,183,106,.13)}.section-title{display:flex;align-items:center;justify-content:space-between;gap:10px}.mini-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}.profile-head{display:flex;align-items:center;justify-content:space-between;gap:12px;background:#f7faff;border:1px solid #e4edf8;border-radius:14px;padding:12px;margin:12px 0}.profile-name{font-size:22px;font-weight:780}.profile-switch{display:flex;gap:8px;align-items:center}.profile-switch select{min-width:160px}.accordion-list details{margin:10px 0}dialog{border:0;border-radius:18px;box-shadow:0 24px 80px rgba(15,30,55,.28);padding:0;width:min(720px,calc(100vw - 24px));max-height:88vh}dialog::backdrop{background:rgba(9,18,33,.45);backdrop-filter:blur(2px)}.modal-card{padding:18px;background:white;overflow:auto;max-height:88vh}@media(max-width:980px){.summary-grid{grid-template-columns:repeat(3,minmax(0,1fr))}.layout{grid-template-columns:1fr}}@media(max-width:620px){main{padding:14px 10px 36px}.topbar{align-items:flex-start}.brand h1{font-size:22px}.summary-grid,.grid,.mini-grid{grid-template-columns:1fr}.value{font-size:18px}section,.panel{border-radius:14px;padding:14px}.actions{flex-direction:column}.actions button,.actions .button{width:100%}.profile-head{align-items:stretch;flex-direction:column}.profile-switch{flex-direction:column;align-items:stretch}.profile-switch select{min-width:0}}
`

const panelHTML = `<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>cfnat Web 管理面板</title><style>{{.CSS}}</style></head><body><main>
<div class="topbar"><div class="brand"><h1>cfnat-linux 控制台</h1><p>统一管理 cfnat 与 Shodan IP Panel</p></div><a class="pill" href="/logout">登出</a></div>
{{if .Message}}<div class="msg">{{.Message}}</div>{{end}}
<section><div class="section-title"><h2>实时状态总览</h2><span class="pill"><span class="live-dot"></span><span id="live-state">实时连接中</span></span></div><div class="summary-grid">
<div class="card"><b>cfnat</b><div class="value" id="sum-cfnat">{{index (index .Payload "summary") "cfnat"}}</div></div>
<div class="card"><b>扫描</b><div class="value" id="sum-scan">{{index (index .Payload "summary") "scan"}}</div></div>
<div class="card"><b>最优 IP</b><div class="value" id="sum-primary">{{index (index .Payload "summary") "primary_ip"}}</div></div>
<div class="card"><b>DNS</b><div class="value" id="sum-dns">{{index (index .Payload "summary") "dns"}}</div></div>
<div class="card"><b>更新</b><div class="value" id="sum-update">{{index (index .Payload "summary") "update"}}</div></div>
<div class="card"><b>Shodan</b><div class="value" id="sum-shodan-state">{{index (index .Payload "shodan") "state"}}</div><div class="muted">IP: <span id="sum-shodan-ips">{{index (index .Payload "shodan") "ips"}}</span></div></div>
</div><p id="sum-shodan-error" class="hint">{{index (index .Payload "shodan") "error"}}</p><details><summary>查看完整运行状态明细</summary><pre id="cfnat-status">{{index (index .Payload "cfnat") "text"}}</pre></details></section>
<div class="layout"><div>
<section><div class="section-title"><h2>cfnat 操作</h2><span class="hint">低风险常用操作</span></div><div class="actions"><form method="post" action="/cfnat/scan"><button>立即重新扫描</button></form></div></section>
<section><h2>cfnat 常用配置</h2><form method="post" action="/cfnat/config"><div class="grid"><div><label>最大优选延迟 ms</label><input name="max_latency" type="number" value="{{.MaxLatencyMS}}"></div><div><label>最小健康 IP 数</label><input name="min_healthy_count" type="number" value="{{.Config.MinHealthyCount}}"></div><div><label>延迟监控间隔 秒</label><input name="latency_monitor_interval" type="number" value="{{.LatencySecs}}"></div><div><label>下载测速最低 MB/s</label><input name="speed_test_min_mbps" value="{{.Config.SpeedTest.MinMBps}}"></div><div><label>下载测速并发</label><input name="speed_test_concurrency" type="number" value="{{.Config.SpeedTest.Concurrency}}"></div></div><label><input style="width:auto" type="checkbox" name="speed_test_enabled" {{if .Config.SpeedTest.Enabled}}checked{{end}}> 启用下载测速</label><details><summary>敏感与高风险设置</summary><div class="grid"><div><label>Web 监听</label><input name="web_listen" value="{{.Config.Web.Listen}}"></div><div><label>Web 用户名</label><input name="web_username" value="{{.Config.Web.Username}}" autocomplete="username"></div><div><label>Web 新密码</label><input name="web_password" type="password" autocomplete="new-password" placeholder="留空不修改"></div><div><label>Cloudflare Zone ID</label><input name="zone_id" value="{{.Config.DNS.ZoneID}}"></div><div><label>DNS 解析域名</label><input name="record_name" value="{{.Config.DNS.RecordName}}"></div></div><label><input style="width:auto" type="checkbox" name="dns_enabled" {{if .Config.DNS.Enabled}}checked{{end}}> 启用 Cloudflare DNS 同步</label><label><input style="width:auto" type="checkbox" name="web_enabled" {{if .Config.Web.Enabled}}checked{{end}}> 启用 Web 管理面板</label><label><input style="width:auto" type="checkbox" name="shodan_enabled" {{if .Config.Shodan.Enabled}}checked{{end}}> 启用 Shodan IP Panel</label><p class="hint">Web 帐密与 SSH 菜单管理密码互不干涉。修改 Web 监听、Web 开关或 Shodan 开关后需重启 cfnat 服务。</p></details><div class="actions"><button>保存 cfnat 配置</button></div></form></section>
</div><div>
<section><div class="section-title"><div><h2>Shodan IP Panel</h2><span class="hint">配置、查询与结果下载集中管理</span></div>{{if .Config.Shodan.Enabled}}<button type="button" class="secondary" onclick="openModal('new-profile-modal')">新增配置</button>{{end}}</div>{{if not .Config.Shodan.Enabled}}<p>Shodan IP Panel 未启用。可在敏感设置中勾选后保存，重启 cfnat 服务生效。</p>{{else}}{{if .ShodanError}}<div class="msg">{{.ShodanError}}</div>{{end}}<div class="profile-head"><div><div class="muted">当前配置</div><div class="profile-name">{{.ShodanConfig.ActiveProfile}}</div></div><form method="post" action="/shodan/switch" class="profile-switch"><select name="profile_name">{{range $name, $_ := .ShodanConfig.Profiles}}<option value="{{$name}}" {{if eq $.ShodanConfig.ActiveProfile $name}}selected{{end}}>{{$name}}</option>{{end}}</select><button class="secondary">切换</button></form></div><div class="accordion-list"><details open><summary>配置状态</summary><div class="mini-grid"><div class="card"><b>任务状态</b><span id="shodan-state-card">{{.ShodanStatus.State}}</span></div><div class="card"><b>API Key</b>{{.ShodanMaskKey}}</div><div class="card"><b>最近成功</b><span id="shodan-success-card">{{if .ShodanProfile.LastSuccessAt}}{{.ShodanProfile.LastSuccessAt}}{{else}}未获取{{end}}</span></div><div class="card"><b>已写入 IP</b><span id="shodan-ips-card">{{.ShodanProfile.UniqueIPsWritten}}</span></div></div><p>当前查询语法</p><pre>{{.ShodanQuery}}</pre>{{if .ShodanStatus.LastError}}<pre>{{.ShodanStatus.LastError}}</pre>{{end}}</details><details><summary>下载与获取</summary><div class="actions"><form method="post" action="/shodan/fetch"><button>获取最新数据</button></form><form method="post" action="/shodan/toggle-download"><button class="secondary">{{if .ShodanProfile.DownloadEnabled}}关闭{{else}}开启{{end}}下载链接</button></form>{{if .ShodanProfile.DownloadEnabled}}<a class="button" href="/shodan/download/{{.ShodanConfig.ActiveProfile}}.txt">下载当前配置 IP</a>{{end}}</div><p class="hint">下载开关只影响当前配置的下载入口。</p></details><details><summary>修改配置</summary><form method="post" action="/shodan/save"><label>Shodan API Key</label><input name="api_key" value="{{.ShodanProfile.APIKey}}" autocomplete="off"><div class="grid"><div><label>Port</label><input name="ports" value="{{.ShodanProfile.Ports}}"></div><div><label>Country</label><input name="countries" value="{{.ShodanProfile.Countries}}"></div><div><label>ASN</label><input name="asns" value="{{.ShodanProfile.ASNs}}"></div><div><label>IP 获取数量</label><input name="fetch_count" type="number" min="1" max="10000" value="{{.ShodanProfile.FetchCount}}"></div></div><label>Keyword</label><textarea name="keywords">{{.ShodanProfile.Keywords}}</textarea><label>Extra filters</label><textarea name="extra_filters">{{.ShodanProfile.ExtraFilters}}</textarea><label>Raw query</label><textarea name="raw_query">{{.ShodanProfile.RawQuery}}</textarea><div class="actions"><button>保存 Shodan 配置</button></div></form></details><details class="danger-zone"><summary>删除配置</summary><p class="hint">删除当前配置不可直接撤销，至少会保留一个配置。</p><form method="post" action="/shodan/delete" onsubmit="return confirm('确认删除当前 Shodan 配置？');"><div class="actions"><button class="danger">删除当前配置</button></div></form></details></div><dialog id="new-profile-modal"><form method="post" action="/shodan/new" class="modal-card"><div class="section-title"><h3>新增 Shodan 配置</h3><button type="button" class="secondary" onclick="closeModal('new-profile-modal')">关闭</button></div><label>配置名</label><input name="profile_name" required placeholder="sg-aws-cloudflare"><label>Shodan API Key</label><input name="api_key" autocomplete="off" placeholder="可留空稍后填写"><div class="grid"><div><label>Port</label><input name="ports" value="443"></div><div><label>Country</label><input name="countries" value="SG"></div><div><label>ASN</label><input name="asns" value="AS16509"></div><div><label>IP 获取数量</label><input name="fetch_count" type="number" min="1" max="10000" value="200"></div></div><label>Keyword</label><textarea name="keywords">cloudflare
Forbidden</textarea><label>Extra filters</label><textarea name="extra_filters" placeholder='product:Cloudflare org:"Amazon.com" ssl:true'></textarea><label>Raw query</label><textarea name="raw_query" placeholder="填写后会覆盖上方组合条件"></textarea><div class="actions"><button>创建并切换</button></div></form></dialog>{{end}}</section>
</div></div>
<script>
function setText(id,v){const el=document.getElementById(id);if(el)el.textContent=v||''}
function cls(id,v){const el=document.getElementById(id);if(!el)return;el.classList.remove('ok','warn','bad');const t=(v||'').toString();if(t.includes('运行')||t.includes('完成')||t.includes('同步')||t==='idle')el.classList.add('ok');else if(t.includes('错误')||t.includes('失败')||t.includes('异常')||t.includes('error'))el.classList.add('bad');else el.classList.add('warn')}
function applyStatus(d){setText('sum-cfnat',d.summary.cfnat);setText('sum-scan',d.summary.scan);setText('sum-primary',d.summary.primary_ip);setText('sum-dns',d.summary.dns);setText('sum-update',d.summary.update);setText('sum-shodan-state',d.shodan.state);setText('sum-shodan-ips',d.shodan.ips);setText('sum-shodan-error',d.shodan.error);setText('shodan-state-card',d.shodan.state);setText('shodan-ips-card',d.shodan.ips);setText('shodan-success-card',d.shodan.last_success||'未获取');setText('cfnat-status',d.cfnat.text);['sum-cfnat','sum-scan','sum-dns','sum-update','sum-shodan-state'].forEach(id=>cls(id,document.getElementById(id)?.textContent))}
function openModal(id){const el=document.getElementById(id);if(el&&el.showModal)el.showModal()}
function closeModal(id){const el=document.getElementById(id);if(el)el.close()}
function connectEvents(){const live=document.getElementById('live-state');const es=new EventSource('/events');es.onopen=()=>{if(live)live.textContent='实时已连接'};es.onerror=()=>{if(live)live.textContent='连接中断，正在重连'};es.addEventListener('status',ev=>{try{applyStatus(JSON.parse(ev.data))}catch(e){}})}
connectEvents();
</script></main></body></html>`
