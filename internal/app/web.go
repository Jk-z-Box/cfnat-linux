package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	ws.tmpl = template.Must(template.New("panel").Funcs(template.FuncMap{
		"join": strings.Join,
	}).Parse(panelHTML))
	mux := http.NewServeMux()
	mux.HandleFunc("/", ws.handleIndex)
	mux.HandleFunc("/login", ws.handleLogin)
	mux.HandleFunc("/logout", ws.handleLogout)
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
	password := r.Form.Get("password")
	if !w.passwordOK(password) {
		w.renderLogin(rw, "管理密码错误。")
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
	if !w.app.cfg.Management.PasswordEnabled {
		return true
	}
	cookie, err := r.Cookie("cfnat_web_session")
	return err == nil && cookie.Value == w.sessionValue()
}

func (w *webServer) sessionValue() string {
	sum := sha256.Sum256([]byte("cfnat-web:" + w.app.cfg.Management.PasswordSHA256))
	return hex.EncodeToString(sum[:])
}

func (w *webServer) passwordOK(password string) bool {
	if !w.app.cfg.Management.PasswordEnabled {
		return true
	}
	sum := sha256.Sum256([]byte(password))
	return hex.EncodeToString(sum[:]) == strings.ToLower(w.app.cfg.Management.PasswordSHA256)
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
		"shodan_enabled":           boolText(r.Form.Get("shodan_enabled") == "on"),
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
	w.redirect(rw, "Shodan 当前配置已保存。")
}

func (w *webServer) handleShodanFetch(rw http.ResponseWriter, r *http.Request) {
	if w.app.cfg.Shodan.Enabled {
		w.shodan.FetchAsync(context.Background())
		w.redirect(rw, "已开始获取 Shodan IP，稍后刷新查看状态。")
		return
	}
	w.redirect(rw, "Shodan IP Panel 未启用。")
}

func (w *webServer) handleShodanToggleDownload(rw http.ResponseWriter, r *http.Request) {
	if err := w.shodan.ToggleDownload(); err != nil {
		w.render(rw, "下载开关切换失败："+err.Error())
		return
	}
	w.redirect(rw, "Shodan 下载链接状态已切换。")
}

func (w *webServer) handleShodanSwitch(rw http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	if err := w.shodan.SwitchProfile(r.Form.Get("profile_name")); err != nil {
		w.render(rw, "切换失败："+err.Error())
		return
	}
	w.redirect(rw, "已切换 Shodan 配置。")
}

func (w *webServer) handleShodanNew(rw http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	if err := w.shodan.NewProfile(r.Form.Get("profile_name")); err != nil {
		w.render(rw, "新增配置失败："+err.Error())
		return
	}
	w.redirect(rw, "已新增 Shodan 配置。")
}

func (w *webServer) handleShodanDelete(rw http.ResponseWriter, r *http.Request) {
	if err := w.shodan.DeleteActive(); err != nil {
		w.render(rw, "删除配置失败："+err.Error())
		return
	}
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
	_, _ = rw.Write([]byte(`<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>cfnat Web Login</title><style>` + css + `</style></head><body><main class="login"><h1>cfnat-linux</h1><p>` + template.HTMLEscapeString(msg) + `</p><form method="post" action="/login"><label>管理密码</label><input name="password" type="password" autofocus><button>登入</button></form></main></body></html>`))
}

func (w *webServer) render(rw http.ResponseWriter, msg string) {
	cfg := w.app.cfg
	var status bytes.Buffer
	PrintStatus(&status, cfg)
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
		"Config":        cfg,
		"StatusText":    status.String(),
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
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:0;background:#f6f7f9;color:#17202a}
main{max-width:1180px;margin:0 auto;padding:24px 16px 48px}.login{max-width:420px;margin-top:12vh;background:white;border:1px solid #dde2e8;border-radius:10px}
h1{margin:0 0 16px}.nav{display:flex;justify-content:space-between;align-items:center}section{background:white;border:1px solid #dde2e8;border-radius:10px;padding:18px;margin:14px 0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}.card{background:#f9fafb;border:1px solid #e6ebf0;border-radius:8px;padding:12px}
label{display:block;font-weight:600;margin:10px 0 6px}input,textarea,select{width:100%;box-sizing:border-box;border:1px solid #cfd7df;border-radius:7px;padding:9px;font-size:14px}textarea{min-height:74px}
button,.button{border:0;border-radius:7px;background:#1769e0;color:white;padding:10px 14px;cursor:pointer;text-decoration:none;display:inline-block}.secondary{background:#566574}.danger{background:#c7362f}
.actions{display:flex;flex-wrap:wrap;gap:10px;margin-top:12px}.msg{background:#edf7ed;border:1px solid #b9dfbc;padding:10px;border-radius:7px;margin:12px 0}pre{white-space:pre-wrap;background:#eef2f6;border-radius:7px;padding:12px;overflow:auto}.hint{color:#657386;font-size:13px}
`

const panelHTML = `<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>cfnat Web 管理面板</title><style>{{.CSS}}</style></head><body><main>
<div class="nav"><h1>cfnat-linux Web 管理面板</h1><a href="/logout">登出</a></div>
{{if .Message}}<div class="msg">{{.Message}}</div>{{end}}
<section><h2>cfnat 狀態</h2><pre>{{.StatusText}}</pre><div class="actions"><form method="post" action="/cfnat/scan"><button>立即重新掃描</button></form></div></section>
<section><h2>cfnat 配置</h2><form method="post" action="/cfnat/config"><div class="grid">
<div><label>最大優選延遲 ms</label><input name="max_latency" type="number" value="{{.MaxLatencyMS}}"></div>
<div><label>最小健康 IP 數</label><input name="min_healthy_count" type="number" value="{{.Config.MinHealthyCount}}"></div>
<div><label>延遲監控間隔 秒</label><input name="latency_monitor_interval" type="number" value="{{.LatencySecs}}"></div>
<div><label>下載測速最低 MB/s</label><input name="speed_test_min_mbps" value="{{.Config.SpeedTest.MinMBps}}"></div>
<div><label>下載測速並發</label><input name="speed_test_concurrency" type="number" value="{{.Config.SpeedTest.Concurrency}}"></div>
<div><label>Web 監聽</label><input name="web_listen" value="{{.Config.Web.Listen}}"></div>
<div><label>Cloudflare Zone ID</label><input name="zone_id" value="{{.Config.DNS.ZoneID}}"></div>
<div><label>DNS 解析域名</label><input name="record_name" value="{{.Config.DNS.RecordName}}"></div>
</div>
<label><input style="width:auto" type="checkbox" name="speed_test_enabled" {{if .Config.SpeedTest.Enabled}}checked{{end}}> 啟用下載測速</label>
<label><input style="width:auto" type="checkbox" name="dns_enabled" {{if .Config.DNS.Enabled}}checked{{end}}> 啟用 Cloudflare DNS 同步</label>
<label><input style="width:auto" type="checkbox" name="web_enabled" {{if .Config.Web.Enabled}}checked{{end}}> 啟用 Web 管理面板</label>
<label><input style="width:auto" type="checkbox" name="shodan_enabled" {{if .Config.Shodan.Enabled}}checked{{end}}> 啟用 Shodan IP Panel</label>
<div class="actions"><button>保存 cfnat 配置</button></div><p class="hint">部分項目保存後需要透過 SSH 菜單重啟 cfnat 服務才會完全生效。</p></form></section>
<section><h2>Shodan IP Panel</h2>{{if not .Config.Shodan.Enabled}}<p>Shodan IP Panel 未啟用。可在上方勾選後保存，然後重啟 cfnat 服務。</p>{{else}}{{if .ShodanError}}<div class="msg">{{.ShodanError}}</div>{{end}}
<div class="grid"><div class="card"><b>任務狀態</b><br>{{.ShodanStatus.State}}</div><div class="card"><b>目前配置</b><br>{{.ShodanConfig.ActiveProfile}}</div><div class="card"><b>API Key</b><br>{{.ShodanMaskKey}}</div><div class="card"><b>已寫入 IP</b><br>{{.ShodanStatus.UniqueIPsWritten}}</div><div class="card"><b>最近成功</b><br>{{.ShodanStatus.LastSuccessAt}}</div></div>
{{if .ShodanStatus.LastError}}<pre>{{.ShodanStatus.LastError}}</pre>{{end}}<p>目前查詢語法</p><pre>{{.ShodanQuery}}</pre>
<div class="actions"><form method="post" action="/shodan/fetch"><button>獲取最新數據</button></form><form method="post" action="/shodan/toggle-download"><button class="secondary">切換下載連結</button></form>{{if .ShodanProfile.DownloadEnabled}}<a class="button" href="/shodan/download/{{.ShodanConfig.ActiveProfile}}.txt">下載目前配置 IP</a>{{end}}</div>
<h3>配置管理</h3><form method="post" action="/shodan/switch"><select name="profile_name">{{range $name, $_ := .ShodanConfig.Profiles}}<option value="{{$name}}" {{if eq $.ShodanConfig.ActiveProfile $name}}selected{{end}}>{{$name}}</option>{{end}}</select><div class="actions"><button class="secondary">切換配置</button></div></form>
<form method="post" action="/shodan/new"><label>新增配置名</label><input name="profile_name" placeholder="sg-aws-cloudflare"><div class="actions"><button class="secondary">新增配置</button></div></form>
<form method="post" action="/shodan/delete"><div class="actions"><button class="danger">刪除目前配置</button></div></form>
<h3>修改目前配置</h3><form method="post" action="/shodan/save"><label>Shodan API Key</label><input name="api_key" value="{{.ShodanProfile.APIKey}}"><div class="grid"><div><label>Port</label><input name="ports" value="{{.ShodanProfile.Ports}}"></div><div><label>Country</label><input name="countries" value="{{.ShodanProfile.Countries}}"></div><div><label>ASN</label><input name="asns" value="{{.ShodanProfile.ASNs}}"></div><div><label>IP 獲取數量</label><input name="fetch_count" type="number" min="1" max="10000" value="{{.ShodanProfile.FetchCount}}"></div></div><label>Keyword</label><textarea name="keywords">{{.ShodanProfile.Keywords}}</textarea><label>Extra filters</label><textarea name="extra_filters">{{.ShodanProfile.ExtraFilters}}</textarea><label>Raw query</label><textarea name="raw_query">{{.ShodanProfile.RawQuery}}</textarea><div class="actions"><button>保存 Shodan 配置</button></div></form>{{end}}</section>
</main></body></html>`
