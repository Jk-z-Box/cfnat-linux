# cfnat-linux

面向 Linux 的 Cloudflare IP 優選、TCP 轉發、健康檢查與 DNS 自動同步服務。

## 功能

- 從本機檔案或 HTTP(S) 位址讀取 IPv4/IPv6 CIDR 或裸 IP，並快取成功下載的遠端 IP 池。
- 隨機抽樣或依順序展開候選 IP。
- 兩階段掃描：先進行輕量 TCP 初篩，再對最快候選執行 TLS、HTTP 狀態碼與延遲檢查，避免大併發完整請求觸發限速。
- 可選下載測速篩選：TCP 初篩後對低延遲候選 IP 進行下載測速，低於指定 MB/s 或無速度的 IP 直接剔除。
- 可透過 `/cdn-cgi/trace` 依 Cloudflare `colo` 篩選資料中心。
- 維護低延遲目標池，依最新延遲排序；新連線始終優先連線目前延遲最低的 IP，失敗時再依序 fallback。
- 預設每 2 秒監控一次池內 IP 延遲，可自訂監控間隔並熱更新轉發順序。
- 定期健康檢查；單個 IP 連續失敗後會先從轉發池剔除，剩餘健康 IP 繼續轉發。
- 當健康 IP 少於自訂門檻時，背景觸發整池重選；重選成功後熱替換目標池。
- 將前 N 個優選 IP 同步為 Cloudflare `A` 或 `AAAA` 記錄。
- 若已同步到 Cloudflare 的 IP 被判定不健康並剔除，會自動把健康 IP 池重新同步到 DNS。
- DNS 不會預設跟隨 2 秒延遲排序同步；可選擇開啟「延遲排序冷卻同步」，按自訂冷卻時間低頻更新。
- DNS 採用「先建立新記錄、再刪除舊記錄」，掃描失敗時絕不清空解析。
- systemd 開機啟動、自動重啟、journald 日誌與低權限執行。
- 首次掃描無結果時保持背景執行並定期重試，不再進入 systemd 重啟循環。
- 支援 Linux amd64、arm64 和 386。

## 工作流程

```text
IP/CIDR 來源 → 候選生成 → TCP 初篩 → 下載測速篩選 → TLS/HTTP 複篩 → 延遲排序 → 目標池 → 最低延遲優先 TCP 轉發
                                  ↓
                         Cloudflare DNS 同步
                                  ↓
                      延遲監控、健康剔除與重新優選
```

## 一鍵安裝

安裝機需要 systemd、curl、tar 和 sha256sum。若系統沒有 Go，安裝腳本會下載經過 SHA-256 校驗的臨時官方 Go 工具鏈；編譯完成後自動刪除，不污染系統環境。

```bash
tar -xzf cfnat-linux-v0.7.1.tar.gz
cd cfnat-linux
sudo ./scripts/install.sh
```

安裝腳本會互動詢問：

- 本機監聽位址；
- IPv4 或 IPv6；
- 最大允許延遲（毫秒）；
- 健康 IP 少於幾個時觸發整池重選；
- 延遲監控間隔（秒）；
- 是否啟用下載測速篩選、最低下載速度、單 IP 測速時間和最多測速候選數；
- 可選 Cloudflare 資料中心；
- 是否同步 DNS；
- Zone ID、完整記錄名稱和 API Token。
- 是否讓 DNS 按延遲排序冷卻同步，以及冷卻時間。

精靈會逐項檢查輸入格式。位址、連接埠、IP 版本、資料中心代碼或 DNS 參數有誤時，會說明原因並重新詢問目前項目，不會退出整個安裝流程。

安裝完成後服務會立即進行首次優選。執行管理面板：

```bash
sudo cfnatctl
```

面板會顯示：

- systemd 服務是否執行；
- 監聽 IP、連接埠和最大允許延遲；
- 延遲監控間隔；
- 下載測速篩選狀態與速度門檻；
- 健康 IP 低於幾個時會整池重選；
- 掃描正在進行、已經完成或失敗；
- 目前最優 IP；
- 優選池每個 IP 的延遲、colo 和健康狀態；
- Cloudflare DNS 是否啟用、是否同步成功、解析網域和同步 IP。
- DNS 延遲排序同步是否啟用，以及冷卻時間。

面板下方提供執行開關、立即重掃、診斷掃描、修改設定、即時日誌以及一鍵關閉並解除安裝。執行狀態同時儲存於 `/var/lib/cfnat/state.json`。

掃描日誌會彙總失敗原因，例如 `tcp_timeout`、`tls`、`status`、`latency` 和 `colo`。這樣可以直接判斷是線路不可達、TLS/SNI、探測網址、延遲閾值還是機房篩選導致無結果。

若啟用下載測速篩選，TCP 初篩完成後會優先取低延遲候選 IP 做下載測速。測速思路參考 `XIU2/CloudflareSpeedTest`：先按 TCP 延遲篩出候選，再逐個下載測速；速度低於 `speed_test.min_mbps` 或完全無下載速度的 IP 不會進入後續 TLS/HTTP 複篩。

也可以直接使用命令：

```bash
cfnatctl status       # 服務狀態
cfnatctl logs         # 即時日誌
cfnatctl pool         # 目前優選池
cfnatctl scan         # 重啟服務並立即重新優選
cfnatctl config       # 進入設定修改選單
cfnatctl restart      # 重啟服務
cfnatctl uninstall    # 確認後關閉並解除安裝
```

## Cloudflare DNS 設定

建議建立一個僅限目標 Zone 的 API Token，權限為：

```text
Zone / DNS / Edit
```

Token 儲存於 `/etc/cfnat/cfnat.env`，權限為 `0640`，不會寫入 JSON、命令列或日誌。

優選記錄必須保持：

```json
"proxied": false
```

如果開啟橙雲，DNS 回應會重新變成 Cloudflare Anycast 位址，客戶端無法直接取得優選 IP。程式會拒絕 `proxied=true` 設定。

DNS 同步只刪除 `comment` 等於 `managed-by:cfnat-linux` 的舊記錄，不刪除同網域名稱下由使用者建立的記錄。為避免短暫空解析，它總是先建立新記錄，再刪除舊記錄。

DNS 同步分為兩類：

- 故障修復型同步：已同步 IP 被剔除、整池重選成功、首次掃描成功時會立即同步，不受冷卻時間限制。
- 延遲排序型同步：只有 `cloudflare_dns.latency_sync_enabled=true` 時才啟用，並且至少間隔 `cloudflare_dns.latency_sync_interval` 後才會把 DNS 更新為目前延遲排序靠前的健康 IP。

如果 `cloudflare_dns.latency_sync_enabled=false`，本地 TCP 仍會每 2 秒按延遲排序，但 DNS 不會因單純延遲排名變化而同步。

## 設定檔

主設定位於 `/etc/cfnat/config.json`，完整範例見 `configs/config.example.json`。

關鍵參數：

| 參數 | 預設值 | 說明 |
|---|---:|---|
| `listen` | `0.0.0.0:1234` | 本機 TCP 監聽位址 |
| `ip_version` | `4` | `4` 或 `6` |
| `ip_sources` | Cloudflare 官方清單 | CIDR 檔案或 URL，可設定多個 |
| `max_candidates` | `2000` | 單輪最多探測的候選數 |
| `concurrency` | `100` | TCP 初篩併發數；完整 TLS/HTTP 複篩自動限制為最多 20 |
| `valid_ip_count` | `20` | 保留的有效 IP 數 |
| `pool_size` | `10` | TCP 轉發目標池大小 |
| `min_healthy_count` | `5` | 健康 IP 少於此數量時觸發整池重選 |
| `target_port` | `443` | 上游 Cloudflare 連接埠 |
| `check_url` | `https://cloudflare.com/cdn-cgi/trace` | HTTP 狀態檢查位址及 TLS SNI 來源 |
| `expected_status` | `200` | 期望回應碼 |
| `max_latency` | `800ms` | TLS/HTTP 首包最大延遲；超過閾值的 IP 直接淘汰 |
| `colos` | `[]` | 例如 `HKG`、`NRT`、`SJC`；空陣列不篩選 |
| `scan_interval` | `6h` | 定期完整重選週期 |
| `latency_monitor_interval` | `2s` | 池內 IP 延遲監控與排序週期 |
| `health_interval` | `60s` | 無可用 IP 時的背景重試週期 |
| `health_failures` | `3` | 單個 IP 連續失敗多少次後判定不健康並剔除 |
| `source_cache_dir` | `/var/lib/cfnat/ip-cache` | 遠端 IP 池成功下載後的本機快取目錄 |
| `speed_test.enabled` | `false` | 是否啟用下載測速篩選 |
| `speed_test.url` | `https://speed.cloudflare.com/__down?bytes=200000000` | 下載測速 URL |
| `speed_test.min_mbps` | `5` | 最低下載速度，單位 MB/s |
| `speed_test.timeout` | `10s` | 單個 IP 下載測速時間 |
| `speed_test.max_candidates` | `50` | TCP 初篩後最多測速的候選 IP 數 |
| `cloudflare_dns.sync_count` | `1` | 同步排名前幾個 IP |
| `cloudflare_dns.ttl` | `1` | Cloudflare API 中 `1` 表示自動 TTL |
| `cloudflare_dns.latency_sync_enabled` | `false` | 是否允許 DNS 按延遲排序冷卻同步 |
| `cloudflare_dns.latency_sync_interval` | `5m` | 延遲排序型 DNS 同步的最小間隔 |

### 使用自訂 IP 池

建立 `/etc/cfnat/ips-v4.txt`：

```text
1.0.0.0/24
1.1.1.0/24
104.16.0.1
```

修改設定：

```json
"ip_sources": [
  "/etc/cfnat/ips-v4.txt",
  "https://example.com/extra-cidr.txt"
]
```

然後執行：

```bash
cfnatctl check
cfnatctl restart
```

## 手動建置

需要 Go 1.22 或更高版本：

```bash
make test
make build
```

生成三個 Linux 架構版本：

```bash
make release VERSION=v0.7.1
```

## 命令列

```bash
cfnat -config ./config.json check-config
cfnat -config ./config.json migrate-config
cfnat -config ./config.json scan
cfnat -config ./config.json status
cfnat -config ./config.json run
cfnat version
```

`scan` 僅輸出掃描結果，不更新 DNS；DNS 只由常駐的 `run` 模式管理。

再次執行安裝腳本升級時，會保留既有設定；只有舊版預設的失效探測位址會遷移為新位址，使用者自訂的 `check_url` 不會被覆蓋。

## 安全與執行邊界

- 服務以獨立的 `cfnat` 系統使用者執行。
- systemd 開啟檔案系統、裝置、權限和核心相關的沙箱限制。
- 僅保留綁定低連接埠所需的 `CAP_NET_BIND_SERVICE`。
- TLS 預設校驗憑證，除非明確設定 `insecure_skip_verify=true`。
- 這是四層 TCP 透傳，不終止 TLS，也不解析 VLESS、Trojan 等上層協定。
- 程式只負責更新 Cloudflare DNS，不會建立 Zone、修改其他記錄或代理狀態。

請遵守伺服器所在地及使用者所在地的法律法規。

## 解除安裝

```bash
sudo ./scripts/uninstall.sh
```

或進入 `sudo cfnatctl`，選擇「一鍵關閉並解除安裝」。

解除安裝腳本保留 `/etc/cfnat` 和 `/var/lib/cfnat`，防止誤刪 Token、設定和執行狀態。
