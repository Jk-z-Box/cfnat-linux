#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_NAME="cfnat-linux"
GO_VERSION="1.26.4"
INSTALL_BIN="/usr/local/bin/cfnat"
CONFIG_DIR="/etc/cfnat"
STATE_DIR="/var/lib/cfnat"
SERVICE_FILE="/etc/systemd/system/cfnat.service"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

die() { echo "错误: $*" >&2; exit 1; }
info() { echo "==> $*"; }
retry() { echo "输入无效: $*，请重新输入。" >&2; }

prompt_listen() {
  local value port_number
  while true; do
    read -r -p "本地监听地址 [0.0.0.0:1234]: " value
    value="${value:-0.0.0.0:1234}"
    if [[ "${value}" =~ ^(\[[0-9A-Fa-f:.%]+\]|[A-Za-z0-9._-]+):([0-9]{1,5})$ ]]; then
      port_number=$((10#${BASH_REMATCH[2]}))
      if (( port_number >= 1 && port_number <= 65535 )); then
        LISTEN="${value}"
        return
      fi
    fi
    retry "监听地址应类似 0.0.0.0:1234 或 [::]:1234，端口范围为 1-65535"
  done
}

prompt_ip_version() {
  local value
  while true; do
    read -r -p "IP 版本 [4]: " value
    value="${value:-4}"
    if [[ "${value}" == "4" || "${value}" == "6" ]]; then
      IP_VERSION="${value}"
      return
    fi
    retry "IP 版本只能是 4 或 6"
  done
}

prompt_max_latency() {
  local value
  while true; do
    read -r -p "最大优选延迟，单位毫秒 [800]: " value
    value="${value:-800}"
    if [[ "${value}" =~ ^[1-9][0-9]*$ ]] && (( value <= 60000 )); then
      MAX_LATENCY="${value}ms"
      return
    fi
    retry "最大延迟必须是 1-60000 的整数（毫秒）"
  done
}

prompt_colos() {
  local value item invalid
  local -a items
  while true; do
    read -r -p "限定数据中心，逗号分隔（留空不限制）: " value
    COLO_JSON=""
    invalid=""
    IFS=',' read -r -a items <<< "${value}"
    for item in "${items[@]}"; do
      item="${item//[[:space:]]/}"
      [[ -z "${item}" ]] && continue
      if [[ ! "${item}" =~ ^[A-Za-z]{3}$ ]]; then
        invalid="${item}"
        break
      fi
      item="$(printf '%s' "${item}" | tr '[:lower:]' '[:upper:]')"
      [[ -n "${COLO_JSON}" ]] && COLO_JSON+=","
      COLO_JSON+="\"${item}\""
    done
    if [[ -z "${invalid}" ]]; then
      return
    fi
    retry "数据中心代码 ${invalid} 格式错误，应为三个英文字母，例如 HKG,SJC"
  done
}

prompt_dns_enabled() {
  local value
  while true; do
    read -r -p "启用 Cloudflare DNS 同步？[y/N]: " value
    case "${value}" in
      y|Y|yes|YES|Yes) DNS_BOOL=true; return ;;
      ""|n|N|no|NO|No) DNS_BOOL=false; return ;;
      *) retry "请输入 y 或 n" ;;
    esac
  done
}

valid_record_name() {
  local name="$1" label
  local -a labels
  [[ "${name}" == *.* && "${name}" != .* && "${name}" != *. && "${name}" != *..* ]] || return 1
  IFS='.' read -r -a labels <<< "${name}"
  for label in "${labels[@]}"; do
    [[ "${label}" =~ ^[A-Za-z0-9]$ || "${label}" =~ ^[A-Za-z0-9][A-Za-z0-9-]{0,61}[A-Za-z0-9]$ ]] || return 1
  done
}

prompt_dns_settings() {
  while true; do
    read -r -p "Cloudflare Zone ID: " ZONE_ID
    [[ "${ZONE_ID}" =~ ^[A-Fa-f0-9]{32}$ ]] && break
    retry "Zone ID 应为 Cloudflare 提供的 32 位十六进制字符串"
  done
  while true; do
    read -r -p "完整记录名（例如 best.example.com）: " RECORD_NAME
    valid_record_name "${RECORD_NAME}" && break
    retry "请输入完整且合法的域名，例如 best.example.com"
  done
  while true; do
    read -r -p "同步前几个优选 IP [1，最大 10]: " SYNC_COUNT
    SYNC_COUNT="${SYNC_COUNT:-1}"
    if [[ "${SYNC_COUNT}" =~ ^[1-9][0-9]*$ ]] && (( SYNC_COUNT <= 10 )); then
      break
    fi
    retry "同步数量必须是 1-10 的整数"
  done
  while true; do
    read -r -s -p "Cloudflare API Token: " TOKEN
    echo
    if [[ -n "${TOKEN}" && "${TOKEN}" != *[[:space:]]* ]]; then
      break
    fi
    retry "API Token 不能为空且不能包含空白字符"
  done
}

[[ "${EUID}" -eq 0 ]] || die "请使用 root 运行：sudo ./scripts/install.sh"
command -v systemctl >/dev/null 2>&1 || die "当前系统未使用 systemd"
[[ -f "${PROJECT_DIR}/go.mod" ]] || die "请在完整项目目录中运行安装脚本"

case "$(uname -m)" in
  x86_64) GO_ARCH="amd64"; GO_SHA="1153d3d50e0ac764b447adfe05c2bcf08e889d42a02e0fe0259bd47f6733ad7f" ;;
  aarch64|arm64) GO_ARCH="arm64"; GO_SHA="ef758ae7c6cf9267c9c0ef080b8965f453d89ab2d25d9eb22de4405925238768" ;;
  i386|i686) GO_ARCH="386"; GO_SHA="5ca0982791791559d11a0eba939617a94c3f37c21aa514a55c415b9167efc658" ;;
  *) die "不支持的 CPU 架构: $(uname -m)" ;;
esac

TMP_DIR="$(mktemp -d)"
cleanup() { rm -rf "${TMP_DIR}"; }
trap cleanup EXIT

BUNDLED_BIN="${PROJECT_DIR}/dist/cfnat-linux-${GO_ARCH}"
if [[ -f "${BUNDLED_BIN}" && -f "${PROJECT_DIR}/dist/SHA256SUMS" ]]; then
  command -v sha256sum >/dev/null 2>&1 || die "缺少 sha256sum，无法校验内置二进制"
  (cd "${PROJECT_DIR}/dist" && sha256sum --check --status SHA256SUMS) || die "内置二进制校验失败"
  info "安装已校验的 Linux ${GO_ARCH} 二进制"
  install -m 0755 "${BUNDLED_BIN}" "${INSTALL_BIN}"
else
  BUILD_GO="$(command -v go || true)"
  if [[ -z "${BUILD_GO}" ]]; then
    command -v curl >/dev/null 2>&1 || die "缺少 curl"
    command -v sha256sum >/dev/null 2>&1 || die "缺少 sha256sum"
    GO_FILE="go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
    info "下载临时 Go ${GO_VERSION} 工具链"
    curl --fail --location --retry 3 "https://go.dev/dl/${GO_FILE}" -o "${TMP_DIR}/${GO_FILE}"
    echo "${GO_SHA}  ${TMP_DIR}/${GO_FILE}" | sha256sum --check --status || die "Go 工具链校验失败"
    mkdir -p "${TMP_DIR}/toolchain"
    tar -xzf "${TMP_DIR}/${GO_FILE}" -C "${TMP_DIR}/toolchain"
    BUILD_GO="${TMP_DIR}/toolchain/go/bin/go"
  fi
  info "编译 ${PROJECT_NAME}"
  (cd "${PROJECT_DIR}" && CGO_ENABLED=0 "${BUILD_GO}" build -trimpath -ldflags="-s -w -X main.version=local" -o "${TMP_DIR}/cfnat" ./cmd/cfnat)
  install -m 0755 "${TMP_DIR}/cfnat" "${INSTALL_BIN}"
fi

if ! getent passwd cfnat >/dev/null; then
  useradd --system --home-dir "${STATE_DIR}" --shell /usr/sbin/nologin cfnat
fi
install -d -o root -g cfnat -m 0750 "${CONFIG_DIR}"
install -d -o cfnat -g cfnat -m 0750 "${STATE_DIR}"

if [[ ! -f "${CONFIG_DIR}/config.json" ]]; then
  info "生成配置文件"
  prompt_listen
  prompt_ip_version
  prompt_max_latency
  if [[ "${IP_VERSION}" == "4" ]]; then SOURCE="https://www.cloudflare.com/ips-v4"; else SOURCE="https://www.cloudflare.com/ips-v6"; fi
  prompt_colos
  DNS_BOOL=false; ZONE_ID=""; RECORD_NAME=""; SYNC_COUNT=1; TOKEN=""
  prompt_dns_enabled
  if [[ "${DNS_BOOL}" == true ]]; then
    prompt_dns_settings
  fi
  if [[ "${IP_VERSION}" == "4" ]]; then RECORD_TYPE="A"; else RECORD_TYPE="AAAA"; fi
  cat > "${CONFIG_DIR}/config.json" <<EOF
{
  "config_version": 3,
  "listen": "${LISTEN}",
  "ip_version": ${IP_VERSION},
  "ip_sources": ["${SOURCE}"],
  "random_ips": true,
  "max_candidates": 2000,
  "valid_ip_count": 20,
  "pool_size": 10,
  "concurrency": 100,
  "target_port": 443,
  "tls": true,
  "tls_server_name": "",
  "insecure_skip_verify": false,
  "check_url": "https://cloudflare.com/cdn-cgi/trace",
  "expected_status": 200,
  "max_latency": "${MAX_LATENCY}",
  "dial_timeout": "3s",
  "colos": [${COLO_JSON}],
  "scan_interval": "6h",
  "health_interval": "60s",
  "health_failures": 3,
  "state_file": "/var/lib/cfnat/state.json",
  "source_cache_dir": "/var/lib/cfnat/ip-cache",
  "log_level": "info",
  "cloudflare_dns": {
    "enabled": ${DNS_BOOL},
    "zone_id": "${ZONE_ID}",
    "record_name": "${RECORD_NAME}",
    "record_type": "${RECORD_TYPE}",
    "sync_count": ${SYNC_COUNT},
    "ttl": 1,
    "proxied": false,
    "token_env": "CF_API_TOKEN",
    "marker": "managed-by:cfnat-linux"
  }
}
EOF
  printf 'CF_API_TOKEN=%q\n' "${TOKEN}" > "${CONFIG_DIR}/cfnat.env"
  chown root:cfnat "${CONFIG_DIR}/config.json" "${CONFIG_DIR}/cfnat.env"
  chmod 0640 "${CONFIG_DIR}/config.json" "${CONFIG_DIR}/cfnat.env"
else
  info "保留已有配置 ${CONFIG_DIR}/config.json"
  cp -p "${CONFIG_DIR}/config.json" "${CONFIG_DIR}/config.json.bak"
  "${INSTALL_BIN}" -config "${CONFIG_DIR}/config.json" migrate-config
  [[ -f "${CONFIG_DIR}/cfnat.env" ]] || { touch "${CONFIG_DIR}/cfnat.env"; chown root:cfnat "${CONFIG_DIR}/cfnat.env"; chmod 0640 "${CONFIG_DIR}/cfnat.env"; }
fi

cat > "${SERVICE_FILE}" <<'EOF'
[Unit]
Description=Cloudflare IP optimizer, TCP forwarder and DNS synchronizer
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=cfnat
Group=cfnat
EnvironmentFile=-/etc/cfnat/cfnat.env
ExecStart=/usr/local/bin/cfnat -config /etc/cfnat/config.json run
Restart=on-failure
RestartSec=10s
TimeoutStopSec=30s
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
ReadWritePaths=/var/lib/cfnat
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

install -d -o root -g root -m 0755 /usr/local/lib/cfnat
install -m 0755 "${PROJECT_DIR}/scripts/cfnatctl.sh" /usr/local/bin/cfnatctl
install -m 0755 "${PROJECT_DIR}/scripts/uninstall.sh" /usr/local/lib/cfnat/uninstall.sh

"${INSTALL_BIN}" -config "${CONFIG_DIR}/config.json" check-config
systemctl daemon-reload
systemctl enable cfnat
systemctl restart cfnat
info "安装完成"
echo "状态: cfnatctl status"
echo "日志: cfnatctl logs"
echo "管理面板: sudo cfnatctl"
