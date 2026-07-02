#!/usr/bin/env bash
set -Eeuo pipefail

CONFIG_FILE="/etc/cfnat/config.json"
ENV_FILE="/etc/cfnat/cfnat.env"
BIN="/usr/local/bin/cfnat"
AUTH_OK=false

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "此操作需要管理员权限，请运行: sudo cfnatctl" >&2
    return 1
  fi
}

management_password_enabled() {
  awk '
    /"management"[[:space:]]*:/ {inside=1}
    inside && /"password_enabled"[[:space:]]*:[[:space:]]*true/ {print "true"; exit}
    inside && /^  }/ {inside=0}
  ' "${CONFIG_FILE}" 2>/dev/null | grep -qx true
}

management_password_hash() {
  awk '
    /"management"[[:space:]]*:/ {inside=1}
    inside && /"password_sha256"/ {print; exit}
    inside && /^  }/ {inside=0}
  ' "${CONFIG_FILE}" 2>/dev/null | sed -E 's/.*"password_sha256"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/'
}

hash_password() {
  printf '%s' "$1" | sha256sum | awk '{print $1}'
}

require_auth() {
  if [[ "${AUTH_OK}" == true ]]; then return 0; fi
  management_password_enabled || { AUTH_OK=true; return 0; }
  local expected input actual
  expected="$(management_password_hash)"
  if [[ ! "${expected}" =~ ^[A-Fa-f0-9]{64}$ ]]; then
    echo "管理密码已启用，但密码哈希无效，请手动检查 ${CONFIG_FILE}。" >&2
    return 1
  fi
  read -r -s -p "管理密码: " input
  echo
  actual="$(hash_password "${input}")"
  if [[ "${actual}" == "${expected}" ]]; then
    AUTH_OK=true
    return 0
  fi
  echo "管理密码错误。" >&2
  return 1
}

pause_screen() {
  echo
  read -r -p "按回车键返回菜单..." _
}

service_active() {
  systemctl is-active --quiet cfnat
}

restart_if_running() {
  if service_active; then
    systemctl restart cfnat
    echo "配置已保存，服务已重启并重新扫描。"
  else
    echo "配置已保存。服务当前关闭，启动后生效。"
  fi
}

json_value() {
  local key="$1"
  sed -n -E "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\"([^\"]*)\".*/\\1/p" | head -n1
}

show_dashboard() {
  if [[ -t 1 && -n "${TERM:-}" ]]; then clear; fi
  echo "============================================================"
  echo "                  cfnat-linux 管理面板"
  echo "============================================================"
  if service_active; then
    echo "systemd 服务    : 运行中"
  else
    echo "systemd 服务    : 已停止"
  fi
  echo "------------------------------------------------------------"
  "${BIN}" -config "${CONFIG_FILE}" status 2>&1 || echo "状态读取失败，请检查配置和日志。"
  echo "============================================================"
}

set_config() {
  local key="$1" value="$2"
  if "${BIN}" -config "${CONFIG_FILE}" config-set "${key}" "${value}"; then
    restart_if_running
    return 0
  fi
  return 1
}

set_config_no_restart() {
  local key="$1" value="$2"
  if "${BIN}" -config "${CONFIG_FILE}" config-set "${key}" "${value}"; then
    echo "配置已保存。"
    return 0
  fi
  return 1
}

edit_listen() {
  local value
  while true; do
    read -r -p "新的监听 IP 和端口（例如 0.0.0.0:1234 或 [::]:1234）: " value
    if set_config listen "${value}"; then return; fi
    echo "输入格式错误，请重新输入。" >&2
  done
}

edit_latency() {
  local value
  while true; do
    read -r -p "最大优选延迟，单位毫秒（例如 300）: " value
    if [[ "${value}" =~ ^[1-9][0-9]*$ ]] && (( value <= 60000 )); then
      if set_config max_latency "${value}ms"; then return; fi
    fi
    echo "请输入 1-60000 的整数。" >&2
  done
}

edit_min_healthy_count() {
  local value
  while true; do
    read -r -p "健康 IP 少于多少个时整池重选（例如 5）: " value
    if [[ "${value}" =~ ^[1-9][0-9]*$ ]]; then
      if set_config min_healthy_count "${value}"; then return; fi
    fi
    echo "请输入不大于 pool_size 的正整数。" >&2
  done
}

edit_latency_monitor_interval() {
  local value
  while true; do
    read -r -p "延迟监控间隔，单位秒（例如 2）: " value
    if [[ "${value}" =~ ^[1-9][0-9]*$ ]] && (( value <= 3600 )); then
      if set_config latency_monitor_interval "${value}s"; then return; fi
    fi
    echo "请输入 1-3600 的整数。" >&2
  done
}

edit_speed_test_min() {
  local value
  while true; do
    read -r -p "最低下载速度，单位 MB/s（例如 5）: " value
    if [[ "${value}" =~ ^[0-9]+([.][0-9]+)?$ ]] && awk "BEGIN {exit !(${value} > 0 && ${value} <= 100000)}"; then
      if set_config speed_test_min_mbps "${value}"; then return; fi
    fi
    echo "请输入大于 0 的数字。" >&2
  done
}

edit_speed_test_concurrency() {
  local value
  while true; do
    read -r -p "下载测速并发数（例如 3）: " value
    if [[ "${value}" =~ ^[1-9][0-9]*$ ]] && (( value <= 50 )); then
      if set_config speed_test_concurrency "${value}"; then return; fi
    fi
    echo "请输入 1-50 的整数。" >&2
  done
}

toggle_speed_test() {
  local value
  while true; do
    read -r -p "启用下载测速筛选？[y/n]: " value
    case "${value}" in
      y|Y|yes|YES|Yes) set_config speed_test_enabled true && return ;;
      n|N|no|NO|No) set_config speed_test_enabled false && return ;;
      *) echo "请输入 y 或 n。" >&2 ;;
    esac
  done
}

edit_zone_id() {
  local value
  while true; do
    read -r -p "新的 Cloudflare Zone ID: " value
    if [[ "${value}" =~ ^[A-Fa-f0-9]{32}$ ]] && set_config zone_id "${value}"; then return; fi
    echo "Zone ID 应为 32 位十六进制字符串，请重新输入。" >&2
  done
}

edit_record_name() {
  local value
  while true; do
    read -r -p "新的完整解析域名（例如 best.example.com）: " value
    if set_config record_name "${value}"; then return; fi
    echo "域名格式错误，请重新输入。" >&2
  done
}

edit_token() {
  local value
  while true; do
    read -r -s -p "新的 Cloudflare API Token: " value
    echo
    if [[ -n "${value}" && "${value}" != *[[:space:]]* ]]; then
      printf 'CF_API_TOKEN=%q\n' "${value}" > "${ENV_FILE}"
      chown root:cfnat "${ENV_FILE}"
      chmod 0640 "${ENV_FILE}"
      restart_if_running
      return
    fi
    echo "Token 不能为空且不能包含空白字符，请重新输入。" >&2
  done
}

toggle_dns() {
  local value
  while true; do
    read -r -p "启用 DNS 同步？[y/n]: " value
    case "${value}" in
      y|Y|yes|YES|Yes) set_config dns_enabled true && return ;;
      n|N|no|NO|No) set_config dns_enabled false && return ;;
      *) echo "请输入 y 或 n。" >&2 ;;
    esac
  done
}

toggle_dns_latency_sync() {
  local value
  while true; do
    read -r -p "启用 DNS 延迟排序冷却同步？[y/n]: " value
    case "${value}" in
      y|Y|yes|YES|Yes) set_config dns_latency_sync_enabled true && return ;;
      n|N|no|NO|No) set_config dns_latency_sync_enabled false && return ;;
      *) echo "请输入 y 或 n。" >&2 ;;
    esac
  done
}

toggle_scan_interval() {
  local value
  while true; do
    read -r -p "启用定时完整重选？[y/n]: " value
    case "${value}" in
      y|Y|yes|YES|Yes) set_config scan_interval_enabled true && return ;;
      n|N|no|NO|No) set_config scan_interval_enabled false && return ;;
      *) echo "请输入 y 或 n。" >&2 ;;
    esac
  done
}

toggle_update_check() {
  local value
  while true; do
    read -r -p "启用定时检查更新？[y/n]: " value
    case "${value}" in
      y|Y|yes|YES|Yes) set_config update_check_enabled true && return ;;
      n|N|no|NO|No) set_config update_check_enabled false && return ;;
      *) echo "请输入 y 或 n。" >&2 ;;
    esac
  done
}

toggle_auto_update() {
  local value
  while true; do
    read -r -p "启用后台自动更新？[y/n]: " value
    case "${value}" in
      y|Y|yes|YES|Yes)
        set_config_no_restart update_auto_update_enabled true || return
        systemctl enable --now cfnat-update.timer >/dev/null 2>&1 || true
        echo "后台自动更新已启用。"
        return
        ;;
      n|N|no|NO|No)
        set_config_no_restart update_auto_update_enabled false || return
        echo "后台自动更新已关闭。"
        return
        ;;
      *) echo "请输入 y 或 n。" >&2 ;;
    esac
  done
}

edit_update_check_interval() {
  local value
  while true; do
    read -r -p "检查更新间隔，单位小时（例如 6）: " value
    if [[ "${value}" =~ ^[1-9][0-9]*$ ]] && (( value <= 720 )); then
      if set_config update_check_interval "${value}h"; then return; fi
    fi
    echo "请输入 1-720 的整数。" >&2
  done
}

update_auto_enabled() {
  awk '
    /"update"[[:space:]]*:/ {inside=1}
    inside && /"auto_update_enabled"[[:space:]]*:[[:space:]]*true/ {print "true"; exit}
    inside && /^  }/ {inside=0}
  ' "${CONFIG_FILE}" 2>/dev/null | grep -qx true
}

run_update() {
  require_root || return
  local mode="${1:-manual}"
  if [[ "${mode}" != "--auto" ]]; then
    require_auth || return
  elif ! update_auto_enabled; then
    echo "后台自动更新未启用。"
    return 0
  fi
  local json latest package_url tmp archive dir
  if ! json="$("${BIN}" -config "${CONFIG_FILE}" check-update)"; then
    return 1
  fi
  if ! grep -q '"update_available"[[:space:]]*:[[:space:]]*true' <<<"${json}"; then
    latest="$(json_value latest_version <<<"${json}")"
    echo "当前已是最新版本${latest:+：${latest}}。"
    return 0
  fi
  latest="$(json_value latest_version <<<"${json}")"
  package_url="$(json_value package_url <<<"${json}")"
  if [[ -z "${package_url}" ]]; then
    echo "发现新版本 ${latest:-未知}，但 Release 中没有找到 cfnat-linux tar.gz 包。" >&2
    return 1
  fi
  echo "发现新版本 ${latest}，开始下载并安装..."
  tmp="$(mktemp -d)"
  archive="${tmp}/cfnat-linux.tar.gz"
  curl -fL --retry 3 -o "${archive}" "${package_url}"
  tar -xzf "${archive}" -C "${tmp}"
  dir="$(find "${tmp}" -mindepth 1 -maxdepth 1 -type d | head -n1)"
  if [[ -z "${dir}" || ! -x "${dir}/scripts/install.sh" ]]; then
    echo "更新包格式不正确，找不到 scripts/install.sh。" >&2
    rm -rf "${tmp}"
    return 1
  fi
  (cd "${dir}" && ./scripts/install.sh)
  rm -rf "${tmp}"
}

edit_management_password() {
  local first second hashed
  while true; do
    read -r -s -p "新的管理密码: " first
    echo
    if [[ ${#first} -lt 6 ]]; then
      echo "管理密码至少 6 位，请重新输入。" >&2
      continue
    fi
    read -r -s -p "再次输入管理密码: " second
    echo
    if [[ "${first}" != "${second}" ]]; then
      echo "两次输入不一致，请重新输入。" >&2
      continue
    fi
    hashed="$(hash_password "${first}")"
    set_config_no_restart management_password_sha256 "${hashed}" || return
    set_config_no_restart management_password_enabled true || return
    AUTH_OK=true
    echo "管理密码已启用/更新。"
    return
  done
}

toggle_management_password() {
  if management_password_enabled; then
    read -r -p "确认关闭管理密码？[y/N]: " value
    case "${value}" in
      y|Y|yes|YES|Yes)
        set_config_no_restart management_password_enabled false
        AUTH_OK=true
        ;;
      *) echo "已取消。" ;;
    esac
  else
    echo "开启管理密码前需要先设置密码。"
    edit_management_password
  fi
}

edit_dns_latency_sync_interval() {
  local value
  while true; do
    read -r -p "DNS 延迟排序同步冷却时间，单位分钟（例如 5）: " value
    if [[ "${value}" =~ ^[1-9][0-9]*$ ]] && (( value <= 10080 )); then
      if set_config dns_latency_sync_interval "${value}m"; then return; fi
    fi
    echo "请输入 1-10080 的整数。" >&2
  done
}

config_menu() {
  require_root || return
  require_auth || return
  while true; do
    echo
    echo "---------------------- 修改配置 ---------------------------"
    echo "  1) 监听 IP 和端口"
    echo "  2) 最大优选延迟"
    echo "  3) Cloudflare API Token"
    echo "  4) Cloudflare Zone ID"
    echo "  5) DNS 解析域名"
    echo "  6) DNS 同步开关"
    echo "  7) 最小健康 IP 数"
    echo "  8) 延迟监控间隔"
    echo "  9) DNS 延迟排序同步开关"
    echo " 10) DNS 延迟排序同步冷却时间"
    echo " 11) 下载测速筛选开关"
    echo " 12) 下载测速最低速度"
    echo " 13) 下载测速并发数"
    echo " 14) 定时完整重选开关"
    echo " 15) 管理密码开关"
    echo " 16) 修改管理密码"
    echo " 17) 定时检查更新开关"
    echo " 18) 后台自动更新开关"
    echo " 19) 检查更新间隔"
    echo " 20) 使用编辑器修改完整配置"
    echo "  0) 返回"
    read -r -p "请选择: " choice
    case "${choice}" in
      1) edit_listen; pause_screen ;;
      2) edit_latency; pause_screen ;;
      3) edit_token; pause_screen ;;
      4) edit_zone_id; pause_screen ;;
      5) edit_record_name; pause_screen ;;
      6) toggle_dns; pause_screen ;;
      7) edit_min_healthy_count; pause_screen ;;
      8) edit_latency_monitor_interval; pause_screen ;;
      9) toggle_dns_latency_sync; pause_screen ;;
      10) edit_dns_latency_sync_interval; pause_screen ;;
      11) toggle_speed_test; pause_screen ;;
      12) edit_speed_test_min; pause_screen ;;
      13) edit_speed_test_concurrency; pause_screen ;;
      14) toggle_scan_interval; pause_screen ;;
      15) toggle_management_password; pause_screen ;;
      16) edit_management_password; pause_screen ;;
      17) toggle_update_check; pause_screen ;;
      18) toggle_auto_update; pause_screen ;;
      19) edit_update_check_interval; pause_screen ;;
      20)
        backup="$(mktemp)"
        cp -p "${CONFIG_FILE}" "${backup}"
        "${EDITOR:-vi}" "${CONFIG_FILE}"
        if "${BIN}" -config "${CONFIG_FILE}" check-config; then
          rm -f "${backup}"
          restart_if_running
        else
          cp -p "${backup}" "${CONFIG_FILE}"
          rm -f "${backup}"
          echo "配置有误，已自动恢复修改前的配置。"
        fi
        pause_screen
        ;;
      0) return ;;
      *) echo "无效选项，请重新输入。" ;;
    esac
  done
}

toggle_service() {
  require_root || return
  require_auth || return
  if service_active; then
    systemctl stop cfnat
    echo "服务已关闭。"
  else
    systemctl start cfnat
    echo "服务已启动，正在扫描。"
  fi
}

restart_scan() {
  require_root || return
  require_auth || return
  systemctl restart cfnat
  echo "服务已重启，正在重新扫描。"
}

uninstall_service() {
  require_root || return
  require_auth || return
  echo "这将停止并卸载 cfnat-linux，但保留配置和状态文件。"
  read -r -p "请输入 UNINSTALL 确认: " answer
  if [[ "${answer}" != "UNINSTALL" ]]; then
    echo "已取消。"
    return
  fi
  /usr/local/lib/cfnat/uninstall.sh
  exit 0
}

interactive_menu() {
  require_root || exit 1
  require_auth || exit 1
  while true; do
    show_dashboard
    echo "  1) 运行开关（启动/停止）"
    echo "  2) 立即重启并重新扫描"
    echo "  3) 修改配置"
    echo "  4) 查看实时日志"
    echo "  5) 运行一次诊断扫描"
    echo "  6) 一键关闭并卸载"
    echo "  7) 立即检查并更新"
    echo "  0) 退出"
    read -r -p "请选择: " choice
    case "${choice}" in
      1) toggle_service; pause_screen ;;
      2) restart_scan; pause_screen ;;
      3) config_menu ;;
      4) journalctl -u cfnat -f ;;
      5) "${BIN}" -config "${CONFIG_FILE}" scan; pause_screen ;;
      6) uninstall_service ;;
      7) run_update manual; pause_screen ;;
      0) exit 0 ;;
      *) echo "无效选项，请重新输入。"; sleep 1 ;;
    esac
  done
}

case "${1:-menu}" in
  menu) interactive_menu ;;
  status) show_dashboard ;;
  start|stop|restart) require_root; require_auth || exit 1; systemctl "$1" cfnat ;;
  logs) journalctl -u cfnat -f ;;
  pool) "${BIN}" -config "${CONFIG_FILE}" status ;;
  check) "${BIN}" -config "${CONFIG_FILE}" check-config ;;
  scan) require_root; restart_scan ;;
  config) config_menu ;;
  update) run_update "${2:-manual}" ;;
  uninstall) uninstall_service ;;
  *) echo "用法: cfnatctl {menu|status|start|stop|restart|logs|pool|check|scan|config|update|uninstall}" >&2; exit 2 ;;
esac
