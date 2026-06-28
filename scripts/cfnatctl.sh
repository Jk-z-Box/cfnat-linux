#!/usr/bin/env bash
set -Eeuo pipefail

CONFIG_FILE="/etc/cfnat/config.json"
ENV_FILE="/etc/cfnat/cfnat.env"
BIN="/usr/local/bin/cfnat"

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "此操作需要管理员权限，请运行: sudo cfnatctl" >&2
    return 1
  fi
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
    echo " 11) 使用编辑器修改完整配置"
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
      11)
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
  systemctl restart cfnat
  echo "服务已重启，正在重新扫描。"
}

uninstall_service() {
  require_root || return
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
  while true; do
    show_dashboard
    echo "  1) 运行开关（启动/停止）"
    echo "  2) 立即重启并重新扫描"
    echo "  3) 修改配置"
    echo "  4) 查看实时日志"
    echo "  5) 运行一次诊断扫描"
    echo "  6) 一键关闭并卸载"
    echo "  0) 退出"
    read -r -p "请选择: " choice
    case "${choice}" in
      1) toggle_service; pause_screen ;;
      2) restart_scan; pause_screen ;;
      3) config_menu ;;
      4) journalctl -u cfnat -f ;;
      5) "${BIN}" -config "${CONFIG_FILE}" scan; pause_screen ;;
      6) uninstall_service ;;
      0) exit 0 ;;
      *) echo "无效选项，请重新输入。"; sleep 1 ;;
    esac
  done
}

case "${1:-menu}" in
  menu) interactive_menu ;;
  status) show_dashboard ;;
  start|stop|restart) require_root; systemctl "$1" cfnat ;;
  logs) journalctl -u cfnat -f ;;
  pool) "${BIN}" -config "${CONFIG_FILE}" status ;;
  check) "${BIN}" -config "${CONFIG_FILE}" check-config ;;
  scan) require_root; restart_scan ;;
  config) config_menu ;;
  uninstall) uninstall_service ;;
  *) echo "用法: cfnatctl {menu|status|start|stop|restart|logs|pool|check|scan|config|uninstall}" >&2; exit 2 ;;
esac
