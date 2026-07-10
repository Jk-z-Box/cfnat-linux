#!/usr/bin/env bash
set -Eeuo pipefail
[[ "${EUID}" -eq 0 ]] || { echo "请使用 root 运行" >&2; exit 1; }
systemctl disable --now cfnat 2>/dev/null || true
systemctl disable --now cfnat-web-restart.path 2>/dev/null || true
systemctl disable --now cfnat-update.timer 2>/dev/null || true
rm -f /etc/systemd/system/cfnat.service /etc/systemd/system/cfnat-web-restart.service /etc/systemd/system/cfnat-web-restart.path /etc/systemd/system/cfnat-update.service /etc/systemd/system/cfnat-update.timer /usr/local/bin/cfnat /usr/local/bin/cfnatctl
rm -rf /usr/local/lib/cfnat
systemctl daemon-reload
echo "程序已卸载。配置和状态仍保留在 /etc/cfnat 与 /var/lib/cfnat。"
echo "确认不再需要后可手动删除这两个目录及 cfnat 系统用户。"
