#!/usr/bin/env bash
set -Eeuo pipefail
[[ "${EUID}" -eq 0 ]] || { echo "请使用 root 运行" >&2; exit 1; }
systemctl disable --now cfnat 2>/dev/null || true
rm -f /etc/systemd/system/cfnat.service /usr/local/bin/cfnat /usr/local/bin/cfnatctl
rm -rf /usr/local/lib/cfnat
systemctl daemon-reload
echo "程序已卸载。配置和状态仍保留在 /etc/cfnat 与 /var/lib/cfnat。"
echo "确认不再需要后可手动删除这两个目录及 cfnat 系统用户。"
