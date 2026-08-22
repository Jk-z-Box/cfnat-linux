#!/usr/bin/env bash
set -Eeuo pipefail
[[ "${EUID}" -eq 0 ]] || { echo "请使用 root 运行" >&2; exit 1; }
if [[ -f /etc/openwrt_release ]]; then
  /etc/init.d/cfnat stop 2>/dev/null || true
  /etc/init.d/cfnat disable 2>/dev/null || true
  rm -f /etc/init.d/cfnat
  if command -v crontab >/dev/null 2>&1; then
    tmp_cron="$(mktemp)"
    crontab -l 2>/dev/null | grep -v '/usr/local/bin/cfnatctl update --auto' > "${tmp_cron}" || true
    crontab "${tmp_cron}" 2>/dev/null || true
    rm -f "${tmp_cron}"
  fi
else
  systemctl disable --now cfnat 2>/dev/null || true
  systemctl disable --now cfnat-web-restart.path 2>/dev/null || true
  systemctl disable --now cfnat-update.timer 2>/dev/null || true
  rm -f /etc/systemd/system/cfnat.service /etc/systemd/system/cfnat-web-restart.service /etc/systemd/system/cfnat-web-restart.path /etc/systemd/system/cfnat-update.service /etc/systemd/system/cfnat-update.timer
  systemctl daemon-reload 2>/dev/null || true
fi
rm -f /usr/local/bin/cfnat /usr/local/bin/cfnatctl
if [[ -f /etc/openwrt_release ]]; then
  [[ -L /usr/bin/cfnat ]] && rm -f /usr/bin/cfnat
  [[ -L /usr/bin/cfnatctl ]] && rm -f /usr/bin/cfnatctl
fi
rm -rf /usr/local/lib/cfnat
echo "程序已卸载。配置和状态仍保留在 /etc/cfnat 与 /var/lib/cfnat。"
echo "确认不再需要后可手动删除这两个目录及 cfnat 系统用户。"
