#!/usr/bin/env bash
#==============================================================================
#  setup_firewall.sh
#  Cowrie 蜜罐主機（Raspberry Pi OS Lite 64-bit）防火牆與防跳板設定
#
#  【架構說明】
#   - 主機本身（INPUT / OUTPUT） → 使用 UFW 管理（語法簡單、不易改壞）
#   - 蜜罐容器（Docker FORWARD）  → 使用 iptables 的 DOCKER-USER 鏈管理
#     原因：UFW 無法控制 Docker 容器的轉發流量，且 Docker 發布的埠會繞過
#     UFW 的入站規則。DOCKER-USER 是 Docker 官方保留給使用者的過濾鏈。
#
#  【規則總覽】
#   入站：
#     22222/tcp  管理用 SSH  → 只允許從 tailscale0 進來（成員 A 使用）
#     22/tcp     Cowrie 蜜罐 → 對外開放（誘捕用）
#     8501/tcp   Streamlit   → 只允許從 tailscale0 進來
#     其餘一律拒絕
#   出站（防跳板 Egress Filtering）：
#     主機：預設拒絕；僅放行 DNS、NTP、DHCP、Tailscale、(選用) 80/443
#     容器：預設全部拒絕主動對外連線，只放行「既有連線的回應」
#
#  【用法】
#     sudo ./setup_firewall.sh               # 套用設定（建議使用）
#     sudo ./setup_firewall.sh --status      # 只顯示目前狀態
#     sudo ./setup_firewall.sh --rollback    # 緊急回滾（關閉防火牆）
#     sudo ./setup_firewall.sh --no-watchdog # 不啟用自動回滾（不建議）
#
#  【可用環境變數覆寫】（sudo 要這樣寫：sudo VAR=值 ./setup_firewall.sh）
#     SSH_ADMIN_PORT / HONEYPOT_PORTS / DASHBOARD_PORT / TS_IF
#     ALLOW_HOST_WEB_OUT / ALLOW_CONTAINER_DNS_NTP / ADMIN_ALLOW_ANYWHERE
#     WATCHDOG_SECS
#==============================================================================

# -E：讓 ERR trap 在函式內也生效；-e：指令失敗即停止；
# -u：使用未定義變數即報錯；pipefail：管線中任何一段失敗都算失敗
set -Eeuo pipefail

#------------------------------------------------------------------------------
# 1. 可調整的設定
#------------------------------------------------------------------------------
SSH_ADMIN_PORT="${SSH_ADMIN_PORT:-22222}"      # 真實管理用 SSH 埠
HONEYPOT_PORTS="${HONEYPOT_PORTS:-22}"         # 蜜罐對外埠（空白分隔，如 "22 23"）
DASHBOARD_PORT="${DASHBOARD_PORT:-8501}"       # Streamlit 儀表板埠
TS_IF="${TS_IF:-tailscale0}"                   # Tailscale 虛擬網卡名稱

# 主機是否允許對外 80/443（apt 更新、docker pull、Tailscale 控制平面都需要）
# 設為 no 會更嚴格，但 Tailscale 與 apt 可能無法運作，建議維持 yes
ALLOW_HOST_WEB_OUT="${ALLOW_HOST_WEB_OUT:-yes}"

# 蜜罐容器是否允許 DNS(53)/NTP(123) 出站。預設 no（最安全）。
# 注意：開啟後攻擊者可能利用 DNS 通道外傳資料。
ALLOW_CONTAINER_DNS_NTP="${ALLOW_CONTAINER_DNS_NTP:-no}"

# 管理 SSH 是否對所有來源開放（yes 會降低安全性，僅供 Tailscale 故障時救急）
ADMIN_ALLOW_ANYWHERE="${ADMIN_ALLOW_ANYWHERE:-no}"

# 自動回滾看門狗的等待秒數
WATCHDOG_SECS="${WATCHDOG_SECS:-180}"

#------------------------------------------------------------------------------
# 2. 內部使用的路徑與變數（一般不需修改）
#------------------------------------------------------------------------------
EGRESS_BIN="/usr/local/sbin/honeypot-egress.sh"
EGRESS_CONF="/etc/honeypot-egress.conf"
EGRESS_UNIT="/etc/systemd/system/honeypot-egress.service"
BACKUP_DIR="/root/firewall-backup-$(date +%Y%m%d-%H%M%S)"
CONFIRM_FILE="/run/setup_firewall.confirmed"

MODE="apply"       # apply | status | rollback
WATCHDOG=1         # 1 = 啟用自動回滾看門狗
FW_TOUCHED=0       # 是否已更動防火牆（出錯時據此決定是否回滾）
FINISHED=0         # 是否已完整完成

#------------------------------------------------------------------------------
# 3. 輸出輔助函式
#------------------------------------------------------------------------------
if [[ -t 1 ]]; then
  C_R=$'\e[31m'; C_G=$'\e[32m'; C_Y=$'\e[33m'; C_B=$'\e[36m'; C_0=$'\e[0m'
else
  C_R=""; C_G=""; C_Y=""; C_B=""; C_0=""
fi
info() { echo "${C_B}[資訊]${C_0} $*"; }
ok()   { echo "${C_G}[完成]${C_0} $*"; }
warn() { echo "${C_Y}[警告]${C_0} $*" >&2; }
die()  { echo "${C_R}[錯誤]${C_0} $*" >&2; exit 1; }

usage() {
  sed -n '2,36p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

#------------------------------------------------------------------------------
# 4. 錯誤處理與自動回滾
#------------------------------------------------------------------------------
# 任何指令失敗時，印出失敗的行號與指令，方便除錯
on_err() {
  echo "${C_R}[錯誤]${C_0} 第 $1 行指令失敗：$2" >&2
}
trap 'on_err "$LINENO" "$BASH_COMMAND"' ERR

# 腳本結束時（不論成功或失敗）都會執行；
# 若中途失敗且已更動防火牆，自動回滾，避免留下「半套」設定把人鎖在外面
on_exit() {
  local rc=$?
  if (( rc != 0 && FW_TOUCHED == 1 && FINISHED == 0 )); then
    warn "腳本異常結束（代碼 ${rc}），自動回滾防火牆以避免鎖死..."
    do_rollback
  fi
}
trap on_exit EXIT
trap 'exit 130' INT TERM   # Ctrl-C 也會走 on_exit 流程

# 回滾：關閉 UFW、移除蜜罐出站規則（不會刪除規則檔，可事後檢視）
do_rollback() {
  local ufw_bin
  ufw_bin="$(command -v ufw || true)"
  [[ -n "$ufw_bin" ]] && "$ufw_bin" --force disable >/dev/null 2>&1 || true
  if [[ -x "$EGRESS_BIN" ]]; then
    "$EGRESS_BIN" stop >/dev/null 2>&1 || true
  fi
  systemctl disable honeypot-egress.service >/dev/null 2>&1 || true
  logger -t setup_firewall "防火牆已回滾（UFW 停用、蜜罐出站規則移除）" 2>/dev/null || true
  warn "已回滾：UFW 已停用、蜜罐出站規則已移除。"
  warn "原始設定備份位於 /root/firewall-backup-*/ 目錄。"
}

#------------------------------------------------------------------------------
# 5. 參數解析
#------------------------------------------------------------------------------
for arg in "$@"; do
  case "$arg" in
    --status)      MODE="status" ;;
    --rollback)    MODE="rollback" ;;
    --no-watchdog) WATCHDOG=0 ;;
    -h|--help)     usage; exit 0 ;;
    *)             die "未知參數：$arg（使用 --help 查看說明）" ;;
  esac
done

(( EUID == 0 )) || die "請使用 root 權限執行：sudo $0"

#------------------------------------------------------------------------------
# 6. 狀態顯示
#------------------------------------------------------------------------------
show_status() {
  echo
  echo "================ UFW 防火牆狀態 ================"
  ufw status verbose || true
  echo
  echo "============ DOCKER-USER 鏈（容器流量入口）============"
  iptables -w 5 -nvL DOCKER-USER 2>/dev/null || warn "找不到 DOCKER-USER 鏈（Docker 可能尚未啟動）"
  echo
  echo "============ HONEYPOT-EGRESS 鏈（蜜罐出站/入站過濾）============"
  iptables -w 5 -nvL HONEYPOT-EGRESS 2>/dev/null || warn "HONEYPOT-EGRESS 鏈不存在（規則未啟用）"
  echo
  echo "================ 目前監聽中的 TCP 埠 ================"
  ss -tlnp || true
  echo
  echo "================ 蜜罐出站服務狀態 ================"
  echo "開機自動啟用：$(systemctl is-enabled honeypot-egress.service 2>/dev/null || echo 未安裝)"
  echo "目前運作狀態：$(systemctl is-active honeypot-egress.service 2>/dev/null || echo 未運作)"
  echo
}

if [[ "$MODE" == "status" ]]; then
  show_status
  exit 0
fi

if [[ "$MODE" == "rollback" ]]; then
  do_rollback
  show_status
  exit 0
fi

#------------------------------------------------------------------------------
# 7. 事前檢查（任何一項不過就中止，此時尚未更動任何防火牆設定）
#------------------------------------------------------------------------------
is_tailscale_ip() {
  # Tailscale 的 IPv4 範圍為 100.64.0.0/10，IPv6 為 fd7a:115c:a1e0::/48
  local ip="$1" o
  if [[ "$ip" =~ ^100\.([0-9]+)\. ]]; then
    o="${BASH_REMATCH[1]}"
    if (( o >= 64 && o <= 127 )); then return 0; fi
  elif [[ "${ip,,}" == fd7a:115c:a1e0:* ]]; then
    return 0
  fi
  return 1
}

preflight() {
  info "進行事前檢查..."

  # 7-1. 必要指令；ufw 若不存在則自動安裝（此時尚未封鎖網路，可正常下載）
  if ! command -v ufw >/dev/null 2>&1; then
    info "未安裝 ufw，嘗試自動安裝..."
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ufw
  fi
  local c
  for c in ufw iptables ss ip systemctl; do
    command -v "$c" >/dev/null 2>&1 || die "找不到必要指令：$c"
  done

  # 7-2. 埠號設定不可衝突
  local p
  for p in $HONEYPOT_PORTS; do
    [[ "$p" != "$SSH_ADMIN_PORT" ]] || die "蜜罐埠($p) 與管理 SSH 埠相同，請檢查設定！"
  done

  # 7-3. 【防鎖死】確認真實 sshd 真的在管理埠上監聽
  local out
  out="$(ss -Hltn "sport = :${SSH_ADMIN_PORT}" || true)"
  [[ -n "$out" ]] || die "沒有任何程式在 Port ${SSH_ADMIN_PORT} 監聽！請先確認 sshd 設定，否則啟用防火牆後無法管理。"
  ok "管理 SSH 已在 Port ${SSH_ADMIN_PORT} 監聽"

  # 7-4. 確認 sshd 沒有同時佔用蜜罐埠（真實 sshd 不應暴露在蜜罐埠上）
  for p in $HONEYPOT_PORTS; do
    out="$(ss -Hltnp "sport = :${p}" || true)"
    if [[ "$out" == *sshd* ]]; then
      warn "Port ${p} 上偵測到真實 sshd！蜜罐埠應只由 Cowrie 容器使用，請檢查 sshd_config。"
    fi
  done

  # 7-5. 【防鎖死】確認 Tailscale 網卡存在（否則「僅限 tailscale0」規則等於把自己鎖外面）
  if [[ "$ADMIN_ALLOW_ANYWHERE" != "yes" ]]; then
    ip link show "$TS_IF" >/dev/null 2>&1 \
      || die "找不到網卡 ${TS_IF}！請先啟動 Tailscale（sudo tailscale up），或暫時用 ADMIN_ALLOW_ANYWHERE=yes 執行。"
    systemctl is-active --quiet tailscaled \
      || warn "tailscaled 服務目前未運作，請確認 Tailscale 連線正常。"
    ok "Tailscale 網卡 ${TS_IF} 存在"
  fi

  # 7-6. Docker 狀態（未啟動不阻擋，開機後規則會自動套用）
  if ! systemctl is-active --quiet docker; then
    warn "Docker 目前未運作；蜜罐出站規則會在 Docker 啟動後自動套用。"
  fi
}

#------------------------------------------------------------------------------
# 8. 備份現有設定
#------------------------------------------------------------------------------
backup_current() {
  info "備份現有防火牆設定到 ${BACKUP_DIR} ..."
  mkdir -p "$BACKUP_DIR"
  cp -a /etc/ufw "$BACKUP_DIR/ufw"
  iptables-save  > "$BACKUP_DIR/iptables.rules"  2>/dev/null || true
  ip6tables-save > "$BACKUP_DIR/ip6tables.rules" 2>/dev/null || true
  ufw status verbose > "$BACKUP_DIR/ufw-status.txt" 2>&1 || true
  ok "備份完成"
}

#------------------------------------------------------------------------------
# 9. 設定 UFW（主機本身的入站 / 出站）
#------------------------------------------------------------------------------
# 非必要規則失敗時只警告、不中止
ufw_try() { ufw "$@" >/dev/null 2>&1 || warn "非必要規則設定失敗（已略過）：ufw $*"; }

configure_ufw() {
  info "設定 UFW 規則（此時 UFW 尚未啟用，不會影響現有連線）..."
  FW_TOUCHED=1

  # 清空舊規則（已於步驟 8 備份）。reset 會先停用 UFW。
  ufw --force reset >/dev/null

  # ---- 預設政策：入站、出站全部拒絕（白名單制）----
  ufw default deny incoming  >/dev/null
  ufw default deny outgoing  >/dev/null
  ufw logging low            >/dev/null

  # ---- 本機迴路 ----
  ufw allow in  on lo >/dev/null
  ufw allow out on lo >/dev/null

  # ================= 入站規則 =================
  # (1)【最重要】管理 SSH：成員 A 透過 Tailscale 連線
  if [[ "$ADMIN_ALLOW_ANYWHERE" == "yes" ]]; then
    warn "ADMIN_ALLOW_ANYWHERE=yes：管理 SSH 對所有來源開放（安全性較低）"
    ufw allow in to any port "$SSH_ADMIN_PORT" proto tcp comment 'Admin SSH (any)' >/dev/null
  else
    ufw allow in on "$TS_IF" to any port "$SSH_ADMIN_PORT" proto tcp comment 'Admin SSH via Tailscale' >/dev/null
  fi

  # (2) 蜜罐埠（對外開放）。Docker 發布的埠實際由 DOCKER-USER 控管，
  #     此規則是為了涵蓋「容器使用 host network」的情況，不影響安全。
  local p
  for p in $HONEYPOT_PORTS; do
    ufw allow in to any port "$p" proto tcp comment 'Cowrie honeypot' >/dev/null
  done

  # (3) Streamlit 儀表板：僅限 Tailscale，避免公開暴露蜜罐資料
  ufw allow in on "$TS_IF" to any port "$DASHBOARD_PORT" proto tcp comment 'Streamlit via Tailscale' >/dev/null

  # (4) 目前這條 SSH 連線若不是來自 Tailscale，暫時加白名單，避免把自己踢出去
  local peers peer ip
  peers="$(ss -Htn state established "( sport = :${SSH_ADMIN_PORT} )" | awk '{print $4}' | sort -u || true)"
  if [[ -n "$peers" && "$ADMIN_ALLOW_ANYWHERE" != "yes" ]]; then
    while read -r peer; do
      [[ -n "$peer" ]] || continue
      ip="${peer%:*}"; ip="${ip#[}"; ip="${ip%]}"; ip="${ip#::ffff:}"
      if is_tailscale_ip "$ip"; then
        info "目前管理連線來自 Tailscale（${ip}），無須額外白名單"
      else
        warn "目前管理連線來自非 Tailscale 位址 ${ip}，暫時加入白名單（確認穩定後請手動刪除）"
        ufw allow from "$ip" to any port "$SSH_ADMIN_PORT" proto tcp comment 'TEMP-current-ssh-session' >/dev/null
      fi
    done <<< "$peers"
  fi

  # ================= 出站規則（主機本身）=================
  # 說明：已建立連線的「回應封包」由 UFW 內建的 ESTABLISHED/RELATED 規則自動放行，
  #       下列只需開放「主機主動發起」的必要連線。
  ufw allow out to any port 53  proto udp comment 'DNS'  >/dev/null
  ufw allow out to any port 53  proto tcp comment 'DNS (TCP)' >/dev/null
  ufw allow out to any port 123 proto udp comment 'NTP'  >/dev/null
  ufw allow out to any port 67  proto udp comment 'DHCP client' >/dev/null

  # Tailscale 本身需要對外連線，否則 Tailscale 會斷線，Port 22222 將無法連入！
  ufw allow out to any port 3478 proto udp comment 'Tailscale STUN' >/dev/null
  ufw_try allow out proto udp from any port 41641 to any comment 'Tailscale WireGuard'

  if [[ "$ALLOW_HOST_WEB_OUT" == "yes" ]]; then
    ufw allow out to any port 80,443 proto tcp comment 'HTTP/HTTPS (apt, docker pull, Tailscale)' >/dev/null
  else
    warn "ALLOW_HOST_WEB_OUT=no：Tailscale 控制平面（443）與 apt 可能無法使用！"
  fi

  ok "UFW 規則設定完成（尚未啟用）"
}

#------------------------------------------------------------------------------
# 10. 安裝「蜜罐容器出站過濾」服務（iptables DOCKER-USER 鏈）
#------------------------------------------------------------------------------
install_egress_service() {
  info "安裝蜜罐容器出站過濾（DOCKER-USER）與 systemd 服務..."

  # 10-1. 設定檔（把本腳本的設定值帶進去）
  cat > "$EGRESS_CONF" <<EOF
# 由 setup_firewall.sh 自動產生，請勿手動編輯（重新執行腳本會覆蓋）
TS_IF="${TS_IF}"
HONEYPOT_PORTS="${HONEYPOT_PORTS}"
ALLOW_CONTAINER_DNS_NTP="${ALLOW_CONTAINER_DNS_NTP}"
EOF
  chmod 644 "$EGRESS_CONF"

  # 10-2. 實際套用規則的腳本（以單引號 heredoc 寫入，內容原樣保留）
  cat > "$EGRESS_BIN" <<'EOS'
#!/usr/bin/env bash
# honeypot-egress.sh — 蜜罐容器流量過濾（掛在 DOCKER-USER 鏈）
# 由 systemd 的 honeypot-egress.service 在 Docker 啟動後呼叫
set -euo pipefail
# shellcheck disable=SC1091
source /etc/honeypot-egress.conf

CHAIN="HONEYPOT-EGRESS"
BRIDGES=("docker0" "br-+")          # Docker 預設橋接網卡與自訂網路(br-xxxx)
ipt() { iptables -w 5 "$@"; }       # -w：等待 xtables 鎖，避免與 UFW/Docker 同時寫入衝突

start() {
  # 建立（或清空）自有鏈，確保重複執行結果一致（冪等）
  ipt -N DOCKER-USER 2>/dev/null || true
  ipt -N "$CHAIN" 2>/dev/null || ipt -F "$CHAIN"

  # [1] 既有連線的回應一律放行（蜜罐被連入後的回應封包、RELATED 的 ICMP 錯誤等）
  ipt -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN

  # [2] 同一個橋接網路內的容器互通（Docker 自身的隔離規則仍會在後面生效）
  for b in "${BRIDGES[@]}"; do
    ipt -A "$CHAIN" -i "$b" -o "$b" -j RETURN
  done

  # [3] （選用）容器 DNS / NTP 出站
  if [[ "${ALLOW_CONTAINER_DNS_NTP}" == "yes" ]]; then
    for b in "${BRIDGES[@]}"; do
      ipt -A "$CHAIN" -i "$b" -p udp --dport 53  -j RETURN
      ipt -A "$CHAIN" -i "$b" -p tcp --dport 53  -j RETURN
      ipt -A "$CHAIN" -i "$b" -p udp --dport 123 -j RETURN
    done
  fi

  # [4]【防跳板核心】容器主動發起的其他所有對外連線：記錄後丟棄
  #     LOG 加了頻率限制，避免被攻擊者灌爆日誌；日誌可用於分析攻擊者行為
  for b in "${BRIDGES[@]}"; do
    ipt -A "$CHAIN" -i "$b" -m limit --limit 6/min --limit-burst 10 \
        -j LOG --log-prefix "HONEYPOT-EGRESS-DROP: " --log-level 4
    ipt -A "$CHAIN" -i "$b" -j DROP
  done

  # [5] 從 Tailscale 進入容器發布埠（如 Streamlit 8501）一律允許
  ipt -A "$CHAIN" -i "$TS_IF" -j RETURN

  # [6] 蜜罐埠：允許任何來源連入（以「原始目的埠」比對，因 Docker 已做過 DNAT）
  for port in $HONEYPOT_PORTS; do
    ipt -A "$CHAIN" -p tcp -m conntrack --ctstate DNAT --ctorigdstport "$port" -j RETURN
  done

  # [7] 其他被 Docker 發布的埠（來源非 Tailscale）：擋下，避免 8501 等埠意外對外暴露
  ipt -A "$CHAIN" -m conntrack --ctstate DNAT -m limit --limit 6/min --limit-burst 10 \
      -j LOG --log-prefix "DOCKER-PUBLISHED-BLOCKED: " --log-level 4
  ipt -A "$CHAIN" -m conntrack --ctstate DNAT -j DROP

  # 把自有鏈掛到 DOCKER-USER 最前面（若已掛載則不重複）
  ipt -C DOCKER-USER -j "$CHAIN" 2>/dev/null || ipt -I DOCKER-USER 1 -j "$CHAIN"
}

stop() {
  while ipt -D DOCKER-USER -j "$CHAIN" 2>/dev/null; do :; done
  ipt -F "$CHAIN" 2>/dev/null || true
  ipt -X "$CHAIN" 2>/dev/null || true
}

case "${1:-}" in
  start)   start ;;
  stop)    stop ;;
  restart) stop; start ;;
  status)  ipt -nvL "$CHAIN" ;;
  *) echo "用法：$0 {start|stop|restart|status}" >&2; exit 2 ;;
esac
EOS
  chmod 755 "$EGRESS_BIN"

  # 10-3. systemd 服務：開機且 Docker 啟動後自動套用；Docker 重啟時一併重啟
  cat > "$EGRESS_UNIT" <<'EOS'
[Unit]
Description=Cowrie 蜜罐容器出站過濾 (DOCKER-USER)
After=docker.service network-online.target
Wants=docker.service
PartOf=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/honeypot-egress.sh start
ExecStop=/usr/local/sbin/honeypot-egress.sh stop

[Install]
WantedBy=multi-user.target
EOS
  chmod 644 "$EGRESS_UNIT"
  systemctl daemon-reload
  ok "出站過濾服務已安裝"
}

#------------------------------------------------------------------------------
# 11. 自動回滾看門狗（防鎖死的最後一道保險）
#------------------------------------------------------------------------------
start_watchdog() {
  local ufw_bin
  ufw_bin="$(command -v ufw)"
  rm -f "$CONFIRM_FILE"
  # 以 setsid 脫離目前的 SSH 連線；即使連線被切斷，看門狗仍會繼續執行
  setsid nohup bash -c "
    sleep ${WATCHDOG_SECS}
    if [ ! -f '${CONFIRM_FILE}' ]; then
      '${ufw_bin}' --force disable
      '${EGRESS_BIN}' stop
      logger -t setup_firewall '逾時未確認，已自動回滾防火牆'
    fi
  " >/dev/null 2>&1 < /dev/null &
  info "已啟動自動回滾看門狗：${WATCHDOG_SECS} 秒內未確認，將自動關閉防火牆"
}

#------------------------------------------------------------------------------
# 12. 啟用規則與驗證
#------------------------------------------------------------------------------
enable_firewall() {
  info "啟用 UFW..."
  ufw --force enable >/dev/null
  info "啟用蜜罐容器出站過濾..."
  systemctl enable honeypot-egress.service >/dev/null 2>&1
  systemctl restart honeypot-egress.service
  ok "防火牆已啟用"
}

verify_rules() {
  info "驗證關鍵規則..."
  local st
  st="$(ufw status || true)"
  [[ "$st" == *"Status: active"* ]] || die "驗證失敗：UFW 未處於啟用狀態"
  [[ "$st" == *"${SSH_ADMIN_PORT}"* ]] || die "驗證失敗：找不到 Port ${SSH_ADMIN_PORT} 的放行規則！"
  local out
  out="$(ss -Hltn "sport = :${SSH_ADMIN_PORT}" || true)"
  [[ -n "$out" ]] || die "驗證失敗：Port ${SSH_ADMIN_PORT} 不再監聽！"
  ok "管理 SSH（Port ${SSH_ADMIN_PORT}）規則存在且仍在監聽"

  out="$(iptables -w 5 -S DOCKER-USER 2>/dev/null || true)"
  if [[ "$out" == *"HONEYPOT-EGRESS"* ]]; then
    ok "DOCKER-USER 已掛載蜜罐出站過濾"
  else
    warn "DOCKER-USER 尚未掛載過濾鏈（Docker 未啟動？）。Docker 啟動後會自動套用，或執行：sudo systemctl restart honeypot-egress"
  fi

  # 主機 DNS 連通性測試（僅警告，不中止）
  if timeout 6 getent hosts deb.debian.org >/dev/null 2>&1; then
    ok "主機 DNS 解析正常"
  else
    warn "主機 DNS 解析失敗，請確認網路或 /etc/resolv.conf 的 DNS 伺服器"
  fi
}

#------------------------------------------------------------------------------
# 13. 主流程
#------------------------------------------------------------------------------
main() {
  echo "=============================================================="
  echo "  Cowrie 蜜罐主機：防火牆與防跳板設定"
  echo "  管理 SSH：${SSH_ADMIN_PORT}（${TS_IF}）｜蜜罐：${HONEYPOT_PORTS}｜儀表板：${DASHBOARD_PORT}"
  echo "=============================================================="

  preflight
  backup_current
  configure_ufw
  install_egress_service

  # 沒有互動式終端機就無法讓使用者確認，只好停用看門狗並提醒
  if (( WATCHDOG == 1 )) && [[ ! -t 0 ]]; then
    warn "偵測不到互動式終端機，無法使用確認機制，已停用自動回滾看門狗。"
    WATCHDOG=0
  fi
  (( WATCHDOG == 1 )) && start_watchdog

  enable_firewall
  verify_rules
  show_status

  if (( WATCHDOG == 1 )); then
    echo "=============================================================="
    echo " 【重要】請不要關閉這個視窗！"
    echo "  1. 另外開一個新終端機，測試能否連線："
    echo "       ssh -p ${SSH_ADMIN_PORT} <使用者>@<本機的 Tailscale IP>"
    echo "  2. 確認新連線成功後，回到這裡輸入大寫 OK 並按 Enter。"
    echo "  3. ${WATCHDOG_SECS} 秒內未確認，防火牆會自動關閉（回到未防護但可連線的狀態）。"
    echo "=============================================================="
    local ans=""
    read -r -t "$WATCHDOG_SECS" -p "請輸入 OK 確認：" ans || true
    echo
    if [[ "$ans" == "OK" ]]; then
      local st
      st="$(ufw status || true)"
      if [[ "$st" != *"Status: active"* ]]; then
        FINISHED=1
        die "確認時間已逾時，看門狗已自動回滾。請重新執行腳本。"
      fi
      touch "$CONFIRM_FILE"
      ok "已確認，防火牆設定生效並持續保護中"
    else
      warn "未收到確認（輸入：'${ans}'），立即回滾"
      do_rollback
      FINISHED=1
      exit 1
    fi
  else
    warn "未使用自動回滾機制。若發生無法連線，請用實體螢幕鍵盤執行：sudo $0 --rollback"
  fi

  FINISHED=1

  cat <<EOF

==============================================================
 設定完成！建議立刻做以下驗證：
--------------------------------------------------------------
 1) 蜜罐容器無法主動對外（應該逾時失敗）：
      docker run --rm --network bridge busybox wget -T 3 -O- http://example.com
    若容器使用自訂網路，請改用 docker exec 進入 cowrie 容器測試。
 2) 查看被擋下的出站嘗試（可作為攻擊行為分析素材）：
      sudo journalctl -k | grep -E 'HONEYPOT-EGRESS-DROP|DOCKER-PUBLISHED-BLOCKED'
 3) 外部掃描蜜罐埠應可連上；${DASHBOARD_PORT} 只有 Tailscale 內可連。
 4) 日後查看狀態：sudo $0 --status
 5) 緊急回滾：    sudo $0 --rollback
 6) 若有「TEMP-current-ssh-session」暫時規則，確認穩定後請刪除：
      sudo ufw status numbered   →   sudo ufw delete <編號>
 備份位置：${BACKUP_DIR}
==============================================================
EOF
}

main
