#!/usr/bin/env bash
#==============================================================================
#  verify_isolation.sh
#  Cowrie 蜜罐「防跳板 / 出站隔離」一鍵驗證腳本
#
#  【測試內容】
#   第 1 章  主機本身：Ping、TCP 直連、curl 抓網頁
#   第 2 章  蜜罐容器：Ping、wget 抓網頁、從 Cowrie 容器內直連（最貼近真實攻擊情境）
#   第 3 章  DNS / NTP：確認被放行的必要服務仍正常
#   第 4 章  防火牆規則：UFW、DOCKER-USER、DROP 計數器、服務狀態
#
#  【判定原則】
#   「預期被阻斷」的測試：連不上 = PASS；連得上 = FAIL（隔離失效！）
#   為避免「網路本身壞掉」造成誤判，腳本會先用 DNS 當對照組，
#   對照組失敗時，被阻斷的項目會標示 WARN（無法判定）而非 PASS。
#
#  【用法】
#     sudo ./verify_isolation.sh                  # 執行全部測試
#     sudo ./verify_isolation.sh --save           # 同時存成純文字報告檔
#     sudo ./verify_isolation.sh --container NAME # 指定蜜罐容器名稱（預設 cowrie）
#     sudo ./verify_isolation.sh --no-color       # 關閉彩色（亦支援 NO_COLOR 環境變數）
#
#  【環境變數】
#     COWRIE_CONTAINER  蜜罐容器名稱（預設 cowrie，找不到會自動搜尋含 cowrie 的容器）
#     HELPER_IMAGE      測試用輔助映像（預設 busybox:latest）
#     SSH_ADMIN_PORT    管理 SSH 埠（預設 22222）
#
#  注意：本腳本「不使用 set -e」，因為「測試失敗」本來就是正常的預期結果，
#        由腳本自行統計 PASS/FAIL 並以結束碼回報（全數無 FAIL 為 0，否則為 1）。
#==============================================================================
set -uo pipefail

#------------------------------------------------------------------------------
# 1. 設定與參數
#------------------------------------------------------------------------------
COWRIE_CONTAINER="${COWRIE_CONTAINER:-cowrie}"
HELPER_IMAGE="${HELPER_IMAGE:-busybox:latest}"
SSH_ADMIN_PORT="${SSH_ADMIN_PORT:-22222}"
HONEYPOT_PORTS="22"
ALLOW_CONTAINER_DNS_NTP="no"

# 讀取 setup_firewall.sh 產生的設定檔，使本腳本與實際設定一致
if [[ -r /etc/honeypot-egress.conf ]]; then
  # shellcheck disable=SC1091
  source /etc/honeypot-egress.conf
fi

SAVE=0
USE_COLOR=1
[[ -t 1 && -z "${NO_COLOR:-}" ]] || USE_COLOR=0

while (( $# > 0 )); do
  case "$1" in
    --save)      SAVE=1 ;;
    --no-color)  USE_COLOR=0 ;;
    --container) shift; COWRIE_CONTAINER="${1:-cowrie}" ;;
    -h|--help)   sed -n '2,32p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "未知參數：$1（使用 --help 查看說明）" >&2; exit 2 ;;
  esac
  shift
done

if (( EUID != 0 )); then
  echo "請使用 root 權限執行（需讀取防火牆規則）：sudo $0" >&2
  exit 2
fi

# --save：同時把畫面輸出存成「去除顏色碼」的純文字檔
REPORT_FILE=""
if (( SAVE == 1 )); then
  REPORT_FILE="./isolation_report_$(date +%Y%m%d_%H%M%S).txt"
  exec > >(tee >(sed -u 's/\x1b\[[0-9;]*[A-Za-z]//g' > "$REPORT_FILE")) 2>&1
fi

#------------------------------------------------------------------------------
# 2. 顏色與版面
#------------------------------------------------------------------------------
if (( USE_COLOR == 1 )); then
  C0=$'\e[0m'; BOLD=$'\e[1m'; DIM=$'\e[2m'
  G=$'\e[32m'; R=$'\e[31m'; Y=$'\e[33m'; B=$'\e[36m'; GR=$'\e[90m'
  BG_G=$'\e[1;97;42m'; BG_R=$'\e[1;97;41m'; BG_Y=$'\e[1;30;43m'
  BG_B=$'\e[1;97;44m'; BG_S=$'\e[1;97;100m'
else
  C0=""; BOLD=""; DIM=""; G=""; R=""; Y=""; B=""; GR=""
  BG_G=""; BG_R=""; BG_Y=""; BG_B=""; BG_S=""
fi

PASS=0; FAIL=0; WARN=0; SKIP=0; INFO=0
IS_TTY=0; [[ -t 1 ]] && IS_TTY=1

hr()  { printf '%s' "$B"; printf '═%.0s' $(seq 1 64); printf '%s\n' "$C0"; }
hr2() { printf '%s' "$GR"; printf '─%.0s' $(seq 1 64); printf '%s\n' "$C0"; }

section() {
  echo
  printf '%s%s %s%s\n' "$BOLD" "$B" "$1" "$C0"
  hr2
}

# 顯示「測試中」提示（只在互動終端機，結果出來後會被覆蓋，截圖更乾淨）
progress() {
  (( IS_TTY == 1 )) && printf '\r\033[K  %s… 測試中：%s%s' "$GR" "$1" "$C0"
  return 0
}
clear_progress() {
  (( IS_TTY == 1 )) && printf '\r\033[K'
  return 0
}

badge() {
  case "$1" in
    PASS) printf '%s PASS %s' "$BG_G" "$C0" ;;
    FAIL) printf '%s FAIL %s' "$BG_R" "$C0" ;;
    WARN) printf '%s WARN %s' "$BG_Y" "$C0" ;;
    INFO) printf '%s INFO %s' "$BG_B" "$C0" ;;
    SKIP) printf '%s SKIP %s' "$BG_S" "$C0" ;;
  esac
}

# result 狀態 編號 標題 預期 實際
result() {
  local st="$1" id="$2" title="$3" exp="$4" act="$5"
  clear_progress
  case "$st" in
    PASS) PASS=$((PASS+1)) ;;
    FAIL) FAIL=$((FAIL+1)) ;;
    WARN) WARN=$((WARN+1)) ;;
    INFO) INFO=$((INFO+1)) ;;
    SKIP) SKIP=$((SKIP+1)) ;;
  esac
  printf ' %s %s%s%s  %s\n' "$(badge "$st")" "$BOLD" "$id" "$C0" "$title"
  printf '        %s預期：%s  │  實際：%s%s\n' "$GR" "$exp" "$act" "$C0"
}

#------------------------------------------------------------------------------
# 3. 探測函式（回傳 0 = 成功連到外部；非 0 = 連不到）
#------------------------------------------------------------------------------
# --- 主機端 ---
probe_host_ping() { timeout 6 ping -c 1 -W 3 8.8.8.8 >/dev/null 2>&1; }

probe_host_tcp853() {
  # 853 是 DNS-over-TLS，Google/Cloudflare 都穩定開放；
  # 但不在我們的出站白名單內，所以「主機」連線應被擋下
  timeout 4 bash -c 'exec 3<>/dev/tcp/8.8.8.8/853' >/dev/null 2>&1 \
    || timeout 4 bash -c 'exec 3<>/dev/tcp/1.1.1.1/853' >/dev/null 2>&1
}

probe_host_web() {
  # 1.1.1.1/cdn-cgi/trace 會直接回傳純文字（含 ip=...），不涉及 DNS 與轉址，判斷最準確
  local o
  o="$(timeout 8 curl -m 6 -fsS http://1.1.1.1/cdn-cgi/trace 2>/dev/null)"
  [[ "$o" == *ip=* ]]
}

# --- 容器端 ---
helper() { timeout 30 docker run --rm --pull=never --network "$CNET" "$HELPER_IMAGE" "$@"; }
probe_c_ping() { helper ping -c 1 -W 3 8.8.8.8 >/dev/null 2>&1; }
probe_c_wget() {
  local o
  o="$(helper wget -q -T 5 -O - http://1.1.1.1/cdn-cgi/trace 2>/dev/null)"
  [[ "$o" == *ip=* ]]
}
probe_cowrie_tcp() {
  docker exec "$CNAME" python3 -c \
    "import socket; s=socket.socket(); s.settimeout(4); s.connect(('1.1.1.1',443))" >/dev/null 2>&1
}

# expect_blocked 編號 標題 探測函式 [探測參數...]
# 預期「連不上」。連上 = FAIL；連不上且對照組正常 = PASS；對照組異常 = WARN
expect_blocked() {
  local id="$1" title="$2"; shift 2
  progress "$id $title"
  if "$@"; then
    result FAIL "$id" "$title" "被阻斷" "竟然連得出去！隔離失效"
  elif (( NET_OK == 1 )); then
    result PASS "$id" "$title" "被阻斷" "無法連線（已阻斷）"
  else
    result WARN "$id" "$title" "被阻斷" "連不上，但網路對照組也失敗，無法判定"
  fi
}

# DROP 規則的封包計數（僅統計蜜罐橋接網卡的出站 DROP 規則）
drop_counter() {
  iptables -w 5 -nvxL HONEYPOT-EGRESS 2>/dev/null \
    | awk '$3=="DROP" && ($6=="docker0" || $6=="br-+") {s+=$1} END{print s+0}'
}

#------------------------------------------------------------------------------
# 4. 報告標頭
#------------------------------------------------------------------------------
UFW_STATUS="$(ufw status verbose 2>&1 || true)"
WEB_ALLOWED=0
grep -Eq '80,443/tcp.*ALLOW OUT' <<<"$UFW_STATUS" && WEB_ALLOWED=1

(( IS_TTY == 1 )) && clear 2>/dev/null
echo
hr
printf '%s%s   🛡  Cowrie 蜜罐 ‧ 防跳板隔離驗證報告%s\n' "$BOLD" "$B" "$C0"
hr
printf '  %s時間%s    %s\n'   "$GR" "$C0" "$(date '+%Y-%m-%d %H:%M:%S %Z')"
printf '  %s主機%s    %s（%s）\n' "$GR" "$C0" "$(hostname)" "$(uname -m)"
printf '  %s核心%s    %s\n'   "$GR" "$C0" "$(uname -r)"
printf '  %s管理 SSH%s %s（僅限 Tailscale）｜蜜罐埠：%s\n' "$GR" "$C0" "$SSH_ADMIN_PORT" "$HONEYPOT_PORTS"
if (( WEB_ALLOWED == 1 )); then
  printf '  %s主機 80/443%s 白名單：開啟（apt / Tailscale 需要）\n' "$GR" "$C0"
else
  printf '  %s主機 80/443%s 白名單：關閉\n' "$GR" "$C0"
fi

#------------------------------------------------------------------------------
# 5. 對照組：確認「網路本身」是通的（透過被放行的 DNS 路徑）
#------------------------------------------------------------------------------
NET_OK=0
if timeout 6 getent hosts deb.debian.org >/dev/null 2>&1; then NET_OK=1; fi

#------------------------------------------------------------------------------
# 6. 第 1 章：主機本身
#------------------------------------------------------------------------------
section "【1】主機本身的出站限制（Host Egress）"

if command -v ping >/dev/null 2>&1; then
  expect_blocked "1.1" "主機 Ping 外部 IP 8.8.8.8" probe_host_ping
else
  result SKIP "1.1" "主機 Ping 外部 IP 8.8.8.8" "被阻斷" "系統未安裝 ping（apt install iputils-ping）"
fi

expect_blocked "1.2" "主機 TCP 直連 8.8.8.8:853（非白名單埠）" probe_host_tcp853

if command -v curl >/dev/null 2>&1; then
  if (( WEB_ALLOWED == 1 )); then
    progress "1.3 主機 curl 外部網頁"
    if probe_host_web; then
      result INFO "1.3" "主機 curl 外部網頁 http://1.1.1.1" "放行（白名單，供 apt/Tailscale）" "可連線，符合設計"
    else
      result WARN "1.3" "主機 curl 外部網頁 http://1.1.1.1" "放行（白名單，供 apt/Tailscale）" "白名單已開卻連不上，請檢查網路"
    fi
  else
    expect_blocked "1.3" "主機 curl 外部網頁 http://1.1.1.1" probe_host_web
  fi
else
  result SKIP "1.3" "主機 curl 外部網頁" "—" "系統未安裝 curl"
fi

#------------------------------------------------------------------------------
# 7. 第 2 章：蜜罐容器（防跳板核心）
#------------------------------------------------------------------------------
section "【2】蜜罐容器的出站限制（防跳板核心）"

CNAME=""; CNET=""; C_READY=0; C_HELPER=0; C_PY=0
COUNTER_BEFORE=0; COUNTER_AFTER=0

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  result SKIP "2.x" "蜜罐容器測試" "—" "Docker 未安裝或未運作"
else
  # 找出蜜罐容器：先找指定名稱，找不到再搜尋映像或名稱含 cowrie 的運作中容器
  if [[ "$(docker inspect -f '{{.State.Running}}' "$COWRIE_CONTAINER" 2>/dev/null)" == "true" ]]; then
    CNAME="$COWRIE_CONTAINER"
  else
    CNAME="$(docker ps --format '{{.Names}} {{.Image}}' | awk 'tolower($0) ~ /cowrie/ {print $1; exit}')"
  fi

  if [[ -z "$CNAME" ]]; then
    result SKIP "2.x" "蜜罐容器測試" "—" "找不到運作中的 Cowrie 容器（可用 --container 指定）"
  else
    NETMODE="$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$CNAME" 2>/dev/null)"
    CNET="$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{"\n"}}{{end}}' "$CNAME" 2>/dev/null | head -n1)"
    printf '  %s容器%s %s｜網路：%s%s\n' "$GR" "$C0" "$CNAME" "${CNET:-?}" ""
    echo

    if [[ "$NETMODE" == "host" || -z "$CNET" || "$CNET" == "host" ]]; then
      result WARN "2.0" "容器網路模式" "bridge（可被 DOCKER-USER 過濾）" "容器使用 host 網路，DOCKER-USER 規則不適用，請改用 bridge 網路！"
    else
      C_READY=1
      # 準備輔助映像（不主動從網路拉取以免干擾；本機沒有時才嘗試 pull 一次）
      if docker image inspect "$HELPER_IMAGE" >/dev/null 2>&1; then
        C_HELPER=1
      else
        progress "取得測試用映像 $HELPER_IMAGE"
        timeout 90 docker pull -q "$HELPER_IMAGE" >/dev/null 2>&1 && C_HELPER=1
        clear_progress
      fi
      docker exec "$CNAME" python3 -c 'pass' >/dev/null 2>&1 && C_PY=1
    fi

    if (( C_READY == 1 )); then
      COUNTER_BEFORE="$(drop_counter)"

      if (( C_HELPER == 1 )); then
        expect_blocked "2.1" "容器 Ping 外部 IP 8.8.8.8" probe_c_ping
        expect_blocked "2.2" "容器 wget 外部網頁 http://1.1.1.1" probe_c_wget
      else
        result SKIP "2.1" "容器 Ping 外部 IP 8.8.8.8" "被阻斷" "缺少 ${HELPER_IMAGE}（可先 docker pull 後重跑）"
        result SKIP "2.2" "容器 wget 外部網頁" "被阻斷" "缺少 ${HELPER_IMAGE}（可先 docker pull 後重跑）"
      fi

      if (( C_PY == 1 )); then
        expect_blocked "2.3" "Cowrie 容器內直連 1.1.1.1:443（模擬攻擊者跳板）" probe_cowrie_tcp
      else
        result SKIP "2.3" "Cowrie 容器內直連 1.1.1.1:443" "被阻斷" "容器內找不到 python3"
      fi

      COUNTER_AFTER="$(drop_counter)"
    fi
  fi
fi

#------------------------------------------------------------------------------
# 8. 第 3 章：DNS / NTP（必要服務應正常）
#------------------------------------------------------------------------------
section "【3】內部 DNS 與 NTP（被放行的必要服務應正常運作）"

NS_LIST="$(awk '/^nameserver/ {printf "%s ", $2}' /etc/resolv.conf 2>/dev/null)"
result INFO "3.0" "目前使用的 DNS 伺服器" "—" "${NS_LIST:-（未偵測到）}"

for d in deb.debian.org example.com; do
  progress "3.x DNS 解析 $d"
  ip="$(timeout 6 getent ahostsv4 "$d" 2>/dev/null | awk 'NR==1{print $1}')"
  if [[ -n "$ip" ]]; then
    case "$d" in
      deb.debian.org) id="3.1" ;;
      *)              id="3.2" ;;
    esac
    result PASS "$id" "DNS 解析 $d" "可正常解析" "$ip"
  else
    case "$d" in
      deb.debian.org) id="3.1" ;;
      *)              id="3.2" ;;
    esac
    result FAIL "$id" "DNS 解析 $d" "可正常解析" "解析失敗（檢查 UFW 是否放行 53/udp）"
  fi
done

if command -v timedatectl >/dev/null 2>&1; then
  sync="$(timedatectl show -p NTPSynchronized --value 2>/dev/null)"
  if [[ "$sync" == "yes" ]]; then
    result PASS "3.3" "NTP 時間同步" "已同步" "NTPSynchronized=yes"
  else
    result WARN "3.3" "NTP 時間同步" "已同步" "尚未同步（剛開機可能需數分鐘；請確認 123/udp 已放行）"
  fi
else
  result SKIP "3.3" "NTP 時間同步" "—" "找不到 timedatectl"
fi

if [[ "$ALLOW_CONTAINER_DNS_NTP" == "yes" ]]; then
  result INFO "3.4" "容器 DNS/NTP 出站" "—" "已開啟（ALLOW_CONTAINER_DNS_NTP=yes），請留意 DNS 外傳風險"
else
  result INFO "3.4" "容器 DNS/NTP 出站" "—" "已關閉（預設最嚴格，容器無法解析外部網域）"
fi

#------------------------------------------------------------------------------
# 9. 第 4 章：防火牆規則狀態
#------------------------------------------------------------------------------
section "【4】防火牆規則清單與狀態檢查"

if grep -q '^Status: active' <<<"$UFW_STATUS"; then
  result PASS "4.1" "UFW 防火牆" "啟用中" "Status: active"
else
  result FAIL "4.1" "UFW 防火牆" "啟用中" "未啟用！"
fi

DEFLINE="$(grep -i '^Default:' <<<"$UFW_STATUS")"
if grep -Eq 'deny \(incoming\)' <<<"$DEFLINE"; then
  result PASS "4.2" "預設入站政策" "deny（拒絕）" "deny (incoming)"
else
  result FAIL "4.2" "預設入站政策" "deny（拒絕）" "${DEFLINE:-無法讀取}"
fi
if grep -Eq 'deny \(outgoing\)' <<<"$DEFLINE"; then
  result PASS "4.3" "預設出站政策（防跳板）" "deny（拒絕）" "deny (outgoing)"
else
  result FAIL "4.3" "預設出站政策（防跳板）" "deny（拒絕）" "${DEFLINE:-無法讀取}"
fi

if grep -Eq "^${SSH_ADMIN_PORT}/tcp.*ALLOW IN" <<<"$UFW_STATUS"; then
  result PASS "4.4" "管理 SSH 放行規則（Port ${SSH_ADMIN_PORT}）" "存在" "已放行"
else
  result FAIL "4.4" "管理 SSH 放行規則（Port ${SSH_ADMIN_PORT}）" "存在" "找不到！可能造成鎖死"
fi

SSHD_LISTEN="$(ss -Hltn "sport = :${SSH_ADMIN_PORT}" 2>/dev/null)"
if [[ -n "$SSHD_LISTEN" ]]; then
  result PASS "4.5" "管理 SSH 監聽狀態" "Port ${SSH_ADMIN_PORT} 監聽中" "監聽中"
else
  result FAIL "4.5" "管理 SSH 監聽狀態" "Port ${SSH_ADMIN_PORT} 監聽中" "沒有程式在監聽"
fi

HP_OK=1
for p in $HONEYPOT_PORTS; do
  [[ -n "$(ss -Hltn "sport = :${p}" 2>/dev/null)" ]] || HP_OK=0
done
if (( HP_OK == 1 )); then
  result PASS "4.6" "蜜罐埠（${HONEYPOT_PORTS}）監聽狀態" "監聽中（誘捕用）" "監聽中"
else
  result WARN "4.6" "蜜罐埠（${HONEYPOT_PORTS}）監聽狀態" "監聽中（誘捕用）" "未監聽，請確認 Cowrie 容器已啟動並發布埠"
fi

if iptables -w 5 -S DOCKER-USER 2>/dev/null | grep -q 'HONEYPOT-EGRESS'; then
  result PASS "4.7" "DOCKER-USER 已掛載蜜罐出站過濾鏈" "已掛載" "HONEYPOT-EGRESS 生效中"
else
  result FAIL "4.7" "DOCKER-USER 已掛載蜜罐出站過濾鏈" "已掛載" "未掛載（sudo systemctl restart honeypot-egress）"
fi

SVC_EN="$(systemctl is-enabled honeypot-egress.service 2>/dev/null || true)"
if [[ "$SVC_EN" == "enabled" ]]; then
  result PASS "4.8" "重開機後自動套用（honeypot-egress.service）" "enabled" "enabled"
else
  result WARN "4.8" "重開機後自動套用（honeypot-egress.service）" "enabled" "${SVC_EN:-未安裝}"
fi

if (( C_READY == 1 )); then
  DELTA=$(( COUNTER_AFTER - COUNTER_BEFORE ))
  if (( DELTA > 0 )); then
    result PASS "4.9" "DROP 計數器（證據）" "測試期間封包數增加" "+${DELTA} 個封包被 DROP 規則攔截"
  else
    result WARN "4.9" "DROP 計數器（證據）" "測試期間封包數增加" "計數無增加（容器測試被略過或規則未命中）"
  fi
else
  result SKIP "4.9" "DROP 計數器（證據）" "測試期間封包數增加" "未執行容器測試"
fi

echo
printf '%s%s  ▌UFW 規則清單%s\n' "$BOLD" "$B" "$C0"
ufw status numbered 2>&1 | sed 's/^/    /'

echo
printf '%s%s  ▌HONEYPOT-EGRESS 鏈（容器流量過濾，含封包計數）%s\n' "$BOLD" "$B" "$C0"
if iptables -w 5 -nvL HONEYPOT-EGRESS --line-numbers >/dev/null 2>&1; then
  iptables -w 5 -nvL HONEYPOT-EGRESS --line-numbers 2>&1 | sed 's/^/    /'
else
  echo "    （鏈不存在）"
fi

#------------------------------------------------------------------------------
# 10. 總結
#------------------------------------------------------------------------------
TOTAL=$(( PASS + FAIL + WARN + SKIP ))
echo
hr
printf '%s%s   📋 測試總結%s\n' "$BOLD" "$B" "$C0"
hr
printf '   %s✔ 通過 PASS%s : %s%d%s\n'  "$G" "$C0" "$BOLD" "$PASS" "$C0"
printf '   %s✘ 失敗 FAIL%s : %s%d%s\n'  "$R" "$C0" "$BOLD" "$FAIL" "$C0"
printf '   %s⚠ 警告 WARN%s : %s%d%s\n'  "$Y" "$C0" "$BOLD" "$WARN" "$C0"
printf '   %s⏭ 略過 SKIP%s : %s%d%s\n'  "$GR" "$C0" "$BOLD" "$SKIP" "$C0"
printf '   %s共計 %d 項（另有 %d 項資訊 INFO）%s\n' "$GR" "$TOTAL" "$INFO" "$C0"
hr2

if (( FAIL > 0 )); then
  printf '   %s%s ✘ 結論：發現隔離缺口，請依上方 FAIL 項目修正後重測 %s\n' "$BG_R" "$BOLD" "$C0"
  RC=1
elif (( WARN > 0 || SKIP > 0 )); then
  printf '   %s%s ⚠ 結論：未發現缺口，但有項目無法完整驗證（見 WARN/SKIP）%s\n' "$BG_Y" "$BOLD" "$C0"
  RC=0
else
  printf '   %s%s ✔ 結論：隔離措施全數生效，蜜罐無法被當作跳板 %s\n' "$BG_G" "$BOLD" "$C0"
  RC=0
fi
hr

if [[ -n "$REPORT_FILE" ]]; then
  printf '  %s純文字報告已儲存：%s%s\n' "$GR" "$REPORT_FILE" "$C0"
  sleep 0.5   # 等待 tee/sed 把內容寫入檔案
fi
echo
exit "$RC"
