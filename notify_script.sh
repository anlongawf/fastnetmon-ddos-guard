#!/usr/bin/env bash
# =============================================================================
# FastNetMon DDoS Guard - Notify Script
# Version: 3.0
# Mô tả: Tích hợp FastNetMon notify_script_path. Tự động phân tích traffic
#         dump, trích xuất destination port, chặn/mở port ở tầng kernel
#         (iptables raw PREROUTING), gọi Pterodactyl API, bắn Discord Webhook.
#
# Thay đổi v3.0:
#   - Bỏ hardcode port range → ước đoán loại game qua Pterodactyl egg/name
#   - Thay Telegram → Discord Webhook (embed message đẹp hơn)
#
# Cách FastNetMon gọi:
#   ./notify_script.sh <IP> <DIRECTION> <ban|unban> <PROTOCOL>
#   Stdin: traffic dump text (FastNetMon tự pipe vào)
# =============================================================================

set -euo pipefail

# =============================================================================
# SECTION 1: CẤU HÌNH - Chỉnh sửa theo môi trường của bạn
# =============================================================================

# --- Discord Webhook ---
# Tạo webhook: Server Settings → Integrations → Webhooks → New Webhook
DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN"

# --- Pterodactyl API (Mặc định tắt, chỉ bật khi muốn tự động suspend server) ---
PTERO_ENABLED=false
PTERO_PANEL_URL="https://panel.yourdomain.com"   # Không có dấu / cuối
PTERO_API_KEY="ptla_YOUR_APPLICATION_API_KEY"    # Admin > Application API
PTERO_ACTION="suspend"                            # "suspend" hoặc "kill"

# --- Đường dẫn file ---
BLOCKED_PORTS_FILE="${BLOCKED_PORTS_FILE:-/var/lib/fastnetmon_guard/blocked_ports.db}"
LOG_FILE="${LOG_FILE:-/var/log/fastnetmon_guard/guard.log}"
DUMP_CACHE_DIR="${DUMP_CACHE_DIR:-/tmp/fastnetmon_dump_cache}"

# --- Cấu hình iptables ---
IPTABLES_CHAIN="${IPTABLES_CHAIN:-FNM_DDOS_GUARD}"
IPTABLES_TABLE="${IPTABLES_TABLE:-raw}"
IPT_CMD="${IPT_CMD:-$(command -v iptables 2>/dev/null || echo /sbin/iptables)}"

# --- Thời gian ban mặc định (giây) ---
DEFAULT_BAN_DURATION="${DEFAULT_BAN_DURATION:-900}"   # 15 phút

# --- File cấu hình bên ngoài (nếu có, sẽ ghi đè các cấu hình bên dưới) ---
GUARD_CONF="${GUARD_CONF:-/etc/fastnetmon_guard/guard.conf}"
if [[ -f "$GUARD_CONF" ]]; then
    # shellcheck source=/dev/null
    source "$GUARD_CONF"
fi

# --- Danh sách Port hệ thống cốt tử - KHÔNG BAO GIỜ ĐƯỢC CHẶN (Chống khóa ngoài Self-Lockout) ---
# 22 (SSH), 80/443 (Web/SSL), 8080 (Wings API), 2022 (Wings SFTP), 53 (DNS), 3306 (MySQL)
PROTECTED_PORTS=(22 80 443 8080 2022 53 3306 5432 6379 27017)

# --- Discord embed colors (decimal) ---
COLOR_BAN=15158332     # Đỏ  #E74C3C
COLOR_UNBAN=3066993    # Xanh lá #2ECC71
COLOR_WARN=16776960    # Vàng #FFFF00

# =============================================================================
# SECTION 2: LOGGING
# =============================================================================

mkdir -p "$(dirname "$BLOCKED_PORTS_FILE")" 2>/dev/null || true
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
mkdir -p "$DUMP_CACHE_DIR" 2>/dev/null || true

log() {
    local level="$1"; shift
    local msg="$*"
    local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
    local log_dir; log_dir="$(dirname "$LOG_FILE")"
    if [[ -w "$LOG_FILE" || ( -d "$log_dir" && -w "$log_dir" ) ]]; then
        echo "[$ts] [$level] $msg" >> "$LOG_FILE" 2>/dev/null || true
    fi
    echo "[$ts] [$level] $msg" >&2
    logger -t "fnm_guard" -p "daemon.${level}" "$msg" 2>/dev/null || true
}

# =============================================================================
# SECTION 3: IPTABLES CHAIN
# =============================================================================

init_iptables_chain() {
    if ! "$IPT_CMD" -t "$IPTABLES_TABLE" -L "$IPTABLES_CHAIN" -n &>/dev/null; then
        "$IPT_CMD" -t "$IPTABLES_TABLE" -N "$IPTABLES_CHAIN"
        log "info" "Tạo chain: $IPTABLES_CHAIN trong bảng $IPTABLES_TABLE"
    fi
    if ! "$IPT_CMD" -t "$IPTABLES_TABLE" -C PREROUTING -j "$IPTABLES_CHAIN" 2>/dev/null; then
        "$IPT_CMD" -t "$IPTABLES_TABLE" -I PREROUTING 1 -j "$IPTABLES_CHAIN"
        log "info" "Gắn $IPTABLES_CHAIN vào PREROUTING (vị trí 1)"
    fi
}

# =============================================================================
# SECTION 4: ĐỌC VÀ PHÂN TÍCH DUMP TRAFFIC
# =============================================================================

read_stdin_dump() {
    local target_ip="$1"
    local cache_file="$DUMP_CACHE_DIR/dump_${target_ip}_$(date +%s).txt"

    # Đảm bảo thư mục cache ghi được, nếu không fallback về /tmp
    if [[ ! -w "$DUMP_CACHE_DIR" ]]; then
        cache_file="/tmp/dump_${target_ip}_$(date +%s).txt"
    fi

    # Chỉ đọc stdin nếu có dữ liệu được pipe vào (không phải terminal tương tác)
    if [[ ! -t 0 ]]; then
        if command -v timeout &>/dev/null; then
            if timeout 3 cat > "$cache_file" 2>/dev/null && [[ -s "$cache_file" ]]; then
                echo "$cache_file"; return 0
            fi
        else
            if cat > "$cache_file" 2>/dev/null && [[ -s "$cache_file" ]]; then
                echo "$cache_file"; return 0
            fi
        fi
    fi

    local fnm_dump="/tmp/fastnetmon_${target_ip}.dump"
    [[ -f "$fnm_dump" ]] && cp "$fnm_dump" "$cache_file" 2>/dev/null && echo "$cache_file" && return 0

    echo ""
}

# Trích xuất top destination port từ dump
# Hỗ trợ nhiều format output của FastNetMon Community:
#   "dst port: 30120 packets: 850000"
#   "Src: 1.2.3.4:11111 -> Dst: 203.0.113.10:30120 (UDP)"
#   {"destination_port": 30120}
extract_top_dst_port() {
    local dump_file="$1"
    [[ -z "$dump_file" || ! -f "$dump_file" ]] && { log "warn" "Không có dump file"; echo ""; return 0; }

    local top_port=""

    # Method 1: Trích xuất chính xác số port đi liền sau từ khóa port
    top_port=$(sed -nE 's/.*(dst port|destination port|(udp|tcp)[[:space:]]+port)[[:space:]]*:?[[:space:]]*([0-9]{1,5}).*/\3/ip' "$dump_file" 2>/dev/null | head -1 || true)
    if [[ -n "$top_port" && "$top_port" =~ ^[0-9]+$ && "$top_port" -ge 1 && "$top_port" -le 65535 ]]; then
        log "info" "Port (method 1 - top ports): $top_port"
        echo "$top_port"
        return 0
    fi

    # Method 2: Packet lines "-> Dst: IP:PORT" - lấy port phổ biến nhất
    top_port=$(grep -oE '(->|Dst:)[[:space:]]*[0-9.]+:([0-9]{4,5})' "$dump_file" 2>/dev/null \
        | grep -oE '[0-9]{4,5}$' \
        | sort | uniq -c | sort -rn \
        | awk 'NR==1{print $2}' || true)
    [[ -n "$top_port" ]] && { log "info" "Port (method 2 - packet lines): $top_port"; echo "$top_port"; return 0; }

    # Method 3: JSON format
    top_port=$(grep -oE '"destination_port"[[:space:]]*:[[:space:]]*([0-9]+)' "$dump_file" 2>/dev/null \
        | grep -oE '[0-9]+$' | head -1 || true)
    [[ -n "$top_port" ]] && { log "info" "Port (method 3 - JSON): $top_port"; echo "$top_port"; return 0; }

    # Method 4: Fallback - port phổ biến nhất trong toàn dump (loại trừ port thông thường 80, 443, 22)
    top_port=$(grep -oE ':[0-9]{4,5}' "$dump_file" 2>/dev/null \
        | tr -d ':' \
        | grep -vE '^(80|443|22|21|23|53|8080|8443)$' \
        | sort | uniq -c | sort -rn \
        | awk 'NR==1{print $2}' || true)
    log "warn" "Port (method 4 - fallback frequency): $top_port"
    echo "$top_port"
}

extract_traffic_stats() {
    local dump_file="$1"
    [[ -z "$dump_file" || ! -f "$dump_file" ]] && { echo "N/A"; return 0; }

    local pps mbps
    pps=$(grep -iE "(pps|packets per second)" "$dump_file" 2>/dev/null \
        | grep -oE '[0-9]+[[:space:]]*(pps|packets)' \
        | grep -oE '^[0-9]+' \
        | sort -rn | head -1 || true)
    mbps=$(grep -iE "(mbps|gbps|bandwidth)" "$dump_file" 2>/dev/null \
        | grep -oE '[0-9]+[[:space:]]*(mbps|gbps)' \
        | head -1 || true)

    local result="${pps:+${pps} PPS}"
    [[ -n "$mbps" ]] && result="${result:+$result / }${mbps}"
    echo "${result:-N/A}"
}

# =============================================================================
# SECTION 5: PTERODACTYL API - Tìm game type và thông tin server
# =============================================================================

# Lấy toàn bộ danh sách server từ Pterodactyl (có cache 60 giây)
_PTERO_CACHE_FILE="$DUMP_CACHE_DIR/ptero_servers_cache.json"
_PTERO_CACHE_TS=0

get_ptero_servers() {
    [[ "$PTERO_ENABLED" != "true" ]] && { echo "{}"; return; }
    [[ "$PTERO_API_KEY" == *"YOUR_APPLICATION_API_KEY"* || "$PTERO_PANEL_URL" == *"yourdomain"* ]] && { echo "{}"; return; }

    local now; now=$(date +%s)
    local age=$(( now - _PTERO_CACHE_TS ))

    # Dùng cache nếu còn mới dưới 60 giây
    if [[ -f "$_PTERO_CACHE_FILE" && $age -lt 60 ]]; then
        cat "$_PTERO_CACHE_FILE"
        return
    fi

    local resp http_code body
    resp=$(curl -s -w "\n%{http_code}" \
        -H "Authorization: Bearer $PTERO_API_KEY" \
        -H "Accept: application/json" \
        "$PTERO_PANEL_URL/api/application/servers?per_page=200&include=allocations" \
        --connect-timeout 8 --max-time 15 2>/dev/null || echo -e "\n000")

    http_code=$(echo "$resp" | tail -1)
    body=$(echo "$resp" | head -n -1)

    if [[ "$http_code" == "200" ]]; then
        echo "$body" > "$_PTERO_CACHE_FILE"
        _PTERO_CACHE_TS=$now
        echo "$body"
    else
        log "error" "Pterodactyl API lỗi: HTTP $http_code"
        # Trả về cache cũ nếu có
        [[ -f "$_PTERO_CACHE_FILE" ]] && cat "$_PTERO_CACHE_FILE" || echo "{}"
    fi
}

# Tìm server theo port → trả về JSON object {id, name, egg_name, owner}
find_ptero_server_info_by_port() {
    local port="$1"
    [[ "$PTERO_ENABLED" != "true" ]] && { echo "{}"; return; }
    [[ ! "$port" =~ ^[0-9]+$ ]] && { echo "{}"; return; }

    log "info" "Tìm Pterodactyl server cho port $port..."

    local servers_json
    servers_json=$(get_ptero_servers)
    [[ -z "$servers_json" || "$servers_json" == "{}" ]] && { echo "{}"; return; }

    # Tìm server có allocation port khớp, lấy thêm: id, name, egg.name, user.email
    local server_info
    server_info=$(echo "$servers_json" | jq -c --arg p "$port" '
        .data[]?
        | select(
            any(.attributes.relationships.allocations.data[]?.attributes.port?; . == ($p | tonumber))
        )
        | {
            id:       .attributes.id,
            uuid:     .attributes.uuid,
            name:     .attributes.name,
            egg_id:   .attributes.egg,
            user_id:  .attributes.user,
            port:     ($p | tonumber)
          }
    ' 2>/dev/null | head -1 || echo "{}")

    if [[ -z "$server_info" || "$server_info" == "null" || "$server_info" == "{}" ]]; then
        log "warn" "Không tìm thấy server Pterodactyl cho port $port"
        echo "{}"
        return
    fi

    log "info" "Tìm thấy server: $server_info"
    echo "$server_info"
}

# Ước đoán loại game từ egg ID hoặc tên server (vì port là random)
# Pterodactyl egg IDs phổ biến:
#   Minecraft Java    = egg id 1  (hoặc theo tên egg)
#   Minecraft Bedrock = egg id 14
#   FiveM/GTA         = egg id 15 hoặc tên chứa "fivem"/"gta"
#   Rust              = egg id 4
detect_game_from_server_info() {
    local server_info="$1"
    local egg_id name

    egg_id=$(echo "$server_info" | jq -r '.egg_id // ""' 2>/dev/null || echo "")
    name=$(echo "$server_info" | jq -r '.name // ""' 2>/dev/null | tr '[:upper:]' '[:lower:]' || echo "")

    # Ưu tiên match tên server (do egg ID có thể khác nhau tùy panel)
    if echo "$name" | grep -qiE "(fivem|gta|five m|five-m|ragemp|altv)"; then
        echo "🚗 GTA FiveM"
    elif echo "$name" | grep -qiE "(minecraft|mc |bedrock|java|paper|spigot|bungeecord|velocity)"; then
        echo "⛏️ Minecraft"
    elif echo "$name" | grep -qiE "(samp|sa-mp|san andreas|openmp|open.mp)"; then
        echo "🔫 SA-MP"
    elif echo "$name" | grep -qiE "(the isle|the_isle|theisle|evrima)"; then
        echo "🦖 The Isle"
    elif echo "$name" | grep -qiE "(rust|oxide)"; then
        echo "🔫 Rust"
    elif echo "$name" | grep -qiE "(ark|asa)"; then
        echo "🦕 ARK"
    elif echo "$name" | grep -qiE "(cs2|csgo|counter.strike|valheim|terraria|palworld)"; then
        echo "🎯 CS2/Other"
    # Fallback theo egg_id nếu tên không match
    elif [[ "$egg_id" == "1" || "$egg_id" == "2" || "$egg_id" == "14" ]]; then
        echo "⛏️ Minecraft"
    elif [[ "$egg_id" == "15" || "$egg_id" == "16" ]]; then
        echo "🚗 GTA FiveM"
    elif [[ "$egg_id" == "4" ]]; then
        echo "🔫 Rust"
    else
        echo "🎮 Game Server"
    fi
}

# Thực hiện action (suspend/unsuspend/kill) trên server
ptero_do_action() {
    local server_id="$1" action="$2"
    [[ -z "$server_id" || "$server_id" == "null" || "$PTERO_ENABLED" != "true" ]] && return
    [[ "$PTERO_API_KEY" == *"YOUR_APPLICATION_API_KEY"* || "$PTERO_PANEL_URL" == *"yourdomain"* ]] && return

    local url http_code
    case "$action" in
        suspend)   url="$PTERO_PANEL_URL/api/application/servers/$server_id/suspend" ;;
        unsuspend) url="$PTERO_PANEL_URL/api/application/servers/$server_id/unsuspend" ;;
        kill)      url="$PTERO_PANEL_URL/api/client/servers/$server_id/power" ;;
        *)         log "error" "Action không hợp lệ: $action"; return ;;
    esac

    if [[ "$action" == "kill" ]]; then
        http_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
            -H "Authorization: Bearer $PTERO_API_KEY" \
            -H "Content-Type: application/json" \
            -d '{"signal":"kill"}' "$url" \
            --connect-timeout 8 --max-time 15 2>/dev/null)
    else
        http_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
            -H "Authorization: Bearer $PTERO_API_KEY" \
            -H "Content-Type: application/json" "$url" \
            --connect-timeout 8 --max-time 15 2>/dev/null)
    fi

    if [[ "$http_code" =~ ^(200|202|204)$ ]]; then
        log "info" "Pterodactyl $action server $server_id: OK (HTTP $http_code)"
    else
        log "error" "Pterodactyl $action server $server_id: FAIL (HTTP $http_code)"
    fi
}

# =============================================================================
# SECTION 6: CHẶN / MỞ PORT BẰNG IPTABLES RAW
# =============================================================================

is_protected_port() {
    local check_port="$1"
    [[ ! "$check_port" =~ ^[0-9]+$ ]] && return 1
    for p in "${PROTECTED_PORTS[@]}"; do
        if [[ "$check_port" -eq "$p" ]] 2>/dev/null; then
            return 0
        fi
    done
    return 1
}

db_lock() {
    local lock_dir; lock_dir="$(dirname "$BLOCKED_PORTS_FILE")"
    if [[ ! -d "$lock_dir" || ! -w "$lock_dir" ]]; then
        return 0
    fi
    if ! command -v flock &>/dev/null; then
        return 0
    fi
    local lockfile="${BLOCKED_PORTS_FILE}.lock"
    exec 200>"$lockfile" 2>/dev/null || return 0
    flock -x -w 5 200 2>/dev/null || log "warn" "Không lấy được DB lock, tiếp tục xử lý..."
}

db_unlock() {
    if command -v flock &>/dev/null; then
        flock -u 200 2>/dev/null || true
    fi
    exec 200>&- 2>/dev/null || true
}

block_port() {
    local port="$1" proto="${2:-udp}" target_ip="$3"

    # Xử lý riêng cho giao thức ICMP
    if [[ "$port" == "icmp" || "$proto" == "icmp" ]]; then
        log "info" "Chặn giao thức ICMP (IP: $target_ip)"
        init_iptables_chain

        if ! "$IPT_CMD" -t "$IPTABLES_TABLE" -C "$IPTABLES_CHAIN" \
                -p icmp -d "$target_ip" -j DROP 2>/dev/null; then
            "$IPT_CMD" -t "$IPTABLES_TABLE" -A "$IPTABLES_CHAIN" \
                -p icmp -d "$target_ip" -j DROP
            log "info" "DROP rule ICMP thêm: -p icmp -d $target_ip"
        else
            log "info" "DROP rule ICMP đã tồn tại: -p icmp -d $target_ip"
        fi

        local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
        local unban_ts
        unban_ts=$(date -d "+${DEFAULT_BAN_DURATION} seconds" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date -v "+${DEFAULT_BAN_DURATION}S" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "N/A")

        db_lock
        if [[ -f "$BLOCKED_PORTS_FILE" && -w "$BLOCKED_PORTS_FILE" ]]; then
            local tmp; tmp=$(mktemp 2>/dev/null || echo "/tmp/fnm_block_$$")
            grep -v "^icmp|${target_ip}|" "$BLOCKED_PORTS_FILE" > "$tmp" 2>/dev/null || true
            mv "$tmp" "$BLOCKED_PORTS_FILE" 2>/dev/null || true
            rm -f "$tmp" 2>/dev/null || true
        fi
        local db_dir; db_dir="$(dirname "$BLOCKED_PORTS_FILE")"
        if [[ -w "$BLOCKED_PORTS_FILE" || ( -d "$db_dir" && -w "$db_dir" ) ]]; then
            echo "icmp|$target_ip|icmp|$ts|$unban_ts|blocked" >> "$BLOCKED_PORTS_FILE" 2>/dev/null || true
        fi
        db_unlock

        # Tích hợp XDP eBPF Map: Thêm rule drop ICMP
        local xdp_mgr="/opt/fastnetmon_guard/compile_xdp.sh"
        [[ ! -f "$xdp_mgr" && -f "$(dirname "${BASH_SOURCE[0]}")/compile_xdp.sh" ]] && xdp_mgr="$(dirname "${BASH_SOURCE[0]}")/compile_xdp.sh"
        if [[ -f "$xdp_mgr" ]]; then
            bash "$xdp_mgr" block "$target_ip" 0 icmp 2>/dev/null || true
        fi

        log "info" "Ghi DB: port=icmp IP=$target_ip blocked_at=$ts"
        return 0
    fi

    # Kiểm tra an toàn giá trị port
    if [[ ! "$port" =~ ^[0-9]+$ || "$port" -lt 1 || "$port" -gt 65535 ]]; then
        log "error" "Port không hợp lệ: $port. Bỏ qua block."
        return 1
    fi

    # Không bao giờ chặn cổng hệ thống
    if is_protected_port "$port"; then
        log "warn" "Bảo vệ cổng hệ thống: $port nằm trong PROTECTED_PORTS. Bỏ qua block!"
        return 0
    fi

    log "info" "Chặn port $port/$proto (IP: $target_ip)"
    init_iptables_chain

    for p in udp tcp; do
        if ! "$IPT_CMD" -t "$IPTABLES_TABLE" -C "$IPTABLES_CHAIN" \
                -p "$p" --dport "$port" -d "$target_ip" -j DROP 2>/dev/null; then
            "$IPT_CMD" -t "$IPTABLES_TABLE" -A "$IPTABLES_CHAIN" \
                -p "$p" --dport "$port" -d "$target_ip" -j DROP
            log "info" "DROP rule thêm: -p $p --dport $port -d $target_ip"
        else
            log "info" "DROP rule đã tồn tại: -p $p --dport $port -d $target_ip"
        fi
    done

    local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
    local unban_ts
    unban_ts=$(date -d "+${DEFAULT_BAN_DURATION} seconds" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date -v "+${DEFAULT_BAN_DURATION}S" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "N/A")

    db_lock
    if [[ -f "$BLOCKED_PORTS_FILE" && -w "$BLOCKED_PORTS_FILE" ]]; then
        local tmp; tmp=$(mktemp 2>/dev/null || echo "/tmp/fnm_block_$$")
        grep -v "^${port}|${target_ip}|" "$BLOCKED_PORTS_FILE" > "$tmp" 2>/dev/null || true
        mv "$tmp" "$BLOCKED_PORTS_FILE" 2>/dev/null || true
        rm -f "$tmp" 2>/dev/null || true
    fi
    local db_dir; db_dir="$(dirname "$BLOCKED_PORTS_FILE")"
    if [[ -w "$BLOCKED_PORTS_FILE" || ( -d "$db_dir" && -w "$db_dir" ) ]]; then
        echo "$port|$target_ip|$proto|$ts|$unban_ts|blocked" >> "$BLOCKED_PORTS_FILE" 2>/dev/null || true
    fi
    db_unlock

    # Tích hợp XDP eBPF Map: Thêm rule drop siêu tốc nếu XDP engine được kích hoạt
    local xdp_mgr="/opt/fastnetmon_guard/compile_xdp.sh"
    [[ ! -f "$xdp_mgr" && -f "$(dirname "${BASH_SOURCE[0]}")/compile_xdp.sh" ]] && xdp_mgr="$(dirname "${BASH_SOURCE[0]}")/compile_xdp.sh"
    if [[ -f "$xdp_mgr" ]]; then
        bash "$xdp_mgr" block "$target_ip" "$port" "$proto" 2>/dev/null || true
    fi

    log "info" "Ghi DB: port=$port IP=$target_ip blocked_at=$ts"
}

unblock_port() {
    local port="$1" target_ip="$2"

    if [[ "$port" == "icmp" ]]; then
        log "info" "Mở lại giao thức ICMP (IP: $target_ip)"
        while "$IPT_CMD" -t "$IPTABLES_TABLE" -C "$IPTABLES_CHAIN" \
                -p icmp -d "$target_ip" -j DROP 2>/dev/null; do
            "$IPT_CMD" -t "$IPTABLES_TABLE" -D "$IPTABLES_CHAIN" \
                -p icmp -d "$target_ip" -j DROP 2>/dev/null || break
            log "info" "Xóa DROP rule ICMP: -d $target_ip"
        done
    elif [[ "$port" =~ ^[0-9]+$ ]]; then
        log "info" "Mở port $port (IP: $target_ip)"
        for p in udp tcp; do
            local max_retries=5
            while "$IPT_CMD" -t "$IPTABLES_TABLE" -C "$IPTABLES_CHAIN" \
                    -p "$p" --dport "$port" -d "$target_ip" -j DROP 2>/dev/null; do
                "$IPT_CMD" -t "$IPTABLES_TABLE" -D "$IPTABLES_CHAIN" \
                    -p "$p" --dport "$port" -d "$target_ip" -j DROP 2>/dev/null || break
                log "info" "Xóa DROP rule: -p $p --dport $port -d $target_ip"
                ((max_retries--)) || break
                [[ $max_retries -le 0 ]] && break
            done
        done
    else
        log "error" "Port unblock không hợp lệ: $port"
        return 1
    fi

    # Tích hợp XDP eBPF Map: Gỡ bỏ rule drop trong XDP Map
    local xdp_mgr="/opt/fastnetmon_guard/compile_xdp.sh"
    [[ ! -f "$xdp_mgr" && -f "$(dirname "${BASH_SOURCE[0]}")/compile_xdp.sh" ]] && xdp_mgr="$(dirname "${BASH_SOURCE[0]}")/compile_xdp.sh"
    if [[ -f "$xdp_mgr" ]]; then
        bash "$xdp_mgr" unblock "$target_ip" "$port" 2>/dev/null || true
    fi

    db_lock
    if [[ -f "$BLOCKED_PORTS_FILE" && -w "$BLOCKED_PORTS_FILE" ]]; then
        local tmp; tmp=$(mktemp 2>/dev/null || echo "/tmp/fnm_unblock_$$")
        grep -v "^${port}|${target_ip}|" "$BLOCKED_PORTS_FILE" > "$tmp" 2>/dev/null || true
        mv "$tmp" "$BLOCKED_PORTS_FILE" 2>/dev/null || true
        rm -f "$tmp" 2>/dev/null || true
    fi
    db_unlock
}

# =============================================================================
# SECTION 7: DISCORD WEBHOOK
# =============================================================================

# Gửi Discord embed message
# $1: title, $2: description, $3: color (decimal), $4+: fields JSON array string
send_discord_embed() {
    local title="$1"
    local description="$2"
    local color="$3"
    local fields_json="${4:-[]}"

    if [[ -z "$DISCORD_WEBHOOK_URL" || "$DISCORD_WEBHOOK_URL" == *"YOUR_ID"* || "$DISCORD_WEBHOOK_URL" != http* ]]; then
        log "warn" "Discord Webhook chưa cấu hình hoặc URL không hợp lệ"
        return
    fi

    local ts_iso; ts_iso=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

    # Build JSON payload (Discord Embed format)
    local payload
    payload=$(jq -n \
        --arg title "$title" \
        --arg desc "$description" \
        --argjson color "$color" \
        --argjson fields "$fields_json" \
        --arg ts "$ts_iso" \
        '{
            "username": "DDoS Guard",
            "avatar_url": "https://i.imgur.com/4M34hi2.png",
            "embeds": [{
                "title": $title,
                "description": $desc,
                "color": $color,
                "fields": $fields,
                "footer": {
                    "text": "FastNetMon DDoS Guard • Pterodactyl Wings"
                },
                "timestamp": $ts
            }]
        }')

    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "$DISCORD_WEBHOOK_URL" \
        -H "Content-Type: application/json" \
        -d "$payload" \
        --connect-timeout 10 --max-time 20 2>/dev/null)

    if [[ "$http_code" == "204" || "$http_code" == "200" ]]; then
        log "info" "Discord webhook gửi thành công (HTTP $http_code)"
    else
        log "error" "Discord webhook thất bại: HTTP $http_code"
    fi
}

# Thông báo BAN
send_discord_ban() {
    local ip="$1" port="$2" proto="$3" game="$4" stats="$5"
    local server_name="${6:-N/A}" server_id="${7:-N/A}"
    local ban_min=$(( DEFAULT_BAN_DURATION / 60 ))
    local unban_ts; unban_ts=$(date -d "+${DEFAULT_BAN_DURATION} seconds" '+%H:%M:%S' 2>/dev/null || date -v "+${DEFAULT_BAN_DURATION}S" '+%H:%M:%S' 2>/dev/null || date '+%H:%M:%S')

    local ptero_fields='[]'
    if [[ "$server_id" != "N/A" && "$server_id" != "" ]]; then
        ptero_fields=$(jq -n \
            --arg name "$server_name" \
            --arg sid "$server_id" \
            --arg action "$PTERO_ACTION" \
            '[
                {"name": "🎮 Server Name",      "value": $name,   "inline": true},
                {"name": "🆔 Pterodactyl ID",   "value": $sid,    "inline": true},
                {"name": "⚡ Action",            "value": $action, "inline": true}
            ]')
    fi

    local port_display="$port/$proto"
    if [[ "$port" == "icmp" || "$proto" == "icmp" ]]; then
        port_display="ICMP (Toàn bộ)"
    fi

    local fields
    fields=$(jq -n \
        --arg ip "$ip" \
        --arg port "$port_display" \
        --arg game "$game" \
        --arg stats "$stats" \
        --arg duration "${ban_min} phút (đến ${unban_ts})" \
        --argjson ptero "$ptero_fields" \
        '[
            {"name": "📌 IP bị tấn công",  "value": ("`" + $ip + "`"),   "inline": true},
            {"name": "🔒 Port bị khóa",    "value": ("`" + $port + "`"), "inline": true},
            {"name": "🎯 Loại game",        "value": $game,               "inline": true},
            {"name": "📊 Traffic",          "value": $stats,              "inline": true},
            {"name": "⏳ Thời gian cách ly","value": $duration,           "inline": true},
            {"name": "🛡️ Tầng chặn",       "value": "`iptables raw PREROUTING`", "inline": true}
        ] + $ptero')

    send_discord_embed \
        "🚨 CẢNH BÁO DDOS PHÁT HIỆN!" \
        "Server game đang bị tấn công. Port đã được **tự động cách ly** tại tầng kernel.\n✅ Các server khác trên node **KHÔNG bị ảnh hưởng**." \
        "$COLOR_BAN" \
        "$fields"
}

# Thông báo UNBAN
send_discord_unban() {
    local ip="$1" port="$2" game="$3"
    local server_name="${4:-N/A}" server_id="${5:-N/A}"

    local fields
    fields=$(jq -n \
        --arg ip "$ip" \
        --arg port "$port" \
        --arg game "$game" \
        --arg name "$server_name" \
        --arg sid "$server_id" \
        '[
            {"name": "📌 IP",             "value": ("`" + $ip + "`"),   "inline": true},
            {"name": "🔓 Port mở lại",    "value": ("`" + $port + "`"), "inline": true},
            {"name": "🎯 Loại game",      "value": $game,               "inline": true},
            {"name": "🎮 Server Name",    "value": $name,               "inline": true},
            {"name": "🆔 Pterodactyl ID", "value": $sid,                "inline": true}
        ]')

    send_discord_embed \
        "✅ PORT ĐÃ ĐƯỢC MỞ LẠI" \
        "Server game đã hoạt động bình thường trở lại." \
        "$COLOR_UNBAN" \
        "$fields"
}

# Thông báo cảnh báo (khi không xác định được port)
send_discord_warn() {
    local ip="$1" msg="$2"

    local fields
    fields=$(jq -n \
        --arg ip "$ip" \
        --arg msg "$msg" \
        '[
            {"name": "📌 IP",       "value": ("`" + $ip + "`"), "inline": true},
            {"name": "⚠️ Chi tiết", "value": $msg,              "inline": false}
        ]')

    send_discord_embed \
        "⚠️ CẢNH BÁO - CẦN KIỂM TRA THỦ CÔNG" \
        "FastNetMon phát hiện bất thường nhưng không tự xử lý được." \
        "$COLOR_WARN" \
        "$fields"
}

# =============================================================================
# SECTION 8: HANDLER CHÍNH
# =============================================================================

handle_ban() {
    local target_ip="$1" direction="$2" protocol="${3:-udp}"

    log "info" "=== BAN EVENT: IP=$target_ip DIR=$direction PROTO=$protocol ==="

    # Đọc dump từ stdin
    local dump_file
    dump_file=$(read_stdin_dump "$target_ip")

    # Trích xuất port từ dump
    local blocked_port
    blocked_port=$(extract_top_dst_port "$dump_file")

    # Fallback: một số phiên bản FastNetMon đặt env var
    [[ -z "$blocked_port" ]] && blocked_port="${FASTNETMON_ATTACK_DETAILS_PORT:-}"

    # Hỗ trợ nhận diện tấn công ICMP flood (không có destination port)
    local proto_clean; proto_clean=$(echo "$protocol" | tr '[:upper:]' '[:lower:]')
    if [[ -z "$blocked_port" ]]; then
        if [[ "$proto_clean" == "icmp" ]] || grep -qiE "(icmp|ping flood)" "$dump_file" 2>/dev/null; then
            blocked_port="icmp"
            protocol="icmp"
            log "info" "Phát hiện tấn công ICMP flood (không có port) -> Cách ly giao thức ICMP"
        fi
    fi

    if [[ -z "$blocked_port" ]]; then
        log "error" "Không xác định được destination port! Abort."
        send_discord_warn "$target_ip" "Không trích xuất được destination port từ dump.\nCần kiểm tra và xử lý thủ công!"
        return 0
    fi

    # Kiểm tra tính hợp lệ của port (chấp nhận "icmp" hoặc số port 1-65535)
    if [[ "$blocked_port" != "icmp" && ( ! "$blocked_port" =~ ^[0-9]+$ || "$blocked_port" -lt 1 || "$blocked_port" -gt 65535 ) ]]; then
        log "error" "Giá trị port không hợp lệ ($blocked_port)! Abort."
        send_discord_warn "$target_ip" "Giá trị port trích xuất không hợp lệ: \`$blocked_port\`.\nCần kiểm tra thủ công!"
        return 0
    fi

    # Bảo vệ chống khóa ngoài (Anti-Lockout Protection): Tuyệt đối không ngắt port SSH/Web/Wings
    if [[ "$blocked_port" != "icmp" ]] && is_protected_port "$blocked_port"; then
        log "warn" "CẢNH BÁO: Phát hiện tấn công vào port hệ thống cốt tử $blocked_port (SSH/Web/Panel). TỪ CHỐI DROP!"
        send_discord_warn "$target_ip" "🚨 **CẢNH BÁO NGUY HIỂM:** Phát hiện tấn công vào Cổng Cốt Tử \`$blocked_port\` (SSH/Web/Wings).\n🛡️ Hệ thống **TỪ CHỐI ngắt port** để tránh làm mất quyền điều khiển máy chủ!\n👉 Vui lòng liên hệ nhà mạng hoặc kích hoạt Anti-DDoS tầng Network."
        return 0
    fi

    # Lấy thống kê traffic
    local stats; stats=$(extract_traffic_stats "$dump_file")
    log "info" "Port tấn công: $blocked_port | Stats: $stats"

    # Chặn port ở tầng kernel
    block_port "$blocked_port" "$protocol" "$target_ip"

    # Tìm thông tin server Pterodactyl (lấy cả tên server và loại game từ egg/name)
    local server_info server_id server_name game_type
    server_info=$(find_ptero_server_info_by_port "$blocked_port")
    server_id=$(echo "$server_info" | jq -r '.id // ""' 2>/dev/null)
    server_name=$(echo "$server_info" | jq -r '.name // "N/A"' 2>/dev/null)
    game_type=$(detect_game_from_server_info "$server_info")
    if [[ "$blocked_port" == "icmp" && ( -z "$server_id" || "$server_id" == "null" ) ]]; then
        game_type="🌐 Network (ICMP Flood)"
    fi

    log "info" "Game: $game_type | Server: $server_name (ID: ${server_id:-N/A})"

    # Thực hiện action Pterodactyl nếu tìm thấy server
    if [[ -n "$server_id" && "$server_id" != "null" ]]; then
        ptero_do_action "$server_id" "$PTERO_ACTION"
    fi

    # Bắn Discord alert
    send_discord_ban "$target_ip" "$blocked_port" "$protocol" \
        "$game_type" "$stats" "$server_name" "${server_id:-N/A}"

    # Dọn cache dump cũ hơn 1 giờ
    find "$DUMP_CACHE_DIR" -name "dump_*.txt" -type f -mmin +60 -delete 2>/dev/null || true

    log "info" "=== BAN HOÀN TẤT: port $blocked_port ==="
}

handle_unban() {
    local target_ip="$1"

    log "info" "=== UNBAN EVENT: IP=$target_ip ==="

    local all_ports_to_unblock=()

    # 1. Thu thập port từ file Database (nếu file tồn tại)
    if [[ -f "$BLOCKED_PORTS_FILE" ]]; then
        while IFS= read -r p; do
            [[ -n "$p" ]] && all_ports_to_unblock+=("$p")
        done < <(grep "^[^|]*|${target_ip}|" "$BLOCKED_PORTS_FILE" 2>/dev/null | cut -d'|' -f1 | sort -u)
    fi

    # 2. Kernel Fallback: Quét trực tiếp bảng iptables để tìm các rule DROP đang gán cho IP này
    # Đảm bảo KHÔNG BAO GIỜ bị kẹt rule kể cả khi file DB bị xóa, mất hoặc server vừa reboot
    if "$IPT_CMD" -t "$IPTABLES_TABLE" -L "$IPTABLES_CHAIN" -n &>/dev/null; then
        while IFS= read -r ipt_port; do
            if [[ -n "$ipt_port" ]]; then
                local exists=false
                if [[ ${#all_ports_to_unblock[@]} -gt 0 ]]; then
                    for existing in "${all_ports_to_unblock[@]}"; do
                        [[ "$existing" == "$ipt_port" ]] && { exists=true; break; }
                    done
                fi
                if [[ "$exists" == "false" ]]; then
                    all_ports_to_unblock+=("$ipt_port")
                    log "info" "Kernel Fallback: Phát hiện rule sót trong iptables cho port $ipt_port (IP: $target_ip)"
                fi
            fi
        done < <("$IPT_CMD" -t "$IPTABLES_TABLE" -S "$IPTABLES_CHAIN" 2>/dev/null \
            | grep -E "\-d[[:space:]]+${target_ip}(/32)?" \
            | grep -oE "\-\-dport[[:space:]]+[0-9]+" \
            | awk '{print $2}' | sort -u || true)

        # Kiểm tra xem có rule ICMP DROP nào của IP này không
        if "$IPT_CMD" -t "$IPTABLES_TABLE" -S "$IPTABLES_CHAIN" 2>/dev/null \
                | grep -qE "\-p[[:space:]]+icmp[[:space:]]+.*\-d[[:space:]]+${target_ip}"; then
            all_ports_to_unblock+=("icmp")
        fi

        # Dọn sạch rule drop cả IP (nếu có tồn tại)
        while "$IPT_CMD" -t "$IPTABLES_TABLE" -C "$IPTABLES_CHAIN" -d "$target_ip" -j DROP 2>/dev/null; do
            "$IPT_CMD" -t "$IPTABLES_TABLE" -D "$IPTABLES_CHAIN" -d "$target_ip" -j DROP 2>/dev/null || break
            log "info" "Xóa rule DROP IP toàn bộ: -d $target_ip"
        done

        # Dọn sạch rule drop cả IP trong XDP Map (nếu có)
        local xdp_mgr="/opt/fastnetmon_guard/compile_xdp.sh"
        [[ ! -f "$xdp_mgr" && -f "$(dirname "${BASH_SOURCE[0]}")/compile_xdp.sh" ]] && xdp_mgr="$(dirname "${BASH_SOURCE[0]}")/compile_xdp.sh"
        if [[ -f "$xdp_mgr" ]]; then
            bash "$xdp_mgr" unblock "$target_ip" 0 2>/dev/null || true
        fi
    fi

    if [[ ${#all_ports_to_unblock[@]} -eq 0 ]]; then
        log "warn" "Không có port hoặc rule nào cần unban cho IP $target_ip"
        return 0
    fi

    for port in "${all_ports_to_unblock[@]}"; do
        [[ -z "$port" ]] && continue

        # Tìm lại thông tin server để unsuspend và notify (nếu bật Pterodactyl)
        local server_info server_id server_name game_type
        server_info=$(find_ptero_server_info_by_port "$port")
        server_id=$(echo "$server_info" | jq -r '.id // ""' 2>/dev/null)
        server_name=$(echo "$server_info" | jq -r '.name // "N/A"' 2>/dev/null)
        game_type=$(detect_game_from_server_info "$server_info")

        unblock_port "$port" "$target_ip"

        # Unsuspend Pterodactyl server (nếu bật)
        if [[ -n "$server_id" && "$server_id" != "null" && "$PTERO_ENABLED" == "true" ]]; then
            ptero_do_action "$server_id" "unsuspend"
        fi

        send_discord_unban "$target_ip" "$port" "$game_type" "$server_name" "${server_id:-N/A}"

        log "info" "=== UNBAN HOÀN TẤT: port $port (IP: $target_ip) ==="
    done

    # Xóa cache Pterodactyl để force refresh lần sau
    rm -f "$_PTERO_CACHE_FILE" 2>/dev/null || true
}

# =============================================================================
# SECTION 9: ENTRY POINT
# =============================================================================

main() {
    if [[ $# -lt 3 ]]; then
        log "error" "Cách dùng: $0 <IP> <DIRECTION> <ban|unban> [PROTOCOL]"
        exit 1
    fi

    local target_ip="$1" direction="$2" event_type="$3" protocol="${4:-udp}"

    if ! echo "$target_ip" | grep -qE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; then
        log "error" "IP không hợp lệ: $target_ip"
        exit 1
    fi

    log "info" "Script called: IP=$target_ip DIR=$direction EVENT=$event_type PROTO=$protocol"

    local event_clean; event_clean=$(echo "$event_type" | tr '[:upper:]' '[:lower:]')
    case "$event_clean" in
        ban)   handle_ban   "$target_ip" "$direction" "$protocol" ;;
        unban) handle_unban "$target_ip" ;;
        *)     log "warn" "Event không xác định: $event_type"; exit 0 ;;
    esac
}

main "$@"
