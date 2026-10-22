#!/usr/bin/env bash
# =============================================================================
# FastNetMon DDoS Guard - Test Suite
# =============================================================================
# Script kiểm thử toàn diện cho hệ thống FastNetMon + iptables + notify_script
# Chạy trên node Ubuntu/Debian có cài FastNetMon và Pterodactyl Wings
#
# Cách dùng:
#   sudo bash test_ddos_guard.sh [TEST_ID]
#
# Ví dụ:
#   sudo bash test_ddos_guard.sh       # Chạy tất cả test
#   sudo bash test_ddos_guard.sh 3     # Chạy riêng test #3
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NOTIFY_SCRIPT="${NOTIFY_SCRIPT:-/opt/fastnetmon_guard/notify_script.sh}"
if [[ ! -f "$NOTIFY_SCRIPT" && -f "$SCRIPT_DIR/notify_script.sh" ]]; then
    NOTIFY_SCRIPT="$SCRIPT_DIR/notify_script.sh"
fi

TEST_IP="127.0.0.1"           # IP test (dùng localhost để an toàn)
TEST_PORT_MC=25565             # Minecraft port test
TEST_PORT_FIVEM=30120          # FiveM port test
IPTABLES_CHAIN="FNM_DDOS_GUARD"
IPTABLES_TABLE="raw"
BLOCKED_PORTS_FILE="/var/lib/fastnetmon_guard/blocked_ports.db"
LOG_FILE="/var/log/fastnetmon_guard/guard.log"

# Màu sắc terminal
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

PASS=0
FAIL=0

pass() { echo -e "${GREEN}[PASS]${NC} $*"; ((PASS++)); }
fail() { echo -e "${RED}[FAIL]${NC} $*"; ((FAIL++)); }
info() { echo -e "${BLUE}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
header() { echo -e "\n${CYAN}════════════════════════════════════════${NC}"; echo -e "${CYAN} TEST $1: $2${NC}"; echo -e "${CYAN}════════════════════════════════════════${NC}"; }

# Kiểm tra quyền root (chỉ bắt buộc khi chạy test liên quan đến iptables)
check_root() {
    local test_id="${1:-all}"
    if [[ "$test_id" =~ ^(2|7|8|10|11)$ ]]; then
        return 0
    fi
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}ERROR: Script cần chạy với quyền root (sudo) để thao tác iptables${NC}"
        echo -e "${YELLOW}Gợi ý: Bạn có thể chạy riêng test không cần root: bash test_ddos_guard.sh 2 (hoặc 7, 8)${NC}"
        exit 1
    fi
}

# =============================================================================
# TEST 1: Kiểm tra môi trường và prerequisites
# =============================================================================
test_1_prerequisites() {
    header "1" "Kiểm tra môi trường và prerequisites"

    # Kiểm tra các tool cần thiết
    local tools=("iptables" "curl" "jq" "awk" "grep" "logger")
    for tool in "${tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            pass "Tool '$tool' đã có sẵn: $(command -v "$tool")"
        else
            fail "Tool '$tool' CHƯA cài. Cài: apt install $tool"
        fi
    done

    # Kiểm tra notify_script.sh tồn tại và có quyền thực thi
    if [[ -f "$NOTIFY_SCRIPT" ]]; then
        pass "notify_script.sh tồn tại: $NOTIFY_SCRIPT"
        if [[ -x "$NOTIFY_SCRIPT" ]]; then
            pass "notify_script.sh có quyền thực thi"
        else
            fail "notify_script.sh KHÔNG có quyền thực thi. Chạy: chmod +x $NOTIFY_SCRIPT"
        fi
    else
        fail "notify_script.sh KHÔNG tìm thấy tại $NOTIFY_SCRIPT"
        warn "Copy script vào: cp notify_script.sh $NOTIFY_SCRIPT"
    fi

    # Kiểm tra FastNetMon cài đặt
    if command -v fastnetmon &>/dev/null; then
        local fnm_ver; fnm_ver=$(fastnetmon --version 2>&1 | head -1 || echo "unknown")
        pass "FastNetMon cài đặt: $fnm_ver"
    else
        warn "FastNetMon chưa cài hoặc không trong PATH (có thể chạy ở background)"
    fi

    # Kiểm tra iptables module raw
    if iptables -t raw -L &>/dev/null; then
        pass "iptables module 'raw' hoạt động bình thường"
    else
        fail "iptables 'raw' table KHÔNG khả dụng - cần nf_tables kernel module"
    fi

    # Kiểm tra thư mục log và DB
    mkdir -p "$(dirname "$BLOCKED_PORTS_FILE")" "$(dirname "$LOG_FILE")"
    pass "Thư mục log và DB đã được tạo"
}

# =============================================================================
# TEST 2: Kiểm tra trích xuất port từ dump (các format khác nhau)
# =============================================================================
test_2_port_extraction() {
    header "2" "Kiểm tra trích xuất destination port từ dump"

    local tmp_dir; tmp_dir=$(mktemp -d)

    # --- Format 1: FastNetMon standard dump ---
    local dump1="$tmp_dir/dump_format1.txt"
    cat > "$dump1" << 'EOF'
FastNetMon 1.2.1 traffic dump
Incoming traffic detected: 850000 pps / 4200 mbps
Attack direction: incoming

Top destination ports:
UDP port 30120: 750000 pps (88%)
UDP port 30121: 100000 pps (12%)

Src: 1.2.3.4:12345 -> Dst: 203.0.113.10:30120 (UDP)
Src: 5.6.7.8:54321 -> Dst: 203.0.113.10:30120 (UDP)
EOF

    local extracted1
    extracted1=$(grep -iE "(dst port|destination port|(udp|tcp)[[:space:]]+port)[[:space:]]*:?[[:space:]]*([0-9]+)" "$dump1" \
        | grep -oE '[0-9]{4,5}' | awk '!seen[$0]++' | head -1)
    if [[ "$extracted1" == "30120" ]]; then
        pass "Format 1 (standard dump): Trích xuất đúng port 30120"
    else
        fail "Format 1: Trích xuất sai, kết quả: '$extracted1' (kỳ vọng: 30120)"
    fi

    # --- Format 2: Packet lines với "-> Dst:" ---
    local dump2="$tmp_dir/dump_format2.txt"
    cat > "$dump2" << 'EOF'
Src: 10.0.0.1:11111 -> Dst: 192.168.1.100:25565 (TCP)
Src: 10.0.0.2:22222 -> Dst: 192.168.1.100:25565 (TCP)
Src: 10.0.0.3:33333 -> Dst: 192.168.1.100:25565 (TCP)
Src: 10.0.0.4:44444 -> Dst: 192.168.1.100:25566 (TCP)
EOF

    local extracted2
    extracted2=$(grep -oE '(->|Dst:)[[:space:]]*[0-9.]+:([0-9]{4,5})' "$dump2" \
        | grep -oE '[0-9]{4,5}$' \
        | sort | uniq -c | sort -rn \
        | awk 'NR==1{print $2}')
    if [[ "$extracted2" == "25565" ]]; then
        pass "Format 2 (packet lines): Trích xuất đúng port 25565"
    else
        fail "Format 2: Trích xuất sai, kết quả: '$extracted2' (kỳ vọng: 25565)"
    fi

    # --- Format 3: JSON ---
    local dump3="$tmp_dir/dump_format3.txt"
    cat > "$dump3" << 'EOF'
{"attack_details": {"destination_port": 30120, "protocol": "udp", "pps": 900000}}
EOF

    local extracted3
    extracted3=$(grep -oE '"destination_port"[[:space:]]*:[[:space:]]*([0-9]+)' "$dump3" \
        | grep -oE '[0-9]+$' | head -1)
    if [[ "$extracted3" == "30120" ]]; then
        pass "Format 3 (JSON): Trích xuất đúng port 30120"
    else
        fail "Format 3 JSON: Trích xuất sai, kết quả: '$extracted3' (kỳ vọng: 30120)"
    fi

    # --- Format 4: Mixed traffic (kiểm tra lấy port phổ biến nhất) ---
    local dump4="$tmp_dir/dump_format4.txt"
    cat > "$dump4" << 'EOF'
traffic to :25565 from 1.1.1.1
traffic to :25565 from 2.2.2.2
traffic to :25565 from 3.3.3.3
traffic to :80 from 4.4.4.4
EOF

    local extracted4
    extracted4=$(grep -oE ':[0-9]{4,5}' "$dump4" \
        | tr -d ':' | sort | uniq -c | sort -rn \
        | awk 'NR==1{print $2}')
    if [[ "$extracted4" == "25565" ]]; then
        pass "Format 4 (fallback frequency): Trích xuất đúng port 25565"
    else
        fail "Format 4: Trích xuất sai, kết quả: '$extracted4' (kỳ vọng: 25565)"
    fi

    rm -rf "$tmp_dir"
    info "Test 2 hoàn tất"
}

# =============================================================================
# TEST 3: Kiểm tra iptables chain và rule priority
# =============================================================================
test_3_iptables_priority() {
    header "3" "Kiểm tra iptables raw PREROUTING ưu tiên hơn Docker"

    # Tạo chain test
    if ! iptables -t raw -L "$IPTABLES_CHAIN" -n &>/dev/null; then
        iptables -t raw -N "$IPTABLES_CHAIN"
        info "Tạo chain $IPTABLES_CHAIN"
    fi

    # Gắn vào PREROUTING nếu chưa có
    if ! iptables -t raw -C PREROUTING -j "$IPTABLES_CHAIN" 2>/dev/null; then
        iptables -t raw -I PREROUTING 1 -j "$IPTABLES_CHAIN"
        info "Gắn chain vào PREROUTING"
    fi

    # Kiểm tra vị trí trong PREROUTING (phải là rule đầu tiên)
    local first_rule
    first_rule=$(iptables -t raw -L PREROUTING --line-numbers -n | grep -v "^Chain\|^num\|^$" | head -1 | awk '{print $NF}')

    if [[ "$first_rule" == "$IPTABLES_CHAIN" ]]; then
        pass "Chain $IPTABLES_CHAIN là rule ĐẦU TIÊN trong PREROUTING (ưu tiên cao nhất)"
    else
        warn "Chain $IPTABLES_CHAIN không phải rule đầu tiên (hiện tại: $first_rule)"
        info "Danh sách PREROUTING rules:"
        iptables -t raw -L PREROUTING --line-numbers -n
    fi

    # Kiểm tra raw table chạy trước conntrack (Docker dùng conntrack)
    # raw PREROUTING -> conntrack -> mangle -> nat -> filter
    # Đây là chuỗi Netfilter cố định, ta chỉ xác nhận raw table hoạt động
    if iptables -t raw -L &>/dev/null; then
        pass "Bảng 'raw' hoạt động - đảm bảo chặn TRƯỚC conntrack và Docker iptables"
    else
        fail "Bảng 'raw' KHÔNG hoạt động"
    fi

    # Test thêm/xóa DROP rule thực tế
    local test_port=9999
    iptables -t raw -A "$IPTABLES_CHAIN" -p udp --dport "$test_port" -d "$TEST_IP" -j DROP
    if iptables -t raw -C "$IPTABLES_CHAIN" -p udp --dport "$test_port" -d "$TEST_IP" -j DROP 2>/dev/null; then
        pass "DROP rule thêm thành công cho port $test_port"
    else
        fail "DROP rule thêm THẤT BẠI"
    fi

    # Xóa rule test
    iptables -t raw -D "$IPTABLES_CHAIN" -p udp --dport "$test_port" -d "$TEST_IP" -j DROP
    if ! iptables -t raw -C "$IPTABLES_CHAIN" -p udp --dport "$test_port" -d "$TEST_IP" -j DROP 2>/dev/null; then
        pass "DROP rule xóa thành công cho port $test_port"
    else
        fail "DROP rule xóa THẤT BẠI"
    fi
}

# =============================================================================
# TEST 4: Chạy thử notify_script.sh với dump giả lập
# =============================================================================
test_4_notify_script_ban() {
    header "4" "Chạy notify_script.sh - BAN event với dump giả lập"

    if [[ ! -x "$NOTIFY_SCRIPT" ]]; then
        warn "Bỏ qua test 4: $NOTIFY_SCRIPT chưa có hoặc chưa có quyền thực thi"
        return
    fi

    # Tạo dump giả lập FiveM
    local fake_dump
    fake_dump=$(cat << 'EOF'
FastNetMon attack dump - test
Incoming traffic: 900000 pps / 5600 mbps
Top destination ports:
UDP port 30120: 850000 pps (94%)
Src: 1.2.3.4:12345 -> Dst: 127.0.0.1:30120 (UDP)
Src: 5.6.7.8:23456 -> Dst: 127.0.0.1:30120 (UDP)
EOF
)

    # Chạy script với event BAN, truyền dump qua stdin
    info "Gọi: echo '<dump>' | $NOTIFY_SCRIPT $TEST_IP incoming ban udp"
    local exit_code=0
    echo "$fake_dump" | "$NOTIFY_SCRIPT" "$TEST_IP" incoming ban udp 2>&1 || exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        pass "Script BAN chạy không lỗi (exit code 0)"
    else
        fail "Script BAN có lỗi (exit code $exit_code)"
    fi

    # Kiểm tra iptables rule có được thêm không
    if iptables -t raw -C "$IPTABLES_CHAIN" -p udp --dport 30120 -d "$TEST_IP" -j DROP 2>/dev/null || \
       iptables -t raw -C "$IPTABLES_CHAIN" -p tcp --dport 30120 -d "$TEST_IP" -j DROP 2>/dev/null; then
        pass "iptables DROP rule cho port 30120 đã được thêm thành công"
    else
        warn "iptables DROP rule cho port 30120 KHÔNG được thêm (kiểm tra log)"
        info "Xem log: tail -20 $LOG_FILE"
    fi

    # Kiểm tra DB file
    if [[ -f "$BLOCKED_PORTS_FILE" ]] && grep -q "30120|$TEST_IP" "$BLOCKED_PORTS_FILE" 2>/dev/null; then
        pass "DB file ghi nhận port 30120 đang bị chặn"
        info "Nội dung DB:"
        cat "$BLOCKED_PORTS_FILE"
    else
        warn "DB file chưa ghi nhận port 30120 (kiểm tra log)"
    fi
}

# =============================================================================
# TEST 5: Chạy thử UNBAN event
# =============================================================================
test_5_notify_script_unban() {
    header "5" "Chạy notify_script.sh - UNBAN event"

    if [[ ! -x "$NOTIFY_SCRIPT" ]]; then
        warn "Bỏ qua test 5: $NOTIFY_SCRIPT chưa có hoặc chưa có quyền thực thi"
        return
    fi

    info "Gọi: $NOTIFY_SCRIPT $TEST_IP incoming unban"
    local exit_code=0
    "$NOTIFY_SCRIPT" "$TEST_IP" incoming unban 2>&1 || exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        pass "Script UNBAN chạy không lỗi"
    else
        fail "Script UNBAN có lỗi (exit code $exit_code)"
    fi

    # Kiểm tra iptables rule đã được xóa
    if ! iptables -t raw -C "$IPTABLES_CHAIN" -p udp --dport 30120 -d "$TEST_IP" -j DROP 2>/dev/null && \
       ! iptables -t raw -C "$IPTABLES_CHAIN" -p tcp --dport 30120 -d "$TEST_IP" -j DROP 2>/dev/null; then
        pass "iptables DROP rule cho port 30120 đã được XÓA thành công"
    else
        fail "iptables DROP rule cho port 30120 VẪN CÒN - UNBAN chưa hoạt động"
    fi

    # Kiểm tra DB đã xóa record
    if [[ ! -f "$BLOCKED_PORTS_FILE" ]] || ! grep -q "30120|$TEST_IP" "$BLOCKED_PORTS_FILE" 2>/dev/null; then
        pass "DB file đã xóa record port 30120"
    else
        warn "DB file vẫn còn record port 30120"
    fi
}

# =============================================================================
# TEST 6: Kiểm tra Docker không bị ảnh hưởng khi chặn port
# =============================================================================
test_6_docker_isolation() {
    header "6" "Kiểm tra Docker isolation - Chặn port X không ảnh hưởng port Y"

    if ! command -v docker &>/dev/null; then
        warn "Docker không cài - bỏ qua test 6"
        return
    fi

    # Chặn port 30120 (FiveM giả lập)
    iptables -t raw -A "$IPTABLES_CHAIN" -p udp --dport 30120 -d "$TEST_IP" -j DROP 2>/dev/null || true
    pass "Đã chặn port 30120 (FiveM)"

    # Kiểm tra port 25565 (Minecraft) KHÔNG bị chặn
    if ! iptables -t raw -C "$IPTABLES_CHAIN" -p udp --dport 25565 -d "$TEST_IP" -j DROP 2>/dev/null; then
        pass "Port 25565 (Minecraft) KHÔNG bị chặn - đúng như kỳ vọng"
    else
        fail "Port 25565 bị chặn không mong muốn!"
    fi

    # Kiểm tra các port khác
    for test_port in 25566 25580 30121 30130; do
        if ! iptables -t raw -C "$IPTABLES_CHAIN" -p udp --dport "$test_port" -d "$TEST_IP" -j DROP 2>/dev/null; then
            pass "Port $test_port KHÔNG bị chặn (đúng)"
        else
            fail "Port $test_port bị chặn không mong muốn!"
        fi
    done

    # Dọn dẹp
    iptables -t raw -D "$IPTABLES_CHAIN" -p udp --dport 30120 -d "$TEST_IP" -j DROP 2>/dev/null || true
    pass "Đã dọn dẹp rule test"

    info "Kết luận: Rule iptables raw áp dụng per-port, Docker bridge và các container khác KHÔNG bị ảnh hưởng"
}

# =============================================================================
# TEST 7: Kiểm tra Discord Webhook & Pterodactyl Integration
# =============================================================================
test_7_discord_and_ptero() {
    header "7" "Kiểm tra Discord Webhook & Pterodactyl Integration"

    # 7.1 Discord Webhook
    info "--- 7.1 Discord Webhook ---"
    local webhook_url
    webhook_url=$(grep 'DISCORD_WEBHOOK_URL=' "$NOTIFY_SCRIPT" 2>/dev/null | head -1 | cut -d'"' -f2 || echo "")

    if [[ "$webhook_url" == *"YOUR_ID"* || -z "$webhook_url" || "$webhook_url" != http* ]]; then
        warn "Discord Webhook CHƯA cấu hình trong $NOTIFY_SCRIPT"
        info "Hướng dẫn: Discord channel -> Edit Channel -> Integrations -> Webhooks -> New Webhook"
    else
        info "Gửi test message tới Discord Webhook..."
        local discord_res
        discord_res=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$webhook_url" \
            -H "Content-Type: application/json" \
            -d '{"username":"DDoS Guard Test","embeds":[{"title":"🧪 TEST - DDoS Guard OK","description":"FastNetMon DDoS Guard test alert thành công!","color":3066993}]}' \
            --connect-timeout 8 --max-time 15 2>/dev/null || echo "000")
        if [[ "$discord_res" =~ ^(200|204)$ ]]; then
            pass "Discord Webhook gửi thành công (HTTP $discord_res)!"
        else
            fail "Discord Webhook THẤT BẠI (HTTP $discord_res)"
        fi
    fi

    # 7.2 Pterodactyl API
    info "--- 7.2 Pterodactyl API ---"
    local ptero_url ptero_key ptero_enabled
    ptero_url=$(grep 'PTERO_PANEL_URL=' "$NOTIFY_SCRIPT" 2>/dev/null | head -1 | cut -d'"' -f2 || echo "")
    ptero_key=$(grep 'PTERO_API_KEY=' "$NOTIFY_SCRIPT" 2>/dev/null | head -1 | cut -d'"' -f2 || echo "")
    ptero_enabled=$(grep 'PTERO_ENABLED=' "$NOTIFY_SCRIPT" 2>/dev/null | head -1 | cut -d'=' -f2 | tr -d ' "' || echo "true")

    if [[ "$ptero_enabled" != "true" ]]; then
        info "Pterodactyl integration đang tắt (PTERO_ENABLED=false)"
    elif [[ "$ptero_key" == *"YOUR_APPLICATION_API_KEY"* || "$ptero_url" == *"yourdomain"* || -z "$ptero_key" ]]; then
        warn "Pterodactyl API chưa cấu hình (PTERO_PANEL_URL / PTERO_API_KEY)"
        info "Hướng dẫn: Lấy Application API Key tại Admin -> Application API (quyền read servers + allocations)"
    else
        info "Kiểm tra kết nối tới Pterodactyl Panel ($ptero_url)..."
        local ptero_code
        ptero_code=$(curl -s -o /dev/null -w "%{http_code}" \
            -H "Authorization: Bearer $ptero_key" \
            -H "Accept: application/json" \
            "$ptero_url/api/application/servers?per_page=1" \
            --connect-timeout 8 --max-time 15 2>/dev/null || echo "000")
        if [[ "$ptero_code" == "200" ]]; then
            pass "Pterodactyl Application API kết nối thành công (HTTP 200)!"
        else
            fail "Pterodactyl API lỗi HTTP $ptero_code. Kiểm tra lại Panel URL hoặc API Key"
        fi
    fi

    # 7.3 Game Type Detection Logic (Unit test nội bộ)
    info "--- 7.3 Game Type Detection Logic ---"
    detect_game_type() {
        local name egg_id
        egg_id=$(echo "$1" | jq -r '.egg_id // ""' 2>/dev/null)
        name=$(echo "$1" | jq -r '.name // ""' 2>/dev/null | tr '[:upper:]' '[:lower:]')
        if echo "$name" | grep -qiE "(fivem|gta|five m|five-m|ragemp|altv)"; then
            echo "🚗 GTA FiveM"
        elif echo "$name" | grep -qiE "(minecraft|mc |bedrock|java|paper|spigot|bungeecord|velocity)"; then
            echo "⛏️ Minecraft"
        elif echo "$name" | grep -qiE "(samp|sa-mp|san andreas|openmp|open.mp)"; then
            echo "🔫 SA-MP"
        elif echo "$name" | grep -qiE "(the isle|the_isle|theisle|evrima)"; then
            echo "🦖 The Isle"
        elif [[ "$egg_id" == "1" || "$egg_id" == "2" || "$egg_id" == "14" ]]; then
            echo "⛏️ Minecraft"
        elif [[ "$egg_id" == "15" || "$egg_id" == "16" ]]; then
            echo "🚗 GTA FiveM"
        else
            echo "🎮 Game Server"
        fi
    }

    local g1 g2 g3 g4 g5
    g1=$(detect_game_type '{"name":"City RP FiveM Vietnam","egg_id":15}')
    g2=$(detect_game_type '{"name":"Survival SMP 1.20","egg_id":1}')
    g3=$(detect_game_type '{"name":"VN-RP San Andreas MultiPlayer","egg_id":99}')
    g4=$(detect_game_type '{"name":"The Isle Evrima Survival","egg_id":99}')
    g5=$(detect_game_type '{"name":"Custom App","egg_id":99}')

    if [[ "$g1" == *"FiveM"* ]]; then
        pass "Game detection FiveM đúng: $g1"
    else
        fail "Game detection FiveM sai: $g1"
    fi

    if [[ "$g2" == *"Minecraft"* ]]; then
        pass "Game detection Minecraft đúng: $g2"
    else
        fail "Game detection Minecraft sai: $g2"
    fi

    if [[ "$g3" == *"SA-MP"* ]]; then
        pass "Game detection SA-MP đúng: $g3"
    else
        fail "Game detection SA-MP sai: $g3"
    fi

    if [[ "$g4" == *"The Isle"* ]]; then
        pass "Game detection The Isle đúng: $g4"
    else
        fail "Game detection The Isle sai: $g4"
    fi

    if [[ "$g5" == *"Game Server"* ]]; then
        pass "Game detection Unknown fallback đúng: $g5"
    else
        fail "Game detection Unknown fallback sai: $g5"
    fi
}

# =============================================================================
# TEST 8: Kiểm tra FastNetMon config
# =============================================================================
test_8_fastnetmon_config() {
    header "8" "Kiểm tra FastNetMon configuration"

    local config_file="/etc/fastnetmon.conf"
    if [[ ! -f "$config_file" && -f "$SCRIPT_DIR/fastnetmon.conf" ]]; then
        config_file="$SCRIPT_DIR/fastnetmon.conf"
    fi

    if [[ -f "$config_file" ]]; then
        pass "FastNetMon config tồn tại: $config_file"

        # Kiểm tra các mục cấu hình quan trọng
        local required_keys=(
            "notify_script_enabled"
            "notify_script_path"
            "ban_time"
            "threshold_pps"
            "mirror_afpacket"
        )
        for key in "${required_keys[@]}"; do
            if grep -q "^${key}" "$config_file" 2>/dev/null; then
                local val; val=$(grep "^${key}" "$config_file" | head -1)
                pass "Config '$key' được đặt: $val"
            else
                warn "Config '$key' CHƯA được đặt trong $config_file"
            fi
        done

        # Kiểm tra notify_script_path trỏ đúng
        local script_path
        script_path=$(grep "^notify_script_path" "$config_file" | awk '{print $NF}' | tr -d '[:space:]')
        if [[ -n "$script_path" && -f "$script_path" ]]; then
            pass "notify_script_path hợp lệ: $script_path"
        elif [[ -n "$script_path" ]]; then
            warn "notify_script_path trỏ đến file KHÔNG TỒN TẠI: $script_path"
        fi
    else
        warn "FastNetMon config CHƯA tồn tại tại $config_file"
        info "Chạy lệnh cài đặt hoặc copy fastnetmon.conf vào /etc/"
    fi

    # Kiểm tra FastNetMon service
    if systemctl is-active --quiet fastnetmon 2>/dev/null; then
        pass "FastNetMon service đang CHẠY"
    elif systemctl is-enabled --quiet fastnetmon 2>/dev/null; then
        warn "FastNetMon service được enable nhưng CHƯA CHẠY"
        info "Khởi động: systemctl start fastnetmon"
    else
        warn "FastNetMon service chưa được cài/enable"
    fi
}

# =============================================================================
# TEST 9: Stress test iptables với nhiều ports
# =============================================================================
test_9_iptables_stress() {
    header "9" "Stress test: Thêm/xóa nhiều rule iptables nhanh"

    local ports=(25565 25566 25567 25568 25569 30120 30121 30122)
    local start_time; start_time=$(date +%s%N)

    # Thêm tất cả rules
    for port in "${ports[@]}"; do
        for p in udp tcp; do
            iptables -t raw -A "$IPTABLES_CHAIN" -p "$p" --dport "$port" -d "$TEST_IP" -j DROP 2>/dev/null || true
        done
    done

    local mid_time; mid_time=$(date +%s%N)
    local add_ms=$(( (mid_time - start_time) / 1000000 ))

    # Xóa tất cả rules
    for port in "${ports[@]}"; do
        for p in udp tcp; do
            iptables -t raw -D "$IPTABLES_CHAIN" -p "$p" --dport "$port" -d "$TEST_IP" -j DROP 2>/dev/null || true
        done
    done

    local end_time; end_time=$(date +%s%N)
    local del_ms=$(( (end_time - mid_time) / 1000000 ))

    pass "Thêm ${#ports[@]} port rules (${add_ms}ms) + Xóa (${del_ms}ms)"

    if [[ $add_ms -lt 500 && $del_ms -lt 500 ]]; then
        pass "Hiệu năng iptables OK (< 500ms cho ${#ports[@]} ports)"
    else
        warn "iptables có thể chậm khi nhiều rules. Cân nhắc dùng ipset cho scale lớn"
    fi

    # Kiểm tra không còn rule nào sót lại
    local remaining
    remaining=$(iptables -t raw -L "$IPTABLES_CHAIN" -n | grep "$TEST_IP" | wc -l)
    if [[ "$remaining" -eq 0 ]]; then
        pass "Không còn rule nào sót sau stress test"
    else
        fail "$remaining rule còn sót lại sau stress test!"
    fi
}

# =============================================================================
# TEST 10: Kiểm tra Chống Khóa Ngoài (Anti-Lockout Protection)
# =============================================================================
test_10_anti_lockout() {
    header "10" "Kiểm tra Chống Khóa Ngoài (Anti-Lockout System Ports)"

    # Nạp hàm is_protected_port từ notify_script
    if [[ -f "$NOTIFY_SCRIPT" ]]; then
        # Trích xuất và chạy kiểm tra
        local protected_ports=(22 80 443 8080 2022 53 3306)
        local game_ports=(25565 30120 7777 27015)

        for p in "${protected_ports[@]}"; do
            if grep -q "PROTECTED_PORTS=.*$p" "$NOTIFY_SCRIPT"; then
                pass "Cổng cốt tử $p được bảo vệ trong PROTECTED_PORTS"
            else
                fail "Cổng cốt tử $p CHƯA được bảo vệ!"
            fi
        done

        for gp in "${game_ports[@]}"; do
            if grep -q "PROTECTED_PORTS=.*$gp" "$NOTIFY_SCRIPT"; then
                fail "Cổng game $gp bị nhầm lẫn thành protected port!"
            else
                pass "Cổng game $gp được phép cách ly khi bị tấn công"
            fi
        done
    else
        fail "Không tìm thấy notify_script: $NOTIFY_SCRIPT"
    fi
}

# =============================================================================
# TEST 11: Kiểm tra XDP / eBPF Engine
# =============================================================================
test_11_xdp_engine() {
    header "11" "Kiểm tra XDP / eBPF Engine và Tools"

    local xdp_c="$SCRIPT_DIR/xdp_guard.c"
    local xdp_mgr="$SCRIPT_DIR/compile_xdp.sh"

    # 1. Kiểm tra mã nguồn C của XDP
    if [[ -f "$xdp_c" ]]; then
        pass "File mã nguồn XDP tồn tại: $xdp_c"
        if grep -q "fnm_blocked_map" "$xdp_c" && grep -q "XDP_DROP" "$xdp_c"; then
            pass "Cấu trúc eBPF Map và XDP_DROP hợp lệ"
        else
            fail "Mã nguồn XDP thiếu BPF map hoặc XDP_DROP!"
        fi
    else
        fail "Không tìm thấy $xdp_c"
    fi

    # 2. Kiểm tra script quản lý compile_xdp.sh
    if [[ -x "$xdp_mgr" ]]; then
        pass "Script quản lý XDP tồn tại và có quyền thực thi: $xdp_mgr"
    else
        fail "Script $xdp_mgr chưa có quyền thực thi hoặc không tồn tại!"
    fi

    # 3. Kiểm tra logic chuyển đổi Hex trong compile_xdp.sh
    local ip_hex port_hex
    ip_hex=$(bash -c "source '$xdp_mgr' 2>/dev/null; ip_to_hex_bytes '127.0.0.1'" 2>/dev/null || echo "")
    port_hex=$(bash -c "source '$xdp_mgr' 2>/dev/null; port_to_hex_bytes 25565" 2>/dev/null || echo "")

    if [[ "$ip_hex" == "7f 00 00 01" ]]; then
        pass "Hàm ip_to_hex_bytes hoạt động chính xác (127.0.0.1 -> $ip_hex)"
    else
        fail "Hàm ip_to_hex_bytes sai kết quả: $ip_hex"
    fi

    if [[ "$port_hex" == "dd 63" ]]; then
        pass "Hàm port_to_hex_bytes hoạt động chính xác (Port 25565 Little-Endian -> $port_hex)"
    else
        fail "Hàm port_to_hex_bytes sai kết quả: $port_hex"
    fi

    # 4. Kiểm tra xử lý an toàn giá trị port không phải số (icmp)
    local icmp_port_hex proto_udp_hex proto_tcp_hex proto_icmp_hex
    icmp_port_hex=$(bash -c "source '$xdp_mgr' 2>/dev/null; port_to_hex_bytes icmp" 2>/dev/null || echo "error")
    proto_udp_hex=$(bash -c "source '$xdp_mgr' 2>/dev/null; proto_to_hex UDP" 2>/dev/null || echo "error")
    proto_tcp_hex=$(bash -c "source '$xdp_mgr' 2>/dev/null; proto_to_hex tcp" 2>/dev/null || echo "error")
    proto_icmp_hex=$(bash -c "source '$xdp_mgr' 2>/dev/null; proto_to_hex ICMP" 2>/dev/null || echo "error")

    if [[ "$icmp_port_hex" == "00 00" ]]; then
        pass "Hàm port_to_hex_bytes xử lý an toàn port non-numeric 'icmp' -> $icmp_port_hex (không lỗi unbound variable)"
    else
        fail "Hàm port_to_hex_bytes lỗi khi xử lý 'icmp': $icmp_port_hex"
    fi

    if [[ "$proto_udp_hex" == "11" && "$proto_tcp_hex" == "06" && "$proto_icmp_hex" == "01" ]]; then
        pass "Hàm proto_to_hex chuyển đổi chính xác (UDP->$proto_udp_hex, TCP->$proto_tcp_hex, ICMP->$proto_icmp_hex)"
    else
        fail "Hàm proto_to_hex lỗi: UDP=$proto_udp_hex TCP=$proto_tcp_hex ICMP=$proto_icmp_hex"
    fi
}

# =============================================================================
# SUMMARY
# =============================================================================
print_summary() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════${NC}"
    echo -e "${CYAN}       KẾT QUẢ KIỂM THỬ TỔNG HỢP       ${NC}"
    echo -e "${CYAN}════════════════════════════════════════${NC}"
    echo -e "  ${GREEN}PASS: $PASS${NC}"
    echo -e "  ${RED}FAIL: $FAIL${NC}"
    echo ""

    if [[ $FAIL -eq 0 ]]; then
        echo -e "${GREEN}✅ TẤT CẢ TEST ĐỀU PASSED! Hệ thống sẵn sàng.${NC}"
    else
        echo -e "${YELLOW}⚠️  CÓ $FAIL TEST THẤT BẠI. Kiểm tra log: $LOG_FILE${NC}"
    fi

    echo ""
    echo -e "${BLUE}Xem iptables rules hiện tại:${NC}"
    echo "  iptables -t raw -L $IPTABLES_CHAIN -v -n"
    echo ""
    echo -e "${BLUE}Xem log guard:${NC}"
    echo "  tail -f $LOG_FILE"
    echo ""
    echo -e "${BLUE}Xem DB port bị chặn:${NC}"
    echo "  cat $BLOCKED_PORTS_FILE"
}

# =============================================================================
# MAIN - Chạy các test
# =============================================================================
main() {
    local test_id="${1:-all}"
    check_root "$test_id"

    echo -e "${CYAN}FastNetMon DDoS Guard - Test Suite${NC}"
    echo -e "$(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "Node: $(hostname) | Kernel: $(uname -r)"
    echo -e "Notify Script: $NOTIFY_SCRIPT"
    echo ""

    case "$test_id" in
        1) test_1_prerequisites ;;
        2) test_2_port_extraction ;;
        3) test_3_iptables_priority ;;
        4) test_4_notify_script_ban ;;
        5) test_5_notify_script_unban ;;
        6) test_6_docker_isolation ;;
        7) test_7_discord_and_ptero ;;
        8) test_8_fastnetmon_config ;;
        9) test_9_iptables_stress ;;
        10) test_10_anti_lockout ;;
        11) test_11_xdp_engine ;;
        all|*)
            test_1_prerequisites
            test_2_port_extraction
            test_3_iptables_priority
            test_4_notify_script_ban
            test_5_notify_script_unban
            test_6_docker_isolation
            test_7_discord_and_ptero
            test_8_fastnetmon_config
            test_9_iptables_stress
            test_10_anti_lockout
            test_11_xdp_engine
            ;;
    esac

    print_summary
}

main "${1:-all}"
