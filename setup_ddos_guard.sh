#!/usr/bin/env bash
# =============================================================================
# FastNetMon DDoS Guard - Automated Interactive Setup Wizard
# =============================================================================
# Mô tả: Tự động cấu hình FastNetMon + Notify Script ngắt port theo từng loại
#         Game Server (Minecraft, SA-MP, GTA V FiveM, The Isle, Custom Game).
# Tương thích: Ubuntu, Debian, CentOS, RHEL
# =============================================================================

set -euo pipefail

# Màu sắc giao diện
C_RESET='\033[0m'
C_BOLD='\033[1m'
C_GREEN='\033[32m'
C_YELLOW='\033[33m'
C_BLUE='\033[34m'
C_CYAN='\033[36m'
C_RED='\033[31m'
C_MAGENTA='\033[35m'

info()  { echo -e "${C_CYAN}[INFO]${C_RESET} $*"; }
pass()  { echo -e "${C_GREEN}[✔ PASS]${C_RESET} $*"; }
warn()  { echo -e "${C_YELLOW}[⚠ WARN]${C_RESET} $*"; }
err()   { echo -e "${C_RED}[✖ FAIL]${C_RESET} $*"; }
header(){
    echo -e "\n${C_BOLD}${C_BLUE}════════════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BOLD}${C_MAGENTA}  $*${C_RESET}"
    echo -e "${C_BOLD}${C_BLUE}════════════════════════════════════════════════════════════════════${C_RESET}"
}

# -----------------------------------------------------------------------------
# 0. KIỂM TRA QUYỀN ROOT
# -----------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    err "Vui lòng chạy script này với quyền root hoặc sudo: sudo bash $0"
    exit 1
fi

clear 2>/dev/null || true
echo -e "${C_BOLD}${C_CYAN}"
cat << 'EOF'
  ______        _     _   _      _   __  __             
 |  ____|      | |   | \ | |    | | |  \/  |            
 | |__ __ _ ___| |_  |  \| | ___| |_| \  / | ___  _ __  
 |  __/ _` / __| __| | . ` |/ _ \ __| |\/| |/ _ \| '_ \ 
 | | | (_| \__ \ |_  | |\  |  __/ |_| |  | | (_) | | | |
 |_|  \__,_|___/\__| |_| \_|\___|\__|_|  |_|\___/|_| |_|
         DDOS GUARD - AUTOMATED SETUP WIZARD
EOF
echo -e "${C_RESET}"
echo -e "${C_BOLD}Hệ thống tự động ngắt PORT tầng Kernel khi bị DDoS cho Game Hosting${C_RESET}\n"

# -----------------------------------------------------------------------------
# 1. THU THẬP THÔNG TIN MẠNG & HỆ THỐNG
# -----------------------------------------------------------------------------
header "BƯỚC 1: KIỂM TRA HỆ THỐNG & CARD MẠNG"

# Số CPU cores
CPU_CORES=$(nproc 2>/dev/null || echo 2)
info "Số CPU cores phát hiện: ${C_BOLD}${CPU_CORES}${C_RESET} (netflow_workers = $CPU_CORES)"

# Lấy danh sách card mạng thực tế (bỏ qua lo, docker, veth, br)
DETECTED_IFACES=()
for iface in $(ip -o link show | awk -F': ' '{print $2}' | grep -vE '^(lo|docker[0-9]*|veth.*|br-.*|virbr.*)'); do
    DETECTED_IFACES+=("$iface")
done

DEFAULT_IFACE="${DETECTED_IFACES[0]:-eth0}"
info "Card mạng đề xuất: ${C_BOLD}${DEFAULT_IFACE}${C_RESET}"
read -rp "Nhập tên card mạng theo dõi [Mặc định: $DEFAULT_IFACE]: " INPUT_IFACE
SELECTED_IFACE="${INPUT_IFACE:-$DEFAULT_IFACE}"

# Lấy Public IP
DETECTED_IP=$(curl -s --connect-timeout 3 ifconfig.me 2>/dev/null || ip route get 1.1.1.1 2>/dev/null | awk '{print $7}' | head -1 || echo "")
info "Public IP máy chủ phát hiện: ${C_BOLD}${DETECTED_IP:-Chưa xác định}${C_RESET}"
read -rp "Nhập Public IP của máy chủ [Mặc định: $DETECTED_IP]: " INPUT_IP
SERVER_PUBLIC_IP="${INPUT_IP:-$DETECTED_IP}"

if [[ -z "$SERVER_PUBLIC_IP" ]]; then
    err "IP máy chủ không được để trống!"
    exit 1
fi

# -----------------------------------------------------------------------------
# 2. CHỌN LOẠI GAME SERVER (CHUYÊN BIỆT 1 GAME CHO MỖI NODE)
# -----------------------------------------------------------------------------
header "BƯỚC 2: CHỌN LOẠI GAME SERVER BẢO VỆ"

echo -e "Chọn game chính đang chạy trên máy chủ này:"
echo -e "  ${C_BOLD}[1]${C_RESET} ⛏️  Minecraft (Java & Bedrock Edition)"
echo -e "  ${C_BOLD}[2]${C_RESET} 🔫 SA-MP (San Andreas Multiplayer)"
echo -e "  ${C_BOLD}[3]${C_RESET} 🚗 GTA V / FiveM"
echo -e "  ${C_BOLD}[4]${C_RESET} 🦖 The Isle (Dinosaur Survival)"
echo -e "  ${C_BOLD}[5]${C_RESET} 🎮 Custom Game (Tự cấu hình game khác)"
echo ""

while true; do
    read -rp "Nhập số lựa chọn [1-5]: " GAME_CHOICE
    case "$GAME_CHOICE" in
        1)
            GAME_NAME="Minecraft"
            GAME_ICON="⛏️ Minecraft"
            DEF_PORT_RANGE="25565-25600"
            DEF_PROTO="tcp/udp"
            DEF_PPS="50000"
            DEF_MBPS="500"
            DEF_FLOWS="3500"
            break
            ;;
        2)
            GAME_NAME="SA-MP"
            GAME_ICON="🔫 SA-MP"
            DEF_PORT_RANGE="7777-7799"
            DEF_PROTO="udp"
            DEF_PPS="35000"
            DEF_MBPS="300"
            DEF_FLOWS="2500"
            break
            ;;
        3)
            GAME_NAME="GTA V (FiveM)"
            GAME_ICON="🚗 GTA FiveM"
            DEF_PORT_RANGE="30120-30200"
            DEF_PROTO="udp/tcp"
            DEF_PPS="100000"
            DEF_MBPS="800"
            DEF_FLOWS="5000"
            break
            ;;
        4)
            GAME_NAME="The Isle"
            GAME_ICON="🦖 The Isle"
            DEF_PORT_RANGE="7777-7790"
            DEF_PROTO="udp"
            DEF_PPS="50000"
            DEF_MBPS="500"
            DEF_FLOWS="3500"
            break
            ;;
        5)
            read -rp "Nhập tên Game: " CUSTOM_NAME
            GAME_NAME="${CUSTOM_NAME:-Custom Game}"
            GAME_ICON="🎮 $GAME_NAME"
            DEF_PORT_RANGE="20000-30000"
            DEF_PROTO="udp/tcp"
            DEF_PPS="50000"
            DEF_MBPS="500"
            DEF_FLOWS="3500"
            break
            ;;
        *)
            warn "Lựa chọn không hợp lệ. Vui lòng nhập số từ 1 đến 5!"
            ;;
    esac
done

pass "Đã chọn cấu hình cho: ${C_BOLD}$GAME_NAME${C_RESET}"

# -----------------------------------------------------------------------------
# 3. NHẬP RANGE PORT TỰ ĐỘNG
# -----------------------------------------------------------------------------
header "BƯỚC 3: NHẬP RANGE PORT GAME"

info "Bạn có thể tự nhập port đơn lẻ, dải port (ví dụ: 25565-25600) hoặc danh sách."
read -rp "Nhập Range Port của $GAME_NAME [Mặc định: $DEF_PORT_RANGE]: " USER_PORT_RANGE
CONFIG_PORT_RANGE="${USER_PORT_RANGE:-$DEF_PORT_RANGE}"
pass "Range port đã thiết lập: ${C_BOLD}$CONFIG_PORT_RANGE${C_RESET}"

# -----------------------------------------------------------------------------
# 4. THIẾT LẬP NGƯỠNG BẢO VỆ (THRESHOLDS)
# -----------------------------------------------------------------------------
header "BƯỚC 4: THIẾT LẬP NGƯỠNG PHÁT HIỆN DDOS"

echo -e "Thông số đề xuất tối ưu cho ${C_BOLD}$GAME_NAME${C_RESET}:"
echo -e "  - Ngưỡng gói tin (PPS): ${C_BOLD}${DEF_PPS}${C_RESET} pps"
echo -e "  - Ngưỡng băng thông (Mbps): ${C_BOLD}${DEF_MBPS}${C_RESET} Mbps"
echo -e "  - Ngưỡng kết nối (Flows): ${C_BOLD}${DEF_FLOWS}${C_RESET} flows"
echo -e "  - Thời gian ban port: ${C_BOLD}900${C_RESET} giây (15 phút)"
echo ""

read -rp "Bạn có muốn dùng thông số đề xuất trên không? [Y/n]: " USE_DEF_THRESHOLDS
USE_DEF_THRESHOLDS="${USE_DEF_THRESHOLDS:-Y}"

if [[ "$USE_DEF_THRESHOLDS" =~ ^[Nn]$ ]]; then
    read -rp "Nhập threshold_pps [Mặc định: $DEF_PPS]: " INPUT_PPS
    CONFIG_PPS="${INPUT_PPS:-$DEF_PPS}"

    read -rp "Nhập threshold_mbps [Mặc định: $DEF_MBPS]: " INPUT_MBPS
    CONFIG_MBPS="${INPUT_MBPS:-$DEF_MBPS}"

    read -rp "Nhập threshold_flows [Mặc định: $DEF_FLOWS]: " INPUT_FLOWS
    CONFIG_FLOWS="${INPUT_FLOWS:-$DEF_FLOWS}"

    read -rp "Nhập thời gian ban (giây) [Mặc định: 900]: " INPUT_BAN_TIME
    CONFIG_BAN_TIME="${INPUT_BAN_TIME:-900}"
else
    CONFIG_PPS="$DEF_PPS"
    CONFIG_MBPS="$DEF_MBPS"
    CONFIG_FLOWS="$DEF_FLOWS"
    CONFIG_BAN_TIME="900"
fi

pass "Ngưỡng áp dụng: PPS=$CONFIG_PPS | Bandwidth=${CONFIG_MBPS}Mbps | Flows=$CONFIG_FLOWS | BanTime=${CONFIG_BAN_TIME}s"

# -----------------------------------------------------------------------------
# 5. CẤU HÌNH DISCORD WEBHOOK & PTERODACTYL
# -----------------------------------------------------------------------------
header "BƯỚC 5: TÍCH HỢP DISCORD & PTERODACTYL (TÙY CHỌN)"

# Discord Webhook
echo -e "Nhập link Discord Webhook để nhận thông báo embed khi bị tấn công & khi mở port:"
read -rp "Discord Webhook URL (bấm Enter để bỏ qua): " INPUT_DISCORD_URL
DISCORD_URL="${INPUT_DISCORD_URL:-https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN}"

# Pterodactyl Panel
read -rp "Bạn có muốn kích hoạt tự động Suspend/Kill server trên Pterodactyl khi bị DDoS? [y/N]: " ENABLE_PTERO
ENABLE_PTERO="${ENABLE_PTERO:-N}"

PTERO_ENABLED="false"
PTERO_URL="https://panel.yourdomain.com"
PTERO_KEY="ptla_YOUR_APPLICATION_API_KEY"
PTERO_ACT="suspend"

if [[ "$ENABLE_PTERO" =~ ^[Yy]$ ]]; then
    PTERO_ENABLED="true"
    read -rp "Nhập URL Pterodactyl Panel (VD: https://panel.domain.com): " PTERO_URL
    read -rp "Nhập Pterodactyl Application API Key (bắt đầu bằng ptla_...): " PTERO_KEY
    read -rp "Hành động khi bị DDoS (suspend/kill) [Mặc định: suspend]: " INPUT_PTERO_ACT
    PTERO_ACT="${INPUT_PTERO_ACT:-suspend}"
fi

# -----------------------------------------------------------------------------
# 6. TRIỂN KHAI VÀ GHI FILE CẤU HÌNH
# -----------------------------------------------------------------------------
header "BƯỚC 6: TRIỂN KHAI CẤU HÌNH HỆ THỐNG"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="/opt/fastnetmon_guard"
TARGET_SCRIPT="$TARGET_DIR/notify_script.sh"

info "Đang tạo các thư mục cần thiết..."
mkdir -p "$TARGET_DIR"
mkdir -p /var/log/fastnetmon_guard
mkdir -p /var/lib/fastnetmon_guard
mkdir -p /tmp/fastnetmon_dump_cache

# Copy và cấu hình notify_script.sh
info "Đang triển khai notify_script.sh vào $TARGET_SCRIPT..."
if [[ -f "$SCRIPT_DIR/notify_script.sh" ]]; then
    cp "$SCRIPT_DIR/notify_script.sh" "$TARGET_SCRIPT"
else
    err "Không tìm thấy notify_script.sh tại $SCRIPT_DIR!"
    exit 1
fi

# Thay thế các cấu hình trong notify_script.sh
sed -i "s|DISCORD_WEBHOOK_URL=.*|DISCORD_WEBHOOK_URL=\"$DISCORD_URL\"|g" "$TARGET_SCRIPT"
sed -i "s|PTERO_ENABLED=.*|PTERO_ENABLED=$PTERO_ENABLED|g" "$TARGET_SCRIPT"
sed -i "s|PTERO_PANEL_URL=.*|PTERO_PANEL_URL=\"$PTERO_URL\"|g" "$TARGET_SCRIPT"
sed -i "s|PTERO_API_KEY=.*|PTERO_API_KEY=\"$PTERO_KEY\"|g" "$TARGET_SCRIPT"
sed -i "s|PTERO_ACTION=.*|PTERO_ACTION=\"$PTERO_ACT\"|g" "$TARGET_SCRIPT"
sed -i "s|DEFAULT_BAN_DURATION=.*|DEFAULT_BAN_DURATION=\"$CONFIG_BAN_TIME\"|g" "$TARGET_SCRIPT"

chmod +x "$TARGET_SCRIPT"
pass "Đã cài đặt notify_script.sh thành công!"

# Ghi IP vào /etc/fastnetmon_networks_list
info "Đang ghi danh sách mạng /etc/fastnetmon_networks_list..."
echo "$SERVER_PUBLIC_IP/32" > /etc/fastnetmon_networks_list
pass "Đã thêm $SERVER_PUBLIC_IP/32 vào /etc/fastnetmon_networks_list"

# Ghi file cấu hình FastNetMon (/etc/fastnetmon.conf)
info "Đang tạo file cấu hình /etc/fastnetmon.conf..."
cat > /etc/fastnetmon.conf << EOF
###############################################################################
# FastNetMon Community Configuration
# Tự động sinh bởi FastNetMon Setup Wizard
# Game Profile: $GAME_NAME | Range Port: $CONFIG_PORT_RANGE
###############################################################################

# 1. Card mạng theo dõi
interfaces = $SELECTED_IFACE

# 2. Engine AF_PACKET bắt gói tin
mirror_afpacket = on
process_incoming_traffic = on
process_outgoing_traffic = on
netflow_workers = $CPU_CORES
afpacket_ring_buffer_size = 67108864

# 3. Ngưỡng phát hiện tấn công DDoS
threshold_pps = $CONFIG_PPS
threshold_mbps = $CONFIG_MBPS
threshold_flows = $CONFIG_FLOWS

ban_for_pps = on
ban_for_bandwidth = on
ban_for_flows = on

# 4. Thời gian ban tự động unban (giây)
ban_time = $CONFIG_BAN_TIME

# 5. Gọi script ngắt port tự động
notify_script_enabled = on
notify_script_path = $TARGET_SCRIPT
notify_script_pass_details = on

# 6. Danh sách subnet/IP theo dõi
networks_list = /etc/fastnetmon_networks_list
white_list = /etc/fastnetmon_whitelist

# 7. Cấu hình log
logging_level = info
EOF

# Đồng bộ file template tại thư mục hiện tại
cp /etc/fastnetmon.conf "$SCRIPT_DIR/fastnetmon.conf" 2>/dev/null || true
pass "Đã tạo /etc/fastnetmon.conf thành công!"

# -----------------------------------------------------------------------------
# 7. KHỞI TẠO BẢNG IPTABLES VÀ DỊCH VỤ
# -----------------------------------------------------------------------------
header "BƯỚC 7: KHỞI TẠO IPTABLES VÀ KHỞI ĐỘNG DỊCH VỤ"

IPTABLES_CHAIN="FNM_DDOS_GUARD"
info "Đang kiểm tra iptables raw chain $IPTABLES_CHAIN..."

if ! iptables -t raw -L "$IPTABLES_CHAIN" -n &>/dev/null; then
    iptables -t raw -N "$IPTABLES_CHAIN"
    pass "Đã tạo chain $IPTABLES_CHAIN trong bảng raw"
fi

if ! iptables -t raw -C PREROUTING -j "$IPTABLES_CHAIN" 2>/dev/null; then
    iptables -t raw -I PREROUTING 1 -j "$IPTABLES_CHAIN"
    pass "Đã gắn $IPTABLES_CHAIN vào vị trí 1 của PREROUTING"
fi

# Khởi động lại FastNetMon
if command -v systemctl &>/dev/null; then
    info "Đang restart dịch vụ FastNetMon..."
    systemctl restart fastnetmon 2>/dev/null || true
    sleep 2
    if systemctl is-active --quiet fastnetmon 2>/dev/null; then
        pass "Dịch vụ FastNetMon đang CHẠY ổn định!"
    else
        warn "FastNetMon chưa chạy hoặc cần reload: systemctl restart fastnetmon"
    fi
fi

# -----------------------------------------------------------------------------
# TỔNG KẾT VÀ HOÀN TẤT
# -----------------------------------------------------------------------------
header "🎉 CÀI ĐẶT THÀNH CÔNG!"

echo -e "Hệ thống FastNetMon DDoS Guard đã sẵn sàng hoạt động:"
echo -e "  🎮 Game được bảo vệ : ${C_BOLD}${GAME_ICON}${C_RESET}"
echo -e "  🚪 Range Port        : ${C_BOLD}${CONFIG_PORT_RANGE}${C_RESET}"
echo -e "  🌐 Interface / IP    : ${C_BOLD}${SELECTED_IFACE} / ${SERVER_PUBLIC_IP}${C_RESET}"
echo -e "  ⚡ Ngưỡng kích hoạt  : ${C_BOLD}${CONFIG_PPS} PPS / ${CONFIG_MBPS} Mbps / ${CONFIG_FLOWS} Flows${C_RESET}"
echo -e "  ⏱️  Thời gian ngắt    : ${C_BOLD}${CONFIG_BAN_TIME} giây (${CONFIG_BAN_TIME}s tự động mở lại)${C_RESET}"
echo -e "  📜 Script xử lý      : ${C_BOLD}${TARGET_SCRIPT}${C_RESET}"
echo -e "  📋 File cấu hình     : ${C_BOLD}/etc/fastnetmon.conf${C_RESET}"
echo ""
echo -e "${C_CYAN}Để chạy kiểm tra toàn diện, bạn có thể thực thi:${C_RESET}"
echo -e "  ${C_BOLD}bash $SCRIPT_DIR/test_ddos_guard.sh${C_RESET}"
echo ""
