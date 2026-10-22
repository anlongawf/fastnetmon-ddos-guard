#!/usr/bin/env bash
# =============================================================================
# FastNetMon DDoS Guard - XDP Engine Compiler & Manager
# =============================================================================
# Quản lý biên dịch, nạp (attach) và gỡ (detach) chương trình XDP eBPF vào card mạng
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BPF_SRC="$SCRIPT_DIR/xdp_guard.c"
BPF_OBJ="$SCRIPT_DIR/xdp_guard.o"
BPF_FS_DIR="/sys/fs/bpf"
PINNED_MAP="$BPF_FS_DIR/fnm_blocked_map"

C_RESET='\033[0m'
C_BOLD='\033[1m'
C_GREEN='\033[32m'
C_CYAN='\033[36m'
C_YELLOW='\033[33m'
C_RED='\033[31m'

info()  { echo -e "${C_CYAN}[INFO]${C_RESET} $*"; }
pass()  { echo -e "${C_GREEN}[✔ PASS]${C_RESET} $*"; }
warn()  { echo -e "${C_YELLOW}[⚠ WARN]${C_RESET} $*"; }
err()   { echo -e "${C_RED}[✖ FAIL]${C_RESET} $*"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        err "Vui lòng chạy với quyền root hoặc sudo: sudo bash $0 $*"
        exit 1
    fi
}

install_deps() {
    info "Đang kiểm tra và cài đặt công cụ biên dịch eBPF / XDP..."
    if command -v apt-get &>/dev/null; then
        apt-get update -y
        apt-get install -y clang llvm libbpf-dev linux-tools-common iproute2 gcc-multilib bpftool || true
    elif command -v dnf &>/dev/null || command -v yum &>/dev/null; then
        yum install -y clang llvm libbpf-devel bpftool iproute || true
    fi
}

build_xdp() {
    info "Đang biên dịch $BPF_SRC sang $BPF_OBJ..."
    if ! command -v clang &>/dev/null; then
        warn "Không tìm thấy clang. Đang tiến hành cài đặt..."
        install_deps
    fi

    if ! command -v clang &>/dev/null; then
        err "Không thể cài đặt clang. Vui lòng cài thủ công: apt install -y clang llvm libbpf-dev"
        exit 1
    fi

    # Biên dịch eBPF
    clang -O2 -g -Wall -target bpf \
        -D__TARGET_ARCH_x86 \
        -I/usr/include \
        -I/usr/include/x86_64-linux-gnu \
        -c "$BPF_SRC" -o "$BPF_OBJ"

    if [[ -f "$BPF_OBJ" ]]; then
        pass "Biên dịch XDP thành công: $BPF_OBJ"
    else
        err "Biên dịch thất bại!"
        exit 1
    fi
}

mount_bpffs() {
    if ! mount | grep -q "on /sys/fs/bpf type bpf"; then
        info "Đang mount /sys/fs/bpf filesystem..."
        mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
    fi
}

attach_xdp() {
    local iface="${1:-eth0}"
    check_root
    mount_bpffs

    if [[ ! -f "$BPF_OBJ" ]]; then
        info "Chưa tìm thấy $BPF_OBJ. Tiến hành biên dịch..."
        build_xdp
    fi

    # Kiểm tra xem card mạng đã có XDP chưa
    if ip link show "$iface" 2>/dev/null | grep -q "xdp"; then
        warn "Interface $iface đã được gắn XDP program trước đó. Đang gỡ bỏ để cập nhật..."
        detach_xdp "$iface" 2>/dev/null || true
    fi

    info "Đang nạp XDP vào card mạng $iface..."

    # Thử chế độ native (xdpdrv - chạy trực tiếp tại driver, nhanh nhất)
    if ip link set dev "$iface" xdpdrv obj "$BPF_OBJ" sec xdp 2>/dev/null; then
        pass "Đã kích hoạt XDP Native Mode trên $iface (Tốc độ tối đa L2)!"
    # Fallback sang chế độ generic (xdpgeneric - hỗ trợ mọi loại card mạng và VPS)
    elif ip link set dev "$iface" xdpgeneric obj "$BPF_OBJ" sec xdp 2>/dev/null; then
        pass "Đã kích hoạt XDP Generic Mode trên $iface (Tương thích cao)!"
    else
        err "Không thể nạp XDP trên interface $iface!"
        info "Hệ thống sẽ tự động fallback về iptables raw PREROUTING."
        exit 1
    fi

    # Pin BPF Map nếu bpftool có sẵn
    if command -v bpftool &>/dev/null; then
        local map_id
        map_id=$(bpftool map list 2>/dev/null | grep "fnm_blocked_map" | awk '{print $1}' | tr -d ':' || echo "")
        if [[ -n "$map_id" && ! -e "$PINNED_MAP" ]]; then
            bpftool map pin id "$map_id" "$PINNED_MAP" 2>/dev/null || true
            pass "Đã pin BPF map tại $PINNED_MAP"
        fi
    fi
}

detach_xdp() {
    local iface="${1:-eth0}"
    check_root
    info "Đang gỡ XDP khỏi interface $iface..."
    ip link set dev "$iface" xdp off 2>/dev/null || true
    ip link set dev "$iface" xdpgeneric off 2>/dev/null || true
    rm -f "$PINNED_MAP" 2>/dev/null || true
    pass "Đã gỡ XDP khỏi $iface thành công!"
}

status_xdp() {
    local iface="${1:-eth0}"
    echo -e "\n${C_BOLD}=== TRẠNG THÁI XDP TRÊN $iface ===${C_RESET}"
    if ip link show "$iface" 2>/dev/null | grep -q "xdp"; then
        pass "XDP đang HOẠT ĐỘNG trên $iface"
        ip link show "$iface" | grep "xdp"
    else
        warn "XDP CHƯA được kích hoạt trên $iface (Đang chạy chế độ iptables raw)"
    fi

    if [[ -e "$PINNED_MAP" ]] && command -v bpftool &>/dev/null; then
        echo -e "\n${C_CYAN}Danh sách Port đang bị XDP Drop:${C_RESET}"
        bpftool map dump pinned "$PINNED_MAP" 2>/dev/null || echo "Trống."
    fi
}

# Thêm/Xóa port trong BPF Map qua bpftool
ip_to_hex_bytes() {
    local ip="$1"
    IFS='.' read -r o1 o2 o3 o4 <<< "$ip"
    printf "%02x %02x %02x %02x" "$o1" "$o2" "$o3" "$o4"
}

port_to_hex_bytes() {
    local port="${1:-0}"
    local p_num=0
    if [[ "$port" =~ ^[0-9]+$ ]]; then
        p_num="$port"
    fi
    local p_low=$(( p_num & 0xFF ))
    local p_high=$(( (p_num >> 8) & 0xFF ))
    printf "%02x %02x" "$p_low" "$p_high"
}

proto_to_hex() {
    local proto; proto=$(echo "${1:-udp}" | tr '[:upper:]' '[:lower:]')
    case "$proto" in
        tcp)  printf "06" ;;
        icmp) printf "01" ;;
        *)    printf "11" ;; # udp default
    esac
}

xdp_map_block() {
    local target_ip="$1" port="${2:-0}" proto="${3:-udp}"
    [[ ! -e "$PINNED_MAP" ]] && return 0
    ! command -v bpftool &>/dev/null && return 0

    local ip_hex port_hex proto_hex
    ip_hex=$(ip_to_hex_bytes "$target_ip")
    port_hex=$(port_to_hex_bytes "$port")
    # Value: dropped_packets(8) + dropped_bytes(8) = 16 bytes zero
    local val_hex="00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"

    local proto_clean; proto_clean=$(echo "$proto" | tr '[:upper:]' '[:lower:]')

    if [[ "$proto_clean" == "icmp" || "$port" == "0" ]]; then
        proto_hex=$(proto_to_hex "$proto_clean")
        local key_hex="$ip_hex $port_hex $proto_hex 00"
        bpftool map update pinned "$PINNED_MAP" key hex $key_hex value hex $val_hex 2>/dev/null || true
    else
        # Khóa cả UDP và TCP trên port này để ngăn chặn đa dạng vector tấn công
        for p in udp tcp; do
            proto_hex=$(proto_to_hex "$p")
            local key_hex="$ip_hex $port_hex $proto_hex 00"
            bpftool map update pinned "$PINNED_MAP" key hex $key_hex value hex $val_hex 2>/dev/null || true
        done
    fi
    info "XDP BPF Map thêm: IP=$target_ip Port=$port Proto=$proto"
}

xdp_map_unblock() {
    local target_ip="$1" port="${2:-0}" proto="${3:-udp}"
    [[ ! -e "$PINNED_MAP" ]] && return 0
    ! command -v bpftool &>/dev/null && return 0

    local ip_hex port_hex proto_hex
    ip_hex=$(ip_to_hex_bytes "$target_ip")
    port_hex=$(port_to_hex_bytes "$port")

    # Xóa cả UDP và TCP key
    for p in udp tcp icmp; do
        proto_hex=$(proto_to_hex "$p")
        local key_hex="$ip_hex $port_hex $proto_hex 00"
        bpftool map delete pinned "$PINNED_MAP" key hex $key_hex 2>/dev/null || true
    done
    info "XDP BPF Map gỡ: IP=$target_ip Port=$port"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    case "${1:-status}" in
        build)
            check_root
            build_xdp
            ;;
        attach)
            attach_xdp "${2:-eth0}"
            ;;
        detach)
            detach_xdp "${2:-eth0}"
            ;;
        status)
            status_xdp "${2:-eth0}"
            ;;
        block)
            xdp_map_block "${2:-}" "${3:-0}" "${4:-udp}"
            ;;
        unblock)
            xdp_map_unblock "${2:-}" "${3:-0}" "${4:-udp}"
            ;;
        *)
            echo "Cách dùng: $0 {build|attach <iface>|detach <iface>|status <iface>|block <IP> <PORT> [PROTO]|unblock <IP> <PORT>}"
            exit 1
            ;;
    esac
fi
