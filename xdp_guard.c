// =============================================================================
// FastNetMon DDoS Guard - High Performance XDP/eBPF Drop Program
// =============================================================================
// Mô tả: Chương trình XDP (eXpress Data Path) loại bỏ gói tin DDoS ngay tại tầng
//         driver card mạng (L2 Ring Buffer) trước khi Linux Kernel phân bổ sk_buff.
// Tốc độ: 10.000.000 - 20.000.000+ PPS trên 1 CPU core.
// =============================================================================

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_BLOCKED_ENTRIES 1024

// Cấu trúc Key tra cứu trong BPF Map
struct block_key {
    __u32 dest_ip;      // IP đích của máy chủ (dạng network byte order)
    __u16 dest_port;    // Port đích bị tấn công (dạng host byte order)
    __u8  protocol;     // IPPROTO_UDP (17), IPPROTO_TCP (6), IPPROTO_ICMP (1), hoặc 0 (tất cả)
    __u8  pad;          // Đệm 1 byte để align bộ nhớ 4 bytes
};

// Cấu trúc Value thống kê trong BPF Map
struct block_stats {
    __u64 dropped_packets;
    __u64 dropped_bytes;
};

// BPF Map dạng Hash lưu trữ danh sách các port/IP bị ngắt
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BLOCKED_ENTRIES);
    __type(key, struct block_key);
    __type(value, struct block_stats);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} fnm_blocked_map SEC(".maps");

SEC("xdp")
int xdp_ddos_guard_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    // 1. Kiểm tra Ethernet Header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 h_proto = eth->h_proto;
    void *l3_hdr = (void *)(eth + 1);

    // Hỗ trợ gói tin gắn nhãn VLAN 802.1Q (0x8100 hoặc 0x88A8)
    if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(0x88A8)) {
        struct {
            __be16 tci;
            __be16 encap_proto;
        } *vlan = l3_hdr;
        if ((void *)(vlan + 1) > data_end)
            return XDP_PASS;
        h_proto = vlan->encap_proto;
        l3_hdr = (void *)(vlan + 1);
    }

    // Chỉ xử lý gói tin IPv4 (0x0800)
    if (h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // 2. Kiểm tra IPv4 Header
    struct iphdr *ip = l3_hdr;
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr))
        return XDP_PASS;
    if ((void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    __u32 dest_ip = ip->daddr;
    __u8 protocol = ip->protocol;
    __u16 dest_port = 0;

    void *trans_hdr = (void *)ip + ip_hdr_len;

    // 3. Trích xuất Destination Port theo giao thức
    __u16 frag_offset = bpf_ntohs(ip->frag_off) & 0x1FFF;
    if (frag_offset == 0) {
        if (protocol == IPPROTO_UDP) {
            struct udphdr *udp = trans_hdr;
            if ((void *)(udp + 1) > data_end)
                return XDP_PASS;
            dest_port = bpf_ntohs(udp->dest);
        } else if (protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = trans_hdr;
            if ((void *)(tcp + 1) > data_end)
                return XDP_PASS;
            dest_port = bpf_ntohs(tcp->dest);
        } else if (protocol == IPPROTO_ICMP) {
            // ICMP không có port -> dùng dest_port = 0
            dest_port = 0;
        } else {
            return XDP_PASS;
        }
    } else {
        // Gói tin phân mảnh tiếp theo (non-first fragment) không có UDP/TCP port
        dest_port = 0;
    }

    // 4. Tra cứu trong BPF Map xem có trong danh sách bị khóa không
    struct block_key key = {
        .dest_ip   = dest_ip,
        .dest_port = dest_port,
        .protocol  = protocol,
        .pad       = 0,
    };

    struct block_stats *stats = bpf_map_lookup_elem(&fnm_blocked_map, &key);
    if (stats) {
        // Cập nhật thống kê packet & byte bị drop
        __sync_fetch_and_add(&stats->dropped_packets, 1);
        __sync_fetch_and_add(&stats->dropped_bytes, (__u64)((long)data_end - (long)data));
        
        // DROP SIÊU TỐC: Hủy gói tin ngay tại Driver card mạng!
        return XDP_DROP;
    }

    // 5. Kiểm tra rule khóa giao thức (ví dụ chặn toàn bộ ICMP tới IP này)
    if (dest_port != 0) {
        struct block_key proto_key = {
            .dest_ip   = dest_ip,
            .dest_port = 0,
            .protocol  = protocol,
            .pad       = 0,
        };
        stats = bpf_map_lookup_elem(&fnm_blocked_map, &proto_key);
        if (stats) {
            __sync_fetch_and_add(&stats->dropped_packets, 1);
            __sync_fetch_and_add(&stats->dropped_bytes, (__u64)((long)data_end - (long)data));
            return XDP_DROP;
        }
    }

    // 6. Kiểm tra rule khóa toàn bộ IP (protocol = 0, dest_port = 0)
    struct block_key ip_key = {
        .dest_ip   = dest_ip,
        .dest_port = 0,
        .protocol  = 0,
        .pad       = 0,
    };
    stats = bpf_map_lookup_elem(&fnm_blocked_map, &ip_key);
    if (stats) {
        __sync_fetch_and_add(&stats->dropped_packets, 1);
        __sync_fetch_and_add(&stats->dropped_bytes, (__u64)((long)data_end - (long)data));
        return XDP_DROP;
    }

    // Gói tin bình thường -> Cho phép đi tiếp vào Linux Network Stack
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
