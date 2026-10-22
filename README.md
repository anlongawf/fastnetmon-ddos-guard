# 🛡️ FastNetMon DDoS Guard for Game Server Hosting

Hệ thống phát hiện DDoS tự động bằng **FastNetMon Community** kết hợp kịch bản ngắt **đúng PORT bị tấn công ở tầng Kernel (iptables raw PREROUTING & XDP eBPF)** dành riêng cho Game Hosting (Pterodactyl / Docker / VPS / Dedicated Server).

---

## 🎯 Điểm Nổi Bật

- ⚡ **Chỉ ngắt đúng PORT bị tấn công**: Không làm sập cả IP máy chủ. Các server game khác và kết nối SSH (22) vẫn hoạt động 100% bình thường.
- 🚀 **Công nghệ Hybrid XDP / eBPF + iptables raw**: Drop gói tin siêu tốc ngay tại Ring Buffer Driver của Card mạng với tốc độ **10.000.000 - 20.000.000+ PPS** mà không hao tổn CPU.
- 🔄 **Hỗ trợ mạng IP Động & NAT**: Tự động tương thích với mô hình Port Forwarding trên Router mạng gia đình/homelab (chỉ cần monitor IP nội bộ `192.168.x.x`).
- 🛡️ **Bảo vệ chống khóa ngoài (Anti-Lockout)**: Tuyệt đối không bao giờ ngắt nhầm cổng SSH (`22`), Web (`80/443`), Wings API (`8080`), Wings SFTP (`2022`), DNS (`53`), Database (`3306`) và VPN Tailscale.
- 🎮 **Profiles game tối ưu sẵn**:
  - ⛏️ **Minecraft** (Java & Bedrock Edition)
  - 🔫 **SA-MP** (San Andreas Multiplayer)
  - 🚗 **GTA V / FiveM**
  - 🦖 **The Isle**
  - 🕹️ **Custom Game** (Tự điền range port game khác)
- 🤖 **Tùy chọn tích hợp Pterodactyl Panel**: Tự động suspend/kill container game bị tấn công trên Wings.
- 🔔 **Thông báo Discord Webhook**: Bắn thông báo embed đẹp mắt bằng tiếng Việt khi bị tấn công và khi mở lại port.
- ⏱️ **Tự động unban**: Tự mở lại port sau thời gian quy định (mặc định 15 phút).

---

## 📦 Cấu Trúc Dự Án

```text
├── setup_ddos_guard.sh  # Script cài đặt tương tác tự động A-Z (Tự cài FastNetMon, cấu hình XDP & iptables)
├── notify_script.sh     # Script xử lý trích xuất port, iptables drop, XDP update & Discord alert
├── compile_xdp.sh       # Script quản lý biên dịch, nạp (attach) và gỡ (detach) XDP eBPF
├── xdp_guard.c          # Mã nguồn chương trình eBPF/XDP drop gói tin siêu tốc tại card mạng
├── test_ddos_guard.sh   # Bộ công cụ test mô phỏng toàn diện (63 bài kiểm thử unit tests)
├── fastnetmon.conf      # File cấu hình mẫu tối ưu cho FastNetMon Community
└── README.md
```

---

## 🚀 Cài Đặt Nhanh

### Cách 1: 1-Click Install (Khuyến nghị - Tự động toàn bộ A-Z)

Script sẽ **tự động kiểm tra và cài đặt FastNetMon Community** từ kho APT Universe, nạp XDP Engine và thiết lập toàn bộ hệ thống:

```bash
curl -sSL https://raw.githubusercontent.com/anlongawf/fastnetmon-ddos-guard/main/setup_ddos_guard.sh | sudo bash
```

---

### Cách 2: Tải qua Git Clone (Dành cho nhà phát triển)

```bash
# 1. Clone repository về máy
git clone https://github.com/anlongawf/fastnetmon-ddos-guard.git

# 2. Di chuyển vào thư mục dự án
cd fastnetmon-ddos-guard

# 3. Cấp quyền thực thi các script
chmod +x setup_ddos_guard.sh notify_script.sh compile_xdp.sh test_ddos_guard.sh

# 4. Chạy trình cài đặt Wizard
sudo bash setup_ddos_guard.sh
```

---

## 🧪 Kiểm Thử Hệ Thống (Test Suite)

Sau khi cài đặt xong, bạn có thể chạy bộ 63 bài test mô phỏng để kiểm tra toàn bộ luồng hoạt động từ trích xuất port, iptables drop, XDP map cho đến Discord webhook:

```bash
sudo bash /opt/fastnetmon_guard/test_ddos_guard.sh
```

---

## 📊 Giám Sát & Quản Trị Hệ Thống

### 1. Xem danh sách các port đang bị cách ly
File cơ sở dữ liệu lưu lại trạng thái thời gian thực của các port đang bị khóa và thời điểm tự động mở lại:
```bash
cat /var/lib/fastnetmon_guard/blocked_ports.db
```
*Định dạng:* `PORT|IP|PROTOCOL|BLOCKED_AT|AUTO_UNBAN_AT|STATUS`  
*Ví dụ:* `25565|192.168.1.36|udp|2026-10-23 00:24:31|2026-10-23 00:39:31|blocked`

---

### 2. Kiểm tra rule iptables ở tầng kernel
Kiểm tra chuỗi `FNM_DDOS_GUARD` trong bảng `raw PREROUTING` để thấy các rule DROP đang có hiệu lực và số lượng packet/byte bị chặn:
```bash
sudo iptables -t raw -L FNM_DDOS_GUARD -v -n
```

---

### 3. Kiểm tra trạng thái lá chắn XDP / eBPF
Xem card mạng có đang chạy XDP Native Mode không và danh sách port/IP đang bị XDP Drop trực tiếp tại L2:
```bash
# Thay ens18 bằng card mạng thực tế của bạn
sudo bash /opt/fastnetmon_guard/compile_xdp.sh status ens18
```

---

### 4. Mở radar theo dõi lưu lượng mạng thời gian thực
Mở bảng điều khiển của FastNetMon để xem số gói tin (PPS), băng thông (Mbps) và số luồng kết nối đang đi vào máy:
```bash
sudo fastnetmon_client
```
*(Bấm phím `q` để thoát).*

---

### 5. Theo dõi log hoạt động của Guard theo thời gian thực
Xem trực tiếp lịch sử phát hiện DDoS, port bị cách ly, gọi API Pterodactyl và bắn Discord:
```bash
tail -f /var/log/fastnetmon_guard/guard.log
```

---

### 6. Quản lý dịch vụ FastNetMon
```bash
# Khởi động lại dịch vụ
sudo systemctl restart fastnetmon

# Xem trạng thái hoạt động
sudo systemctl status fastnetmon

# Xem log hệ thống của FastNetMon
sudo journalctl -u fastnetmon -f
```

---

## 📄 Giấy phép

Dự án này được phát hành dưới giấy phép [MIT](LICENSE).
Mọi đóng góp (Pull Request & Issue) đều được hoan nghênh!
