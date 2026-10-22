# 🛡️ FastNetMon DDoS Guard for Game Server Hosting

Hệ thống phát hiện DDoS tự động bằng **FastNetMon Community** kết hợp kịch bản ngắt **đúng PORT bị tấn công ở tầng Kernel (iptables raw PREROUTING)** dành riêng cho Game Hosting (Pterodactyl / Docker / Dedicated Server).

---

## 🎯 Điểm Nổi Bật

- ⚡ **Chỉ ngắt đúng PORT bị tấn công**: Không làm sập cả IP máy chủ, các game server khác và kết nối SSH (22) vẫn hoạt động 100% bình thường.
- 🚀 **Công nghệ Hybrid XDP / eBPF + iptables raw**: Hỗ trợ drop gói tin siêu tốc ngay tại Ring Buffer Driver của Card mạng với tốc độ **10.000.000 - 20.000.000+ PPS** mà không tốn CPU.
- 🛡️ **Bảo vệ chống khóa ngoài (Anti-Lockout)**: Tuyệt đối không bao giờ ngắt nhầm cổng SSH (22), Web (80/443), Wings API (8080) và Tailscale.
- 🎮 **Profiles game chuyên biệt**: Hỗ trợ tối ưu hóa cấu hình cho:
  - ⛏️ **Minecraft** (Java & Bedrock)
  - 🔫 **SA-MP** (San Andreas Multiplayer)
  - 🚗 **GTA V / FiveM**
  - 🦖 **The Isle**
  - 🕹️ **Custom Game**
- 🚪 **Tùy biến Range Port**: Tự nhập dải port theo thực tế số container trên máy chủ.
- 🤖 **Tùy chọn tích hợp Pterodactyl Panel**: Tự động suspend/unsuspend container game trên Wings.
- 🔔 **Thông báo Discord Webhook**: Bắn thông báo embed đẹp mắt bằng tiếng Việt khi bị tấn công và khi mở lại port.
- ⏱️ **Tự động unban**: Tự mở lại port sau thời gian quy định (mặc định 15 phút).

---

## 📦 Cấu Trúc Dự Án

```text
├── setup_ddos_guard.sh  # Script cài đặt tương tác tự động A-Z (CLI Wizard)
├── notify_script.sh     # Script xử lý trích xuất port, iptables drop, XDP update & Discord alert
├── compile_xdp.sh       # Script quản lý biên dịch, nạp (attach) và gỡ (detach) XDP eBPF
├── xdp_guard.c          # Mã nguồn chương trình eBPF/XDP drop gói tin siêu tốc tại card mạng
├── test_ddos_guard.sh   # Bộ công cụ test mô phỏng toàn diện trước khi đưa vào chạy thật
├── fastnetmon.conf      # File cấu hình mẫu tối ưu cho FastNetMon Community
└── .gitignore
```

---

## 🚀 Cài Đặt Nhanh

### Cách 1: 1-Click Install (Khuyến nghị - Không cần clone git)

Chỉ cần chạy duy nhất 1 dòng lệnh trên máy chủ Linux:

```bash
curl -sSL https://raw.githubusercontent.com/anlongawf/fastnetmon-ddos-guard/main/setup_ddos_guard.sh | sudo bash
```

### Cách 2: Clone repository thủ công

```bash
git clone https://github.com/anlongawf/fastnetmon-ddos-guard.git
cd fastnetmon-ddos-guard
chmod +x setup_ddos_guard.sh test_ddos_guard.sh compile_xdp.sh
sudo bash setup_ddos_guard.sh
```

Trong quá trình chạy, bạn sẽ được chọn loại game, nhập range port, ngưỡng DDoS mong muốn và điền Discord Webhook.

### 3. Kiểm thử hệ thống

Sau khi cài đặt xong, bạn có thể chạy bộ test mô phỏng để đảm bảo iptables, script và FastNetMon hoạt động hoàn hảo:

```bash
sudo bash test_ddos_guard.sh
```

---

## 📊 Xem Trạng Thái Hệ Thống

- **Xem rule iptables đang chặn port:**
  ```bash
  sudo iptables -t raw -L FNM_DDOS_GUARD -v -n
  ```

- **Xem danh sách port đang bị chặn:**
  ```bash
  cat /var/lib/fastnetmon_guard/blocked_ports.db
  ```

- **Theo dõi log bảo vệ thời gian thực:**
  ```bash
  tail -f /var/log/fastnetmon_guard/guard.log
  ```

- **Theo dõi lưu lượng FastNetMon:**
  ```bash
  sudo fastnetmon_client
  ```

---

## 📄 Giấy phép

Dự án này được phát hành dưới giấy phép MIT.
