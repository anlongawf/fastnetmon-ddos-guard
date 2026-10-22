# 🛡️ FastNetMon DDoS Guard for Game Server Hosting

Hệ thống phát hiện DDoS tự động bằng **FastNetMon Community** kết hợp kịch bản ngắt **đúng PORT bị tấn công ở tầng Kernel (iptables raw PREROUTING)** dành riêng cho Game Hosting (Pterodactyl / Docker / Dedicated Server).

---

## 🎯 Điểm Nổi Bật

- ⚡ **Chỉ ngắt đúng PORT bị tấn công**: Không làm sập cả IP máy chủ, các game server khác và kết nối SSH (22) vẫn hoạt động 100% bình thường.
- 🚀 **Tối ưu tầng Kernel**: Sử dụng bảng `raw PREROUTING` để drop traffic ngay lập tức, không làm nghẽn CPU bởi conntrack.
- 🎮 **Profiles game chuyên biệt**: Hỗ trợ tối ưu hóa cấu hình cho:
  - ⛏️ **Minecraft** (Java & Bedrock)
  - 🔫 **SA-MP** (San Andreas Multiplayer)
  - 🚗 **GTA V / FiveM**
  - 🦖 **The Isle**
  - 🕹️ **Custom Game**
- 🚪 **Tùy biến Range Port**: Tự nhập dải port theo thực tế số container trên máy chủ.
- 🤖 **Tự động hóa với Pterodactyl Panel**: Tự động suspend container bị đánh để giải phóng CPU/RAM, và unsuspend khi hết đợt tấn công.
- 🔔 **Thông báo Discord Webhook**: Bắn thông báo embed đẹp mắt bằng tiếng Việt khi bị tấn công và khi mở lại port.
- ⏱️ **Tự động unban**: Tự mở lại port và unsuspend server sau thời gian quy định (mặc định 15 phút).

---

## 📦 Cấu Trúc Dự Án

```text
├── setup_ddos_guard.sh  # Script cài đặt tương tác tự động A-Z (CLI Wizard)
├── notify_script.sh     # Script xử lý trích xuất port, iptables drop & Discord alert
├── test_ddos_guard.sh   # Bộ công cụ test mô phỏng toàn diện trước khi đưa vào chạy thật
├── fastnetmon.conf      # File cấu hình mẫu tối ưu cho FastNetMon Community
└── .gitignore
```

---

## 🚀 Cài Đặt Nhanh

### 1. Tải về máy chủ

```bash
git clone https://github.com/anlongawf/fastnetmon-ddos-guard.git
cd fastnetmon-ddos-guard
chmod +x setup_ddos_guard.sh test_ddos_guard.sh
```

### 2. Chạy kịch bản cài đặt tự động

```bash
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
