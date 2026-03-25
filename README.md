#  WebIDS-ModSec-SIEM: Centralized Web Intrusion Detection & Alerting System

## Giới thiệu (Overview)

Dự án này là một hệ thống Giám sát và Cảnh báo An toàn thông tin Web (Web IDS/SIEM) được xây dựng theo kiến trúc **Phòng thủ chiều sâu (Defense in Depth)**.

Hệ thống kết hợp sức mạnh ngăn chặn mạnh mẽ của Web Application Firewall (WAF) ở Tầng ứng dụng (Layer 7) và khả năng lưu trữ, phân tích log tập trung của hệ sinh thái SIEM. Đặc biệt, hệ thống được tích hợp module Python Automation để gửi cảnh báo tấn công theo thời gian thực (Real-time Alerting) đến đội ngũ quản trị qua Telegram.

---

## Kiến trúc Hệ thống (System Architecture)

Hệ thống được chia làm 2 vùng (Zone) hoạt động độc lập:

1. **Vùng Phòng thủ (Defense Zone):**
   - Sử dụng **ModSecurity (WAF)** hoạt động như một Reverse Proxy để lọc traffic độc hại trước khi tiến vào Web Server (DVWA).
   - Chặn đứng các cuộc tấn công Web phổ biến: SQL Injection, XSS, Command Injection,...

2. **Vùng Giám sát & Cảnh báo (SOC / SIEM Zone):**
   - **Filebeat:** Thu thập log của ModSecurity ngay lập tức.
   - **Elasticsearch & Kibana:** Lưu trữ log tập trung, tương quan dữ liệu và hiển thị Dashboard giám sát.
   - **Python Alerting Module:** Tự động truy vấn API của Elasticsearch để phát hiện các hành vi vượt mặt WAF (như Brute Force) và đẩy cảnh báo khẩn cấp về Telegram.

---

## 🚀 Tính năng nổi bật (Key Features)

- **Real-time Blocking:** Chặn tự động các payload độc hại dựa trên bộ luật OWASP CRS.
- **Centralized Logging:** Gom log từ nhiều nguồn về một mối, dễ dàng truy vết (Forensics) và phân tích sự cố.
- **Automated Telegram Alerts:** Bot giám sát 24/7, tự động bóc tách IP Hacker, loại tấn công, thời gian và thông báo trực tiếp qua Telegram.
- **Containerized Environment:** Toàn bộ hạ tầng được đóng gói bằng Docker & Docker Compose, dễ dàng triển khai ở bất kỳ đâu.

---

## Công nghệ sử dụng (Tech Stack)

- **Infrastructure:** Docker, Docker Compose, Linux (Ubuntu)
- **Security / WAF:** ModSecurity (Nginx), OWASP Core Rule Set
- **SIEM:** Filebeat, Elasticsearch, Kibana
- **Automation / Scripting:** Python 3, Telegram Bot API, KQL (Kibana Query Language)

---

## Cấu trúc Thư mục (Folder Structure)
```text
WebIDS-ModSec-SIEM/
├── docker-compose.yml       # File khởi tạo toàn bộ hạ tầng mạng và container
├── .env                     # (Ignored) File chứa cấu hình bảo mật & Token Telegram
├── filebeat/                # Cấu hình Filebeat thu thập log
├── modsecurity/             # Cấu hình Nginx, ModSec và Rate Limit
├── telegram_alert.py        # Script Python giám sát và cảnh báo thời gian thực
└── README.md
```

---

## Hướng dẫn cài đặt (Installation & Setup)

**1. Clone kho lưu trữ:**
```bash
git clone https://github.com/thanhhieutiet/WebIDS-ModSec-SIEM.git
cd WebIDS-ModSec-SIEM
```

**2. Cấu hình biến môi trường:**

Tạo file `.env` tại thư mục gốc và cấu hình API Key của Telegram:
```env
TELEGRAM_BOT_TOKEN="your_bot_token_here"
TELEGRAM_CHAT_ID="your_chat_id_here"
```

**3. Khởi chạy hệ thống:**
```bash
docker-compose up -d
```

**4. Khởi động Module Cảnh báo:**
```bash
python3 telegram_alert.py
```

---

## Lộ trình Phát triển (Roadmap)

- [x] **Phase 1:** Triển khai WAF ModSecurity và ELK Stack.
- [x] **Phase 2:** Phát triển module cảnh báo tự động qua Telegram (SQLi, XSS, Brute Force).
- [ ] **Phase 3 (Upcoming):** Tích hợp AI (Mô hình Deep Learning TabNet/FT-Transformer) phân tích NetFlow (L3/L4) để phát hiện và cảnh báo các cuộc tấn công DDoS, Botnet, Network Brute Force.
- [ ] **Phase 4 (Upcoming):** Nâng cấp từ IDS lên IPS: Tự động gọi lệnh Firewall Hệ điều hành (`iptables`/`ufw`) để khóa vĩnh viễn IP Hacker.
