# ⚡ CYBER SOC DASHBOARD - AAA ACCOUNTING INTEGRATION

Hệ thống giám sát an ninh mạng (SOC Dashboard) tích hợp xác thực và ghi nhật ký tập trung (AAA) thông qua FreeRADIUS và OpenVPN. Thay vì phân tích log thủ công, hệ thống sử dụng cơ sở dữ liệu SQL để quản lý phiên người dùng và kết hợp với Snort để phân tích rủi ro thời gian thực.

## 📊 Phân nhóm dữ liệu

| Nhóm dữ liệu | Thành phần | Nguồn lấy |
| :--- | :--- | :--- |
| **Định danh** | Username, IP, Thời gian Start | MariaDB (RADIUS) |
| **Hoạt động** | Upload, Download, Online Time | MariaDB (RADIUS) |
| **An ninh** | Ping, Scan, HTTP, Risk Score | Snort Log + Python |
| **Cảnh báo** | Login/Logout, Spike Alerts | SocketIO (Real-time) |

## 🛠️ Yêu cầu hệ thống
- **Hệ điều hành**: Linux (Ubuntu/Debian)
- **Dịch vụ**: FreeRADIUS, MySQL/MariaDB, OpenVPN, Snort
- **Ngôn ngữ**: Python 3.x

---

## 🚀 Các bước cài đặt

### 1. Cấu hình FreeRADIUS & MySQL
Để RADIUS có thể lưu dữ liệu phiên (Accounting) vào Database:

1. **Khởi tạo Database và User**:
   Đăng nhập vào MySQL (`sudo mysql -u root -p`) và chạy các lệnh:
   ```sql
   CREATE DATABASE radius;
   CREATE USER 'radius'@'localhost' IDENTIFIED BY 'radpass';
   GRANT ALL PRIVILEGES ON radius.* TO 'radius'@'localhost';
   FLUSH PRIVILEGES;
   ```
2. **Bật module SQL trong FreeRADIUS**:
   ```bash
   sudo ln -s /etc/freeradius/3.0/mods-available/sql /etc/freeradius/3.0/mods-enabled/
   ```
3. **Cấu hình kết nối**:
   Chỉnh sửa file `/etc/freeradius/3.0/mods-enabled/sql`, cập nhật thông tin trong khối `sql { ... }`:
   ```conf
    sql {
        driver = "rlm_sql_mysql"
        dialect = "mysql"
        server = "localhost"
        port = 3306
        login = "radius"
        password = "radpass"
        radius_db = "radius"
    }
   ```
4. **Kích hoạt Accounting SQL**:
   Mở `/etc/freeradius/3.0/sites-enabled/default`, tìm phần `accounting { ... }` và đảm bảo có dòng `sql` (hoặc `-sql`).
5. **Khởi tạo cấu trúc bảng (Import Schema)**:
   ```bash
   sudo cat /etc/freeradius/3.0/mods-config/sql/main/mysql/schema.sql | sudo mysql -u root -p radius
   ```

### 2. Cấu hình OpenVPN
Sử dụng plugin `radiusplugin` để kết nối OpenVPN với RADIUS.

1. **Cấu hình Plugin**: Chỉnh sửa `/etc/openvpn/radiusplugin.conf` để trỏ về RADIUS Server (127.0.0.1) với port `1812` và `1813`.
2. **Kích hoạt trong Server**: Thêm dòng sau vào `/etc/openvpn/server.conf`:
   ```conf
   plugin /usr/lib/openvpn/openvpn-radius-plugin.so /etc/openvpn/radiusplugin.conf
   ```

### 3. Cài đặt Dashboard (Python)
1. **Cài đặt thư viện**:
   ```bash
   pip install flask flask-socketio mysql-connector-python
   ```
2. **Cấu hình Database**:
   Mở `app.py` và cập nhật biến `DB_CONFIG` với thông tin Database RADIUS của bạn.
3. **Chạy ứng dụng**:
   ```bash
   python app.py
   ```

## 🛡️ Cơ chế tính toán rủi ro (Risk Analysis)
Hệ thống sử dụng Snort để theo dõi các IP được cấp từ RADIUS:
- **Ping**: +1 điểm rủi ro.
- **HTTP Alert**: +0.5 điểm rủi ro.
- **Port Scan**: +3 điểm rủi ro.

Mức độ cảnh báo:
- 🟢 **LOW**: Risk < 10
- 🟡 **MEDIUM**: 10 <= Risk < 20
- 🔴 **HIGH**: Risk >= 20

---
**Author**: TranXuanDuc28
**Repository**: [AAA-Accounting](https://github.com/TranXuanDuc28/AAA-Accounting.git)
