import mysql.connector
from mysql.connector import Error
from flask import Flask, render_template
from flask_socketio import SocketIO
import time
import re
from collections import Counter
from datetime import datetime

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ===== CONFIGURATION =====
SNORT_LOG = "/var/log/snort/alert"

# FreeRADIUS MySQL Config (Cập nhật thông tin DB của bạn tại đây)
DB_CONFIG = {
    "host": "localhost",
    "user": "radius",
    "password": "radpass",  # Thay bằng password thật của user radius
    "database": "radius"
}

prev_users_set = set()
prev_stats = {"PING": 0, "SCAN": 0, "HTTP": 0}


@app.route("/")
def index():
    return render_template("index.html")


# ===== DATABASE CONNECTION =====
def get_db_connection():
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        if connection.is_connected():
            return connection
    except Error as e:
        print(f"Error connecting to MySQL: {e}")
    return None


# ===== READ SNORT LOG =====
def get_recent_snort_logs(n=300):
    try:
        with open(SNORT_LOG, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            block = 1024
            data = b""

            while size > 0 and data.count(b"\n") < n:
                step = min(block, size)
                f.seek(size - step)
                data = f.read(step) + data
                size -= step

        return data.decode(errors="ignore").splitlines()
    except Exception as e:
        print(f"Snort Log Error: {e}")
        return []


# ===== RADIUS ACCOUNTING USERS =====
def get_vpn_users_from_radius():
    users = []
    conn = get_db_connection()
    if not conn:
        return users

    try:
        cursor = conn.cursor(dictionary=True)
        # Query lấy các session đang hoạt động và băng thông
        query = """
            SELECT 
                username as user, 
                framedipaddress as ip, 
                acctstarttime as start_time,
                acctinputoctets as upload,
                acctoutputoctets as download
            FROM radacct 
            WHERE acctstoptime IS NULL
        """
        cursor.execute(query)
        rows = cursor.fetchall()
        
        now = datetime.now()
        for row in rows:
            start = row['start_time']
            duration_seconds = int((now - start).total_seconds())
            
            # Chuyển đổi Bytes sang MB cho dễ đọc
            up_mb = round(row['upload'] / (1024 * 1024), 2)
            down_mb = round(row['download'] / (1024 * 1024), 2)
            
            users.append({
                "user": row['user'],
                "ip": row['ip'],
                "epoch": int(start.timestamp()),
                "online_raw": duration_seconds,
                "upload": up_mb,
                "download": down_mb
            })
    except Error as e:
        print(f"RADIUS Query Error: {e}")
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()
            
    return users


# ===== PARSE SNORT LOG =====
def parse_snort_line(line):
    # Regex tìm IP nguồn và đích
    ip = re.search(r"(\d+\.\d+\.\d+\.\d+).*->\s*(\d+\.\d+\.\d+\.\d+)", line)
    proto = re.search(r"\{(.*?)\}", line)

    if not ip:
        return None

    src, dst = ip.groups()
    proto = proto.group(1) if proto else ""

    if "ICMP" in proto:
        t = "PING"
    elif "HTTP" in line:
        t = "HTTP"
    elif "TCP" in proto:
        t = "SCAN"
    else:
        t = "OTHER"

    return {"src": src, "dst": dst, "type": t, "raw": line}


# ===== ANALYZE =====
def analyze():
    global prev_users_set, prev_stats

    # 1. Lấy dữ liệu Snort (Dành cho Risk Analysis)
    snort_raw = get_recent_snort_logs()
    parsed_alerts = [p for p in (parse_snort_line(l) for l in snort_raw) if p]
    stats = Counter([p["type"] for p in parsed_alerts])

    # 2. Lấy dữ liệu VPN từ RADIUS Accounting
    vpn_users = get_vpn_users_from_radius()
    
    users_data = []
    now_ts = int(time.time())

    for u in vpn_users:
        ip = u["ip"]
        # Lọc logs của riêng user này từ Snort Alerts
        user_logs = [p for p in parsed_alerts if ip in (p["src"], p["dst"])]

        ping = [p for p in user_logs if p["type"] == "PING"]
        scan = [p for p in user_logs if p["type"] == "SCAN"]
        http = [p for p in user_logs if p["type"] == "HTTP"]

        # Tính Risk Score
        risk = len(scan)*3 + len(ping) + len(http)*0.5

        level = "LOW"
        if risk > 20: level = "HIGH"
        elif risk > 10: level = "MEDIUM"

        users_data.append({
            "user": u["user"],
            "ip": ip,
            "online": f"{u['online_raw'] // 60}m",
            "upload": f"{u['upload']} MB",
            "download": f"{u['download']} MB",
            "ping": len(ping),
            "scan": len(scan),
            "http": len(http),
            "risk": int(risk),
            "level": level,
            "ping_logs": [x["raw"] for x in ping][-5:],
            "scan_logs": [x["raw"] for x in scan][-5:],
            "http_logs": [x["raw"] for x in http][-5:]
        })

    # 3. Quản lý Events (Login/Logout)
    current_set = set(u["ip"] for u in users_data)
    events = {
        "login": list(current_set - prev_users_set),
        "logout": list(prev_users_set - current_set),
        "alerts": []
    }

    if stats["SCAN"] > prev_stats.get("SCAN", 0) + 5:
        events["alerts"].append("🚨 Scan spike detected!")

    prev_users_set = current_set
    prev_stats = stats

    return {"stats": stats, "users": users_data, "events": events}


# ===== REALTIME STREAM =====
def stream():
    while True:
        try:
            socketio.emit("update", analyze())
        except Exception as e:
            print(f"Stream Error: {e}")
        socketio.sleep(2)


@socketio.on("connect")
def connect():
    print(f"Dashboard Client connected at {datetime.now()}")


if __name__ == "__main__":
    # Lưu ý: Cần cài đặt mysql-connector-python
    socketio.start_background_task(stream)
    socketio.run(app, host="0.0.0.0", port=5000)
