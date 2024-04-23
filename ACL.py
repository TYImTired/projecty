import subprocess
import re
import time
import threading
import sys
import os
import sqlite3

# Настройки для обнаружения DDoS-атаки
LIMIT = 100  # Изначальное значение лимита запросов
LOG_FILE_PATH = "/var/log/nginx/access.log"
NGINX_BLOCKED_IPS_FILE = "/etc/nginx/blocked_ips.conf"

# Глобальная переменная для управления мониторингом
running = False

def connect_db():
    try:
        return sqlite3.connect("blocked_ips.db")
    except sqlite3.Error as e:
        print(f"Database connection error: {e}")
        return None

def create_table():
    conn = connect_db()
    if conn is not None:
        try:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    block_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    block_duration INTEGER DEFAULT 1  -- Duration of the block in minutes
                );
            """)
            conn.commit()
        except sqlite3.Error as e:
            print(f"Error creating table: {e}")
        finally:
            conn.close()


def set_limit(new_limit):
    global LIMIT
    LIMIT = new_limit
    print(f"New limit set: {LIMIT} requests per minute")

request_details = {}

def classify_traffic(ip, line):
    request_size_threshold = 5000  # Example size threshold in bytes
    request_rate_threshold = 100   # Example rate threshold per minute
    content_length_match = re.search(r"Content-Length: (\d+)", line)
    content_length = int(content_length_match.group(1)) if content_length_match else 0

    current_time = time.time()
    if ip not in request_details:
        request_details[ip] = {"count": 1, "start_time": current_time}
    else:
        request_details[ip]["count"] += 1
        if (current_time - request_details[ip]["start_time"]) > 60:
            request_details[ip] = {"count": 1, "start_time": current_time}

    if request_details[ip]["count"] > request_rate_threshold or content_length > request_size_threshold:
        return True
    return False

def block_ip(ip_address):
    conn = connect_db()
    if conn is not None:
        try:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO blocked_ips (ip_address, block_duration) VALUES (?, 1) ON CONFLICT(ip_address) DO UPDATE SET block_duration = block_duration * 2", (ip_address,))
            conn.commit()
        except sqlite3.Error as e:
            print(f"Error blocking IP: {e}")
        finally:
            conn.close()
        update_nginx_configuration()

def update_nginx_configuration():
    conn = connect_db()
    if conn is not None:
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT ip_address FROM blocked_ips WHERE block_time + block_duration * 60 > strftime('%s', 'now')")
            active_blocks = cursor.fetchall()
            with open(NGINX_BLOCKED_IPS_FILE, "w") as file:
                for ip in active_blocks:
                    file.write(f"deny {ip[0]};\n")
            os.system("nginx -s reload")
        except Exception as e:
            print(f"Error updating NGINX configuration: {e}")
        finally:
            conn.close()

def process_log_line(line):
    ip_address = re.search(r'[0-9]+(?:\.[0-9]+){3}', line).group(0)
    if ip_address and classify_traffic(ip_address, line):
        print(f"Malicious traffic detected from IP: {ip_address}")
        block_ip(ip_address)

def monitor_log_file():
    process = subprocess.Popen(['tail', '-F', LOG_FILE_PATH], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    while running:
        line = process.stdout.readline().decode('utf-8').strip()
        if line:
            process_log_line(line)

def start_monitoring():
    global running
    running = True
    monitoring_thread = threading.Thread(target=monitor_log_file)
    monitoring_thread.daemon = True
    monitoring_thread.start()
    print("Monitoring started.")

def stop_monitoring():
    global running
    running = False
    print("Monitoring stopped.")

if __name__ == "__main__":
    create_table()
    start_monitoring()  # Automatically start monitoring at script start
    try:
        while True:
            time.sleep(60)
            update_nginx_configuration()  # Periodically update NGINX configuration
    except KeyboardInterrupt:
        stop_monitoring()
