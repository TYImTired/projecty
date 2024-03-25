import os
import subprocess
import re
import time
import sqlite3
import threading
import sys

# Настройки для обнаружения DDoS-атаки
MAX_REQUESTS_PER_MINUTE = 100
MAX_POST_REQUESTS = 50
LOG_FILE_PATH = "/var/log/nginx/access.log"
NGINX_BLOCKED_IPS_FILE = "/etc/nginx/blocked_ips.conf"

# Глобальная переменная для управления мониторингом
running = False

# Инициализация базы данных
def init_db():
    conn = sqlite3.connect('blocked_ips.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip TEXT PRIMARY KEY,
            block_time TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

# Обновление файла Nginx с заблокированными IP
def update_nginx_blocked_ips():
    conn = sqlite3.connect('blocked_ips.db')
    cursor = conn.cursor()
    cursor.execute('SELECT ip FROM blocked_ips')
    ips = cursor.fetchall()
    with open(NGINX_BLOCKED_IPS_FILE, "w") as file:
        for ip in ips:
            file.write(f"deny {ip[0]};\n")
    conn.close()
    os.system("nginx -s reload")

# Добавление заблокированного IP в базу данных
def log_blocked_ip(ip_address):
    conn = sqlite3.connect('blocked_ips.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO blocked_ips (ip, block_time) VALUES (?, ?)', 
                   (ip_address, time.strftime('%Y-%m-%d %H:%M:%S')))
    conn.commit()
    conn.close()
    update_nginx_blocked_ips()

# Блокировка IP-адреса
def block_ip(ip_address):
    os.system(f"iptables -A INPUT -s {ip_address} -j DROP")
    log_blocked_ip(ip_address)
    print(f"Blocked IP: {ip_address}")

# Обработка строки лога
def process_log_line(line, ip_counter, post_request_counter):
    ip_address = re.findall(r'[0-9]+(?:\.[0-9]+){3}', line)
    if ip_address:
        ip = ip_address[0]
        request_type = "POST" if "POST" in line else "GET"

        ip_counter[ip] = ip_counter.get(ip, 0) + 1
        if request_type == "POST":
            post_request_counter[ip] = post_request_counter.get(ip, 0) + 1

        if ip_counter[ip] > MAX_REQUESTS_PER_MINUTE or post_request_counter[ip] > MAX_POST_REQUESTS:
            block_ip(ip)
            ip_counter[ip] = 0
            post_request_counter[ip] = 0

# Мониторинг лог-файла
def monitor_log_file():
    global running
    ip_counter = {}
    post_request_counter = {}
    process = subprocess.Popen(['tail', '-F', LOG_FILE_PATH], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    while running:
        line = process.stdout.readline().decode('utf-8')
        if not line:
            time.sleep(0.1)
            continue
        process_log_line(line, ip_counter, post_request_counter)

# Функции запуска и остановки мониторинга
def start_monitoring():
    global running
    running = True
    monitoring_thread = threading.Thread(target=monitor_log_file)
    monitoring_thread.start()
    print("Мониторинг запущен.")

def stop_monitoring():
    global running
    running = False
    print("Мониторинг остановлен.")

# Главный цикл управления
if __name__ == "__main__":
    init_db()
    while True:
        command = input("Введите 'start' для запуска, 'stop' для остановки или 'exit' для выхода: ")
        if command == "start":
            if not running:
                start_monitoring()
            else:
                print("Мониторинг уже запущен")
        elif command == "stop":
            if running:
                stop_monitoring()
            else:
                print("Мониторинг не запущен.")
        elif command == "exit":
            if running:
                stop_monitoring()
            print("Выход из программы.")
            sys.exit(0)