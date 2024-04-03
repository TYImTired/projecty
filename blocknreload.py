import subprocess
import re
import time
import threading
import sys
import os

# Настройки для обнаружения DDoS-атаки
MAX_REQUESTS_PER_MINUTE = 100
MAX_POST_REQUESTS = 50
LOG_FILE_PATH = "/var/log/nginx/access.log"
NGINX_BLOCKED_IPS_FILE = "/etc/nginx/blocked_ips.conf"

# Глобальная переменная для управления мониторингом
running = False

# Блокировка IP-адреса
def block_ip(ip_address):
    with open(NGINX_BLOCKED_IPS_FILE, "a") as file:
        file.write(f"deny {ip_address};\n")
    os.system("nginx -s reload")
    print(f"Blocked IP in Nginx: {ip_address}")


# Просмотр заблокированных IP-адресов
def show_blocked_ips():
    if not os.path.exists(NGINX_BLOCKED_IPS_FILE):
        print("Файл заблокированных IP не найден.")
        return
    with open(NGINX_BLOCKED_IPS_FILE, "r") as file:
        blocked_ips = file.readlines()
    if blocked_ips:
        print("Заблокированные IP-адреса:")
        for ip in blocked_ips:
            print(ip.strip())
    else:
        print("Нет заблокированных IP-адресов.")

# Обработка строки лога
def process_log_line(line, ip_counter, post_request_counter):
    ip_address = re.findall(r'[0-9]+(?:\.[0-9]+){3}', line)
    if ip_address:
        ip = ip_address[0]

        # Инициализация счетчика для нового IP-адреса, если он еще не встречался
        ip_counter[ip] = ip_counter.get(ip, 0)
        post_request_counter[ip] = post_request_counter.get(ip, 0)

        # Здесь уже можно безопасно использовать ip_counter[ip] и post_request_counter[ip]
        request_type = "POST" if "POST" in line else "GET"
        ip_counter[ip] += 1
        if request_type == "POST":
            post_request_counter[ip] += 1

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
    while True:
        command = input("Введите 'start' для запуска, 'stop' для остановки, 'show' для просмотра заблокированных IP, или 'exit' для выхода: ")
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
        elif command == "show":
            show_blocked_ips()
        elif command == "exit":
            if running:
                stop_monitoring()
            print("Выход из программы.")
            sys.exit(0)
