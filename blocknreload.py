import subprocess
import re
import time
import threading
import sys
import os

# Настройки для обнаружения DDoS-атаки
LIMIT = 100  # Изначальное значение лимита запросов
LOG_FILE_PATH = "/var/log/nginx/access.log"
NGINX_BLOCKED_IPS_FILE = "/etc/nginx/blocked_ips.conf"

# Глобальная переменная для управления мониторингом
running = False

# Установка лимита оператором
def set_limit(new_limit):
    global LIMIT
    LIMIT = new_limit
    print(f"Новый лимит установлен: {LIMIT} запросов")

# Блокировка IP-адреса
def block_ip(ip_address):
    already_blocked = False

    # Проверка наличия IP-адреса в списке заблокированных
    if os.path.exists(NGINX_BLOCKED_IPS_FILE):
        with open(NGINX_BLOCKED_IPS_FILE, "r") as file:
            for line in file:
                if f"deny {ip_address};" in line:
                    already_blocked = True
                    break

    # Блокировка IP-адреса, если он еще не заблокирован
    if not already_blocked:
        with open(NGINX_BLOCKED_IPS_FILE, "a") as file:
            file.write(f"deny {ip_address};\n")
        os.system("nginx -s reload")
        print(f"Blocked IP in Nginx: {ip_address}")
    else:
        print(f"IP уже заблокирован: {ip_address}")

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

def process_log_line(line, ip_details):
    ip_address = re.findall(r'[0-9]+(?:\.[0-9]+){3}', line)
    if ip_address:
        ip = ip_address[0]
        if ip not in ip_details:
            ip_details[ip] = {"count": 0, "start_time": time.time(), "end_time": time.time(), "alerted": False, "blocked": False}

        # Проверка, не заблокирован ли уже IP
        if ip_details[ip]["blocked"]:
            return

        ip_details[ip]["count"] += 1
        ip_details[ip]["end_time"] = time.time()

        dtime = max(ip_details[ip]["end_time"] - ip_details[ip]["start_time"], 1)
        curkoef = LIMIT / dtime
        limkoef = LIMIT / 60
        r = limkoef / curkoef

        if r > 1:
            block_ip(ip)
            ip_details[ip]["blocked"] = True
        elif 0.85 <= r <= 1 and not ip_details[ip]["alerted"]:
            print(f"Внимание: возможное начало атаки от {ip}")
            ip_details[ip]["alerted"] = True
        # В противном случае, считаем трафик нормальным

# Мониторинг лог-файла
def monitor_log_file():
    ip_details = {}
    process = subprocess.Popen(['tail', '-F', LOG_FILE_PATH], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    while running:
        line = process.stdout.readline().decode('utf-8')
        if not line:
            time.sleep(0.1)
            continue
        process_log_line(line, ip_details)

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
    ip_details = {}  # Словарь для хранения деталей по IP-адресам
    while True:
        command = input("Введите команду ('start', 'stop', 'show', 'set', 'exit'): ")
        if command == "start":
            start_monitoring()
        elif command == "stop":
            stop_monitoring()
        elif command == "show":
            show_blocked_ips()
        elif command == "set":
            try:
                new_limit = int(input("Введите новый лимит запросов: "))
                set_limit(new_limit)
            except ValueError:
                print("Ошибка: Введите целое число.")
        elif command == "exit":
            if running:
                stop_monitoring()
            print("Выход из программы.")
            sys.exit(0)