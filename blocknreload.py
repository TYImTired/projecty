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

# Подключение к базе данных
def connect_db():
    return sqlite3.connect("blocked_ips.db")

# Создание таблицы, если она еще не создана
def create_table():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            block_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()
    conn.close()

# Установка лимита оператором
def set_limit(new_limit):
    global LIMIT
    LIMIT = new_limit
    print(f"Новый лимит установлен: {LIMIT} запросов")

# Класс ACL для управления списками доступа
class ACL:
    def __init__(self):
        self.rules = []  # Список для хранения правил

    def add_rule(self, action, ip_address):
        self.rules.append((action, ip_address))

    def check_ip(self, ip_address):
        for action, rule_ip in self.rules:
            if rule_ip == ip_address:
                return action == 'permit'
        return False  # implicit deny

    def list_rules(self):
        return self.rules

# Создание экземпляра ACL
acl = ACL()

# Блокировка IP-адреса
def block_ip(ip_address):
    already_blocked = False
    if os.path.exists(NGINX_BLOCKED_IPS_FILE):
        with open(NGINX_BLOCKED_IPS_FILE, "r") as file:
            for line in file:
                if f"deny {ip_address};" in line:
                    already_blocked = True
                    break
    if not already_blocked:
        with open(NGINX_BLOCKED_IPS_FILE, "a") as file:
            file.write(f"deny {ip_address};\n")
        os.system("nginx -s reload")
        add_blocked_ip_to_db(ip_address)
        print(f"Blocked IP in Nginx and added to DB: {ip_address}")
    else:
        print(f"IP уже заблокирован: {ip_address}")

# Добавление заблокированного IP в базу данных
def add_blocked_ip_to_db(ip_address):
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO blocked_ips (ip_address) VALUES (?)", (ip_address,))
    conn.commit()
    conn.close()

# Обработка строки лога
def process_log_line(line, ip_details):
    ip_address = re.findall(r'[0-9]+(?:\.[0-9]+){3}', line)
    if ip_address:
        ip = ip_address[0]
        if not acl.check_ip(ip):  # Проверка по ACL
            print(f"Access denied for IP: {ip} by ACL")
            return  # Пропустить обработку этого IP
        # Продолжить обработку, если доступ разрешен
        if ip not in ip_details:
            ip_details[ip] = {"count": 0, "start_time": time.time(), "end_time": time.time(), "alerted": False, "blocked": False}
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
    monitoring_thread.daemon = True  # Сделать поток демоническим
    monitoring_thread.start()
    print("Мониторинг запущен.")

def stop_monitoring():
    global running
    running = False
    print("Мониторинг остановлен.")

# Главный цикл управления
if __name__ == "__main__":
    create_table()  # Убедиться, что таблица для IP-адресов создана
    while True:
        command = input("Введите команду ('start', 'stop', 'show', 'set', 'acl', 'exit'): ")
        if command == "start":
            if not running:
                start_monitoring()
            else:
                print("Мониторинг уже запущен.")
        elif command == "stop":
            if running:
                stop_monitoring()
            else:
                print("Мониторинг не запущен.")
        elif command == "show":
            show_blocked_ips()
        elif command == "set":
            try:
                new_limit = int(input("Введите новый лимит запросов: "))
                if new_limit > 0:
                    set_limit(new_limit)
                else:
                    print("Ошибка: Лимит должен быть положительным числом.")
            except ValueError:
                print("Ошибка: Введите целое число.")
        elif command == "acl":
            action = input("Введите действие (add, remove, list): ")
            if action == "add":
                ip_action = input("Введите действие (permit/deny) для IP: ")
                ip = input("Введите IP-адрес: ")
                acl.add_rule(ip_action, ip)
            elif action == "remove":
                ip = input("Введите IP-адрес для удаления: ")
                acl.rules = [rule for rule in acl.rules if rule[1] != ip]
                print(f"Правило для {ip} удалено.")
            elif action == "list":
                for rule in acl.list_rules():
                    print(f"{rule[0]} {rule[1]}")
        elif command == "exit":
            if running:
                stop_monitoring()
            print("Выход из программы.")
            sys.exit(0)
