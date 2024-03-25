import re
from collections import Counter
import os

def analyze_log(log_file_path):
    ip_counter = Counter()

    with open(log_file_path, 'r') as log_file:
        for line in log_file:
            match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
            if match:
                ip_address = match.group(0)
                ip_counter[ip_address] += 1

    return ip_counter

def block_ips(ip_counter, threshold):
    blocked_ips = []
    for ip, count in ip_counter.items():
        if count > threshold:
            blocked_ips.append(ip)
            # Добавляем правило блокировки в конфигурационный файл Nginx
            with open('/etc/nginx/nginx.conf', 'a') as nginx_conf:
                nginx_conf.write(f"\n\n# Blocked IP: {ip}\n")
                nginx_conf.write(f"location / {\n")
                nginx_conf.write(f"    deny {ip};\n")
                nginx_conf.write(f"}\n")
            print(f"Blocked IP: {ip} with {count} requests")

    return blocked_ips

def print_top_ips(ip_counter, top_count=10):
    print("Top {} IP addresses:".format(top_count))
    for ip, count in ip_counter.most_common(top_count):
        print("{}: {} requests".format(ip, count))

if __name__ == "__main__":
    log_file_path = 'path/to/your/nginx/access.log' # Укажите путь к вашему файлу логов Nginx
    threshold = 100 # Задайте порог запросов для блокировки
    ip_counter = analyze_log(log_file_path)
    print_top_ips(ip_counter)
    block_ips(ip_counter, threshold)
