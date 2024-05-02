import tkinter as tk
from tkinter import messagebox
import threading

# Импорт необходимых функций
from blocknreload import start_monitoring, stop_monitoring, show_blocked_ips, set_limit, create_table

def run_monitoring():
    monitoring_thread = threading.Thread(target=start_monitoring)
    monitoring_thread.daemon = True
    monitoring_thread.start()

def stop_monitoring_gui():
    stop_monitoring()
    messagebox.showinfo("Monitoring", "Мониторинг остановлен.")

def start_monitoring_gui():
    run_monitoring()
    messagebox.showinfo("Monitoring", "Мониторинг запущен.")

def show_ips():
    ips = show_blocked_ips()
    messagebox.showinfo("Blocked IPs:", ips)

def set_limit_gui():
    limit = limit_entry.get()
    try:
        limit = int(limit)
        set_limit(limit)
        messagebox.showinfo("Set Limit", f"Лимит установлен: {limit}")
    except ValueError:
        messagebox.showerror("Error", "Введите целое число.")

def create_table_gui():
    create_table()
    messagebox.showinfo("Таблица создана")

app = tk.Tk()
app.title("DDoS Monitoring Tool")

start_button = tk.Button(app, text="Start Monitoring", command=start_monitoring_gui)
start_button.pack(pady=5)

stop_button = tk.Button(app, text="Stop Monitoring", command=stop_monitoring_gui)
stop_button.pack(pady=5)

create_button = tk.Button(app, text="Create table", command=create_table_gui)
create_button.pack(pady=5)

show_button = tk.Button(app, text="Show Blocked IPs", command=show_ips)
show_button.pack(pady=5)

limit_label = tk.Label(app, text="Set Request Limit:")
limit_label.pack()

limit_entry = tk.Entry(app)
limit_entry.pack()

set_limit_button = tk.Button(app, text="Set Limit", command=set_limit_gui)
set_limit_button.pack(pady=5)

app.mainloop()
