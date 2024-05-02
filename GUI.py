import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import threading

# Импорт необходимых функций
from blocknreload import start_monitoring, stop_monitoring, show_blocked_ips, set_limit, create_table, get_blocked_ips

app = tk.Tk()
app.title("DDoS Monitoring Tool")

# Создание вкладок
tab_control = ttk.Notebook(app)

# Вкладка управления
control_tab = ttk.Frame(tab_control)
tab_control.add(control_tab, text='Control')

# Вкладка просмотра базы данных
data_tab = ttk.Frame(tab_control)
tab_control.add(data_tab, text='Database View')
tab_control.pack(expand=1, fill='both')

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

# Элементы управления на вкладке Control
start_button = tk.Button(control_tab, text="Start Monitoring", command=lambda: start_monitoring_gui())
start_button.pack(pady=5)

stop_button = tk.Button(control_tab, text="Stop Monitoring", command=lambda: stop_monitoring_gui())
stop_button.pack(pady=5)

create_button = tk.Button(control_tab, text="Create table", command=lambda: create_table_gui())
create_button.pack(pady=5)

show_button = tk.Button(control_tab, text="Show Blocked IPs", command=lambda: show_ips())
show_button.pack(pady=5)

limit_label = tk.Label(control_tab, text="Set Request Limit:")
limit_label.pack()

limit_entry = tk.Entry(control_tab)
limit_entry.pack()

set_limit_button = tk.Button(control_tab, text="Set Limit", command=lambda: set_limit_gui())
set_limit_button.pack(pady=5)

# Таблица для отображения данных на вкладке Database View
tree = ttk.Treeview(data_tab)
tree['columns'] = ("IP Address", "Block Time")
tree.column("#0", width=0, stretch=tk.NO)
tree.column("IP Address", anchor=tk.W, width=120)
tree.column("Block Time", anchor=tk.W, width=120)

tree.heading("#0", text="", anchor=tk.W)
tree.heading("IP Address", text="IP Address", anchor=tk.W)
tree.heading("Block Time", text="Block Time", anchor=tk.W)

tree.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

def update_database_view():
    """Fetch data from the database and update the Treeview."""
    for i in tree.get_children():
        tree.delete(i)
    blocked_ips = get_blocked_ips()  # This function needs to return a list of tuples (ip_address, block_time)
    for ip in blocked_ips:
        tree.insert("", tk.END, values=(ip[0], ip[1]))

# Обновление данных при переключении на вкладку Database View
def on_tab_selected(event):
    selected_tab = event.widget.select()
    tab_text = event.widget.tab(selected_tab, "text")
    if tab_text == "Database View":
        update_database_view()

tab_control.bind("<<NotebookTabChanged>>", on_tab_selected)

app.mainloop()
