import tkinter as tk
from tkinter import ttk, messagebox
import threading

from ACL import create_table, monitor_log_file, update_nginx_configuration

def start_monitoring():
    global running
    if not running:
        running = True
        monitoring_thread = threading.Thread(target=monitor_log_file, daemon=True)
        monitoring_thread.start()
        status_label.config(text="Monitoring: Running")
        print("Monitoring started.")
    else:
        messagebox.showinfo("Info", "Monitoring is already running.")

def stop_monitoring():
    global running
    if running:
        running = False
        status_label.config(text="Monitoring: Stopped")
        print("Monitoring stopped.")
    else:
        messagebox.showinfo("Info", "Monitoring is not active.")

def update_configuration():
    try:
        update_nginx_configuration()
        messagebox.showinfo("Success", "NGINX configuration updated successfully.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to update configuration: {e}")

def create_gui():
    root = tk.Tk()
    root.title("NGINX IP Blocker Management")

    # Start Button
    start_button = ttk.Button(root, text="Start Monitoring", command=start_monitoring)
    start_button.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

    # Stop Button
    stop_button = ttk.Button(root, text="Stop Monitoring", command=stop_monitoring)
    stop_button.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

    # Update Button
    update_button = ttk.Button(root, text="Update NGINX Config", command=update_configuration)
    update_button.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky="ew")

    # Status Label
    global status_label
    status_label = ttk.Label(root, text="Monitoring: Not Running", font=('Helvetica', 10))
    status_label.grid(row=2, column=0, columnspan=2, padx=10, pady=10)

    root.mainloop()

if __name__ == "__main__":
    create_table()  # Make sure our database is ready before starting the GUI
    create_gui()