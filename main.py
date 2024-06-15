import psutil
import time
from datetime import datetime
from flask import Flask, request, jsonify
import openai
import os
import sqlite3
import requests
from threading import Thread
from email.mime.text import MIMEText
import smtplib
from dotenv import load_dotenv
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
import fitz  # PyMuPDF

load_dotenv()

app = Flask(__name__)

# OpenAI API configuration
openai.api_key = os.getenv("OPENAI_API_KEY")

# List of suspicious processes to monitor
suspicious_processes = ["powershell.exe", "ftp.exe"]
log_file = "security_monitor.log"
monitoring = True

# Initialize database
def init_db():
    conn = sqlite3.connect('logs.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY, log TEXT)''')
    conn.commit()
    conn.close()

init_db()

def log_event(event):
    with open(log_file, "a") as log:
        log.write(f"{datetime.now()} - {event}\n")

def kill_process(process_name):
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'].lower() == process_name:
            proc.kill()
            log_event(f"Killed process: {process_name}")
            notify_suspicious_process(process_name)

def monitor_processes():
    global monitoring
    while monitoring:
        for proc_name in suspicious_processes:
            kill_process(proc_name)
        time.sleep(1)

def stop_monitoring():
    global monitoring
    monitoring = False

def collect_logs():
    logs = ""
    with open(log_file, "r") as log:
        logs = log.read()
    return logs

def send_logs(logs):
    response = requests.post('http://localhost:5001/analyze_log', json={"log": logs})
    if response.status_code == 200:
        analysis = response.json().get('analysis')
        print(f"Analysis: {analysis}")
        if "threat" in analysis.lower():
            send_email("Security Threat Detected", analysis, "user@example.com")
            messagebox.showwarning("Security Threat Detected", analysis)
    else:
        print("Error sending logs")

def send_email(subject, body, to):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = 'your_email@example.com'
    msg['To'] = to

    with smtplib.SMTP('smtp.example.com', 587) as server:
        server.starttls()
        server.login('your_email@example.com', 'your_password')
        server.sendmail('your_email@example.com', to, msg.as_string())

@app.route('/analyze_log', methods=['POST'])
def analyze_log():
    log = request.json.get('log')

    # Save log to database
    conn = sqlite3.connect('logs.db')
    c = conn.cursor()
    c.execute('INSERT INTO logs (log) VALUES (?)', (log,))
    conn.commit()
    conn.close()

    # Analyze log with OpenAI
    response = openai.Completion.create(
        model="text-davinci-003",
        prompt=f"Analyze this log for security threats: {log}",
        max_tokens=50
    )

    analysis = response.choices[0].text.strip()
    return jsonify({"analysis": analysis})

@app.route('/analyze_file', methods=['POST'])
def analyze_file():
    file_content = request.files['file'].read()

    # Use OpenAI API to analyze the file content
    response = openai.Completion.create(
        model="text-davinci-003",
        prompt=f"Analyze this file for security threats: {file_content}",
        max_tokens=50
    )

    analysis = response.choices[0].text.strip()
    return jsonify({"analysis": analysis})

def start_monitoring_thread():
    global monitor_thread
    monitor_thread = Thread(target=monitor_processes)
    monitor_thread.start()

def stop_monitoring_thread():
    stop_monitoring()
    monitor_thread.join()

def start_gui():
    def start_monitoring_callback():
        start_monitoring_thread()
        log_event("Started monitoring suspicious processes.")
        messagebox.showinfo("Monitoring", "Started monitoring suspicious processes.")

    def stop_monitoring_callback():
        stop_monitoring_thread()
        log_event("Stopped monitoring script.")
        messagebox.showinfo("Monitoring", "Stopped monitoring suspicious processes.")

    def analyze_logs_callback():
        logs = collect_logs()
        send_logs(logs)

    def analyze_file_callback():
        file_path = filedialog.askopenfilename()
        if file_path:
            with open(file_path, 'rb') as file:
                response = requests.post('http://localhost:5001/analyze_file', files={'file': file})
                if response.status_code == 200:
                    analysis = response.json().get('analysis')
                    messagebox.showinfo("File Analysis", f"Analysis: {analysis}")
                else:
                    messagebox.showerror("Error", "Error analyzing file")

    root = tk.Tk()
    root.title("Security Monitor")
    root.geometry("300x300")

    start_button = tk.Button(root, text="Start Monitoring", command=start_monitoring_callback, width=25)
    start_button.pack(pady=10)

    stop_button = tk.Button(root, text="Stop Monitoring", command=stop_monitoring_callback, width=25)
    stop_button.pack(pady=10)

    analyze_button = tk.Button(root, text="Analyze Logs", command=analyze_logs_callback, width=25)
    analyze_button.pack(pady=10)

    file_button = tk.Button(root, text="Analyze File", command=analyze_file_callback, width=25)
    file_button.pack(pady=10)

    # Adding the logo to the GUI
    logo_path = "assets/logo.png"
    if os.path.exists(logo_path):
        logo = Image.open(logo_path)
        logo = logo.resize((50, 50), Image.LANCZOS)
        logo = ImageTk.PhotoImage(logo)

        logo_label = tk.Label(root, image=logo)
        logo_label.image = logo
        logo_label.pack(pady=10)
    else:
        messagebox.showerror("Error", f"Logo file not found. Please ensure '{logo_path}' is in the project directory.")

    root.mainloop()

if __name__ == '__main__':
    # Start Flask app in a separate thread
    flask_thread = Thread(target=app.run, kwargs={"debug": True, "use_reloader": False, "port": 5001})
    flask_thread.start()

    # Start GUI
    start_gui()
