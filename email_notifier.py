import smtplib
from email.mime.text import MIMEText

def notify_suspicious_process(process_name):
    send_email("Suspicious Process Killed", f"The process {process_name} was killed due to suspicion.", "user@example.com")

def send_email(subject, body, to):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = 'your_email@example.com'
    msg['To'] = to

    with smtplib.SMTP('smtp.example.com', 587) as server:
        server.starttls()
        server.login('your_email@example.com', 'your_password')
        server.sendmail('your_email@example.com', to, msg.as_string())
