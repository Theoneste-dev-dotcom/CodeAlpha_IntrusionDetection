import smtplib
import time
import os
import pandas as pd
import re
from my_password import password

# SMTP server information
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "theodufi.rw@gmail.com"
RECIPIENT_EMAIL = "theonestedufitimana015@gmail.com"
ATTACK_PATTERNS = ["2100498", "2000001", "2000002", "2000003", "2000004", "2100001", "2100002", "2100003", "2100004", "2100005", "2100006"]
LOG_FILE_PATH = "/var/log/suricata/fast.log"

def send_email(sender, recipient, subject, body):
    """Send an email notification."""
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as smtp:
            smtp.starttls()  # Secure the connection
            smtp.login(sender, password)
            smtp.sendmail(sender, recipient, f"Subject: {subject}\n\n{body}")
            print("Email sent successfully.")
    except Exception as e:
        print(f"Failed to send email: {e}")

def check_log_file(filename):
    """Check the log file for specific attack patterns and send email if detected."""
    now = pd.Timestamp.now()

    with open(filename, "r") as log_file:
        for line in log_file:
            # Extract the timestamp and check if it is recent enough
            try:
                event_time = pd.to_datetime(line[:20])
                if event_time > now:
                    # Check for attack patterns in the log line
                    attack_code = re.search(r':2\d+:', line)
                    if attack_code and attack_code.group(0).replace(':', '') in ATTACK_PATTERNS:
                        print("Attack detected.")
                        send_email(SENDER_EMAIL, RECIPIENT_EMAIL, "IDS Alert: Suspicious Activity Detected", line)
                        break
            except Exception as e:
                print(f"Error parsing line: {line}\nError: {e}")

def main():
    """Continuously monitor the log file."""
    while True:
        check_log_file(LOG_FILE_PATH)
        time.sleep(5)

if __name__ == "__main__":
    main()
