# ===============================
# SOC Log Analyzer (Enterprise Version - Phase 9)
# Features:
# - Real-time monitoring
# - Universal log parser
# - Severity classification
# - CSV reporting
# - Duplicate alert prevention
# - Alert history with expiry (24 hr)
# - Root login detection
# - Multiple username attack detection
# - Successful login detection
# ===============================

from collections import defaultdict
import time
import csv
import re
from datetime import datetime, timedelta


# ---------------- CONFIGURATION ----------------

log_file = "C:\\Projects\\CyberSecurity\\Log_Analyzer\\Shared_logs\\log.txt"
report_file = "realtime_attack_report.csv"
alert_history_file = "alert_history.csv"
# NEW: security event storage
security_event_file = "security_events.csv"

# Store IP + time
alerted_ips = {}

# Alert expiry time
ALERT_EXPIRY_HOURS = 24

# ---------------- EVENT DEDUPLICATION ----------------

recent_events = {}

# same event block time (seconds)
EVENT_COOLDOWN = 300   # 5 minutes
# ---------------- FILE POINTER TRACKING ----------------
last_position = 0


# ---------------- UNIVERSAL IP EXTRACTOR ----------------
def extract_ip(line):

    # detect IPv4 or localhost IPv6
    ip_match = re.search(r"(?:\d{1,3}\.){3}\d{1,3}|::1", line)

    if ip_match:
        return ip_match.group(0)

    return None


# ---------------- UNIVERSAL USERNAME EXTRACTOR ----------------
def extract_username(line):

    match = re.search(r"for\s+(?:invalid user\s+)?(\w+)", line.lower())

    if match:
        return match.group(1)

    return None


# ---------------- ALERT HISTORY MANAGEMENT ----------------

def load_alert_history():
    try:
        with open(alert_history_file, "r") as file:
            reader = csv.reader(file)
            for row in reader:
                ip, timestamp = row
                alerted_ips[ip] = datetime.fromisoformat(timestamp)
    except FileNotFoundError:
        pass


def save_alert(ip):
    now = datetime.now()

    with open(alert_history_file, "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([ip, now.isoformat()])

    alerted_ips[ip] = now


def is_alert_expired(ip):

    if ip not in alerted_ips:
        return True

    last_alert_time = alerted_ips[ip]
    expiry_time = last_alert_time + timedelta(hours=ALERT_EXPIRY_HOURS)

    return datetime.now() > expiry_time

# ---------------- SECURITY EVENT LOGGER ----------------
def log_security_event(event_type, ip, username, severity):

    event_key = f"{event_type}_{ip}"

    current_time = datetime.now()

    # check if event already happened recently
    if event_key in recent_events:
        last_time = recent_events[event_key]

        if (current_time - last_time).seconds < EVENT_COOLDOWN:
            return   # skip duplicate event

    # store event time
    recent_events[event_key] = current_time

    # write to CSV
    with open(security_event_file, "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([
            current_time,
            event_type,
            ip,
            username,
            severity
        ])


# ---------------- MAIN ANALYZER ----------------
def analyze_logs():
    
    global last_position

    failed_logins = defaultdict(int)
    usernames_by_ip = defaultdict(set)
    successful_logins = defaultdict(int)

    report_data = []
    new_threat_found = False

    try:
        with open(log_file, "r", errors="ignore") as file:
             
                file.seek(last_position)

                for line in file:   
                
                    line_lower: str = line.lower()

                    ip = extract_ip(line)
                    username = extract_username(line)
        # save new position

                # -------- FAILED LOGIN DETECTION --------
                if "failed" in line_lower and "password" in line_lower:

                    if ip:
                        failed_logins[ip] += 1

                    if ip and username:
                        usernames_by_ip[ip].add(username)

                    # Root login detection
                    if username == "root":
                        print("🚨 CRITICAL: Root login attempt detected")
                        log_security_event("ROOT_ATTACK", ip, username, "CRITICAL")


                # -------- SUCCESSFUL LOGIN DETECTION --------
                if "accepted" in line_lower and "password" in line_lower:

                    if ip:
                        successful_logins[ip] += 1
                        print(f"⚠️ Successful login from {ip} — verify activity")
                        log_security_event("SUCCESS_LOGIN", ip, username, "MEDIUM")
                last_position = file.tell()       
 

        print("\n🚨 Real-Time SOC Monitoring:\n")

        # Process detected IPs
        for ip, count in failed_logins.items():

            # Multiple username attack detection
            if len(usernames_by_ip[ip]) >= 3:
                print(f"🚨 Multiple username attack from {ip}")
                log_security_event("MULTI_USER_ATTACK", ip, "multiple", "HIGH")


            # Duplicate control + expiry check
            if ip in alerted_ips and not is_alert_expired(ip):
                continue

            new_threat_found = True

            # Severity classification
            if count >= 5:
                severity = "HIGH"
                message = f"🔥 Brute Force Attack from {ip} ({count} attempts)"

            elif count >= 3:
                severity = "MEDIUM"
                message = f"⚠️ Suspicious activity from {ip} ({count} attempts)"

            else:
                severity = "LOW"
                message = f"Failed login from {ip} ({count} attempts)"

            print(message)
            log_security_event("BRUTE_FORCE", ip, "unknown", severity)


            report_data.append([datetime.now(), ip, count, severity])

            save_alert(ip)

        if not new_threat_found:
            print("✅ No new threats detected")

        # Write attack report
        if report_data:
            with open(report_file, "a", newline="") as file:
                writer = csv.writer(file)
                writer.writerows(report_data)

    except FileNotFoundError:
        print("Log file not found")


# ---------------- PROGRAM START ----------------

print("✅ Enterprise SOC monitoring started (Press Ctrl+C to stop)")

load_alert_history()

while True:
    analyze_logs()
    time.sleep(10)
