# 🛡️ Enterprise SOC Log Analyzer

## 📌 Project Overview
Enterprise SOC Log Analyzer is a Python-based mini SIEM (Security Information and Event Management) system designed to simulate real-time Security Operations Center (SOC) monitoring and threat detection workflows.

The system analyzes system logs, detects security threats, classifies severity levels, and provides a visualization dashboard for security event analysis.

---

## 🏗️ Architecture
Linux/Kali Logs → VM Shared Folder → Python Log Analyzer → Threat Detection Engine → CSV Storage → Streamlit Dashboard

---

## 🚀 Features
- Real-time log monitoring
- Universal regex-based log parser
- Brute force attack detection (failed login tracking)
- Root login attack detection (critical alert)
- Multiple username attack detection
- Successful login monitoring
- Threat severity classification (LOW / MEDIUM / HIGH / CRITICAL)
- Threat scoring system
- Duplicate alert prevention using alert history
- Security event logging (timestamp, IP, username, severity)
- CSV-based attack reporting
- File pointer tracking (reads only new logs)
- Interactive Streamlit dashboard for visualization

---

## 🛠️ Technologies Used
- Python
- Regular Expressions (Regex)
- Streamlit
- Pandas
- Plotly
- CSV Logging

---

## ▶️ How to Run

### Install dependencies
pip install -r requirements.txt

### Run Log Analyzer
python LogAnalyzer.py

### Run Dashboard
streamlit run Dashboard.py

---

## 🎯 Project Goal
To simulate enterprise SOC monitoring workflows and security event analysis for cybersecurity learning and threat detection research.

---

## 🔮 Future Improvements
- Rule-based detection engine
- Threat intelligence integration (VirusTotal / AbuseIPDB)
- MITRE ATT&CK mapping
- Database integration
- Machine learning anomaly detection
- Multi-log source support

---

## 📸 Screenshots

### Dashboard View 1
![Dashboard1](Screenshots/dashboard.png)

### Dashboard View 2
![Dashboard2](Screenshots/dashboard2.png)

### Dashboard View 3
![Dashboard3](Screenshots/dashboard3.png)


## 👨‍💻 Author
Aakash Kadaganche

