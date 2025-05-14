# 📧 Email Security Analyzer Tool

A powerful, Python-based tool to analyze emails for phishing indicators, malicious links, and attachments using VirusTotal, IMAP, and keyword analysis.

---

## 🔰 Features

- ✅ Secure IMAP login to any mail provider
- 🛡️ VirusTotal URL and attachment scanning support
- 🔍 Keyword-based phishing detection
- 📅 Custom date-range filtering for emails
- 🧪 Full or limited scans (latest N emails)
- 📄 Clean argument help

---

## 📸 Screenshot
![Screenshot from 2025-05-14 23-18-49](https://github.com/user-attachments/assets/dc76f246-5bf0-4e04-978f-bb18b75701be)


---
## 🔧 Setup
Clone the repo (or copy the file):
```bash
git clone https://github.com/devkumar-swipe/Email_Filtering-toolkit.git
cd Email_Filtering-toolkit
```
Install dependencies:
```bash
pip install -r requirements.txt
```
OR
```
pip install requests
```
## 🧑‍💻 Usage
help
```bash
python3 email_Analyzer.py -h
```

```bash
python3 email_Analyzer.py --email you@example.com --password yourpassword --vt-api-key YOUR_VT_KEY
```
## Optional arguments:
# Argument	Description
--imap	IMAP server (default: imap.gmail.com)
--days	Check emails from last N days (default: 3)
--limit	Limit number of emails scanned (default: 10)
--full-scan	Scan entire mailbox (overrides --limit)

(Optional) Get a free VirusTotal API key and insert it via --vt-api-key.(https://www.virustotal.com/)


### 🛑 Disclaimer
This tool is for educational and research purposes only.
Do not use it on email accounts you do not own or have permission to analyze.




## 🔮 Future Enhancements
🔁 Automation via Cron Jobs
📬 Notifications and Alerts
📊 Logging and Reporting
🔗 Threat Intelligence Integration
🔐 OAuth Support
🐳 Dockerization
🧠 Machine Learning-Based Detection (Planned)

### 👤 Author
AwesomeVed
Cybersecurity Student & Bug Bounty Hunter
mail: devkumarmahto204@outlook.com



