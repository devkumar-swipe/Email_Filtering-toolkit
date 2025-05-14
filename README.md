# 📧 Email Security Analyzer Tool

A powerful, Python-based tool to analyze emails for phishing indicators, malicious links, and attachments using VirusTotal, IMAP, and keyword analysis.

---

## 🔰 Features

- ✅ Secure IMAP login to any mail provider
- 🛡️ VirusTotal URL and attachment scanning support
- 🔍 Keyword-based phishing detection
- 📅 Custom date-range filtering for emails
- 🧪 Full or limited scans (latest N emails)
- 📄 Clean CLI with banner and argument help

---

## 📸 Screenshot
![Screenshot from 2025-05-14 23-18-49](https://github.com/user-attachments/assets/dc76f246-5bf0-4e04-978f-bb18b75701be)


---
## 🔧 Setup
Clone the repo (or copy the file):
```bash
git clone https://github.com//email-analyzer
cd email-analyzer
```
Install dependencies:
```bash
pip install -r requirements.txt
```
## 🧑‍💻 Usage

```bash
python3 email_Analyzer.py --email you@example.com --password yourpassword --vt-api-key YOUR_VT_KEY
```
## Optional arguments:
# Argument	Description
--imap	IMAP server (default: imap.gmail.com)
--days	Check emails from last N days (default: 3)
--limit	Limit number of emails scanned (default: 10)
--full-scan	Scan entire mailbox (overrides --limit)




