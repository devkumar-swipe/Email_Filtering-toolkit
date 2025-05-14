# Email Analyzer with VirusTotal Integration

This Python-based tool is designed to analyze email content for phishing and malware indicators. It leverages the [VirusTotal API](https://www.virustotal.com/) to scan and report URLs and file attachments found in email messages.

## 📌 Features

- **Email Parsing & Analysis**
  - Extracts sender, subject, and content
  - Detects suspicious keywords and patterns
  - Extracts and inspects URLs
  - Evaluates phishing indicators

- **VirusTotal Integration**
  - Checks URLs and attachments for malware
  - Supports rate-limited scanning and analysis
  - Uses URL encoding and file hashing for querying

- **Logging**
  - Logs activities and analysis results to `email_analyzer.log`
  - Rotating file handler to prevent log bloating

- **Regex-based Pattern Detection**
  - Detects phishing-related keywords
  - Identifies suspicious URLs and sender mismatches

## 🚀 How to Use

### 1. Clone the repository:
```bash
git clone https://github.com/yourusername/email-analyzer-vt.git
cd email-analyzer-vt
```

### Install dependencies:
```
pip install requests
```
3. Run the analyzer:
```
python3 email_analyzer.py
```
### ⚠️ Note: You’ll need a valid VirusTotal API key to use scanning features.

### 🗂 File Structure

email_analyzer.py - Main script with Email and VirusTotal analysis classes

email_analyzer.log - Log file (auto-generated)

README.md - Project documentation

### 🧩 Sample Output (JSON)
json
```
{
  "is_phishing": true,
  "is_malicious": true,
  "suspicious_keywords": ["verify", "urgent", "login"],
  "suspicious_urls": ["http://malicious.example.com"],
  "malicious_urls": ["http://malicious.example.com"],
  "malicious_attachments": [],
  "sender": "example@spoofed.com",
  "subject": "Urgent: Verify your Account"
}
```

### 🔮 Future Aspects
This tool is a solid base for a more comprehensive email forensics and phishing detection framework. Future enhancements may include:

Email Automation: Automatically fetch and analyze emails from IMAP servers (e.g., Gmail, Outlook).

Web GUI Dashboard: A browser-based interface for easier email upload and result visualization.

Attachment Sandbox Analysis: Integration with tools like Cuckoo Sandbox for dynamic file analysis.

Threat Intelligence Integration: Cross-reference URLs and IPs with other threat intel feeds.

Machine Learning: Build models to classify phishing vs. safe emails based on extracted features.

Real-time Alerts: Notify security teams when malicious content is detected.

