#!/usr/bin/env python3

import argparse
import imaplib
import email
import getpass
import datetime
import sys
import time
import re
import requests

# Banner
def print_banner():
    banner = """
    ███████╗███╗   ███╗ █████╗ ██╗     ██╗         ███████╗███████╗██████╗ 
    ██╔════╝████╗ ████║██╔══██╗██║     ██║         ██╔════╝██╔════╝██╔══██╗
    █████╗  ██╔████╔██║███████║██║     ██║         █████╗  █████╗  ██████╔╝
    ██╔══╝  ██║╚██╔╝██║██╔══██║██║     ██║         ██╔══╝  ██╔══╝  ██╔═══╝ 
    ███████╗██║ ╚═╝ ██║██║  ██║███████╗███████╗    ██║     ███████╗██║     
    ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝    ╚═╝     ╚══════╝╚═╝     
                                                                      
    Email Security Analyzer - by AwesomeVed
    Feel Free to connect : devkumarmahto204@outlook.com
    """
    print(banner)

# CLI Handler
class EmailSecurityCLI:
    def __init__(self):
        self.args = self.parse_args()

    def parse_args(self):
        parser = argparse.ArgumentParser(description="Analyze and detect phishing/malicious content in emails.")
        parser.add_argument('--email', required=True, help='Your email address')
        parser.add_argument('--imap', default='imap.gmail.com', help='IMAP server (default: imap.gmail.com)')
        parser.add_argument('--vt-api-key', help='VirusTotal API key')
        parser.add_argument('--days', type=int, default=7, help='How many days back to scan (default: 7)')
        parser.add_argument('--limit', type=int, default=20, help='Maximum number of emails to scan (default: 20)')
        parser.add_argument('--full-scan', action='store_true', help='Perform full body scan (slower)')
        return parser.parse_args()

# Main Analyzer
class EmailSecurityAnalyzer:
    def __init__(self, email_address, password, imap_server, vt_api_key, days, limit, full_scan):
        self.email_address = email_address
        self.password = password
        self.imap_server = imap_server
        self.vt_api_key = vt_api_key
        self.days = days
        self.limit = limit
        self.full_scan = full_scan
        self.conn = None

    def connect(self):
        try:
            print("[*] Connecting to IMAP server...")
            self.conn = imaplib.IMAP4_SSL(self.imap_server)
            self.conn.login(self.email_address, self.password)
            self.conn.select('INBOX')
            print("[+] Connected successfully.")
        except imaplib.IMAP4.error as e:
            print(f"[!] Login failed: {e}")
            sys.exit(1)

    def search_recent_emails(self):
        since_date = (datetime.datetime.now() - datetime.timedelta(days=self.days)).strftime("%d-%b-%Y")
        result, data = self.conn.search(None, f'(SINCE {since_date})')
        if result != 'OK':
            print("[!] Failed to search inbox.")
            return []

        email_ids = data[0].split()[-self.limit:]
        return email_ids

    def analyze_emails(self, email_ids):
        for num in email_ids:
            result, data = self.conn.fetch(num, '(RFC822)')
            if result != 'OK':
                print("[!] Error fetching email.")
                continue

            msg = email.message_from_bytes(data[0][1])
            subject = msg['Subject']
            from_ = msg['From']
            print(f"\n[Email] From: {from_} | Subject: {subject}")

            body = self.get_email_body(msg)
            if self.contains_phishing_keywords(body):
                print("[!] Potential phishing detected based on keywords.")

            urls = self.extract_urls(body)
            for url in urls:
                print(f"[*] Found URL: {url}")
                if self.vt_api_key:
                    self.scan_url_virustotal(url)

    def get_email_body(self, msg):
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == 'text/plain':
                    return part.get_payload(decode=True).decode('utf-8', errors='ignore')
        else:
            return msg.get_payload(decode=True).decode('utf-8', errors='ignore')
        return ""

    def contains_phishing_keywords(self, text):
        keywords = ['password', 'login', 'verify your account', 'urgent', 'suspended', 'click here']
        return any(keyword.lower() in text.lower() for keyword in keywords)

    def extract_urls(self, text):
        return re.findall(r'https?://[^\s]+', text)

    def scan_url_virustotal(self, url):
        try:
            print(f"[*] Scanning URL on VirusTotal: {url}")
            headers = {'x-apikey': self.vt_api_key}
            response = requests.post('https://www.virustotal.com/api/v3/urls',
                                     headers=headers, data={'url': url})
            if response.status_code == 200:
                scan_id = response.json()['data']['id']
                analysis = requests.get(f'https://www.virustotal.com/api/v3/analyses/{scan_id}', headers=headers)
                stats = analysis.json()['data']['attributes']['stats']
                print(f"[+] VT Scan Result: {stats['malicious']} malicious, {stats['suspicious']} suspicious")
            else:
                print(f"[!] VirusTotal scan failed: {response.status_code}")
        except Exception as e:
            print(f"[!] Error scanning URL: {e}")

if __name__ == "__main__":
    print_banner()
    cli = EmailSecurityCLI()

    try:
        email_password = getpass.getpass(prompt='Enter your email password securely: ')
        analyzer = EmailSecurityAnalyzer(
            email_address=cli.args.email,
            password=email_password,
            imap_server=cli.args.imap,
            vt_api_key=cli.args.vt_api_key,
            days=cli.args.days,
            limit=cli.args.limit,
            full_scan=cli.args.full_scan
        )
        analyzer.connect()
        email_ids = analyzer.search_recent_emails()
        analyzer.analyze_emails(email_ids)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        sys.exit(0)
