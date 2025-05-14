#!/usr/bin/env python3
import imaplib
import email
import re
import requests
import hashlib
import base64
import time
import json
import argparse
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
import logging
from logging.handlers import RotatingFileHandler
import getpass
import mailbox
import os

# Configure logging
def setup_logging():
    log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    
    # File handler with rotation (10MB per file, max 5 files)
    file_handler = RotatingFileHandler(
        'email_analyzer.log', 
        maxBytes=10*1024*1024, 
        backupCount=5
    )
    file_handler.setFormatter(log_formatter)
    file_handler.setLevel(logging.INFO)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(log_formatter)
    console_handler.setLevel(logging.INFO)
    
    # Create logger
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

logger = setup_logging()

class VirusTotalAnalyzer:
    """Handles all VirusTotal API interactions with proper rate limiting"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3/"
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
        self.last_request_time = 0
        self.min_request_interval = 15  # seconds (VT public API limit)
    
    def _rate_limit(self):
        """Ensure we don't exceed VirusTotal API rate limits"""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.min_request_interval:
            wait_time = self.min_request_interval - elapsed
            time.sleep(wait_time)
        self.last_request_time = time.time()
    
    def scan_url(self, url: str) -> Dict:
        """Submit a URL for scanning to VirusTotal"""
        self._rate_limit()
        try:
            response = requests.post(
                f"{self.base_url}urls",
                headers=self.headers,
                data={"url": url},
                timeout=30
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"VirusTotal URL scan failed for {url}: {str(e)}")
            return {"error": str(e)}
    
    def get_url_report(self, url: str) -> Dict:
        """Get the report for a URL"""
        self._rate_limit()
        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            response = requests.get(
                f"{self.base_url}urls/{url_id}",
                headers=self.headers,
                timeout=30
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"VirusTotal URL report failed for {url}: {str(e)}")
            return {"error": str(e)}
    
    def get_file_report(self, file_hash: str) -> Dict:
        """Get the report for a file by its hash"""
        self._rate_limit()
        try:
            response = requests.get(
                f"{self.base_url}files/{file_hash}",
                headers=self.headers,
                timeout=30
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"VirusTotal file report failed for {file_hash}: {str(e)}")
            return {"error": str(e)}
    
    def is_malicious(self, vt_report: Dict, threshold: int = 1) -> bool:
        """Check if a VirusTotal report indicates malicious content"""
        if 'error' in vt_report:
            return False
        
        if 'data' in vt_report and 'attributes' in vt_report['data']:
            attributes = vt_report['data']['attributes']
            if 'last_analysis_stats' in attributes:
                return attributes['last_analysis_stats']['malicious'] >= threshold
        
        return False

class EmailAnalyzer:
    """Core email analysis functionality"""
    
    def __init__(self, vt_api_key: Optional[str] = None):
        self.vt_analyzer = VirusTotalAnalyzer(vt_api_key) if vt_api_key else None
        
        # Compile regex patterns once
        self.url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        )
        self.domain_pattern = re.compile(
            r'(?:https?://)?(?:www\.)?([^/]+)'
        )
        self.suspicious_keywords = [
            'urgent', 'verify', 'account', 'suspended', 'password', 'login',
            'security', 'alert', 'bank', 'paypal', 'irs', 'social security',
            'click', 'link', 'confirm', 'immediately', 'action required',
            'update', 'credentials', 'limited time', 'offer', 'warning'
        ]
    
    def analyze_email(self, email_msg: email.message.Message) -> Dict:
        """Analyze an email message for phishing and malicious content"""
        analysis = {
            'is_phishing': False,
            'is_malicious': False,
            'suspicious_keywords': [],
            'suspicious_urls': [],
            'malicious_urls': [],
            'malicious_attachments': [],
            'virustotal_checks': [],
            'attachments': [],
            'sender': self._get_sender(email_msg),
            'subject': email_msg.get('subject', 'No Subject'),
            'date': email_msg.get('date', 'Unknown'),
            'message_id': email_msg.get('message-id', '')
        }
        
        # Extract email content
        email_text = self._extract_email_text(email_msg)
        
        # Analyze text content
        text_analysis = self._analyze_text_content(email_text)
        analysis.update(text_analysis)
        
        # Extract and analyze URLs
        urls = self.url_pattern.findall(email_text)
        analysis['suspicious_urls'] = urls
        if self.vt_analyzer:
            url_analysis = self._analyze_urls(urls)
            analysis.update(url_analysis)
        
        # Analyze attachments
        if email_msg.is_multipart():
            attachment_analysis = self._analyze_attachments(email_msg)
            analysis.update(attachment_analysis)
        
        # Final determination
        analysis['is_phishing'] = (
            analysis.get('keyword_score', 0) > 3 or
            len(analysis['suspicious_urls']) > 0 or
            analysis.get('sender_mismatch', False)
        )
        
        analysis['is_malicious'] = (
            len(analysis['malicious_urls']) > 0 or
            len(analysis['malicious_attachments']) > 0
        )
        
        return analysis
    
    def _get_sender(self, msg: email.message.Message) -> str:
        """Extract and clean sender information"""
        sender = msg.get('from', 'unknown')
        # Extract just the email address if it's in angle brackets
        match = re.search(r'<([^>]+)>', sender)
        if match:
            return match.group(1)
        return sender
    
    def _extract_email_text(self, msg: email.message.Message) -> str:
        """Extract text content from email"""
        email_text = ""
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain":
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            email_text += payload.decode('utf-8', errors='replace')
                    except Exception as e:
                        logger.warning(f"Failed to decode email part: {str(e)}")
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    email_text = payload.decode('utf-8', errors='replace')
            except Exception as e:
                logger.warning(f"Failed to decode email: {str(e)}")
        
        return email_text
    
    def _analyze_text_content(self, text: str) -> Dict:
        """Analyze the text content for phishing indicators"""
        lower_text = text.lower()
        found_keywords = [
            kw for kw in self.suspicious_keywords 
            if kw in lower_text
        ]
        
        # Calculate keyword score (weighted by frequency)
        keyword_score = sum(
            1 for kw in self.suspicious_keywords 
            if kw in lower_text
        )
        
        # Check for sender mismatch (common in phishing)
        sender_mismatch = False
        if "dear customer" in lower_text or "dear user" in lower_text:
            sender_mismatch = True
        
        return {
            'suspicious_keywords': found_keywords,
            'keyword_score': keyword_score,
            'sender_mismatch': sender_mismatch,
            'urgency_detected': any(
                word in lower_text 
                for word in ['urgent', 'immediately', 'asap', 'right away']
            )
        }
    
    def _analyze_urls(self, urls: List[str]) -> Dict:
        """Analyze URLs using VirusTotal"""
        results = {
            'malicious_urls': [],
            'virustotal_checks': []
        }
        
        unique_urls = list(set(urls))  # Avoid duplicate checks
        
        for url in unique_urls:
            try:
                # First get existing report
                report = self.vt_analyzer.get_url_report(url)
                
                # If no existing report, submit for scanning
                if 'error' in report:
                    scan_result = self.vt_analyzer.scan_url(url)
                    if 'error' not in scan_result:
                        time.sleep(15)  # Wait for scan to complete
                        report = self.vt_analyzer.get_url_report(url)
                
                results['virustotal_checks'].append({
                    'url': url,
                    'report': report
                })
                
                if self.vt_analyzer.is_malicious(report):
                    results['malicious_urls'].append(url)
            
            except Exception as e:
                logger.error(f"URL analysis failed for {url}: {str(e)}")
                results['virustotal_checks'].append({
                    'url': url,
                    'error': str(e)
                })
        
        return results
    
    def _analyze_attachments(self, msg: email.message.Message) -> Dict:
        """Analyze email attachments using VirusTotal"""
        results = {
            'attachments': [],
            'malicious_attachments': []
        }
        
        if not self.vt_analyzer:
            return results
        
        for part in msg.walk():
            if part.get_filename() and part.get_content_disposition() == 'attachment':
                try:
                    filename = part.get_filename()
                    attachment_data = part.get_payload(decode=True)
                    if not attachment_data:
                        continue
                    
                    # Calculate file hash
                    file_hash = hashlib.sha256(attachment_data).hexdigest()
                    
                    # Get file report from VirusTotal
                    report = self.vt_analyzer.get_file_report(file_hash)
                    
                    attachment_info = {
                        'filename': filename,
                        'size': len(attachment_data),
                        'hash': file_hash,
                        'report': report
                    }
                    
                    results['attachments'].append(attachment_info)
                    
                    if self.vt_analyzer.is_malicious(report):
                        results['malicious_attachments'].append(filename)
                
                except Exception as e:
                    logger.error(f"Attachment analysis failed: {str(e)}")
                    results['attachments'].append({
                        'filename': part.get_filename(),
                        'error': str(e)
                    })
        
        return results

class EmailScanner:
    """Handles email account connection and scanning operations"""
    
    def __init__(self, email: str, password: str, imap_server: str = 'imap.gmail.com'):
        self.email = email
        self.password = password
        self.imap_server = imap_server
        self.mail = None
    
    def connect(self) -> bool:
        """Connect to the IMAP server"""
        try:
            self.mail = imaplib.IMAP4_SSL(self.imap_server)
            self.mail.login(self.email, self.password)
            logger.info(f"Successfully connected to {self.imap_server}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to email server: {str(e)}")
            return False
    
    def disconnect(self):
        """Close the IMAP connection"""
        if self.mail:
            try:
                self.mail.logout()
            except Exception:
                pass
    
    def scan_mailbox(self, mailbox: str = 'INBOX', days: int = 7, 
                    limit: int = 100) -> List[Dict]:
        """Scan emails in the specified mailbox"""
        if not self.mail:
            if not self.connect():
                return []
        
        try:
            # Select mailbox
            self.mail.select(mailbox)
            
            # Calculate date range
            since_date = (datetime.now() - timedelta(days=days)).strftime('%d-%b-%Y')
            
            # Search for emails in date range
            status, messages = self.mail.search(
                None, 
                f'(SINCE "{since_date}")'
            )
            if status != 'OK':
                logger.error("Failed to search emails")
                return []
            
            email_ids = messages[0].split()
            email_ids = email_ids[-limit:]  # Limit number of emails
            
            results = []
            analyzer = EmailAnalyzer()  # Without VT for initial scan
            
            for email_id in email_ids:
                try:
                    # Fetch the email
                    status, data = self.mail.fetch(email_id, '(RFC822)')
                    if status != 'OK':
                        continue
                    
                    raw_email = data[0][1]
                    email_msg = email.message_from_bytes(raw_email)
                    
                    # Basic analysis (without VT for speed)
                    analysis = analyzer.analyze_email(email_msg)
                    
                    results.append({
                        'id': email_id.decode(),
                        'subject': analysis['subject'],
                        'from': analysis['sender'],
                        'date': analysis['date'],
                        'is_phishing': analysis['is_phishing'],
                        'suspicious_keywords': analysis['suspicious_keywords'],
                        'suspicious_urls': analysis['suspicious_urls'],
                        'has_attachments': len(analysis['attachments']) > 0
                    })
                
                except Exception as e:
                    logger.error(f"Failed to process email {email_id}: {str(e)}")
            
            return results
        
        except Exception as e:
            logger.error(f"Error scanning mailbox: {str(e)}")
            return []
    
    def get_email(self, email_id: str) -> Optional[email.message.Message]:
        """Retrieve a specific email by ID"""
        if not self.mail:
            if not self.connect():
                return None
        
        try:
            status, data = self.mail.fetch(email_id, '(RFC822)')
            if status == 'OK':
                return email.message_from_bytes(data[0][1])
        except Exception as e:
            logger.error(f"Failed to fetch email {email_id}: {str(e)}")
        
        return None

class EmailSecurityTool:
    """Main application class with CLI interface"""
    
    def __init__(self):
        self.vt_api_key = None
        self.scanner = None
        self.report_dir = "reports"
        os.makedirs(self.report_dir, exist_ok=True)
    
    def run(self):
        """Main entry point for the application"""
        parser = argparse.ArgumentParser(
            description="Professional Email Security Analyzer",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )
        parser.add_argument('email', help="Email address to scan")
        parser.add_argument('-s', '--server', default='imap.gmail.com',
                          help="IMAP server address")
        parser.add_argument('-d', '--days', type=int, default=7,
                          help="Number of days to scan back")
        parser.add_argument('-l', '--limit', type=int, default=50,
                          help="Maximum number of emails to scan")
        parser.add_argument('--vt-key', help="VirusTotal API key")
        parser.add_argument('--full-scan', action='store_true',
                          help="Perform full scan with VirusTotal checks")
        
        args = parser.parse_args()
        
        # Get password securely
        password = getpass.getpass(f"Enter password for {args.email}: ")
        
        # Initialize scanner
        self.scanner = EmailScanner(args.email, password, args.server)
        if not self.scanner.connect():
            return
        
        # Load VirusTotal API key if provided
        self.vt_api_key = args.vt_key
        if args.full_scan and not self.vt_api_key:
            logger.warning("Full scan requested but no VirusTotal API key provided")
            args.full_scan = False
        
        # Scan mailbox
        logger.info(f"Scanning last {args.days} days of emails (max {args.limit} emails)")
        scan_results = self.scanner.scan_mailbox('INBOX', args.days, args.limit)
        
        # Generate report
        report = {
            'scan_date': datetime.now().isoformat(),
            'email': args.email,
            'scan_parameters': {
                'days': args.days,
                'limit': args.limit,
                'full_scan': args.full_scan
            },
            'summary': {
                'total_emails': len(scan_results),
                'phishing_suspected': sum(1 for e in scan_results if e['is_phishing']),
                'with_suspicious_urls': sum(1 for e in scan_results if e['suspicious_urls']),
                'with_attachments': sum(1 for e in scan_results if e['has_attachments'])
            },
            'emails': scan_results
        }
        
        # Perform detailed analysis on suspicious emails if requested
        if args.full_scan:
            logger.info("Performing detailed analysis on suspicious emails...")
            analyzer = EmailAnalyzer(self.vt_api_key)
            
            for email_data in report['emails']:
                if email_data['is_phishing'] or email_data['suspicious_urls']:
                    email_msg = self.scanner.get_email(email_data['id'])
                    if email_msg:
                        full_analysis = analyzer.analyze_email(email_msg)
                        email_data.update({
                            'full_analysis': full_analysis,
                            'is_malicious': full_analysis['is_malicious']
                        })
            
            report['summary']['malicious_emails'] = sum(
                1 for e in report['emails'] if e.get('is_malicious', False)
            )
        
        # Save report
        report_filename = os.path.join(
            self.report_dir,
            f"email_scan_{args.email}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        with open(report_filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Scan complete. Report saved to {report_filename}")
        
        # Display summary
        print("\n=== Scan Summary ===")
        print(f"Emails scanned: {report['summary']['total_emails']}")
        print(f"Phishing suspected: {report['summary']['phishing_suspected']}")
        if args.full_scan:
            print(f"Malicious content found: {report['summary']['malicious_emails']}")
        print(f"\nFull report saved to: {report_filename}")
        
        # Clean up
        self.scanner.disconnect()

if __name__ == "__main__":
    try:
        tool = EmailSecurityTool()
        tool.run()
    except KeyboardInterrupt:
        print("\nScan cancelled by user")
    except Exception as e:
        logger.error(f"Application error: {str(e)}")
        print(f"An error occurred. Check the log file for details.")
