import re
import os
import sys
from collections import defaultdict

# Configuration
if sys.platform.startswith('linux'):
    LOG_FILE_PATH = "/var/log/auth.log"  # Standard path for Ubuntu/Debian
else:
    LOG_FILE_PATH = "mock_auth.log"  # For local testing

ALERT_THRESHOLD = 5  # Failed attempts threshold before alerting
ALERT_OUTPUT_FILE = "alerts.txt"

# Regex pattern for SSH failure logs
FAILED_PATTERN = re.compile(
    r'.*Failed password for (?:invalid user |)(\S+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port \d+'
)

def extract_ip_and_user(line):
    """Extract source IP and username from failed login attempts."""
    match = FAILED_PATTERN.search(line)
    return (match.group(2), match.group(1)) if match else (None, None)

def analyze_logs(log_path):
    """Analyze log file for potential brute-force attacks."""
    print(f"[*] Starting log analysis on: {log_path}")
    
    failed_attempts = defaultdict(int)
    total_lines = 0
    alerted_ips = set()
    
    if not os.path.exists(log_path):
        print(f"\n[CRITICAL ERROR] Log file not found at: {log_path}")
        print("[HINT] Ensure mock_auth.log exists for local testing.")
        return
    
    try:
        with open(log_path, 'r') as f:
            for line in f:
                total_lines += 1
                
                if 'Failed password' in line and 'ssh' in line:
                    ip, user = extract_ip_and_user(line)
                    
                    if ip:
                        failed_attempts[ip] += 1
                        
                        if failed_attempts[ip] >= ALERT_THRESHOLD and ip not in alerted_ips:
                            alert_message = (
                                f"[ALERT - BRUTE FORCE] "
                                f"Source IP: {ip} | Attempts: {failed_attempts[ip]} | "
                                f"Target User: {user} | Log Timestamp: {line.split(' ', 3)[0:2]}..."
                            )
                            
                            print("\n" + "="*70)
                            print(alert_message)
                            print("="*70 + "\n")
                            
                            with open(ALERT_OUTPUT_FILE, 'a') as alert_f:
                                alert_f.write(f"{alert_message}\n")
                            
                            alerted_ips.add(ip)
    
    except Exception as e:
        print(f"[FATAL ERROR] Failed during file processing: {e}")
        return
    
    print(f"\n[INFO] Analysis complete. Scanned {total_lines} lines.")
    print(f"[INFO] Found {len(alerted_ips)} potential brute-force attempts.")
    print(f"[INFO] Alerts saved to '{ALERT_OUTPUT_FILE}'")

if __name__ == "__main__":
    if os.path.exists(ALERT_OUTPUT_FILE):
        os.remove(ALERT_OUTPUT_FILE)
        print(f"[*] Cleaned up previous alert file: '{ALERT_OUTPUT_FILE}'")
    
    analyze_logs(LOG_FILE_PATH)