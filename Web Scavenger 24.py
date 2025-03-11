#!/usr/bin/env python3

import requests
import json
import subprocess
import re
import os
import time
import logging
from zapv2 import ZAPv2  # type: ignore

# OWASP ZAP Configuration
ZAP_URL = "http://localhost:8080"
zap = ZAPv2(proxies={"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"})

# SQLMap Configuration
SQLMAP_PATH = "/usr/bin/sqlmap"  # Update with your SQLMap path

# Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("websec.log"), logging.StreamHandler()]
)

# Validate Target URL
def validate_target(url):
    if not url.startswith(("http://", "https://")):
        raise ValueError("Invalid URL. Use 'http://' or 'https://'")
    return url

# Check if ZAP is running
def is_zap_running():
    try:
        response = requests.get(ZAP_URL)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False

# Basic Vulnerability Scanner
def basic_scanner(target_url):
    logging.info(f"Performing a basic vulnerability scan on {target_url}")
    try:
        response = requests.get(target_url, timeout=10)
        xss_patterns = re.compile(r"<script.*?>|alert\(|onerror=|onload=", re.IGNORECASE)
        if xss_patterns.search(response.text):
            logging.warning("Possible XSS vulnerability detected!")
        else:
            logging.info("No XSS patterns found.")
    except requests.exceptions.RequestException as e:
        logging.error(f"Basic scan failed: {e}")

# OWASP ZAP Security Scan
def zap_scan(target_url):
    if not is_zap_running():
        logging.error("OWASP ZAP is not running. Please start ZAP before running this script.")
        return

    logging.info("Starting OWASP ZAP scan...")
    try:
        zap.spider.scan(target_url)
        while int(zap.spider.status()) < 100:
            time.sleep(2)

        zap.ascan.scan(target_url)  # Active scan
        logging.info("Active scan started. Waiting 2 minutes...")
        time.sleep(120)

        alerts = zap.core.alerts()
        logging.info("ZAP scan completed. Results saved to 'zap_results.json'.")
        with open("zap_results.json", "w") as f:
            json.dump(alerts, f, indent=4)
    except Exception as e:
        logging.error(f"ZAP scan failed: {e}")

# SQLMap SQL Injection Scanner
def sqlmap_scan(target_url):
    if not os.path.exists(SQLMAP_PATH):
        logging.error("SQLMap not found! Make sure it's installed.")
        return

    logging.info("Starting SQLMap scan...")
    try:
        command = [SQLMAP_PATH, "-u", target_url, "--batch", "--dbs"]
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)

        if result.returncode != 0:
            logging.error(f"SQLMap error: {result.stderr}")
        else:
            logging.info("SQLMap scan completed. Results saved to 'sqlmap_results.json'.")
            with open("sqlmap_results.json", "w") as f:
                json.dump(result.stdout, f)
    except subprocess.TimeoutExpired:
        logging.error("SQLMap scan timed out.")

# XSS Scanner
def xss_scan(target_url):
    logging.info("Starting XSS scan...")
    test_payloads = [
        "<script>alert(1)</script>",
        "javascript:alert(1)",
        "'><img src=x onerror=alert(1)>",
        "\"><svg/onload=alert(1)>"
    ]

    for payload in test_payloads:
        try:
            response = requests.get(f"{target_url}?q={payload}", timeout=10)
            if payload in response.text:
                logging.warning(f"Potential XSS vulnerability detected with payload: {payload}")
            else:
                logging.info("No XSS vulnerability detected.")
        except requests.exceptions.RequestException as e:
            logging.error(f"XSS scan failed: {e}")

# Main Function
def main(target_url):
    logging.info("Starting WebSec Analyzer...")
    basic_scanner(target_url)
    zap_scan(target_url)
    sqlmap_scan(target_url)
    xss_scan(target_url)
    logging.info("WebSec Analyzer completed all tests.")

# Entry Point
if __name__ == "__main__":
    # Prompt the user to enter the target URL
    target_url = input("Enter the target URL to scan (e.g., http://example.com): ").strip()

    # Validate URL
    try:
        TARGET_URL = validate_target(target_url)
        main(TARGET_URL)
    except ValueError as e:
        logging.error(e)