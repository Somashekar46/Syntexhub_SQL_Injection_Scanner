# Syntexhub_SQL_Injection_Scanner
# 🔍 SQL Injection Vulnerability Scanner

## Syntexhub Cybersecurity Internship Project

![Python Version](https://img.shields.io/badge/Python-3.7+-blue.svg)
![License](https://img.shields.io/badge/License-Educational%20Use-green.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20Mac-lightgrey.svg)

## 📌 Project Overview

A professional **SQL Injection Scanner** built for the Syntexhub Cybersecurity Internship program. This tool detects SQL injection vulnerabilities in web applications using multiple detection techniques with concurrent scanning capabilities.

### 🎯 Key Features

| Feature | Description |
|---------|-------------|
| **18+ Payloads** | Error-based, Union-based, Boolean-based, Time-based, Destructive |
| **Concurrent Scanning** | Multi-threaded testing (configurable 1-20 threads) |
| **Rate Limiting** | Configurable delays for ethical scanning |
| **Database Fingerprinting** | Auto-detects MySQL, PostgreSQL, MSSQL, Oracle, SQLite |
| **Multiple Reports** | JSON, TXT, and HTML formats |
| **Responsive GUI** | Modern dark-themed interface with real-time updates |
| **CLI Version** | Command-line interface for automation |

---

## 🚀 Quick Start

### Prerequisites

```bash
# Install required packages
pip install requests
# Run the vulnerable test application
python vulnerable_app.py
Access at: http://localhost:5000/?id=1
### Run the Scanner(GUI Version (Recommended))
 python sql_scanner_gui.py
### CLI Version
# Basic scan
python advanced_sql_scanner.py "http://localhost:5000/?id=1"
# With custom settings
python advanced_sql_scanner.py "http://localhost:5000/?id=1" GET 10
### Scan Online Test Target (Legal)
python advanced_sql_scanner.py "http://testphp.vulnweb.com/artists.php?artist=1" GET 5

*** ### 🏗️ Project Structure
Syntexhub_SQLi_Scanner/
│
├── advanced_sql_scanner.py      # CLI version with concurrency
├── sql_scanner_gui.py           # GUI version with responsive design
├── vulnerable_app.py            # Local test target (SQLite)
│
├── scan_report.html             # Generated HTML report
├── scan_report.json             # Generated JSON report
├── scan_report_detailed.txt     # Generated text report
│
└── README.md                    # This file
 
