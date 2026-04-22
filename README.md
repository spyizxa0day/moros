
![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=flat&logo=python)
![Version](https://img.shields.io/badge/Version-v1.0-brightgreen)
![License](https://img.shields.io/badge/License-MIT-green.svg)
[![Follow on X](https://img.shields.io/badge/Follow-@spyizxa-000000?style=flat&logo=x)](https://x.com/spyizxa)
![Telegram](https://img.shields.io/badge/Contact-%40spyizxa__0day-2CA5E0?logo=telegram)

## MOROS
**The moros tool is a red team tool kit containing 26 features.**

## Features

| #  | Module                        | Description                                              |
|----|-------------------------------|----------------------------------------------------------|
| 01 | IP Info Scanner               | Full geolocation, ISP, ASN, coordinates                 |
| 02 | DNS & WHOIS Lookup            | A records + complete WHOIS                               |
| 03 | SQL Injection Scanner         | Error-based, Blind, Time-based – auto detection          |
| 04 | XSS Scanner                   | Reflected, DOM, stored payload testing                   |
| 05 | LFI/RFI Scanner               | /etc/passwd, remote inclusion, null byte                |
| 06 | Directory Fuzzer              | 10k+ paths with common.txt (blazing fast)               |
| 07 | SSRF Scanner                  | 169.254.169.254, localhost, file://, gopher://           |
| 08 | SSH & FTP Brute Force         | Multi-user + multi-password, no limits                   |
| 09 | IDOR Tester                   | Automatic ID enumeration + content diff detection        |
| 10 | Reverse Shell Generator      | Bash, Python, PHP, Netcat, PowerShell (save option)      |
| 11 | Payload Generator             | msfvenom one-liners (Windows/Linux/Web/Android)          |
| 12 | CMS Detector                  | WordPress, Joomla, Drupal, Magento – instant             |
| 13 | Backup File Finder            | .bak, .swp, .env, wp-config.php~, config.php.bak etc.    |
| 14 | PHP Code Injection            | system(), shell_exec(), eval(), phpinfo() tests          |
| 15 | CSRF POC Generator            | Auto HTML proof-of-concept creator                       |
| 16 | File Upload Bypass            | .php.jpg, %00, .htaccess, double ext, magic bytes        |
| 17 | WordPress Brute Force         | Optimized wp-login.php attack                            |
| 18 | WAF Detector                  | Cloudflare, Akamai, Imperva, AWS WAF, ModSecurity       |
| 19 | Webhook Exploiter             | SSRF + reflected XSS on webhooks                         |
| 20 | Email Leak Checker            | Search breached credentials (demo)                       |
| 21 | Exploit-DB Search             | Local/offline exploit search (demo)                      |
| 22 | Reverse IP Lookup             | Find all domains hosted on same IP                       |
| 23 | Custom Wordlist Generator     | Leet, numbers, special chars, mutations                  |
| 24 | Fast Port Scanner             | TCP connect scan (1-65535)                               |
| 25 | Malware Analyzer              | Detect PHP/JS webshells + MD5/SHA1/SHA256 hashes         |
| 26 | Reporting System              | TXT • CSV • HTML • JSON full reports with timestamps     |

## Installation

```bash
git clone https://github.com/spyizxa0day/moros.git
cd moros
pip install -r requirements.txt
python moros.py
