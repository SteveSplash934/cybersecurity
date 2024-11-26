# Web Hacking Tools Cheatsheet: Quick Commands for Ethical Hackers

# Author: @whiteshepherdsec | Steve Splash

## Wfuzz
```bash
# Author: @whiteshepherdsec

# Wfuzz Cheatsheet: Quick Commands

# Basic Fuzzing Example
wfuzz -c -w /path/to/wordlist.txt -u https://example.com/FUZZ

# Fuzz with Filtering HTTP Status Codes
wfuzz -c -w /path/to/wordlist.txt -u https://example.com/FUZZ --hc 404

# Fuzz GET Parameters
wfuzz -c -w /path/to/wordlist.txt -u "https://example.com/?param=FUZZ"

# Fuzz POST Data
wfuzz -c -w /path/to/wordlist.txt -u https://example.com/login -d "username=FUZZ&password=admin"

# Save Results to a File
wfuzz -c -w /path/to/wordlist.txt -u https://example.com/FUZZ -o results.txt

# Tags: #CyberSecurity #BugBounty #EthicalHacking #Fuzzing #Wfuzz
```

## ZAP (OWASP Zed Attack Proxy)

```bash
# Author: @whiteshepherdsec

# ZAP (OWASP Zed Attack Proxy) Cheatsheet: Quick Commands

# Start ZAP in Headless Mode
zap.sh -daemon -host 127.0.0.1 -port 8080

# Spider a Target Website
zap-cli spider https://example.com

# Active Scan on Target
zap-cli active-scan https://example.com

# List Alerts from the Last Scan
zap-cli alerts

# Export Alerts to a File
zap-cli report -o zap_report.html -f html

# Tags: #OWASP #WebSecurity #EthicalHacking #BugBounty #ZAP
```

## Shodan
```bash
# Author: @whiteshepherdsec

# Shodan Cheatsheet: Quick Commands

# Search for Open Ports on a Target
shodan search "ip:1.2.3.4"

# List Services on a Specific Host
shodan host 1.2.3.4

# Search for Specific Vulnerabilities
shodan search "vuln:CVE-2022-XXXXX"

# Search for Devices by Banner
shodan search "Apache/2.4.49"

# Export Results to a File
shodan search "default password" --limit 100 --fields ip_str,port,org,hostnames > results.csv

# Tags: #Shodan #CyberSecurity #InternetOfThings #NetworkScanning #BugBounty
```
## SQLmap
```bash
# Author: @whiteshepherdsec

# SQLmap Cheatsheet: Quick Commands

# Basic SQL Injection Test
sqlmap -u "https://example.com/page.php?id=1"

# Specify POST Data
sqlmap -u "https://example.com/login.php" --data="username=admin&password=FUZZ"

# Use a Proxy for Requests
sqlmap -u "https://example.com/page.php?id=1" --proxy "http://127.0.0.1:8080"

# Detect Database Information
sqlmap -u "https://example.com/page.php?id=1" --banner

# Dump a Specific Database
sqlmap -u "https://example.com/page.php?id=1" -D dbname --dump

# Search for a Specific Table
sqlmap -u "https://example.com/page.php?id=1" -D dbname --search -T users

# Bypass WAF or Filters
sqlmap -u "https://example.com/page.php?id=1" --random-agent --tamper="space2comment"

# Save Scan Output to a File
sqlmap -u "https://example.com/page.php?id=1" -o

# Tags: #SQLInjection #BugBounty #EthicalHacking #DatabaseSecurity #SQLmap
```

## Nikto
```bash
# Author: @whiteshepherdsec

# Nikto Cheatsheet: Quick Commands

# Basic Web Server Scan
nikto -h https://example.com

# Scan with a Specified Port
nikto -h https://example.com -p 8080

# Use a Proxy for Scanning
nikto -h https://example.com -useproxy http://127.0.0.1:8080

# Save Scan Results to a File
nikto -h https://example.com -o output.txt

# Scan a Target with SSL
nikto -h https://example.com -ssl

# Disable SSL Certificate Check
nikto -h https://example.com -nossl

# Perform a Full Scan with All Plugins
nikto -h https://example.com -Plugins all

# Tags: #WebSecurity #VulnerabilityScanning #Nikto #CyberSecurity #BugBounty
```

## Dirb
```bash
# Author: @whiteshepherdsec

# Dirb Cheatsheet: Quick Commands

# Basic Directory Brute-forcing
dirb https://example.com /path/to/wordlist.txt

# Use a Proxy for Requests
dirb https://example.com /path/to/wordlist.txt -p http://127.0.0.1:8080

# Filter HTTP Response Codes (e.g., only 200)
dirb https://example.com /path/to/wordlist.txt -r

# Add Custom Extensions
dirb https://example.com /path/to/wordlist.txt -X .php,.html,.txt

# Output Results to a File
dirb https://example.com /path/to/wordlist.txt -o output.txt

# Recursive Scanning
dirb https://example.com /path/to/wordlist.txt -R

# Tags: #DirectoryBruteForce #WebSecurity #Dirb #CyberSecurity #BugBounty
```

## Nuclei
```bash
# Author: @whiteshepherdsec

# Nuclei Cheatsheet: Quick Commands

# Basic Vulnerability Scan
nuclei -u https://example.com

# Scan Using a Specific Template
nuclei -u https://example.com -t /path/to/template.yaml

# Use a Template Category (e.g., CVEs)
nuclei -u https://example.com -tl cves

# Scan Multiple URLs from a File
nuclei -l /path/to/urls.txt

# Exclude Specific Templates
nuclei -u https://example.com -et /path/to/exclude-template.yaml

# Save Results to a File
nuclei -u https://example.com -o output.txt

# Enable Rate-Limiting
nuclei -u https://example.com -rl 50

# Update Nuclei Templates
nuclei -ut

# Tags: #VulnerabilityScanning #CyberSecurity #Nuclei #BugBounty #EthicalHacking
```

## Gobuster
```bash
# Author: @whiteshepherdsec

# Gobuster Cheatsheet: Quick Commands

# Directory Fuzzing
gobuster dir -u https://example.com -w /path/to/wordlist.txt

# DNS Subdomain Brute-forcing
gobuster dns -d example.com -w /path/to/subdomain-list.txt

# Virtual Host Fuzzing
gobuster vhost -u https://example.com -w /path/to/wordlist.txt

# Use a Proxy for Requests
gobuster dir -u https://example.com -w /path/to/wordlist.txt -p http://127.0.0.1:8080

# Save Results to a File
gobuster dir -u https://example.com -w /path/to/wordlist.txt -o results.txt

# Tags: #DirectoryBruteForce #SubdomainScanning #Gobuster #CyberSecurity #BugBounty
```
