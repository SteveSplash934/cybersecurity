# Password Cracking and Authentication Cheatsheet

## Ncrack Cheatsheet

**Basic Authentication Brute-forcing**
```bash
ncrack -p 22,23,80 192.168.1.100
```

**Specify User and Password Files**
```bash
ncrack -p 22 -U /path/to/userlist.txt -P /path/to/passwordlist.txt 192.168.1.100
```

**Service-Specific Brute-forcing**
```bash
ncrack -p ssh 192.168.1.100     # SSH
ncrack -p ftp 192.168.1.100     # FTP
ncrack -p rdp 192.168.1.100     # RDP
```

**Parallel Brute-forcing Multiple Services**
```bash
ncrack -p ssh,ftp,rdp 192.168.1.100
```

**Limit Connection Attempts**
```bash
ncrack -p 22 --connection-limit 5 192.168.1.100
```

**Rate-limiting Login Attempts**
```bash
ncrack -p 22 --rate 10 192.168.1.100
```

**Stop After Successful Login**
```bash
ncrack -p 22 --stop-on-success 192.168.1.100
```

**Verbose Output**
```bash
ncrack -p 22,80 192.168.1.100 -v
```

**Specify Timeout**
```bash
ncrack -p 22,23,80 192.168.1.100 --timeout 10m
```

**Save Output to File**
```bash
ncrack -p 22,80 192.168.1.100 -oN results.txt
```

---

## DNSChef Cheatsheet

**Spoof Specific DNS Records**
```bash
dnschef --fakeip 192.168.1.100 --fakedomains example.com
```

**Redirect All A Queries to a Specific IP**
```bash
dnschef --fakeip 192.168.1.100
```

**Redirect MX Queries to a Fake Mail Server**
```bash
dnschef --fakemail example.mail.server
```

**Log All DNS Queries to a File**
```bash
dnschef --logfile dnschef.log
```

**Serve as an Open Recursive DNS Server**
```bash
dnschef --recursive
```

**Bind to a Specific Interface**
```bash
dnschef --interface 192.168.1.1
```

**Specify a Custom DNS Port**
```bash
dnschef --port 5353
```

**Run in Verbose Mode**
```bash
dnschef --verbose
```

---

## Binwalk Cheatsheet

**Scan for Embedded Files and Data**
```bash
binwalk file.bin
```

**Extract All Embedded Files**
```bash
binwalk -e file.bin
```

**Specify an Output Directory for Extraction**
```bash
binwalk -e -C /path/to/output file.bin
```

**Analyze Specific Offsets in the File**
```bash
binwalk file.bin -R "0x1000"
```

**Limit Search by File Type**
```bash
binwalk -T "png" file.bin
```

**Combine with dd to Extract Data**
```bash
binwalk -R '\x89PNG' file.bin | dd of=image.png bs=1 skip=$OFFSET
```

**Suppress Warnings in Output**
```bash
binwalk -q file.bin
```

**Perform Entropy Analysis**
```bash
binwalk -E file.bin
```

**Verbose Output Mode**
```bash
binwalk -v file.bin
```

**Save Results to a File**
```bash
binwalk -e file.bin -o results.txt
```

---

## Bully Cheatsheet

**Start WPS Brute-forcing on a Specific Interface**
```bash
bully wlan0 -b <BSSID> -c <CHANNEL>
```

**Save Results to a File**
```bash
bully wlan0 -b <BSSID> -c <CHANNEL> -o output.log
```

**Use a Specific Pin**
```bash
bully wlan0 -b <BSSID> -c <CHANNEL> -p <PIN>
```

**Verbose Output**
```bash
bully wlan0 -b <BSSID> -c <CHANNEL> -v
```

**Skip Checking for Pixie-Dust Vulnerabilities**
```bash
bully wlan0 -b <BSSID> -c <CHANNEL> --skip-crack
```

**Resume a Previous Session**
```bash
bully wlan0 -b <BSSID> -c <CHANNEL> --recall
```

**Ignore AP Lockouts**
```bash
bully wlan0 -b <BSSID> -c <CHANNEL> --ignore-locks
```

---

## Medusa Cheatsheet

**Basic Brute-forcing for SSH**
```bash
medusa -h <TARGET_IP> -u <USERNAME> -P /path/to/passwordlist.txt -M ssh
```

**Brute-force a Service on a Specific Port**
```bash
medusa -h <TARGET_IP> -u <USERNAME> -P /path/to/passwordlist.txt -M ssh -n 2222
```

**Use Multiple Threads for Faster Brute-forcing**
```bash
medusa -h <TARGET_IP> -u <USERNAME> -P /path/to/passwordlist.txt -M ssh -t 5
```

**Save Results to a File**
```bash
medusa -h <TARGET_IP> -u <USERNAME> -P /path/to/passwordlist.txt -M ssh -O results.txt
```

**Specify a Target Range of IPs**
```bash
medusa -H /path/to/iplist.txt -u <USERNAME> -P /path/to/passwordlist.txt -M ssh
```

**Specify a Timeout for Connections**
```bash
medusa -h <TARGET_IP> -u <USERNAME> -P /path/to/passwordlist.txt -M ssh -T 10
```

---

## Hydra Cheatsheet

**Basic Brute-forcing for SSH**
```bash
hydra -l <USERNAME> -P /path/to/passwordlist.txt ssh://<TARGET_IP>
```

**Brute-force HTTP Login**
```bash
hydra -l <USERNAME> -P /path/to/passwordlist.txt http-post-form "/login.php:username=^USER^&password=^PASS^:F=incorrect"
```

**Parallel Brute-forcing Multiple Targets**
```bash
hydra -L /path/to/userlist.txt -P /path/to/passwordlist.txt ssh://<TARGET_IP1>,<TARGET_IP2>
```

**Save Results to a File**
```bash
hydra -l <USERNAME> -P /path/to/passwordlist.txt ssh://<TARGET_IP> -o results.txt
```

**Limit Connection Rate**
```bash
hydra -l <USERNAME> -P /path/to/passwordlist.txt ssh://<TARGET_IP> -t 4
```

**Stop After Finding a Valid Login**
```bash
hydra -l <USERNAME> -P /path/to/passwordlist.txt ssh://<TARGET_IP> -f
```

**Specify a Proxy for the Attack**
```bash
hydra -l <USERNAME> -P /path/to/passwordlist.txt ssh://<TARGET_IP> -x 127.0.0.1:8080
```
