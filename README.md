# 🕷️ **GhostScan -- Automated Bug Hunter**

### **Advanced Recon & Subdomain Enumeration Framework for Bug Bounty Hunters**

GhostScan is a **high-performance reconnaissance automation framework**
built for bug bounty hunters, penetration testers, and cybersecurity
researchers.\
It combines multiple passive + active recon engines, port scanning,
directory discovery, WHOIS lookups, screenshots, and more --- **all
fully automated in one tool**.

**Educational Purpose Only**

GhostScan is written in Python 3.13 and optimized for Kali Linux.

## ⚡ **Features at a Glance**

### 🔍 Subdomain Enumeration

-   crt.sh Passive Enumeration\
-   RapidDNS Lookup\
-   Wordlist-based Brute-Force Enumeration\
-   Smart DNS Resolution Validation\
-   Auto-Filter Dead / Wildcard Subdomains

### ⚡ Port & Service Scanning

-   Powered by **Nmap + python-nmap**\
-   Detects open ports, services, versions

### 📂 Directory Bruteforce

-   Custom or default wordlist\
-   Auto-detects status codes and alive paths

### 🌍 WHOIS & Domain Intelligence

-   Registrar, expiry, email, DNS, ASN info

### 🖼️ Screenshot Capture

-   HTML → Image via **imgkit (wkhtmltopdf)**\
-   Stores visual proof of recon findings

### 🎨 UI & Output

-   Hacker-style ASCII Banner (pyfiglet)\
-   Clean logs with colorized output\
-   Supports saving results to a file

### 🧪 Compatibility

-   Python **3.10 -- 3.13**\
-   Works on **Kali, Ubuntu, ParrotOS**

## 📦 **Project Structure**

    GhostScan/
    ├── ghostscan.py
    ├── requirements.txt
    └── README.md

## 🛠️ **Installation**

### 1. Clone the Repository

``` bash
git clone https://github.com/0xDEADVrm/GhostScan.git
cd GhostScan
```

### 2. Install Python Dependencies

``` bash
pip install -r requirements.txt
```

### 3. Install System Dependencies

``` bash
sudo apt install nmap wkhtmltopdf
```

## ▶️ **Usage**

### Basic Scan

``` bash
python3 ghostscan.py -d example.com
```

### Extended Example

``` bash
python3 ghostscan.py -d google.com --threads 50 -o report.txt
```

## 🧩 **All Command-Line Options**

  Flag          Description
  ------------- -------------------------
  `-d`          Target domain
  `-o`          Save results
  `-w`          Custom wordlist
  `--threads`   Thread count
  `--no-dns`    Disable DNS brute force
  `--simple`    Minimal output

## 📚 **Requirements**

    requests==2.32.3
    aiohttp==3.10.5
    beautifulsoup4==4.12.3
    dnspython==2.7.0
    python-nmap==0.7.1
    pyfiglet==1.0.2
    colorama==0.4.6
    tldextract==5.1.1
    whois==0.9.27
    imgkit==1.2.4
    lxml==5.2.2

## ⚠️ Disclaimer

For **authorized testing only**.

## ⭐ Contributing

PRs welcome.

## 📄 License

MIT License.
