<h1 align="center">
  <br>
  <a href="https://github.com/hawtsauceTR/capsaicin"><img src="https://via.placeholder.com/200/FF0080/FFFFFF?text=CAPSAICIN+v1.5" alt="Capsaicin" width="200"></a>
  <br>
  Capsaicin v1.5
  <br>
</h1>

<h4 align="center">🌶️ The Red Team Edition: Intelligent Web Fuzzer & WAF Hunter.</h4>

<p align="center">
  <a href="#key-features">Features</a> •
  <a href="#how-it-works">Architecture</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage-examples">Usage</a> •
  <a href="#disclaimer">Disclaimer</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Language-Go%201.21+-00ADD8?style=for-the-badge&logo=go">
  <img src="https://img.shields.io/badge/Category-Offensive%20Security-red?style=for-the-badge">
  <img src="https://img.shields.io/badge/Release-v1.5-FF0080?style=for-the-badge">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge">
</p>

---

## 💀 What is Capsaicin?

**Capsaicin** is not just a directory scanner; it is a context-aware **Attack Framework** written in **Go (Golang)**. Designed for Bug Bounty Hunters and Red Teamers, it prioritizes **intelligence over raw speed**.

While traditional tools blindly hammer the server, Capsaicin analyzes the target's behavior, identifies defense mechanisms (WAFs), detects sensitive data leaks in real-time, and automatically adapts its scanning strategy.

## ✨ Key Features

### 🛡️ Passive WAF Fingerprinting
Automatically analyzes response headers (`Server`, `X-Amz-Cf-Id`) and cookies (`__cfduid`, `BIGipServer`) to detect:
* **Cloudflare**
* **AWS WAF**
* **Akamai**
* **Imperva**
* **F5 BigIP**

### 🧠 Smart Auto-Calibration
Before scanning, Capsaicin probes the server with random non-existent paths to learn its "404 Signature" (Size, Word Count, Lines). It creates a dynamic filter to **eliminate False Positives** automatically.

### 🔐 Secret Detection (Sensors)
Scans every response body (200 OK) for leaked credentials using regex patterns:
* AWS Access Keys (`AKIA...`)
* Google API Keys
* Private Keys (RSA/DSA)
* Slack Tokens / Generic API Tokens

### 🔄 Recursive & Adaptive
* **Recursive Scanning:** If a directory is found, it automatically queues it for deeper scanning.
* **Method Fuzzing:** If a path returns `405 Method Not Allowed`, it automatically tries `POST`, `PUT`, `DELETE`.
* **403 Bypass:** Attempts to bypass restrictions using headers like `X-Forwarded-For`, `X-Original-URL`.

---

## 🛠️ Architecture & Technologies

Capsaicin is built for performance and reliability using modern Go patterns:

* **Core Language:** Go (Golang) 1.21+
* **Concurrency:** Implements a **Worker Pool** pattern with buffered Channels for non-blocking I/O.
* **HTTP Engine:** Custom `net/http` client with optimized Transport (Keep-Alives, Timeouts) and User-Agent rotation.
* **CLI Interface:** Uses ANSI escape codes for a high-contrast "Cyberpunk" neon UI.
* **Reporting:** Generates strictly typed JSON output and self-contained HTML reports with embedded CSS/JS.

---

## 📦 Installation

### Method 1: Go Install (Recommended)
The easiest way to install if you have Go configured.

```bash
go install [github.com/hawtsauceTR/capsaicin@latest](https://github.com/hawtsauceTR/capsaicin@latest)



Method 2: Build from Source

If you want to modify the code or build manually.

# 1. Clone the repository
git clone [https://github.com/hawtsauceTR/capsaicin.git](https://github.com/hawtsauceTR/capsaicin.git)

# 2. Navigate to the directory
cd capsaicin

# 3. Build the binary
go build -o capsaicin main.go

# 4. Move to PATH (Optional, for global usage)
sudo mv capsaicin /usr/local/bin/


🚀 Usage Examples

1. The "Quick Scan"

Basic directory scanning against a single target.
Bash

capsaicin -u [http://target.com](http://target.com) -w /usr/share/wordlists/dirb/common.txt

2. The "Authenticated" Scan (Red Team)

Scan behind a login page using session cookies or tokens.
Bash

capsaicin -u [https://admin.target.com](https://admin.target.com) -w wordlist.txt \
  -H "Cookie: PHPSESSID=a1b2c3d4e5" \
  -H "Authorization: Bearer eyJhbGci..."

3. The "Bug Bounty" Mode (Full Power)

Enables recursive scanning (depth 2), verbose output, HTML reporting, and specific extensions.
Bash

capsaicin -u [https://target.com](https://target.com) -w wordlist.txt \
  -x php,aspx,txt \
  -v \
  -depth 2 \
  -html report.html

4. The Pipeline (Multi-Target)

Feed subdomains from tools like subfinder or httpx directly into Capsaicin via STDIN.
Bash

cat subdomains.txt | capsaicin -w wordlist.txt -t 100

🚩 Command Line Arguments

Flag	Description	Default
-u	Target URL (e.g., http://example.com)	-
-w	Path to wordlist file	-
-t	Number of concurrent threads	50
-x	File extensions (comma separated: php,html,txt)	-
-H	Custom headers (e.g., -H "Cookie: ..."). Can be used multiple times.	-
-v	Verbose mode (Print all attempted URLs)	false
--depth	Recursive scanning depth (0 = disabled)	0
--html	Path to generate HTML report file	-
-o	Path to save JSON output	-
--timeout	Request timeout in seconds	10

⚠️ Disclaimer

Capsaicin is developed for educational purposes and authorized security testing only.

    Do not use this tool on targets you do not have explicit permission to test.

    The author (Hawtsauce) is not responsible for any misuse or damage caused by this program.

    Scanning targets without prior mutual consent is illegal.

<p align="center"> Made with Go by <a href="https://www.google.com/search?q=https://github.com/hawtsauceTR">Hawtsauce</a> </p>
