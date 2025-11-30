# CY.Recon - Reconnaissance Tool
## By Cyberveins | Team ID: CY202501NAND

Professional reconnaissance suite with graphical and command-line interfaces.

⚠️ **FOR AUTHORIZED SECURITY TESTING ONLY** ⚠️

---

## Features

### Passive Recon
- DNS records (A, AAAA, CNAME, MX, NS, TXT)
- WHOIS domain information
- HTTP/HTTPS headers analysis
- Technology fingerprinting
- Certificate transparency subdomain discovery

### Active Recon
- TCP port scanning with configurable ports
- Service banner grabbing
- Network enumeration

### Web Recon
- robots.txt collection
- Intelligent web crawler
- Link and form discovery
- Page title extraction

### Reporting
- Real-time console output
- JSON export
- Markdown report generation

---

## Installation

### Prerequisites
- Python 3.7+
- pip package manager

### Setup

```bash
cd CY.Recon
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## Usage

### Web GUI (Recommended)

```bash
./run_gui.sh
```

Or directly:

```bash
python3 super_recon_gui.py
```

Then open your browser to: **http://127.0.0.1:5000**

**Features:**
- Black background with cyan/green highlights
- Professional header with Cyberveins branding
- Left panel for target configuration
- Real-time output display
- Export as JSON or Markdown
- Module toggle (Passive/Active/Web)

### Command Line

```bash
python3 super_recon.py example.com
python3 super_recon.py https://target.com --ports 80,443,8080
python3 super_recon.py 192.0.2.1 --ports 1-1024 --json
python3 super_recon.py target.com --markdown report.md --no-active
```

**Options:**
- `--no-passive` - Skip passive reconnaissance
- `--no-active` - Skip active port scanning
- `--no-web` - Skip web crawler
- `--ports PORT_LIST` - Specify ports (default: 80,443,8080,8443,22,25,53,3306,5432)
- `--max-pages N` - Max pages to crawl (default: 20)
- `--json` - Output JSON only
- `--markdown FILE` - Save Markdown report

---

## GUI Interface

### Layout

**Header:** Cyan gradient with "CY.Recon By Cyberveins" branding

**Left Panel:**
- Target configuration (domain/IP/URL)
- Port specification
- Module toggles (Passive, Active, Web)
- Control buttons (Start/Stop)
- Export options (JSON/Markdown)

**Right Panel:**
- Real-time scan results
- Green-on-black terminal style output
- Status indicator

**Footer:** Team credit and version info

### Color Scheme
- Background: Black (#0d0d0d / #1a1a1a)
- Text: White (#ffffff)
- Accents: Cyan (#00bfff)
- Output: Green (#00ff00)
- Warnings: Red (#ff6b6b)

---

## File Structure

```
CY.Recon/
├── super_recon.py          # Core reconnaissance engine
├── super_recon_gui.py      # Web/Tkinter GUI interface
├── run_gui.sh              # GUI launcher script
├── requirements.txt        # Python dependencies
└── README.md               # This file
```

---

## Dependencies

- **requests** - HTTP requests
- **beautifulsoup4** - Web scraping
- **dnspython** - DNS resolution
- **python-whois** - WHOIS lookup
- **tldextract** - Domain extraction
- **flask** - Web interface
- **werkzeug** - WSGI utilities

---

## Examples

### Scan a website
```bash
python3 super_recon_gui.py  # Open web interface
# Enter: example.com
# Toggle modules as needed
# Click: ▶ START SCAN
```

### Quick CLI scan
```bash
python3 super_recon.py scanme.nmap.org
```

### Aggressive scan with custom ports
```bash
python3 super_recon.py 192.0.2.0 --ports 1-1024 --max-pages 50 --markdown report.md
```

### JSON export for automation
```bash
python3 super_recon.py target.com --json > results.json
```

---

## Performance Tips

- **Port scanning**: Reduce port range for faster results (default is ~11 ports)
- **Web crawling**: Lower max-pages value for quick surveys (default: 20)
- **Passive only**: Use `--no-active --no-web` for speed

---

## Disclaimer

This tool is designed for **authorized security testing only**. Users are responsible for:
- Obtaining proper authorization before testing
- Complying with all applicable laws and regulations
- Not using for malicious purposes
- Respecting target systems and data

**Unauthorized access to computer systems is illegal.**

---

## Support

For issues or questions about the CY.Recon tool, ensure you have:
1. Latest Python installed
2. All dependencies from requirements.txt
3. Proper authorization for your target

---

## Version
- **v1.0.0**
- © 2025 Cyberveins
- Created by: TEAM ID - CY202501NAND
