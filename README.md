# GUI-Based-Phishing-Detection-tool

 Overview
PhishScan is a Python desktop application with a sleek GUI (Tkinter/CustomTkinter) for real-time phishing URL detection. It's designed for investigators—for example, Gujarat Police—to analyse phishing threats using heuristics, OSINT, and threat intelligence.

##  Highlights
-  Heuristic Analysis (URL patterns, punycode, domain age, redirections)
-  OSINT & Network probing (WHOIS, DNS, reverse IP lookup, SSL, port scan, geolocation + map embed)
-  Threat Intelligence (Google Safe Browsing, VirusTotal, AbuseIPDB)
-  Clean, modular code (`heuristics.py`, `threat_intel.py`, `main_gui.py`)
-  Evidence-grade visuals and exports (formatted JSON, interactive map)

##  Installation
1. Clone the repo:
    ```bash
    git clone https://github.com/your-username/phishscan.git
    cd phishscan
    ```
2. Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

##  Usage
- Run GUI mode:
    ```bash
    python main_gui.py
    ```
- Or use CLI scanner:
    ```bash
    python main.py
    ```
