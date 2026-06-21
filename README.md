# 🔥 Firewall Log Analyzer

> A Python tool that parses firewall logs, identifies suspicious activity, and exports structured reports to Excel.

![Python](https://img.shields.io/badge/Python-3776AB?style=flat&logo=python&logoColor=white)
![Excel](https://img.shields.io/badge/Excel_Export-217346?style=flat&logo=microsoft-excel&logoColor=white)
![Security](https://img.shields.io/badge/Defensive_Security-red?style=flat)

---

## 📌 Purpose

Real firewalls generate thousands of log entries daily. Manually reading them is impractical. This tool:

- Parses raw firewall log files
- Extracts blocked IPs, protocols, ports, and timestamps
- Identifies repeated offenders and suspicious patterns
- Exports a clean, formatted Excel report

Built from real sysadmin experience working with firewall logs.

---

## 📁 Folder Structure

```
firewall-log-analyzer/
├── analyzer.py           # Main log parser script
├── report_generator.py   # Excel report builder
├── sample_logs/          # Example log files for testing
│   └── sample_firewall.log
├── output/               # Generated Excel reports (gitignored)
├── requirements.txt      # Python dependencies
└── README.md
```

---

## 🧰 Technologies

| Tool | Purpose |
|------|---------|
| Python 3 | Core language |
| pandas | Log data processing |
| openpyxl | Excel file generation |
| re (regex) | Log line parsing |

---

## 🚀 Setup & Usage

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Add Your Log File

Place your firewall log file in the `sample_logs/` folder.

### 3. Run the Analyzer

```bash
python analyzer.py --log sample_logs/sample_firewall.log
```

### 4. View Report

The Excel report is saved to `output/firewall_report.xlsx`.

---

## 📊 What the Report Shows

| Column | Description |
|--------|-------------|
| Timestamp | When the event occurred |
| Source IP | Originating IP address |
| Destination IP | Target IP address |
| Port | Destination port |
| Protocol | TCP / UDP / ICMP |
| Action | ALLOW / DENY / DROP |
| Count | How many times this occurred |

---

## 🔮 Future Improvements

- Add IP geolocation lookup
- Detect port scan patterns automatically
- Add email alerting for high-threat events
- Support multiple log formats (pfSense, Cisco ASA, Kerio)
- Build a simple web dashboard
