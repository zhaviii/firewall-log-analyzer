# 🔥 Huawei Firewall Log Analyzer

> A Python tool that parses real Huawei firewall logs, reconstructs connection sessions, detects policy violations, and generates a full interactive HTML security report.

![Python](https://img.shields.io/badge/Python-3776AB?style=flat&logo=python&logoColor=white)
![HTML Report](https://img.shields.io/badge/Report-HTML-orange?style=flat)
![Huawei](https://img.shields.io/badge/Huawei_Firewall-CF0A2C?style=flat)
![Version](https://img.shields.io/badge/version-3.0-blue?style=flat)

---

## 📌 About This Project

Built from real experience analyzing Huawei firewall logs at work. The logs contain thousands of connection events daily — reading them manually is impossible. This tool automates the analysis and produces a professional HTML report.

**This is production-tested code** — it was iterated through multiple versions based on real data, fixing critical bugs discovered by cross-checking parser output against actual log files.

---

## ✨ Features

- **Session reconstruction** — uses real `BeginTime`/`EndTime` fields from each log entry to accurately calculate connection durations (not just the moment the log was written)
- **No double-counting** — correctly handles the fact that Huawei firewalls emit both a top-level POLICY line and a SECLOG line per event; only SECLOG lines are counted
- **Per-PC activity cards** — collapsible cards for each internal IP, showing all apps used, session times, data transferred
- **Application categorization** — classifies apps as COMPANY (safe), WORK (allowed), OTHER, or CRITICAL (blocked/policy violation)
- **Blocked attempt tracking** — shows which policy blocked which app, how many times, and bytes leaked before the block
- **MAC-binding anomaly detection** — flags any internal IP seen with more than one distinct MAC address (possible spoofing)
- **Executive summary panel** — top blocked policies, bandwidth consumers, MAC anomalies — all visible at a glance
- **Hourly traffic chart** — 24-hour bar chart of network activity
- **Cross-midnight session flag** — marks sessions that started before midnight (previous day)
- **Filter & search** — filter by IP, app name, or risk level (Safe / Work / Other / Critical)
- **Print to PDF** — built-in print button exports the full report as PDF
- **UTC+5 timezone correction** — converts all timestamps to local time (Uzbekistan/Tashkent)

---

## 🐛 Bugs Fixed in v3 (vs v2)

| Bug | Severity | Description |
|-----|----------|-------------|
| BUG-5 | Critical | Denied events counted **twice** — POLICY + SECLOG both incremented the counter |
| BUG-6 | Critical | DNS connections inflated ~2x — synthetic DNS events added on top of real ones |
| BUG-7 | Critical | Session duration was always **0s** — used log timestamp instead of BeginTime/EndTime |
| BUG-8 | Medium | Blocked-connection bytes polluted total traffic stats |
| BUG-9 | Medium | HTTPS-based DoH blocks (8.8.8.8:443) showed as generic HTTPS, not as blocked |
| BUG-10 | Low | BitTorrent (`BT` app name) not recognized in RED_BLOCK category |

---

## 📁 Project Structure

```
firewall-log-analyzer/
├── analyzer_v3.py          # Main script (current version)
├── analyzer.py             # Simplified version for learning/reference
├── report_generator.py     # Excel report module (early version)
├── sample_logs/
│   └── sample_firewall.log # Example log for testing
├── output/                 # Generated reports (gitignored)
├── requirements.txt        # Dependencies
└── README.md
```

---

## 🚀 Usage

### Requirements

```bash
pip install -r requirements.txt
```

### Run

```bash
python analyzer_v3.py path/to/your/logfile.txt
```

**Windows users:** Drag and drop the log file onto `run_analyzer.bat`

### Output

The HTML report is saved in the **same folder as your log file**:
```
1781684141029_2026-06-15_report.html
```
On Windows, it opens automatically in your default browser.

---

## 📊 Report Sections

### Header Stats
| Metric | Description |
|--------|-------------|
| Active PCs | Number of internal IPs seen in the log |
| Total Data | Bytes transferred (successful connections only) |
| Connection Events | Total SECLOG events parsed |
| Denied | Blocked connection attempts |
| PCs w/ Blocks | How many PCs hit a block policy |
| Critical PCs | PCs with RED_BLOCK category activity |

### Executive Summary
- Top blocked policies (with app names and bytes leaked)
- Top 5 bandwidth consumers
- MAC-binding anomalies

### Per-PC Cards
Each internal IP gets a card showing:
- Risk level badge (SAFE / WORK / OTHER / CRITICAL)
- Active time window and total data
- All applications used with session times and data volumes
- Blocked attempt summary by policy name

---

## 🔧 Configuration

Edit the top of `analyzer_v3.py` to customize:

```python
# Your internal subnet prefix
SUBNET_PREFIX = "192.168.100."

# Firewall timezone offset from UTC
FW_UTC_OFFSET = timedelta(hours=5)  # UTC+5 for Uzbekistan
```

### Application Categories

| Category | Color | Meaning |
|----------|-------|---------|
| COMPANY | 🟢 Green | Microsoft, Google Workspace, corporate tools |
| WORK | 🔵 Blue | Telegram, Zoom, Yandex, DNS |
| OTHER | ⚫ Grey | Unclassified apps |
| CRITICAL | 🔴 Red | Blocked apps — P2P, VPN, social media, gaming |

---

## 💡 Technical Notes

- Only `SECLOG` lines (SESSION_TEARDOWN / PACKET_DENY) are used for accounting
- Top-level `POLICY` lines are scanned only for MAC addresses
- Sessions within 600 seconds of each other are merged into one session record
- Blocked bytes are tracked separately and excluded from traffic totals

---

## 🔮 Planned Improvements

- [ ] Support multiple log formats (pfSense, Cisco ASA, FortiGate)
- [ ] IP geolocation lookup for external IPs
- [ ] Automatic port scan pattern detection
- [ ] Email alerting for critical events
- [ ] Multi-day log comparison

---

## 👤 Author

**Temurbek** — System Administrator & CS Student, Uzbekistan
- GitHub: [@zhaviii](https://github.com/zhaviii)
- Email: temurbek.n@icloud.com
