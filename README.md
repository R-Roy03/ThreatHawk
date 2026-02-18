# 🦅 ThreatHawk

**AI-Powered Endpoint Detection & Response (EDR) System**

ThreatHawk is a real-time security monitoring agent that detects suspicious activities on your system using rule-based analysis and machine learning.

---

## 🎯 Features

- Process Monitoring — Detects suspicious processes (mimikatz, keylogger, etc.)
- Network Monitoring — Flags connections to suspicious ports & port scans
- File Integrity — Watches for suspicious file changes (.exe, .bat, .ps1)
- System Metrics — Tracks CPU, memory, disk usage in real-time
- ML Anomaly Detection — Isolation Forest algorithm to find unusual behavior
- Threat Scoring — Automatic 0.0 to 1.0 threat scoring for every event
- REST API — Full FastAPI backend with Swagger documentation
- Live Dashboard — Dark-themed real-time security dashboard
- One-Click Scan — Manual scan trigger from dashboard

---

## 🛠️ Tech Stack

| Component | Technology |
|----------|-----------|
| Backend | Python 3.10+ |
| API Framework | FastAPI |
| Database | SQLite + SQLAlchemy (Async) |
| ML Engine | scikit-learn (Isolation Forest) |
| Frontend | HTML, CSS, JavaScript |
| Monitoring | psutil, watchdog |
| Auth Ready | python-jose (JWT) |

---

## 📂 Project Structure

ThreatHawk/
├── main.py                     # Entry point
├── requirements.txt           # Dependencies
├── config/
│   └── default.yaml           # Configuration
├── src/
│   ├── core/
│   │   ├── config.py          # Settings management
│   │   ├── constants.py       # All constants
│   │   ├── exceptions.py      # Custom errors
│   │   └── engine.py          # Main engine
│   ├── collectors/
│   │   ├── base_collector.py
│   │   ├── process_collector.py
│   │   ├── network_collector.py
│   │   ├── file_collector.py
│   │   └── system_collector.py
│   ├── analyzers/
│   │   ├── threat_scorer.py
│   │   └── event_analyzer.py
│   ├── ml/
│   │   └── models/
│   │       └── anomaly_detector.py
│   ├── api/
│   │   ├── app.py
│   │   ├── routes/
│   │   │   ├── routes.py
│   │   │   └── dashboard.py
│   │   └── schemas/
│   │       └── schemas.py
│   ├── database/
│   │   ├── connection.py
│   │   └── models.py
│   ├── dashboard/
│   │   └── templates/
│   │       └── base.html
│   └── utils/
│       ├── logger.py
│       └── helpers.py
└── tests/

---

## 🚀 Quick Start

### 1. Clone the repo

git clone https://github.com/R-Roy03/ThreatHawk.git
cd ThreatHawk

### 2. Setup virtual environment

python -m venv venv

Windows:
venv\Scripts\activate

Linux/Mac:
source venv/bin/activate

### 3. Install dependencies

pip install -r requirements.txt

### 4. Run the application

python main.py

### 5. Open in browser

Dashboard: http://localhost:8000/dashboard  
API Docs:  http://localhost:8000/docs

---

## 📡 API Endpoints

GET    /                     — Health check  
GET    /api/dashboard        — Dashboard stats  
GET    /api/events           — All security events  
GET    /api/events/{id}      — Single event  
GET    /api/alerts           — All alerts  
PUT    /api/alerts/{id}      — Update alert status  
POST   /api/scan             — Trigger manual scan  
GET    /dashboard            — Web dashboard  

---

## 🧠 How It Works

1. COLLECT  → Collectors scan processes, network, files  
2. ANALYZE  → Threat scorer evaluates each event  
3. DETECT   → ML model flags anomalies  
4. ALERT    → High-score events become alerts  
5. DISPLAY  → Dashboard shows everything in real-time  

---

## 👤 Author

Rakesh Raushan

---

## 📜 License

MIT License
