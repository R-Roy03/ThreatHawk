<div align="center">

# 🦅 ThreatHawk

### AI-Powered Endpoint Detection & Response (EDR) System

Real-time threat monitoring with ML-based anomaly detection, live dashboard & REST API.

---

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-Backend-green)
![ML](https://img.shields.io/badge/ML-IsolationForest-orange)
![SQLite](https://img.shields.io/badge/Database-SQLite-lightgrey)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Status](https://img.shields.io/badge/Status-Active-success)

</div>

---

## 🚀 Overview

ThreatHawk is a modern Endpoint Detection & Response (EDR) platform designed to monitor system activity in real time and detect suspicious behavior using rule-based analysis combined with machine learning.

It continuously collects system telemetry, analyzes events, detects anomalies, assigns threat scores, and provides actionable alerts via a live dashboard and REST API.

---

## ✨ Key Features

✅ Real-time process monitoring  
✅ Network connection inspection  
✅ File integrity monitoring  
✅ ML anomaly detection (Isolation Forest)  
✅ Threat scoring engine  
✅ FastAPI backend with Swagger docs  
✅ Live security dashboard  
✅ Manual scan trigger  
✅ SQLite event storage  
✅ Modular security engine  

---

## 🧠 How It Works

```
Collect → Analyze → Detect → Score → Alert → Visualize
```

1. Collectors monitor system processes, network, files, and metrics  
2. Analyzer evaluates behavior patterns  
3. ML model detects anomalies  
4. Threat scorer assigns risk score  
5. Alerts generated for suspicious activity  
6. Dashboard displays events in real time  

---

## 🏗 Architecture

```
System Sensors
     ↓
Collectors Layer
     ↓
Analysis Engine
     ↓
ML Detection
     ↓
Threat Scoring
     ↓
Database + API
     ↓
Dashboard
```

---

## 🛠 Tech Stack

- Python 3.10+
- FastAPI
- SQLite
- SQLAlchemy (Async)
- scikit-learn
- psutil
- watchdog
- HTML / CSS / JavaScript

---

## 📂 Project Structure

```
ThreatHawk/
├── main.py
├── requirements.txt
├── config/
├── src/
│   ├── collectors/
│   ├── analyzers/
│   ├── ml/
│   ├── api/
│   ├── database/
│   ├── dashboard/
│   └── utils/
└── tests/
```

---

## ⚡ Quick Start

### Clone Repository

```bash
git clone https://github.com/yourusername/ThreatHawk.git
cd ThreatHawk
```

### Setup Environment

```bash
python -m venv venv
venv\Scripts\activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Run Application

```bash
python main.py
```

---

## 🌐 Access

Dashboard → http://localhost:8000/dashboard  
API Docs → http://localhost:8000/docs  

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|-------|---------|------------|
| GET | / | Health check |
| GET | /api/events | Security events |
| GET | /api/alerts | Alerts |
| POST | /api/scan | Manual scan |
| GET | /dashboard | Dashboard |

---

## 🔒 Use Cases

- Malware detection research
- Blue team monitoring
- SOC simulation
- Cybersecurity learning
- Endpoint security experiments
- Threat hunting practice

---

## 🧪 Future Improvements

- SIEM integration
- Alert notifications (Slack / Email)
- Multi-agent deployment
- Cloud monitoring support
- Behavior baselining
- Threat intelligence feeds
- RBAC authentication
- Docker deployment

---

## 👤 Author

**Rakesh Raushan**


---

## 📜 License

MIT License

---

<div align="center">

⭐ If you like this project, consider giving it a star!

</div>
