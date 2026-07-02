![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-Backend-009688?logo=fastapi)
![Gemini AI](https://img.shields.io/badge/Google-Gemini_AI-4285F4?logo=google)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Hackathon_Project-orange)
![AI Powered](https://img.shields.io/badge/AI-Powered-purple)

# 🚔 PRAHARI AI
### AI-Powered Digital Public Safety Intelligence Platform

> **PRAHARI AI** is an intelligent public safety platform that leverages Artificial Intelligence, Graph Intelligence, Geospatial Analytics, and Large Language Models (LLMs) to proactively detect, prevent, and investigate digital fraud, organized scam networks, and counterfeit currency circulation.

---

## 📌 Problem Statement

Traditional fraud investigation systems are largely reactive, requiring victims to report incidents before authorities can take action.

PRAHARI AI transforms this approach by providing predictive intelligence that helps:

- 👮 Law Enforcement Agencies
- 🏦 Financial Institutions
- 👥 Citizens

detect, disrupt, and respond to cyber fraud in real time.

---

# ✨ Key Features

## 🤖 AI Scam Detection

- Detects Digital Arrest scams
- Identifies phishing and social engineering attacks
- Real-time AI-powered fraud classification
- Explainable AI responses using Gemini AI

---

## 🕸 Fraud Network Graph Intelligence

- Maps scammer relationships
- Identifies fraud rings
- Connects victims, devices, accounts, and phone numbers
- Visual network intelligence dashboard

---

## 🗺 Geospatial Crime Intelligence

- Crime hotspot visualization
- Interactive maps
- Fraud complaint clustering
- Resource deployment intelligence
- Heatmap generation

---

## 💵 Counterfeit Currency Detection

- AI-assisted fake currency identification
- Image-based note analysis
- Security feature verification
- Confidence score prediction

---

## 💬 Citizen Fraud Shield

- Real-time fraud assistance
- WhatsApp Integration
- Multi-language support
- Instant fraud risk assessment
- AI-generated guidance

---

## 📊 Real-Time Dashboard

- Live analytics
- Scam statistics
- Fraud trends
- Threat intelligence
- Interactive charts
- System health monitoring

---

# 🏗 System Architecture

```
                Citizens / Police / Banks
                         │
                         ▼
                 React Frontend Dashboard
                         │
                         ▼
                  FastAPI Backend API
                         │
     ┌──────────┬──────────────┬──────────────┐
     ▼          ▼              ▼              ▼
 Scam AI    Graph AI     Geospatial AI   Currency AI
     │          │              │              │
     └──────────┴──────────────┴──────────────┘
                         │
                         ▼
                     Gemini AI
                         │
                         ▼
                   PostgreSQL Database
```

---

# 🛠 Tech Stack

### Frontend

- HTML5
- CSS3
- JavaScript
- Chart.js
- Leaflet Maps

### Backend

- FastAPI
- Python
- Uvicorn

### AI & Machine Learning

- Google Gemini AI
- Scikit-learn
- NetworkX
- Pillow

### Database

- SQLite / PostgreSQL

### APIs & Services

- Twilio WhatsApp API
- ngrok
- REST APIs

---

# 📂 Project Structure

```
PRAHARI-AI/
│
├── backend/
│   ├── main.py
│   ├── database.py
│   ├── graph_intel.py
│   ├── geospatial.py
│   ├── gemini_classifier.py
│   ├── counterfeit_currency.py
│   ├── websocket_manager.py
│   ├── forecasting.py
│   ├── audit_log.py
│   ├── requirements.txt
│   └── .env
│
├── frontend/
│   ├── index.html
│   ├── css/
│   ├── js/
│   └── assets/
│
└── README.md
```

---

# 🚀 Installation

## Clone Repository

```bash
git clone https://github.com/yourusername/PRAHARI-AI.git
cd PRAHARI-AI
```

---

## Backend Setup

```bash
cd backend

python -m venv venv

venv\Scripts\activate      # Windows

pip install -r requirements.txt
```

Create `.env`

```env
GEMINI_API_KEY=YOUR_API_KEY
```

Run Backend

```bash
python -m uvicorn main:app --reload
```

Backend runs on:

```
http://localhost:8000
```

Swagger Documentation

```
http://localhost:8000/docs
```

---

## Frontend

Open the frontend using VS Code Live Server

or

```bash
npm install
npm run dev
```

---

# 📸 Screenshots

Add screenshots here:

- Dashboard
- Fraud Detection
- Crime Map
- Graph Intelligence
- WhatsApp Demo
- Counterfeit Detection

---

# 🔥 Demo Workflow

1. User submits suspicious message.
2. AI classifies fraud risk.
3. Gemini generates explanation.
4. Fraud network is analyzed.
5. Crime hotspot is mapped.
6. Alert is generated.
7. Dashboard updates in real time.

---

# 🎯 Future Enhancements

- Voice Scam Detection
- Deepfake Detection
- Face Recognition
- Predictive Crime Analytics
- Mobile Application
- Blockchain-based Evidence Storage
- Multi-city Intelligence Sharing
- Advanced Explainable AI

---

# 👨‍💻 Team

**Project Name:** PRAHARI AI

Developed for an AI Hackathon.

---

# 📜 License

This project is licensed under the **MIT License**.

---

# ⭐ Support

If you like this project, please consider giving it a ⭐ on GitHub.

---

## 📬 Contact

For questions, suggestions, or collaboration:

📧 Email: your-email@example.com

🔗 GitHub: https://github.com/yourusername

---

## 🚀 Tagline

**"Detecting Fraud. Protecting Citizens. Mapping Threat Networks."**
