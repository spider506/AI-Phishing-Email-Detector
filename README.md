# 🛡️ AI-Powered Phishing Email Detection System

> 🚧 **Status:** Active Development (Version 0.5)

An AI-powered phishing email detection and threat analysis platform built using **Python**, **Flask**, and **Machine Learning**. The application analyzes email content, URLs, domains, authentication headers, and threat intelligence to identify phishing attempts and generate comprehensive security reports.

---

## 📌 Overview

Phishing remains one of the most common cyber threats targeting individuals and organizations. This project combines Machine Learning with rule-based security analysis to classify emails as **Phishing** or **Legitimate** while providing detailed explanations of the detected threats.

The system performs URL reputation checks, domain analysis, email header validation, IOC extraction, and automated risk scoring to assist security analysts in identifying malicious emails.

---

## 🚀 Features

* 🤖 Machine Learning-based phishing email classification
* 🌐 URL extraction and analysis
* 🛡️ VirusTotal URL reputation lookup
* 🌍 WHOIS domain information and domain age analysis
* 📧 Gmail API integration for scanning recent emails
* 🔍 Email header analysis (SPF, DKIM, DMARC)
* ⚠️ Indicator of Compromise (IOC) extraction
* 📊 Dynamic risk scoring engine
* 📄 PDF report generation
* 🗂️ Scan history management using SQLite
* 📈 Dashboard displaying scan statistics

---

## 🛠️ Technology Stack

| Category             | Technologies                              |
| -------------------- | ----------------------------------------- |
| Programming Language | Python                                    |
| Web Framework        | Flask                                     |
| Machine Learning     | Scikit-learn, Joblib                      |
| Database             | SQLite                                    |
| Frontend             | HTML, CSS, JavaScript                     |
| APIs                 | Gmail API, VirusTotal API                 |
| Security             | WHOIS Lookup, SPF, DKIM, DMARC Validation |

---

## 📂 Project Structure

```text
AI-Phishing-Email-Detector/
│
├── app.py
├── phishing_model.pkl
├── requirements.txt
├── README.md
├── .gitignore
│
├── modules/
│   ├── db_manager.py
│   ├── gmail_fetcher.py
│   ├── header_analyzer.py
│   ├── ioc_extractor.py
│   ├── keyword_analyzer.py
│   ├── pdf_report.py
│   ├── risk_engine.py
│   ├── url_checker.py
│   └── whois_checker.py
│
├── templates/
├── static/
└── Screenshots will be added after the project reaches the first stable release.
```

---

## ⚙️ Installation

### Clone the repository

```bash
git clone https://github.com/spider506/AI-Phishing-Email-Detector.git
cd AI-Phishing-Email-Detector
```

### Create a virtual environment

```bash
python -m venv venv
```

Activate it

Windows

```bash
venv\Scripts\activate
```

Linux/macOS

```bash
source venv/bin/activate
```

### Install dependencies

```bash
pip install -r requirements.txt
```

---

## 🔑 Configuration

Create your own Google OAuth credentials and VirusTotal API key.

The following files should **NOT** be committed to GitHub:

* credentials.json
* token.json
* token.pickle
* .env

---

## ▶️ Run the Application

```bash
python app.py
```

Open your browser and visit:

```text
http://127.0.0.1:5000
```

---

## 📷 Screenshots

Add screenshots of:

* Home Page
* Email Analysis
* Gmail Scanner
* Dashboard
* PDF Report

---

## 🎯 Future Enhancements

* Deep Learning models for phishing detection
* Attachment malware analysis
* QR code phishing detection
* Real-time email monitoring
* Docker deployment
* Cloud deployment (AWS/Azure)
* Multi-user authentication
* Threat intelligence integration

---

## 📚 Learning Outcomes

This project demonstrates practical experience in:

* Machine Learning
* Email Security
* Threat Intelligence
* Secure Web Development
* REST API Integration
* Flask Development
* Cybersecurity Automation
* Risk Assessment
* Python Programming

---

## 📄 License

This project is licensed under the MIT License.

---

## 👨‍💻 Author

**Shaik Feroz Ali**

Cybersecurity Graduate | Python Developer | Security Enthusiast

GitHub: https://github.com/spider506

LinkedIn: https://www.linkedin.com/in/shaik-feroz-ali/
