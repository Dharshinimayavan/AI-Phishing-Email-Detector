# 🛡️ PhishGuard - AI-Based Phishing Email Detector

## 📌 Project Overview

PhishGuard is an AI-based web application designed to detect whether an email is legitimate or potentially phishing.

The system uses Machine Learning and Natural Language Processing techniques to analyze email content and identify suspicious patterns.

It provides the prediction result, model confidence, risk level, risk score, and detection indicators.

---

## 🎯 Objective

The main objective of PhishGuard is to help users identify potentially harmful phishing emails before interacting with suspicious links or sharing sensitive information.

---

## 🚀 Features

- AI-based phishing email detection
- Legitimate email detection
- Machine Learning prediction
- Confidence score
- Risk level classification
- Risk score from 0 to 100
- Detection indicators
- Email scan history
- Dashboard
- Scan reports
- Report download
- User registration and login
- Secure password storage
- Change password option
- Logout functionality

---

## 🤖 Machine Learning

The project uses:

- TF-IDF Vectorization
- Logistic Regression
- Scikit-learn

The trained model analyzes the text content of an email and predicts whether it is phishing or legitimate.

---

## 🛠️ Technologies Used

### Frontend
- HTML
- CSS

### Backend
- Python
- Flask

### Machine Learning
- Scikit-learn
- TF-IDF
- Logistic Regression
- Joblib

### Database
- SQLite

---

## 📂 Project Structure

```text
AI-Phishing-Email-Detector/
│
├── app.py
├── phishing_model.pkl
├── history.db
├── requirements.txt
├── README.md
│
├── dataset/
│   └── phishing_email.csv
│
├── templates/
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   ├── history.html
│   ├── dashboard.html
│   ├── reports.html
│   ├── details.html
│   └── settings.html
│
└── venv/