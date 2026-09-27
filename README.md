# 🛡️ PhishGuard - AI-Based Phishing Email Detector

## 🌐 Live Project

🔗 **PhishGuard Live Demo:**  
https://phishguard-hdva.onrender.com

The project is deployed using Render and is publicly accessible for testing.

---

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
- Joblib

The trained machine learning model analyzes the text content of an email and predicts whether it is phishing or legitimate.

---

## 📊 Model Performance

The trained model achieved approximately **98.49% accuracy** on the test dataset.

The model uses TF-IDF to convert email text into numerical features and Logistic Regression for classification.

---

## 🛠️ Technologies Used

### Frontend

- HTML
- CSS
- JavaScript

### Backend

- Python
- Flask

### Machine Learning

- Scikit-learn
- TF-IDF
- Logistic Regression
- Joblib

### Database

- PostgreSQL
- Render PostgreSQL

### Deployment

- Render
- Gunicorn

### Development Tools

- Visual Studio Code
- Git
- GitHub

---

## 🔄 System Workflow

```text
User
  ↓
Login / Register
  ↓
Enter Email Content
  ↓
Text Preprocessing
  ↓
TF-IDF Vectorization
  ↓
Logistic Regression Model
  ↓
Prediction
  ↓
Phishing / Legitimate
  ↓
Confidence & Risk Analysis
  ↓
Save Scan History
  ↓
Dashboard / Reports
