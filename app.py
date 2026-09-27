from flask import Flask, render_template, request, make_response, redirect, session

import joblib
import sqlite3
import re

from datetime import datetime

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)


app = Flask(__name__)

app.secret_key = "phishguard_secret_key"

model = joblib.load("phishing_model.pkl")


# ==============================
# CREATE DATABASE
# ==============================

def create_database():

    conn = sqlite3.connect("history.db")

    cursor = conn.cursor()

    # Scan history table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            result TEXT,
            confidence REAL,
            risk TEXT,
            timestamp TEXT
        )
    """)

    # Add email column if it does not exist
    try:

        cursor.execute(
            "ALTER TABLE history ADD COLUMN email TEXT"
        )

    except sqlite3.OperationalError:

        pass

    # Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    conn.commit()

    conn.close()


# ==============================
# FIND PHISHING REASONS
# ==============================

def find_reasons(email_text, prediction):

    reasons = []

    text = email_text.lower()

    # Legitimate email
    if prediction == 0:

        reasons.append(
            "No major phishing indicators detected."
        )

        return reasons

    urgent_words = [
        "urgent",
        "immediately",
        "verify now",
        "act now",
        "account suspended",
        "limited time"
    ]

    sensitive_words = [
        "password",
        "bank details",
        "credit card",
        "otp",
        "login details",
        "personal information"
    ]

    link_words = [
        "click here",
        "click the link",
        "verify your account",
        "open the link"
    ]

    # Urgent language
    for word in urgent_words:

        if word in text:

            reasons.append(
                "Urgent or threatening language detected."
            )

            break

    # Sensitive information
    for word in sensitive_words:

        if word in text:

            reasons.append(
                "Request for sensitive information detected."
            )

            break

    # Suspicious links
    for word in link_words:

        if word in text:

            reasons.append(
                "Suspicious link or verification language detected."
            )

            break

    # URL detection
    urls = re.findall(
        r"https?://[^\s]+",
        text
    )

    if urls:

        reasons.append(
            "URL or web link detected in the email."
        )

    # Shortened URL
    short_url_words = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly"
    ]

    for word in short_url_words:

        if word in text:

            reasons.append(
                "Shortened URL detected, which may hide the actual destination."
            )

            break

    # Default reason
    if not reasons:

        reasons.append(
            "ML model detected characteristics commonly associated with phishing emails."
        )

    return reasons


# ==============================
# CALCULATE RISK SCORE
# ==============================

def calculate_risk_score(email_text, prediction):

    text = email_text.lower()

    score = 0

    # ML prediction
    if prediction == 1:

        score += 50

    urgent_words = [
        "urgent",
        "immediately",
        "verify now",
        "act now",
        "account suspended",
        "limited time"
    ]

    sensitive_words = [
        "password",
        "bank details",
        "credit card",
        "otp",
        "login details",
        "personal information"
    ]

    link_words = [
        "click here",
        "click the link",
        "verify your account",
        "open the link"
    ]

    # Urgent language
    for word in urgent_words:

        if word in text:

            score += 10

            break

    # Sensitive information
    for word in sensitive_words:

        if word in text:

            score += 15

            break

    # Suspicious link
    for word in link_words:

        if word in text:

            score += 10

            break

    # URL
    urls = re.findall(
        r"https?://[^\s]+",
        text
    )

    if urls:

        score += 10

    # Short URL
    short_url_words = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly"
    ]

    for word in short_url_words:

        if word in text:

            score += 5

            break

    # Maximum score
    if score > 100:

        score = 100

    # Legitimate email limit
    if prediction == 0:

        score = min(score, 25)

    return score


# ==============================
# LOGIN REQUIRED
# ==============================

def login_required():

    if "user_id" not in session:

        return False

    return True


# ==============================
# LOGIN
# ==============================

@app.route("/login", methods=["GET", "POST"])
def login():

    error = ""

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        conn = sqlite3.connect(
            "history.db"
        )

        cursor = conn.cursor()

        cursor.execute("""
            SELECT id, name, email, password
            FROM users
            WHERE email = ?
        """, (email,))

        user = cursor.fetchone()

        conn.close()

        if user and check_password_hash(
            user[3],
            password
        ):

            session["user_id"] = user[0]

            session["user_name"] = user[1]

            session["user_email"] = user[2]

            return redirect("/")

        else:

            error = "Invalid email or password."

    return render_template(
        "login.html",
        error=error
    )


# ==============================
# REGISTER
# ==============================

@app.route("/register", methods=["GET", "POST"])
def register():

    error = ""

    if request.method == "POST":

        name = request.form.get(
            "name",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        # Password match
        if password != confirm_password:

            error = "Passwords do not match."

            return render_template(
                "register.html",
                error=error
            )

        # Password length
        if len(password) < 6:

            error = (
                "Password must contain at least 6 characters."
            )

            return render_template(
                "register.html",
                error=error
            )

        conn = sqlite3.connect(
            "history.db"
        )

        cursor = conn.cursor()

        # Check existing user
        cursor.execute("""
            SELECT id
            FROM users
            WHERE email = ?
        """, (email,))

        existing_user = cursor.fetchone()

        if existing_user:

            conn.close()

            error = (
                "An account with this email already exists."
            )

            return render_template(
                "register.html",
                error=error
            )

        # Hash password
        hashed_password = generate_password_hash(
            password
        )

        # Insert user
        cursor.execute("""
            INSERT INTO users
            (name, email, password)
            VALUES (?, ?, ?)
        """, (
            name,
            email,
            hashed_password
        ))

        conn.commit()

        conn.close()

        return redirect("/login")

    return render_template(
        "register.html",
        error=error
    )


# ==============================
# LOGOUT
# ==============================

@app.route("/logout")
def logout():

    session.clear()

    return redirect("/login")


# ==============================
# HOME / EMAIL DETECTOR
# ==============================

@app.route("/", methods=["GET", "POST"])
def home():

    if not login_required():

        return redirect("/login")

    result = ""

    confidence = ""

    risk = ""

    reasons = []

    risk_score = 0

    if request.method == "POST":

        email_text = request.form.get(
            "email",
            ""
        ).strip()

        if email_text == "":

            result = "Please enter an email."

        else:

            # ML prediction
            prediction = model.predict(
                [email_text]
            )[0]

            # Probability
            probabilities = model.predict_proba(
                [email_text]
            )[0]

            confidence = round(
                max(probabilities) * 100,
                2
            )

            # Result
            if prediction == 1:

                result = "Phishing Email"

                risk = "HIGH"

            else:

                result = "Legitimate Email"

                risk = "LOW"

            # Detection reasons
            reasons = find_reasons(
                email_text,
                prediction
            )

            # Risk score
            risk_score = calculate_risk_score(
                email_text,
                prediction
            )

            # Save scan
            conn = sqlite3.connect(
                "history.db"
            )

            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO history
                (email, result, confidence, risk, timestamp)
                VALUES (?, ?, ?, ?, ?)
            """, (
                email_text,
                result,
                confidence,
                risk,
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            ))

            conn.commit()

            conn.close()

    return render_template(
        "index.html",
        result=result,
        confidence=confidence,
        risk=risk,
        reasons=reasons,
        risk_score=risk_score
    )


# ==============================
# HISTORY
# ==============================

@app.route("/history")
def history():

    if not login_required():

        return redirect("/login")

    conn = sqlite3.connect(
        "history.db"
    )

    cursor = conn.cursor()

    # Total scans
    cursor.execute("""
        SELECT COUNT(*)
        FROM history
    """)

    total_scans = cursor.fetchone()[0]

    # Phishing count
    cursor.execute("""
        SELECT COUNT(*)
        FROM history
        WHERE result = 'Phishing Email'
    """)

    phishing_count = cursor.fetchone()[0]

    # Legitimate count
    cursor.execute("""
        SELECT COUNT(*)
        FROM history
        WHERE result = 'Legitimate Email'
    """)

    legitimate_count = cursor.fetchone()[0]

    # All records
    cursor.execute("""
        SELECT
            id,
            result,
            confidence,
            risk,
            timestamp
        FROM history
        ORDER BY id DESC
    """)

    records = cursor.fetchall()

    conn.close()

    return render_template(
        "history.html",
        records=records,
        total_scans=total_scans,
        phishing_count=phishing_count,
        legitimate_count=legitimate_count
    )


# ==============================
# DELETE SCAN
# ==============================

@app.route(
    "/delete/<int:scan_id>",
    methods=["POST"]
)
def delete_scan(scan_id):

    if not login_required():

        return redirect("/login")

    conn = sqlite3.connect(
        "history.db"
    )

    cursor = conn.cursor()

    cursor.execute("""
        DELETE FROM history
        WHERE id = ?
    """, (scan_id,))

    conn.commit()

    conn.close()

    return redirect("/history")


# ==============================
# DASHBOARD
# ==============================

@app.route("/dashboard")
def dashboard():

    if not login_required():

        return redirect("/login")

    conn = sqlite3.connect(
        "history.db"
    )

    cursor = conn.cursor()

    # Total scans
    cursor.execute("""
        SELECT COUNT(*)
        FROM history
    """)

    total_scans = cursor.fetchone()[0]

    # Phishing count
    cursor.execute("""
        SELECT COUNT(*)
        FROM history
        WHERE result = 'Phishing Email'
    """)

    phishing_count = cursor.fetchone()[0]

    # Legitimate count
    cursor.execute("""
        SELECT COUNT(*)
        FROM history
        WHERE result = 'Legitimate Email'
    """)

    legitimate_count = cursor.fetchone()[0]

    # Average confidence
    cursor.execute("""
        SELECT AVG(confidence)
        FROM history
    """)

    average_confidence = cursor.fetchone()[0]

    # Recent scans
    cursor.execute("""
        SELECT
            id,
            result,
            confidence,
            risk,
            timestamp
        FROM history
        ORDER BY id DESC
        LIMIT 5
    """)

    recent_scans = cursor.fetchall()

    conn.close()

    # Average confidence
    if average_confidence is None:

        average_confidence = 0

    else:

        average_confidence = round(
            average_confidence,
            2
        )

    # Percentage
    if total_scans > 0:

        phishing_percentage = round(
            (phishing_count / total_scans) * 100,
            1
        )

        legitimate_percentage = round(
            (legitimate_count / total_scans) * 100,
            1
        )

    else:

        phishing_percentage = 0

        legitimate_percentage = 0

    return render_template(
        "dashboard.html",
        total_scans=total_scans,
        phishing_count=phishing_count,
        legitimate_count=legitimate_count,
        average_confidence=average_confidence,
        phishing_percentage=phishing_percentage,
        legitimate_percentage=legitimate_percentage,
        recent_scans=recent_scans
    )


# ==============================
# REPORTS
# ==============================

@app.route("/reports")
def reports():

    if not login_required():

        return redirect("/login")

    conn = sqlite3.connect(
        "history.db"
    )

    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            result,
            confidence,
            risk,
            timestamp
        FROM history
        ORDER BY id DESC
    """)

    reports = cursor.fetchall()

    conn.close()

    return render_template(
        "reports.html",
        reports=reports
    )


# ==============================
# DETAILS
# ==============================

@app.route("/details/<int:scan_id>")
def details(scan_id):

    if not login_required():

        return redirect("/login")

    conn = sqlite3.connect(
        "history.db"
    )

    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            email,
            result,
            confidence,
            risk,
            timestamp
        FROM history
        WHERE id = ?
    """, (scan_id,))

    record = cursor.fetchone()

    conn.close()

    if record is None:

        return "Scan record not found.", 404

    # Database values
    scan_id = record[0]

    email = record[1]

    result = record[2]

    confidence = record[3]

    risk = record[4]

    timestamp = record[5]

    # Convert result into prediction
    if result == "Phishing Email":

        prediction = "Phishing Email"

        prediction_value = 1

    else:

        prediction = "Legitimate Email"

        prediction_value = 0

    # Detection reasons
    reasons = find_reasons(
        email,
        prediction_value
    )

    # Risk score
    risk_score = calculate_risk_score(
        email,
        prediction_value
    )

    return render_template(
        "details.html",
        scan_id=scan_id,
        email=email,
        prediction=prediction,
        confidence=confidence,
        risk=risk,
        timestamp=timestamp,
        reasons=reasons,
        risk_score=risk_score
    )


# ==============================
# DOWNLOAD REPORT
# ==============================

@app.route("/report/<int:scan_id>")
def report(scan_id):

    if not login_required():

        return redirect("/login")

    conn = sqlite3.connect(
        "history.db"
    )

    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            email,
            result,
            confidence,
            risk,
            timestamp
        FROM history
        WHERE id = ?
    """, (scan_id,))

    record = cursor.fetchone()

    conn.close()

    if record is None:

        return "Scan record not found.", 404

    scan_id = record[0]

    email = record[1]

    result = record[2]

    confidence = record[3]

    risk = record[4]

    timestamp = record[5]

    prediction = (
        1
        if result == "Phishing Email"
        else 0
    )

    reasons = find_reasons(
        email,
        prediction
    )

    risk_score = calculate_risk_score(
        email,
        prediction
    )

    # Result information
    if result == "Phishing Email":

        result_icon = "⚠️"

        result_class = "phishing"

        risk_icon = "🔴"

        recommendation_title = (
            "Do Not Interact With This Email"
        )

        recommendation_text = (
            "This email has been classified as potentially "
            "phishing. Do not click links, download attachments, "
            "or provide passwords, OTPs, banking information, "
            "or other sensitive information."
        )

    else:

        result_icon = "✅"

        result_class = "legitimate"

        risk_icon = "🟢"

        recommendation_title = (
            "No Major Phishing Indicators"
        )

        recommendation_text = (
            "The email has been classified as legitimate by "
            "the PhishGuard detection model. However, users "
            "should still verify unexpected requests before "
            "sharing sensitive information."
        )

    # Detection indicators
    indicator_html = ""

    for reason in reasons:

        indicator_html += f"""
        <div class="indicator">
            <span class="indicator-icon">⚠️</span>
            <span>{reason}</span>
        </div>
        """

    # Generate report HTML
    html = f"""
<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width, initial-scale=1.0">

<title>
    PhishGuard Security Report #{scan_id}
</title>

<style>

* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;
    padding: 0;
    font-family:
        Arial,
        Helvetica,
        sans-serif;
    background: #f4f7fb;
    color: #1f2937;
}}

.container {{
    width: 90%;
    max-width: 1000px;
    margin: 40px auto;
}}

.report {{
    background: white;
    border-radius: 16px;
    overflow: hidden;
    box-shadow:
        0 8px 30px
        rgba(0, 0, 0, 0.08);
}}

/* HEADER */

.header {{
    background:
        linear-gradient(
            135deg,
            #0f172a,
            #1e3a8a
        );
    color: white;
    padding: 35px;
}}

.logo {{
    font-size: 28px;
    font-weight: bold;
}}

.logo span {{
    color: #60a5fa;
}}

.header h1 {{
    margin-top: 25px;
    margin-bottom: 8px;
    font-size: 30px;
}}

.header p {{
    color: #dbeafe;
}}

/* SECTIONS */

.section {{
    padding: 30px;
}}

.section-title {{
    font-size: 20px;
    font-weight: bold;
    margin-bottom: 20px;
    color: #111827;
}}

/* SUMMARY */

.grid {{
    display: grid;
    grid-template-columns:
        repeat(4, 1fr);
    gap: 18px;
}}

.card {{
    border: 1px solid #e5e7eb;
    border-radius: 12px;
    padding: 20px;
    background: #fafafa;
}}

.label {{
    font-size: 13px;
    color: #6b7280;
    margin-bottom: 8px;
}}

.value {{
    font-size: 18px;
    font-weight: bold;
    color: #111827;
}}

.phishing {{
    color: #dc2626;
}}

.legitimate {{
    color: #16a34a;
}}

/* CONFIDENCE */

.confidence-box {{
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 12px;
    padding: 22px;
}}

.confidence-header {{
    display: flex;
    justify-content:
        space-between;
    margin-bottom: 12px;
}}

.confidence-value {{
    font-weight: bold;
    color: #2563eb;
}}

.progress {{
    width: 100%;
    height: 12px;
    background: #e5e7eb;
    border-radius: 20px;
    overflow: hidden;
}}

.progress-bar {{
    height: 100%;
    width: {confidence}%;
    background: #2563eb;
    border-radius: 20px;
}}

/* RISK */

.risk-box {{
    background: #fef2f2;
    border: 1px solid #fecaca;
    border-radius: 12px;
    padding: 22px;
}}

.risk-header {{
    display: flex;
    justify-content:
        space-between;
    margin-bottom: 15px;
}}

.risk-title {{
    font-weight: bold;
    color: #991b1b;
}}

.risk-score {{
    font-size: 22px;
    font-weight: bold;
    color: #dc2626;
}}

.risk-progress {{
    width: 100%;
    height: 12px;
    background: #fee2e2;
    border-radius: 20px;
    overflow: hidden;
}}

.risk-progress-bar {{
    height: 100%;
    width: {risk_score}%;
    background: #dc2626;
    border-radius: 20px;
}}

/* EMAIL */

.email-box {{
    background: #f8fafc;
    border: 1px solid #e5e7eb;
    border-radius: 12px;
    padding: 22px;
    white-space: pre-wrap;
    word-wrap: break-word;
    font-size: 14px;
    line-height: 1.7;
    color: #374151;
}}

/* INDICATORS */

.indicator {{
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 14px 16px;
    margin-bottom: 10px;
    background: #fff7ed;
    border: 1px solid #fed7aa;
    border-radius: 10px;
    color: #9a3412;
    font-size: 14px;
}}

.indicator-icon {{
    font-size: 17px;
}}

/* RECOMMENDATION */

.recommendation {{
    background: #eff6ff;
    border: 1px solid #bfdbfe;
    border-radius: 12px;
    padding: 22px;
}}

.recommendation h3 {{
    color: #1e40af;
    margin-top: 0;
}}

.recommendation p {{
    color: #374151;
    line-height: 1.7;
}}

/* FOOTER */

.footer {{
    border-top: 1px solid #e5e7eb;
    padding: 25px;
    text-align: center;
    color: #6b7280;
    font-size: 13px;
}}

.footer strong {{
    color: #374151;
}}

/* MOBILE */

@media (max-width: 800px) {{

    .grid {{
        grid-template-columns:
            repeat(2, 1fr);
    }}

}}

@media (max-width: 550px) {{

    .container {{
        width: 95%;
        margin: 20px auto;
    }}

    .header {{
        padding: 25px 20px;
    }}

    .section {{
        padding: 20px;
    }}

    .grid {{
        grid-template-columns: 1fr;
    }}

}}

</style>

</head>


<body>

<div class="container">

<div class="report">


<!-- HEADER -->

<div class="header">

<div class="logo">

    🛡️ <span>PhishGuard</span>

</div>

<h1>
    Phishing Email Detection Report
</h1>

<p>
    Detailed AI-based security analysis
    for Scan #{scan_id}
</p>

</div>


<!-- SUMMARY -->

<div class="section">

<div class="section-title">
    📊 Scan Summary
</div>

<div class="grid">


<div class="card">

<div class="label">
    Scan ID
</div>

<div class="value">
    #{scan_id}
</div>

</div>


<div class="card">

<div class="label">
    Detection Result
</div>

<div class="value {result_class}">
    {result_icon} {result}
</div>

</div>


<div class="card">

<div class="label">
    Risk Level
</div>

<div class="value {result_class}">
    {risk_icon} {risk}
</div>

</div>


<div class="card">

<div class="label">
    Scan Date & Time
</div>

<div class="value">
    {timestamp}
</div>

</div>


</div>

</div>


<!-- CONFIDENCE -->

<div class="section">

<div class="section-title">
    🎯 Model Confidence
</div>

<div class="confidence-box">

<div class="confidence-header">

<span>
    Prediction Confidence
</span>

<span class="confidence-value">
    {confidence}%
</span>

</div>

<div class="progress">

<div class="progress-bar"></div>

</div>

</div>

</div>


<!-- RISK SCORE -->

<div class="section">

<div class="section-title">
    ⚠️ Risk Assessment
</div>

<div class="risk-box">

<div class="risk-header">

<span class="risk-title">
    Overall Risk Score
</span>

<span class="risk-score">
    {risk_score}/100
</span>

</div>

<div class="risk-progress">

<div class="risk-progress-bar"></div>

</div>

</div>

</div>


<!-- EMAIL -->

<div class="section">

<div class="section-title">
    📧 Scanned Email
</div>

<div class="email-box">
{email}
</div>

</div>


<!-- INDICATORS -->

<div class="section">

<div class="section-title">
    🚨 Detection Indicators
</div>

{indicator_html}

</div>


<!-- RECOMMENDATION -->

<div class="section">

<div class="section-title">
    🔐 Security Recommendation
</div>

<div class="recommendation">

<h3>
    {recommendation_title}
</h3>

<p>
    {recommendation_text}
</p>

</div>

</div>


<!-- FOOTER -->

<div class="footer">

<p>
    <strong>PhishGuard</strong>
    — AI-Based Phishing Email Detector
</p>

<p>
    Automated security analysis report
</p>

</div>


</div>

</div>

</body>

</html>
"""

    response = make_response(html)

    response.headers["Content-Type"] = (
        "text/html; charset=utf-8"
    )

    response.headers["Content-Disposition"] = (
        f"attachment; "
        f"filename=PhishGuard_Report_{scan_id}.html"
    )

    return response


# ==============================
# CHANGE PASSWORD
# ==============================

@app.route(
    "/change-password",
    methods=["POST"]
)
def change_password():

    if not login_required():

        return redirect("/login")

    current_password = request.form.get(
        "current_password",
        ""
    )

    new_password = request.form.get(
        "new_password",
        ""
    )

    confirm_password = request.form.get(
        "confirm_password",
        ""
    )

    # Check new password length
    if len(new_password) < 6:

        return """
        <script>
            alert("New password must contain at least 6 characters.");
            window.location.href = "/settings";
        </script>
        """

    # Check new passwords match
    if new_password != confirm_password:

        return """
        <script>
            alert("New passwords do not match.");
            window.location.href = "/settings";
        </script>
        """

    # Get logged-in user
    user_id = session.get("user_id")

    conn = sqlite3.connect(
        "history.db"
    )

    cursor = conn.cursor()

    cursor.execute("""
        SELECT password
        FROM users
        WHERE id = ?
    """, (user_id,))

    user = cursor.fetchone()

    if user is None:

        conn.close()

        return redirect("/login")

    stored_password = user[0]

    # Verify current password
    if not check_password_hash(
        stored_password,
        current_password
    ):

        conn.close()

        return """
        <script>
            alert("Current password is incorrect.");
            window.location.href = "/settings";
        </script>
        """

    # Generate new hashed password
    new_hashed_password = generate_password_hash(
        new_password
    )

    # Update password
    cursor.execute("""
        UPDATE users
        SET password = ?
        WHERE id = ?
    """, (
        new_hashed_password,
        user_id
    ))

    conn.commit()

    conn.close()

    return """
    <script>
        alert("Password changed successfully!");
        window.location.href = "/settings";
    </script>
    """


# ==============================
# SETTINGS
# ==============================

@app.route("/settings")
def settings():

    if not login_required():

        return redirect("/login")

    return render_template(
        "settings.html"
    )


# ==============================
# RUN APPLICATION
# ==============================

create_database()

if __name__ == "__main__":
    app.run(debug=True)