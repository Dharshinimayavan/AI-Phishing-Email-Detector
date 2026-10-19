
from flask import (
    Flask,
    render_template,
    render_template_string,
    request,
    make_response,
    redirect,
    session
)

import joblib
import os
import psycopg2
import re
import html

from datetime import datetime
from functools import wraps
from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)


# ==========================================
# APPLICATION CONFIGURATION
# ==========================================

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "local-development-secret-change-before-deployment"
)

model = joblib.load("phishing_model.pkl")


# ==========================================
# DATABASE CONNECTION
# ==========================================

def get_db_connection():

    database_url = os.environ.get("DATABASE_URL")

    if not database_url:
        raise RuntimeError(
            "DATABASE_URL environment variable is not set."
        )

    return psycopg2.connect(database_url)


# ==========================================
# CREATE / UPDATE DATABASE TABLES
# ==========================================

def create_database():

    conn = get_db_connection()

    try:
        with conn.cursor() as cursor:

            # Users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    name TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL
                )
            """)

            # Scan history table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS history (
                    id SERIAL PRIMARY KEY,
                    result TEXT,
                    confidence REAL,
                    risk TEXT,
                    timestamp TEXT,
                    email TEXT
                )
            """)

            # Add user_id to existing databases
            cursor.execute("""
                ALTER TABLE history
                ADD COLUMN IF NOT EXISTS user_id INTEGER
                REFERENCES users(id)
            """)

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


# ==========================================
# LOGIN REQUIRED DECORATOR
# ==========================================

def login_required(view_function):

    @wraps(view_function)
    def wrapper(*args, **kwargs):

        if "user_id" not in session:
            return redirect("/login")

        return view_function(*args, **kwargs)

    return wrapper


# ==========================================
# FIND PHISHING REASONS
# ==========================================

def find_reasons(email_text, prediction):

    reasons = []
    text = email_text.lower()

    if prediction == 0:
        return [
            "No major phishing indicators detected."
        ]

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

    for word in urgent_words:
        if word in text:
            reasons.append(
                "Urgent or threatening language detected."
            )
            break

    for word in sensitive_words:
        if word in text:
            reasons.append(
                "Request for sensitive information detected."
            )
            break

    for word in link_words:
        if word in text:
            reasons.append(
                "Suspicious link or verification language detected."
            )
            break

    urls = re.findall(
        r"https?://[^\s]+",
        text
    )

    if urls:
        reasons.append(
            "URL or web link detected in the email."
        )

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
                "Shortened URL detected, which may hide "
                "the actual destination."
            )
            break

    if not reasons:
        reasons.append(
            "The ML model detected characteristics commonly "
            "associated with phishing emails."
        )

    return reasons


# ==========================================
# CALCULATE RISK SCORE
# ==========================================

def calculate_risk_score(email_text, prediction):

    text = email_text.lower()
    score = 0

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

    if any(word in text for word in urgent_words):
        score += 10

    if any(word in text for word in sensitive_words):
        score += 15

    if any(word in text for word in link_words):
        score += 10

    if re.findall(r"https?://[^\s]+", text):
        score += 10

    short_url_words = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly"
    ]

    if any(word in text for word in short_url_words):
        score += 5

    score = min(score, 100)

    if prediction == 0:
        score = min(score, 25)

    return score


# ==========================================
# GET ONE USER'S SCAN
# ==========================================

def get_user_scan(scan_id):

    conn = get_db_connection()

    try:
        with conn.cursor() as cursor:

            cursor.execute("""
                SELECT
                    id,
                    email,
                    result,
                    confidence,
                    risk,
                    timestamp
                FROM history
                WHERE id = %s
                  AND user_id = %s
            """, (
                scan_id,
                session["user_id"]
            ))

            return cursor.fetchone()

    finally:
        conn.close()


# ==========================================
# LOGIN
# ==========================================

@app.route("/login", methods=["GET", "POST"])
def login():

    error = ""

    if "user_id" in session:
        return redirect("/")

    if request.method == "POST":

        email = request.form.get(
            "email", ""
        ).strip().lower()

        password = request.form.get(
            "password", ""
        )

        conn = get_db_connection()

        try:
            with conn.cursor() as cursor:

                cursor.execute("""
                    SELECT id, name, email, password
                    FROM users
                    WHERE email = %s
                """, (email,))

                user = cursor.fetchone()

        finally:
            conn.close()

        if user and check_password_hash(
            user[3], password
        ):

            session.clear()
            session["user_id"] = user[0]
            session["user_name"] = user[1]
            session["user_email"] = user[2]

            return redirect("/")

        error = "Invalid email or password."

    return render_template(
        "login.html",
        error=error
    )


# ==========================================
# REGISTER
# ==========================================

@app.route("/register", methods=["GET", "POST"])
def register():

    error = ""

    if "user_id" in session:
        return redirect("/")

    if request.method == "POST":

        name = request.form.get(
            "name", ""
        ).strip()

        email = request.form.get(
            "email", ""
        ).strip().lower()

        password = request.form.get(
            "password", ""
        )

        confirm_password = request.form.get(
            "confirm_password", ""
        )

        if not name or not email or not password:
            error = "Please fill in all required fields."

        elif len(name) > 150:
            error = "Name is too long."

        elif len(email) > 254:
            error = "Email address is too long."

        elif password != confirm_password:
            error = "Passwords do not match."

        elif len(password) < 6:
            error = (
                "Password must contain at least 6 characters."
            )

        if error:
            return render_template(
                "register.html",
                error=error
            )

        hashed_password = generate_password_hash(
            password
        )

        conn = get_db_connection()

        try:
            with conn.cursor() as cursor:

                cursor.execute("""
                    INSERT INTO users
                    (name, email, password)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (email) DO NOTHING
                    RETURNING id
                """, (
                    name,
                    email,
                    hashed_password
                ))

                created_user = cursor.fetchone()

            conn.commit()

            if created_user is None:
                error = (
                    "An account with this email already exists."
                )

                return render_template(
                    "register.html",
                    error=error
                )

        except Exception:
            conn.rollback()
            raise

        finally:
            conn.close()

        return redirect("/login")

    return render_template(
        "register.html",
        error=error
    )


# ==========================================
# LOGOUT
# ==========================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect("/login")


# ==========================================
# HOME / EMAIL DETECTOR
# ==========================================

@app.route("/", methods=["GET", "POST"])
@login_required
def home():

    result = ""
    confidence = ""
    risk = ""
    reasons = []
    risk_score = 0
    email_text = ""

    if request.method == "POST":

        email_text = request.form.get(
            "email", ""
        ).strip()

        if not email_text:

            result = "Please enter an email."

        elif len(email_text) > 50000:

            result = "Email text is too long."

        else:

            prediction = int(
                model.predict([email_text])[0]
            )

            probabilities = model.predict_proba(
                [email_text]
            )[0]

            confidence = round(
                float(max(probabilities)) * 100,
                2
            )

            if prediction == 1:
                result = "Phishing Email"
                risk = "HIGH"
            else:
                result = "Legitimate Email"
                risk = "LOW"

            reasons = find_reasons(
                email_text,
                prediction
            )

            risk_score = calculate_risk_score(
                email_text,
                prediction
            )

            conn = get_db_connection()

            try:
                with conn.cursor() as cursor:

                    cursor.execute("""
                        INSERT INTO history
                        (
                            user_id,
                            email,
                            result,
                            confidence,
                            risk,
                            timestamp
                        )
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (
                        session["user_id"],
                        email_text,
                        result,
                        confidence,
                        risk,
                        datetime.now().strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    ))

                conn.commit()

            except Exception:
                conn.rollback()
                raise

            finally:
                conn.close()

    return render_template(
        "index.html",
        result=result,
        confidence=confidence,
        risk=risk,
        reasons=reasons,
        risk_score=risk_score
    )


# ==========================================
# HISTORY
# ==========================================

@app.route("/history")
@login_required
def history():

    user_id = session["user_id"]

    conn = get_db_connection()

    try:
        with conn.cursor() as cursor:

            cursor.execute("""
                SELECT COUNT(*)
                FROM history
                WHERE user_id = %s
            """, (user_id,))

            total_scans = cursor.fetchone()[0]

            cursor.execute("""
                SELECT COUNT(*)
                FROM history
                WHERE user_id = %s
                  AND result = 'Phishing Email'
            """, (user_id,))

            phishing_count = cursor.fetchone()[0]

            cursor.execute("""
                SELECT COUNT(*)
                FROM history
                WHERE user_id = %s
                  AND result = 'Legitimate Email'
            """, (user_id,))

            legitimate_count = cursor.fetchone()[0]

            cursor.execute("""
                SELECT id, result, confidence, risk, timestamp
                FROM history
                WHERE user_id = %s
                ORDER BY id DESC
            """, (user_id,))

            records = cursor.fetchall()

    finally:
        conn.close()

    return render_template(
        "history.html",
        records=records,
        total_scans=total_scans,
        phishing_count=phishing_count,
        legitimate_count=legitimate_count
    )


# ==========================================
# DELETE OWN SCAN ONLY
# ==========================================

@app.route("/delete/<int:scan_id>", methods=["POST"])
@login_required
def delete_scan(scan_id):

    conn = get_db_connection()

    try:
        with conn.cursor() as cursor:

            cursor.execute("""
                DELETE FROM history
                WHERE id = %s
                  AND user_id = %s
            """, (
                scan_id,
                session["user_id"]
            ))

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

    return redirect("/history")


# ==========================================
# DASHBOARD
# ==========================================

@app.route("/dashboard")
@login_required
def dashboard():

    user_id = session["user_id"]

    conn = get_db_connection()

    try:
        with conn.cursor() as cursor:

            cursor.execute("""
                SELECT
                    COUNT(*),
                    COUNT(*) FILTER (
                        WHERE result = 'Phishing Email'
                    ),
                    COUNT(*) FILTER (
                        WHERE result = 'Legitimate Email'
                    ),
                    AVG(confidence)
                FROM history
                WHERE user_id = %s
            """, (user_id,))

            stats = cursor.fetchone()

            total_scans = stats[0]
            phishing_count = stats[1]
            legitimate_count = stats[2]
            average_confidence = stats[3]

            cursor.execute("""
                SELECT id, result, confidence, risk, timestamp
                FROM history
                WHERE user_id = %s
                ORDER BY id DESC
                LIMIT 5
            """, (user_id,))

            recent_scans = cursor.fetchall()

    finally:
        conn.close()

    if average_confidence is None:
        average_confidence = 0
    else:
        average_confidence = round(
            float(average_confidence), 2
        )

    if total_scans > 0:

        phishing_percentage = round(
            phishing_count / total_scans * 100, 1
        )

        legitimate_percentage = round(
            legitimate_count / total_scans * 100, 1
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


# ==========================================
# REPORTS LIST
# ==========================================

@app.route("/reports")
@login_required
def reports():

    conn = get_db_connection()

    try:
        with conn.cursor() as cursor:

            cursor.execute("""
                SELECT id, result, confidence, risk, timestamp
                FROM history
                WHERE user_id = %s
                ORDER BY id DESC
            """, (session["user_id"],))

            report_records = cursor.fetchall()

    finally:
        conn.close()

    return render_template(
        "reports.html",
        reports=report_records
    )


# ==========================================
# SCAN DETAILS
# ==========================================

@app.route("/details/<int:scan_id>")
@login_required
def details(scan_id):

    record = get_user_scan(scan_id)

    if record is None:
        return "Scan record not found.", 404

    scan_id = record[0]
    email_text = record[1]
    result = record[2]
    confidence = record[3]
    risk = record[4]
    timestamp = record[5]

    prediction_value = (
        1 if result == "Phishing Email" else 0
    )

    reasons = find_reasons(
        email_text,
        prediction_value
    )

    risk_score = calculate_risk_score(
        email_text,
        prediction_value
    )

    return render_template(
        "details.html",
        scan_id=scan_id,
        email=email_text,
        prediction=result,
        result=result,
        confidence=confidence,
        risk=risk,
        timestamp=timestamp,
        reasons=reasons,
        risk_score=risk_score
    )


# ==========================================
# DOWNLOAD HTML REPORT
# ==========================================

@app.route("/report/<int:scan_id>")
@login_required
def report(scan_id):

    record = get_user_scan(scan_id)

    if record is None:
        return "Scan record not found.", 404

    scan_id = record[0]
    email_text = record[1]
    result = record[2]
    confidence = float(record[3] or 0)
    risk = record[4]
    timestamp = record[5]

    prediction_value = (
        1 if result == "Phishing Email" else 0
    )

    reasons = find_reasons(
        email_text,
        prediction_value
    )

    risk_score = calculate_risk_score(
        email_text,
        prediction_value
    )

    if prediction_value == 1:

        result_class = "phishing"
        result_icon = "⚠️"
        recommendation_title = "Do Not Interact With This Email"
        recommendation_text = (
            "This email was classified as potentially phishing. "
            "Do not click suspicious links or share passwords, "
            "OTPs, banking information, or other sensitive data."
        )

    else:

        result_class = "legitimate"
        result_icon = "✅"
        recommendation_title = "No Major Phishing Indicators"
        recommendation_text = (
            "The model classified this email as legitimate. "
            "This does not guarantee safety. Verify unexpected "
            "requests before sharing sensitive information."
        )

    # Render a complete downloadable HTML report.
    # Jinja autoescaping protects email text and reason strings.

    report_html = render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PhishGuard Report #{{ scan_id }}</title>

<style>
* { box-sizing: border-box; }
body {
    margin: 0;
    padding: 25px;
    background: #080f1e;
    color: #e2e8f0;
    font-family: Arial, sans-serif;
}
.container {
    max-width: 900px;
    margin: 20px auto;
    background: #111c30;
    border: 1px solid #263750;
    border-radius: 16px;
    overflow: hidden;
}
.header {
    background: #162b4a;
    padding: 30px;
}
.header h1 { color: #38bdf8; }
.section { padding: 25px 30px; }
.card {
    background: #0b1425;
    border: 1px solid #263750;
    border-radius: 10px;
    padding: 18px;
    margin-bottom: 14px;
    overflow-wrap: anywhere;
}
.label { color: #94a3b8; font-size: 13px; }
.value { margin-top: 8px; font-size: 17px; }
.phishing { color: #fb7185; }
.legitimate { color: #4ade80; }
.muted { color: #94a3b8; }
.progress {
    background: #263750;
    height: 12px;
    border-radius: 8px;
    overflow: hidden;
    margin-top: 12px;
}
.bar { height: 100%; background: #38bdf8; }
.riskbar { height: 100%; background: #fb7185; }
.email {
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    line-height: 1.7;
}
.indicator {
    padding: 12px;
    margin: 10px 0;
    border-radius: 8px;
    background: #17243a;
    border: 1px solid #334155;
}
.footer {
    padding: 20px;
    border-top: 1px solid #263750;
    text-align: center;
    color: #94a3b8;
    font-size: 13px;
}
@media print {
    body { background: white; color: #111827; padding: 0; }
    .container { border: 0; }
    .header, .card, .indicator {
        background: white;
        color: #111827;
    }
}
</style>
</head>

<body>
<div class="container">

<div class="header">
    <h1>🛡️ PhishGuard</h1>
    <h2>Phishing Email Detection Report</h2>
    <p>Scan #{{ scan_id }} · AI-based security analysis</p>
</div>

<div class="section">
    <h2>Scan Summary</h2>

    <div class="card">
        <div class="label">Detection Result</div>
        <div class="value {{ result_class }}">
            {{ result_icon }} {{ result }}
        </div>
    </div>

    <div class="card">
        <div class="label">Risk Level</div>
        <div class="value {{ result_class }}">{{ risk }}</div>
    </div>

    <div class="card">
        <div class="label">Date and Time</div>
        <div class="value">{{ timestamp }}</div>
    </div>

    <div class="card">
        <div class="label">Model Confidence</div>
        <div class="value">{{ confidence }}%</div>
        <div class="progress">
            <div class="bar" style="width: {{ confidence }}%"></div>
        </div>
    </div>

    <div class="card">
        <div class="label">Risk Score</div>
        <div class="value">{{ risk_score }}/100</div>
        <div class="progress">
            <div class="riskbar" style="width: {{ risk_score }}%"></div>
        </div>
    </div>
</div>

<div class="section">
    <h2>Scanned Email</h2>
    <div class="card email">{{ email_text }}</div>
</div>

<div class="section">
    <h2>Detection Indicators</h2>
    {% for reason in reasons %}
        <div class="indicator">{{ reason }}</div>
    {% endfor %}
</div>

<div class="section">
    <h2>Security Recommendation</h2>
    <div class="card">
        <h3>{{ recommendation_title }}</h3>
        <p class="muted">{{ recommendation_text }}</p>
    </div>
</div>

<div class="footer">
    PhishGuard — AI-Based Phishing Email Detector
    <br>Automated security analysis report
</div>

</div>
</body>
</html>
""",
        scan_id=scan_id,
        result=result,
        result_class=result_class,
        result_icon=result_icon,
        risk=risk,
        timestamp=timestamp,
        confidence=confidence,
        risk_score=risk_score,
        email_text=email_text,
        reasons=reasons,
        recommendation_title=recommendation_title,
        recommendation_text=recommendation_text
    )

    response = make_response(report_html)

    response.headers["Content-Type"] = (
        "text/html; charset=utf-8"
    )

    response.headers["Content-Disposition"] = (
        f"attachment; filename=PhishGuard_Report_{scan_id}.html"
    )

    return response


# ==========================================
# CHANGE PASSWORD
# ==========================================

@app.route("/change-password", methods=["POST"])
@login_required
def change_password():

    current_password = request.form.get(
        "current_password", ""
    )

    new_password = request.form.get(
        "new_password", ""
    )

    confirm_password = request.form.get(
        "confirm_password", ""
    )

    if len(new_password) < 6:
        return """
        <script>
            alert("New password must contain at least 6 characters.");
            window.location.href = "/settings";
        </script>
        """

    if new_password != confirm_password:
        return """
        <script>
            alert("New passwords do not match.");
            window.location.href = "/settings";
        </script>
        """

    user_id = session["user_id"]

    conn = get_db_connection()

    try:
        with conn.cursor() as cursor:

            cursor.execute("""
                SELECT password
                FROM users
                WHERE id = %s
            """, (user_id,))

            user = cursor.fetchone()

            if user is None:
                return redirect("/logout")

            if not check_password_hash(
                user[0], current_password
            ):
                return """
                <script>
                    alert("Current password is incorrect.");
                    window.location.href = "/settings";
                </script>
                """

            new_hashed_password = generate_password_hash(
                new_password
            )

            cursor.execute("""
                UPDATE users
                SET password = %s
                WHERE id = %s
            """, (
                new_hashed_password,
                user_id
            ))

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

    return """
    <script>
        alert("Password changed successfully!");
        window.location.href = "/settings";
    </script>
    """


# ==========================================
# SETTINGS
# ==========================================

@app.route("/settings")
@login_required
def settings():

    return render_template(
        "settings.html"
    )


# ==========================================
# INITIALIZE DATABASE
# ==========================================

create_database()


# ==========================================
# RUN APPLICATION LOCALLY
# ==========================================

if __name__ == "__main__":
    app.run(debug=True)
