import os
import json
import re
import sqlite3
import ssl
import socket
import requests
import ipaddress
import certifi
import secrets
import string
from datetime import datetime, timezone
from urllib.parse import urlparse

from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request, redirect, url_for, session, flash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "darkwatch.db")
app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

load_dotenv()

app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY")

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False

URLHAUS_AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY", "").strip()
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_type TEXT NOT NULL,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                risk TEXT NOT NULL,
                summary TEXT NOT NULL,
                details TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            if request.path.startswith("/api/"):
                return jsonify({"error": "Please log in to continue."}), 401

            return redirect(url_for("login"))

        return view(*args, **kwargs)

    return wrapped_view


def urlhaus_check(url):
    if not URLHAUS_AUTH_KEY:
        return {
            "status": "Not configured",
            "message": "URLhaus API key is missing."
        }

    try:
        response = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            headers={"Auth-Key": URLHAUS_AUTH_KEY},
            timeout=15,
            verify=certifi.where()
        )

        response.raise_for_status()
        result = response.json()

        if result.get("query_status") == "ok":
            return {
                "status": "Listed",
                "message": "This URL is listed in the URLhaus malware database.",
                "threat": result.get("threat"),
                "url_status": result.get("url_status"),
                "tags": result.get("tags", [])
            }

        if result.get("query_status") == "no_results":
            return {
                "status": "Not listed",
                "message": "No matching URL was found in URLhaus."
            }

        return {
            "status": "Error",
            "message": result.get("query_status", "Unknown API response.")
        }

    except requests.RequestException as exc:
        return {
            "status": "Unavailable",
            "message": "Could not connect to URLhaus: " + str(exc)[:200]
        }
def save_scan(scan_type, target, status, risk, summary, details):
    with db() as conn:
        conn.execute(
            """INSERT INTO scans
            (scan_type, target, status, risk, summary, details, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_type,
                target,
                status,
                risk,
                summary,
                json.dumps(details),
                datetime.now(timezone.utc).isoformat(timespec="seconds")
            )
        )


def normalize_url(raw_url):

    value = raw_url.strip()

    if not value:
        raise ValueError("Enter a website URL.")

    if not re.match(r"^https?://", value, re.I):
        value = "https://" + value

    parsed = urlparse(value)

    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Enter a valid http or https URL.")

    # Avoid localhost/private network targets
    host = parsed.hostname.lower()

    if host in ("localhost", "localhost.localdomain") or host.endswith(".local"):
        raise ValueError("Local/private network targets are not supported.")

    try:
        ip = socket.gethostbyname(host)
        parts = [int(p) for p in ip.split(".")]

        if (parts[0] == 10 or parts[0] == 127 or
            (parts[0] == 192 and parts[1] == 168) or
            (parts[0] == 172 and 16 <= parts[1] <= 31) or
            parts[0] == 0):
            raise ValueError("Private network targets are not supported.")

    except socket.gaierror:
        pass

    return value, parsed


def website_check(raw_url):
    url, parsed = normalize_url(raw_url)
    findings = []
    risk_points = 0
    status_code = None

    try:
        response = requests.get(
            url, timeout=10, allow_redirects=True,
            headers={"User-Agent": "DarkWatch-Student-Project/1.0"},
            stream=True
        )
        status_code = response.status_code
        final_url = response.url
        headers = response.headers
        response.close()
        if status_code >= 500:
            findings.append("Website returned a server error (HTTP {}).".format(status_code))
            risk_points += 1
        elif status_code >= 400:
            findings.append("Website returned HTTP {}.".format(status_code))
        else:
            findings.append("Website responded with HTTP {}.".format(status_code))
        if urlparse(final_url).scheme != "https":
            findings.append("Final page is not using HTTPS.")
            risk_points += 2
        security_headers = {
            "Strict-Transport-Security": "HSTS",
            "Content-Security-Policy": "Content Security Policy",
            "X-Content-Type-Options": "X-Content-Type-Options",
            "X-Frame-Options": "X-Frame-Options"
        }
        missing = [label for header, label in security_headers.items() if header not in headers]
        if missing:
            findings.append("Missing common security headers: " + ", ".join(missing) + ".")
            risk_points += min(2, len(missing))
        else:
            findings.append("Common security headers were present.")
    except requests.RequestException as exc:
        findings.append("Could not retrieve the website: {}.".format(str(exc)[:180]))
        risk_points += 2
        final_url = url

    tls_result = "Not checked (HTTP URL)."
    if parsed.scheme == "https":
        try:
            context = ssl.create_default_context(cafile=certifi.where())
            with socket.create_connection((parsed.hostname, parsed.port or 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=parsed.hostname) as secure_sock:
                    cert = secure_sock.getpeercert()
                    tls_result = "Valid TLS certificate; expires: " + cert.get("notAfter", "date unavailable")
        except Exception as exc:
            tls_result = "TLS verification failed: " + str(exc)[:150]
            findings.append(tls_result)
            risk_points += 2
               
    urlhaus_result = urlhaus_check(url)

    if urlhaus_result["status"] == "Listed":
        findings.append("WARNING: URL is listed in the URLhaus malware database.")
        risk_points += 5

    elif urlhaus_result["status"] == "Not listed":
        findings.append("URLhaus: No matching malware URL found.")

    else:
        findings.append(
            "URLhaus check: " + urlhaus_result["message"]
        )
    if risk_points >= 4:
        risk = "High"
    elif risk_points >= 2:
        risk = "Medium"
    else:
        risk = "Low"
    details = {
        "checked_url": url,
        "final_url": final_url,
        "http_status": status_code,
        "tls": tls_result,
        "findings": findings,
        "urlhaus": urlhaus_result,
        "important_limit": "This is a basic defensive check, not proof that a website is hacked or safe."
    }

    status = "No compromise confirmed"
    summary = "Basic website checks completed. No breach confirmation is made by this scan."

    save_scan("Website", url, status, risk, summary, details)

    return {"target": url, "status": status, "risk": risk, "summary": summary, **details}

def email_breach_check(email):
    email = email.strip().lower()

    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise ValueError("Enter a valid email address.")

    api_url = "https://api.xposedornot.com/v1/check-email/"

    response = requests.get(
        api_url + requests.utils.quote(email, safe=""),
        timeout=15,
        verify=certifi.where()
    )

    if response.status_code == 404:
        result = {
            "status": "No breach found",
            "risk": "Low",
            "breaches": [],
            "summary": "No matching breach was found in this source."
        }

    elif response.status_code == 200:
        data = response.json()

        breach_data = data.get("breaches", [])
        breach_names = []

        for group in breach_data:
            if isinstance(group, list):
                breach_names.extend(group)
            elif isinstance(group, str):
                breach_names.append(group)

        if breach_names:
            result = {
                "status": "Email found in breach data",
                "risk": "High",
                "breaches": breach_names,
                "summary": "This email was found in known breach records."
            }
        else:
            result = {
                "status": "No breach found",
                "risk": "Low",
                "breaches": [],
                "summary": "No matching breach was found in this source."
            }

    elif response.status_code == 429:
        raise RuntimeError("XposedOrNot API rate limit reached. Try again later.")

    else:
        raise RuntimeError(
            "XposedOrNot API returned HTTP {}.".format(response.status_code)
        )

    save_scan(
        "Email",
        email,
        result["status"],
        result["risk"],
        result["summary"],
        result
    )

    return {"target": email, **result}
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if len(username) < 3:
            flash("Username must contain at least 3 characters.")
            return redirect(url_for("register"))

        if not re.match(r"^[A-Za-z0-9_]+$", username):
            flash("Username can contain only letters, numbers and underscores.")
            return redirect(url_for("register"))

        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            flash("Enter a valid email address.")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Password must contain at least 8 characters.")
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Passwords do not match.")
            return redirect(url_for("register"))

        try:
            with db() as conn:
                conn.execute(
                    """
                    INSERT INTO users (username, email, password_hash, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        username,
                        email,
                        generate_password_hash(password),
                        datetime.now(timezone.utc).isoformat()
                    )
                )

            flash("Registration successful. Please log in.")
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            flash("Username or email already exists.")
            return redirect(url_for("register"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        with db() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE email = ?",
                (email,)
            ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]

            return redirect(url_for("dashboard"))

        flash("Invalid email or password.")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("index.html")


@app.route("/api/stats")
@login_required
def stats():
    with db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        websites = conn.execute("SELECT COUNT(*) FROM scans WHERE scan_type='Website'").fetchone()[0]
        emails = conn.execute("SELECT COUNT(*) FROM scans WHERE scan_type='Email'").fetchone()[0]
        recent = conn.execute("SELECT id, scan_type, target, status, risk, created_at FROM scans ORDER BY id DESC LIMIT 8").fetchall()
    return jsonify({"total": total, "websites": websites, "emails": emails,
                    "recent": [dict(row) for row in recent]})


@app.route("/api/check-website", methods=["POST"])
@login_required
def api_check_website():
    try:
        data = request.get_json(force=True)
        return jsonify(website_check(data.get("url", "")))
    except (ValueError, RuntimeError) as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception:
        app.logger.exception("Website scan failed")
        return jsonify({"error": "Unexpected error while checking the website."}), 500


@app.route("/api/check-email", methods=["POST"])
@login_required
def api_check_email():
    try:
        data = request.get_json(force=True)
        return jsonify(email_breach_check(data.get("email", "")))
    except (ValueError, RuntimeError) as exc:
        return jsonify({"error": str(exc)}), 400
    except requests.RequestException:
        return jsonify({"error": "Could not contact the breach intelligence API."}), 502
    except Exception:
        app.logger.exception("Email scan failed")
        return jsonify({"error": "Unexpected error while checking the email."}), 500

# Password Generator API
@app.route("/api/generate-password", methods=["POST"])
@login_required
def api_generate_password():
    try:
        data = request.get_json(silent=True) or {}

        length = int(data.get("length", 16))

        if length < 8 or length > 64:
            raise ValueError("Password length must be between 8 and 64.")

        categories = []

        if data.get("uppercase", True):
            categories.append(string.ascii_uppercase)

        if data.get("lowercase", True):
            categories.append(string.ascii_lowercase)

        if data.get("numbers", True):
            categories.append(string.digits)

        if data.get("symbols", True):
            categories.append("!@#$%^&*()-_=+?")

        if not categories:
            raise ValueError("Select at least one character type.")

        if len(categories) > length:
            raise ValueError("Password length is too short.")

        password_chars = [
            secrets.choice(category) for category in categories
        ]

        all_characters = "".join(categories)

        while len(password_chars) < length:
            password_chars.append(secrets.choice(all_characters))

        secrets.SystemRandom().shuffle(password_chars)

        password = "".join(password_chars)

        return jsonify({
            "password": password,
            "length": length,
            "strength": "Strong"
        })

    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


# IP Address Threat Checker API
@app.route("/api/check-ip", methods=["POST"])
@login_required
def api_check_ip():
    try:
        data = request.get_json(silent=True) or {}
        ip = data.get("ip", "").strip()

        if not ip:
            return jsonify({"error": "Enter an IP address."}), 400

        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({"error": "Invalid IP address."}), 400

        if not ip_obj.is_global:
            return jsonify({"error": "Enter a public IP address."}), 400

        response = requests.get(
            f"https://ipwho.is/{ip}",
            timeout=10
        )

        result = response.json()

        if not result.get("success"):
            return jsonify({
                "error": result.get("message", "IP lookup failed.")
            }), 400

        connection = result.get("connection") or {}

        return jsonify({
            "ip": result.get("ip"),
            "country": result.get("country"),
            "region": result.get("region"),
            "city": result.get("city"),
            "latitude": result.get("latitude"),
            "longitude": result.get("longitude"),
            "isp": connection.get("isp"),
            "organization": connection.get("org")
        })

    except requests.RequestException:
        return jsonify({
            "error": "Unable to connect to IP lookup service."
        }), 502

    except Exception:
        return jsonify({
            "error": "Something went wrong."
        }), 500

# Dashboard Statistics API
@app.route("/api/dashboard-stats", methods=["GET"])
@login_required
def api_dashboard_stats():
    with db() as conn:

        total = conn.execute(
            "SELECT COUNT(*) FROM scans"
        ).fetchone()[0]

        high = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE LOWER(risk) = 'high'"
        ).fetchone()[0]

        medium = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE LOWER(risk) = 'medium'"
        ).fetchone()[0]

        low = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE LOWER(risk) = 'low'"
        ).fetchone()[0]

        recent = conn.execute("""
            SELECT scan_type, target, status, risk, created_at
            FROM scans
            ORDER BY id DESC
            LIMIT 10
        """).fetchall()

    return jsonify({
        "total_scans": total,
        "high_risk": high,
        "medium_risk": medium,
        "low_risk": low,
        "recent_scans": [
            {
                "scan_type": row[0],
                "target": row[1],
                "status": row[2],
                "risk": row[3],
                "created_at": row[4]
            }
            for row in recent
        ]
    })


# Clear Scan History API
@app.route("/api/clear-history", methods=["DELETE"])
@login_required
def api_clear_history():
    with db() as conn:
        conn.execute("DELETE FROM scans")

    return jsonify({
        "message": "Scan history cleared successfully."
    })


# Initialize Database
init_db()

# Run Application
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)


    
