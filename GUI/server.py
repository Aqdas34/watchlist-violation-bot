from flask import Flask, request, jsonify
import json
import re
import ipaddress
from copy import deepcopy

CONFIG_FILE = "sharing_config.json"
app = Flask(__name__)

EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# ---------------- Utilities ----------------

def load_config():
    with open(CONFIG_FILE, "r") as f:
        return json.load(f)

def save_config(data):
    with open(CONFIG_FILE, "w") as f:
        json.dump(data, f, indent=2)

def is_valid_email(email):
    return EMAIL_REGEX.match(email)

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_port(port):
    try:
        port = int(port)
        return 1 <= port <= 65535
    except (ValueError, TypeError):
        return False

# ---------------- Routes ----------------

@app.route("/config", methods=["GET"])
def get_config():
    return jsonify(load_config())

@app.route("/config", methods=["PATCH"])
def update_config():
    payload = request.json
    if not payload:
        return jsonify({"error": "Empty request"}), 400

    config = load_config()
    updated = deepcopy(config)

    # ---------- EMAIL ----------
    email = payload.get("admin_email")
    if email:
        if not is_valid_email(email):
            return jsonify({"error": "Invalid admin email"}), 400
        updated["email"]["admin_email"] = email

    # ---------- SMTP ----------
    if payload.get("smtp_host"):
        updated["email"]["smtp_host"] = payload["smtp_host"]

    if payload.get("smtp_email"):
        if not is_valid_email(payload["smtp_email"]):
            return jsonify({"error": "Invalid SMTP email"}), 400
        updated["email"]["smtp_email"] = payload["smtp_email"]

    if payload.get("smtp_password"):
        updated["email"]["smtp_password"] = payload["smtp_password"]

    port = payload.get("smtp_port")
    if port is not None:
        if not is_valid_port(port):
            return jsonify({"error": "smtp_port must be 1–65535"}), 400
        updated["email"]["smtp_port"] = int(port)

    # ---------- EXCLUSIONS ----------
    accounts = payload.get("exclude_accounts")
    if accounts:
        for a in accounts:
            if not is_valid_email(a):
                return jsonify({"error": f"Invalid exclusion email: {a}"}), 400
        updated["exclusions"]["accounts"] = accounts

    ips = payload.get("exclude_ips")
    if ips:
        for ip in ips:
            if not is_valid_ip(ip):
                return jsonify({"error": f"Invalid IP address: {ip}"}), 400
        updated["exclusions"]["ips"] = ips

    dids = payload.get("exclude_dids")
    if dids:
        updated["exclusions"]["dids"] = dids

    save_config(updated)
    return jsonify({"status": "success"})

# ---------------- Run ----------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
