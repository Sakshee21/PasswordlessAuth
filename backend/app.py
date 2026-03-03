

from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import base64
import os
import hashlib
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature

app = Flask(__name__)
CORS(app,resources={r"/*": {"origins": "*"}})

DB_FILE = "securebank.db"

LOGIN_NONCES = {}
OPERATION_NONCES = {}
OPERATION_BASE_RISK = {
    "READ": 0.2,
    "WRITE": 0.4,
    "TRANSFER": 0.6,
    "DELETE": 0.9
}
# =====================================================
# DATABASE INIT
# =====================================================

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            public_key TEXT NOT NULL,
            last_ip TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user TEXT,
            result TEXT,
            timestamp REAL,
            riskScore REAL,
            action TEXT,
            prev_hash TEXT,
            current_hash TEXT
        )
    """)

    conn.commit()
    conn.close()

init_db()

# =====================================================
# HELPER FUNCTIONS
# =====================================================

def compute_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()


def verify_signature(public_key_pem, nonce_b64, signature_b64):
    try:
        public_key = load_pem_public_key(public_key_pem.encode())
        signature = base64.b64decode(signature_b64)
        nonce_bytes = base64.b64decode(nonce_b64)

        public_key.verify(
            signature,
            nonce_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=32
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print("Verification error:", e)
        return False

def calculate_operation_risk(username, operation, ip, context):
    risk = 0.0
    amount = context.get("amount", 0)

    # 1️⃣ Base Operation Risk
    if operation == "TRANSFER":
        risk += 0.2
    elif operation == "CLOSE_ACCOUNT":
        risk += 0.6
    elif operation == "ACCOUNT_DETAILS":
        risk += 0.3
    elif operation == "SENSITIVE_RECORDS":
        risk += 0.1

    # 2️⃣ Transaction Amount Risk (progressive, not static)
    if amount > 10000:
        risk += 0.5
    elif amount > 5000:
        risk += 0.3
    elif amount > 1000:
        risk += 0.1

    # 3️⃣ IP Anomaly
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT last_ip FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()

    if row and row[0] and row[0] != ip:
        risk += 0.3

    # 4️⃣ Time-Based Risk (Unusual time demo)
    current_hour = time.localtime().tm_hour
    if current_hour < 6 or current_hour > 22:
        risk += 0.2

    # 5️⃣ Rapid Activity Risk (simple memory tracking)
    if username in OPERATION_NONCES:
        risk += 0.1

    return min(risk, 1.0)
# def calculate_operation_risk(username, operation, context, ip):
#     risk = 0

#     # 1️⃣ Base operation risk
#     OPERATION_BASE_RISK = {
#         "READ": 0.2,
#         "WRITE": 0.4,
#         "TRANSFER": 0.5,
#         "DELETE": 0.9
#     }

#     risk += OPERATION_BASE_RISK.get(operation, 0)

#     # 2️⃣ Transaction amount risk
#     if operation == "TRANSFER":
#         amount = float(context.get("amount", 0))

#         if amount > 10000:
#             risk += 0.4
#         elif amount > 5000:
#             risk += 0.2

#     # 3️⃣ IP anomaly detection
#     conn = sqlite3.connect(DB_FILE)
#     c = conn.cursor()
#     c.execute("SELECT last_ip FROM users WHERE username=?", (username,))
#     row = c.fetchone()
#     conn.close()

#     if row and row[0] and row[0] != ip:
#         risk += 0.3

#     # 4️⃣ Unusual time detection
#     current_hour = time.localtime().tm_hour

#     # Assume normal hours = 8 AM to 8 PM
#     if current_hour < 8 or current_hour > 20:
#         risk += 0.2

#     # 5️⃣ Rapid request detection
#     conn = sqlite3.connect(DB_FILE)
#     c = conn.cursor()
#     c.execute("""
#         SELECT COUNT(*) FROM logs
#         WHERE user=? AND timestamp > ?
#     """, (username, time.time() - 30))
#     recent_requests = c.fetchone()[0]
#     conn.close()

#     if recent_requests > 5:
#         risk += 0.2

#     return min(risk, 1.0)   

def log_event(username, result, risk, action):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute("SELECT current_hash FROM logs ORDER BY id DESC LIMIT 1")
    prev = c.fetchone()
    prev_hash = prev[0] if prev else "GENESIS"

    timestamp = time.time()
    log_data = f"{username}{result}{timestamp}{risk}{action}"
    current_hash = compute_hash(prev_hash + log_data)

    c.execute("""
        INSERT INTO logs 
        (user, result, timestamp, riskScore, action, prev_hash, current_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        username, result, timestamp, risk, action,
        prev_hash, current_hash
    ))

    conn.commit()
    conn.close()


# =====================================================
# USER REGISTRATION
# =====================================================

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data["username"]
    public_key = data["publicKey"]

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute("SELECT username FROM users WHERE username=?", (username,))
    if c.fetchone():
        conn.close()
        return jsonify({"status": "EXISTS"})

    c.execute("INSERT INTO users (username, public_key) VALUES (?, ?)",
              (username, public_key))
    conn.commit()
    conn.close()

    return jsonify({"status": "REGISTERED"})


# =====================================================
# LOGIN (RSA AUTH)
# =====================================================

# @app.route("/challenge", methods=["POST"])
# def challenge():
#     username = request.json["username"]

#     nonce = base64.b64encode(os.urandom(32)).decode()
#     LOGIN_NONCES[username] = nonce

#     return jsonify({"nonce": nonce})

@app.route("/challenge", methods=["POST"])
def challenge():
    username = request.json["username"]

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT username FROM users WHERE username=?", (username,))
    exists = c.fetchone()
    conn.close()

    if not exists:
        return jsonify({"error": "User not found"}), 404

    nonce = base64.b64encode(os.urandom(32)).decode()
    LOGIN_NONCES[username] = nonce

    return jsonify({"nonce": nonce})
# @app.route("/login", methods=["POST"])
# def login():
#     data = request.json
#     username = data["username"]
#     signature = data["signature"]

#     if username not in LOGIN_NONCES:
#         return jsonify({"status": "DENIED"})

#     nonce = LOGIN_NONCES.pop(username)

#     conn = sqlite3.connect(DB_FILE)
#     c = conn.cursor()
#     c.execute("SELECT public_key FROM users WHERE username=?", (username,))
#     row = c.fetchone()
#     conn.close()

#     if not row:
#         return jsonify({"status": "DENIED"})

#     ok = verify_signature(row[0], nonce, signature)
#     ip = request.remote_addr

#     if ok:
#         conn = sqlite3.connect(DB_FILE)
#         c = conn.cursor()
#         c.execute("UPDATE users SET last_ip=? WHERE username=?", (ip, username))
#         conn.commit()
#         conn.close()

#     risk = 0.1 if ok else 0.9
#     log_event(username, "LOGIN_SUCCESS" if ok else "LOGIN_DENIED", risk, "LOGIN")

#     return jsonify({"status": "SUCCESS" if ok else "DENIED"})
@app.route("/login", methods=["POST"])
def login():
    try:
        data = request.json
        username = data.get("username")
        signature = data.get("signature")

        if not username or not signature:
            return jsonify({"status": "DENIED", "error": "Missing data"})

        if username not in LOGIN_NONCES:
            return jsonify({"status": "DENIED", "error": "No nonce found"})

        nonce = LOGIN_NONCES.pop(username)

        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT public_key FROM users WHERE username=?", (username,))
        row = c.fetchone()
        conn.close()

        if not row:
            return jsonify({"status": "DENIED", "error": "User not found"})

        ok = verify_signature(row[0], nonce, signature)

        ip = request.remote_addr

        if ok:
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute("UPDATE users SET last_ip=? WHERE username=?", (ip, username))
            conn.commit()
            conn.close()

        risk = 0.1 if ok else 0.9
        log_event(username, "LOGIN_SUCCESS" if ok else "LOGIN_DENIED", risk, "LOGIN")
        print("Nonce from memory:", nonce)
        print("Signature received:", signature[:20])
        return jsonify({"status": "SUCCESS" if ok else "DENIED"})

    except Exception as e:
        print("LOGIN ERROR:", e)
        return jsonify({"status": "ERROR", "message": str(e)}), 500

# =====================================================
# CONTEXT-AWARE OPERATION CHALLENGE
# =====================================================

# @app.route("/operation-challenge", methods=["POST"])
# def operation_challenge():
#     data = request.json
#     username = data["username"]
#     operation = data["operation"]

#     nonce = base64.b64encode(os.urandom(16)).decode()

#     OPERATION_NONCES[username] = {
#         "nonce": nonce,
#         "operation": operation,
#         "timestamp": time.time()
#     }

#     return jsonify({"nonce": nonce, "operation": operation})

@app.route("/operation-challenge", methods=["POST"])
def operation_challenge():
    data = request.json
    username = data["username"]
    operation = data["operation"]
    context = data.get("context", {})

    # Bind context into hash
    context_string = f"{username}{operation}{str(context)}"
    context_hash = hashlib.sha256(context_string.encode()).hexdigest()

    nonce = base64.b64encode(os.urandom(16)).decode()

    OPERATION_NONCES[username] = {
        "nonce": nonce,
        "operation": operation,
        "context_hash": context_hash,
        "timestamp": time.time()
    }

    return jsonify({
        "nonce": nonce,
        "operation": operation
    })
# =====================================================
# EXECUTE OPERATION WITH RISK ENGINE
# =====================================================
@app.route("/execute-operation", methods=["POST"])
def execute_operation():
    data = request.json
    username = data["username"]
    operation = data["operation"]
    nonce = data["nonce"]
    context = data.get("context", {})

    if username not in OPERATION_NONCES:
        return jsonify({"status": "DENY", "reason": "No nonce"})

    stored = OPERATION_NONCES.pop(username)

    # Verify nonce + operation
    if nonce != stored["nonce"] or operation != stored["operation"]:
        return jsonify({"status": "DENY", "reason": "Context mismatch"})

    # Expiry check (60 sec)
    if time.time() - stored["timestamp"] > 60:
        return jsonify({"status": "DENY", "reason": "Expired"})

    # Verify context hash
    context_string = f"{username}{operation}{str(context)}"
    incoming_hash = hashlib.sha256(context_string.encode()).hexdigest()

    if incoming_hash != stored["context_hash"]:
        return jsonify({"status": "DENY", "reason": "Tampered context"})

    ip = request.remote_addr
    risk = calculate_operation_risk(username, operation,ip,context)

    if risk < 0.3:
        decision = "ALLOW"
    elif risk < 0.7:
        decision = "STEP_UP"
    else:
        decision = "DENY"

    log_event(username, decision, risk, operation)

    return jsonify({
        "status": decision,
        "risk": risk
    })
# @app.route("/execute-operation", methods=["POST"])
# def execute_operation():
#     data = request.json
#     username = data["username"]
#     operation = data["operation"]
#     nonce = data["nonce"]

#     if username not in OPERATION_NONCES:
#         return jsonify({"status": "DENY", "reason": "No nonce"})

#     stored = OPERATION_NONCES.pop(username)

#     if nonce != stored["nonce"] or operation != stored["operation"]:
#         return jsonify({"status": "DENY", "reason": "Context mismatch"})

#     if time.time() - stored["timestamp"] > 60:
#         return jsonify({"status": "DENY", "reason": "Expired"})

#     ip = request.remote_addr
#     risk = calculate_operation_risk(username, operation, ip)

#     if risk < 0.3:
#         decision = "ALLOW"
#     elif risk < 0.7:
#         decision = "STEP_UP"
#     else:
#         decision = "DENY"

#     log_event(username, decision, risk, operation)

#     return jsonify({"status": decision, "risk": risk})
@app.route("/stepup-challenge", methods=["POST"])
def stepup_challenge():
    data = request.json
    username = data["username"]
    operation = data["operation"]

    nonce = base64.b64encode(os.urandom(32)).decode()

    OPERATION_NONCES[username] = {
        "nonce": nonce,
        "operation": operation,
        "timestamp": time.time(),
        "stepup": True
    }

    return jsonify({"nonce": nonce})

@app.route("/stepup-verify", methods=["POST"])
def stepup_verify():
    data = request.json
    username = data["username"]
    operation = data["operation"]
    signature = data["signature"]

    if username not in OPERATION_NONCES:
        return jsonify({"status": "DENY"})

    stored = OPERATION_NONCES.pop(username)

    if stored["operation"] != operation:
        return jsonify({"status": "DENY"})

    if time.time() - stored["timestamp"] > 60:
        return jsonify({"status": "DENY"})

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT public_key FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()

    if not row:
        return jsonify({"status": "DENY"})

    ok = verify_signature(row[0], stored["nonce"], signature)

    if ok:
        log_event(username, "STEPUP_SUCCESS", 0.2, operation)
        return jsonify({"status": "UPGRADED_ALLOW"})
    else:
        log_event(username, "STEPUP_DENIED", 0.9, operation)
        return jsonify({"status": "DENY"})

if __name__ == "__main__":
    app.run(debug=True)