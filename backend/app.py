"""
SecureBank Backend (Merged Version)

Features
• RSA nonce challenge authentication
• Context-bound nonce protection
• Risk Policy Engine evaluation
• Step-up authentication
• Tamper-evident audit logs (hash chained)
• Session + IP tracking
"""

import base64
import hashlib
import json
import secrets
import sqlite3
import time

from flask import Flask, g, jsonify, request
from flask_cors import CORS

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

from risk_policy import RiskPolicyEngine


app = Flask(__name__)
CORS(app)

DB_PATH = "securebank.db"
NONCE_TTL = 60

risk_engine = RiskPolicyEngine()


# =====================================================
# DATABASE CONNECTION
# =====================================================

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db:
        db.close()


# =====================================================
# DATABASE INIT
# =====================================================

def init_db():
    db = get_db()

    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        public_key TEXT NOT NULL,
        created_at REAL,
        last_ip TEXT
    );

    CREATE TABLE IF NOT EXISTS nonces (
        token TEXT PRIMARY KEY,
        username TEXT,
        operation TEXT,
        context_hash TEXT,
        expires_at REAL,
        used INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS sessions (
        username TEXT PRIMARY KEY,
        login_timestamp REAL,
        fingerprint TEXT
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user TEXT,
        action TEXT,
        result TEXT,
        risk_score REAL,
        reason TEXT,
        timestamp REAL,
        hash TEXT
    );
    """)

    db.commit()


# =====================================================
# AUDIT LOG HASH CHAIN
# =====================================================

def previous_hash(db):
    row = db.execute(
        "SELECT hash FROM audit_logs ORDER BY id DESC LIMIT 1"
    ).fetchone()

    return row["hash"] if row else "GENESIS"


def write_audit(db, user, action, result, risk=0, reason=None):

    prev = previous_hash(db)
    ts = time.time()

    entry = f"{prev}|{user}|{action}|{result}|{risk}|{ts}"
    new_hash = hashlib.sha256(entry.encode()).hexdigest()

    db.execute(
        """INSERT INTO audit_logs
        (user, action, result, risk_score, reason, timestamp, hash)
        VALUES (?,?,?,?,?,?,?)""",
        (user, action, result, risk, reason, ts, new_hash),
    )

    db.commit()


# =====================================================
# SIGNATURE VERIFICATION
# =====================================================

def verify_signature(public_key_pem, nonce_b64, signature_b64):

    try:
        pub = serialization.load_pem_public_key(
            public_key_pem.encode(),
            backend=default_backend()
        )

        nonce_bytes = base64.b64decode(nonce_b64)
        sig_bytes = base64.b64decode(signature_b64)

        pub.verify(
            sig_bytes,
            nonce_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=32
            ),
            hashes.SHA256()
        )

        return True

    except (InvalidSignature, Exception):
        return False


# =====================================================
# REGISTER
# =====================================================

@app.post("/register")
def register():

    data = request.json
    username = data.get("username")
    public_key = data.get("publicKey")

    db = get_db()

    exists = db.execute(
        "SELECT username FROM users WHERE username=?",
        (username,)
    ).fetchone()

    if exists:
        return jsonify({"status": "EXISTS"})

    db.execute(
        "INSERT INTO users VALUES (?,?,?,?)",
        (username, public_key, time.time(), None)
    )

    db.commit()

    write_audit(db, username, "REGISTER", "SUCCESS")

    return jsonify({"status": "REGISTERED"})


# =====================================================
# LOGIN CHALLENGE
# =====================================================

@app.post("/challenge")
def challenge():

    username = request.json["username"]

    db = get_db()

    user = db.execute(
        "SELECT username FROM users WHERE username=?",
        (username,)
    ).fetchone()

    if not user:
        return jsonify({"error": "User not found"}), 404

    nonce_bytes = secrets.token_bytes(32)
    nonce_b64 = base64.b64encode(nonce_bytes).decode()

    expires = time.time() + NONCE_TTL

    db.execute(
        "INSERT INTO nonces VALUES (?,?,?,?,?,0)",
        (nonce_b64, username, "LOGIN", None, expires)
    )

    db.commit()

    return jsonify({"nonce": nonce_b64})


# =====================================================
# LOGIN VERIFY
# =====================================================

@app.post("/login")
def login():

    data = request.json

    username = data["username"]
    signature = data["signature"]
    fingerprint = data.get("deviceFingerprint")

    db = get_db()

    user = db.execute(
        "SELECT public_key FROM users WHERE username=?",
        (username,)
    ).fetchone()

    if not user:
        return jsonify({"status": "FAILED"}), 404

    nonce = db.execute(
        """SELECT token, expires_at
        FROM nonces
        WHERE username=? AND operation='LOGIN' AND used=0
        ORDER BY expires_at DESC LIMIT 1""",
        (username,)
    ).fetchone()

    if not nonce:
        return jsonify({"status": "FAILED", "reason": "No nonce"})

    if time.time() > nonce["expires_at"]:
        return jsonify({"status": "FAILED", "reason": "Expired"})

    ok = verify_signature(user["public_key"], nonce["token"], signature)

    if not ok:
        write_audit(db, username, "LOGIN", "DENIED")
        return jsonify({"status": "FAILED"}), 401

    db.execute(
        "UPDATE nonces SET used=1 WHERE token=?",
        (nonce["token"],)
    )

    ip = request.remote_addr

    db.execute(
        """INSERT INTO sessions VALUES (?,?,?)
        ON CONFLICT(username)
        DO UPDATE SET login_timestamp=?, fingerprint=?""",
        (username, time.time(), fingerprint,
         time.time(), fingerprint)
    )

    db.execute(
        "UPDATE users SET last_ip=? WHERE username=?",
        (ip, username)
    )

    db.commit()

    write_audit(db, username, "LOGIN", "SUCCESS")

    return jsonify({"status": "SUCCESS"})


# =====================================================
# OPERATION CHALLENGE
# =====================================================

@app.post("/operation-challenge")
def operation_challenge():

    data = request.json

    username = data["username"]
    operation = data["operation"]
    context = data.get("context", {})

    db = get_db()

    decision = risk_engine.evaluate(username, operation, context, db)

    if decision.status == "DENY":

        write_audit(
            db, username, operation, "DENIED",
            decision.score
        )

        return jsonify({
            "status": "DENIED",
            "risk": decision.score,
            "factors": getattr(decision, "factors", []),
            "reason": getattr(decision, "reason", "Denied by risk policy."),
        }), 403

    context_string = json.dumps({
        "username": username,
        "operation": operation,
        "amount": context.get("amount")
    }, sort_keys=True)

    context_hash = hashlib.sha256(context_string.encode()).hexdigest()

    nonce = base64.b64encode(secrets.token_bytes(32)).decode()
    expires_at = time.time() + NONCE_TTL

    # Determine risk level label from score
    score = decision.score
    if score >= 70:
        risk_level = "HIGH"
    elif score >= 40:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    db.execute(
        "INSERT INTO nonces VALUES (?,?,?,?,?,0)",
        (nonce, username, operation, context_hash, expires_at)
    )

    db.commit()

    return jsonify({
        "nonce":       nonce,
        "contextHash": context_hash,   # SHA-256 of {username, operation, amount}
        "expiresAt":   expires_at,     # Unix timestamp in seconds
        "riskLevel":   risk_level,     # "LOW" | "MEDIUM" | "HIGH"
        "riskScore":   score,
        "status":      "OK",
    })


# =====================================================
# EXECUTE OPERATION
# =====================================================

@app.post("/execute-operation")
def execute_operation():

    data = request.json

    username = data["username"]
    operation = data["operation"]
    nonce = data["nonce"]
    signature = data["signature"]
    context = data.get("context", {})

    db = get_db()

    nonce_row = db.execute(
        """SELECT * FROM nonces
        WHERE token=? AND username=? AND operation=? AND used=0""",
        (nonce, username, operation)
    ).fetchone()

    if not nonce_row:
        return jsonify({"status": "DENIED"})

    user = db.execute(
        "SELECT public_key FROM users WHERE username=?",
        (username,)
    ).fetchone()

    if not verify_signature(user["public_key"], nonce, signature):
        return jsonify({"status": "DENIED"})

    decision = risk_engine.evaluate(username, operation, context, db)

    db.execute(
        "UPDATE nonces SET used=1 WHERE token=?",
        (nonce,)
    )

    db.commit()

    if decision.status == "DENY":
        write_audit(db, username, operation, "DENIED", decision.score)
        return jsonify({
            "status": "DENIED",
            "risk": decision.score,
            "factors": getattr(decision, "factors", []),
            "reason": getattr(decision, "reason", "Operation denied."),
        })

    if decision.status == "STEP_UP":
        return jsonify({
            "status": "STEP_UP",
            "risk": decision.score,
            "factors": getattr(decision, "factors", []),
            "reason": getattr(decision, "reason", "Step-up authentication required."),
        })

    write_audit(db, username, operation, "SUCCESS", decision.score)

    return jsonify({
        "status": "ALLOW",
        "risk": decision.score,
    })


# =====================================================
# STEP-UP AUTHENTICATION
# =====================================================

@app.post("/stepup-challenge")
def stepup_challenge():

    username = request.json["username"]
    operation = request.json["operation"]

    nonce = base64.b64encode(secrets.token_bytes(32)).decode()

    db = get_db()

    db.execute(
        "INSERT INTO nonces VALUES (?,?,?,?,?,0)",
        (nonce, username, operation, None, time.time()+NONCE_TTL)
    )

    db.commit()

    return jsonify({"nonce": nonce})


@app.post("/stepup-verify")
def stepup_verify():

    data = request.json

    username = data["username"]
    operation = data["operation"]
    signature = data["signature"]
    nonce = data["nonce"]

    db = get_db()

    user = db.execute(
        "SELECT public_key FROM users WHERE username=?",
        (username,)
    ).fetchone()

    if not verify_signature(user["public_key"], nonce, signature):
        write_audit(db, username, operation, "STEPUP_DENIED")
        return jsonify({"status": "DENIED"})

    write_audit(db, username, operation, "STEPUP_SUCCESS")

    return jsonify({"status": "UPGRADED_ALLOW"})


# =====================================================
# LOG APIs
# =====================================================

@app.get("/logs")
def logs():

    db = get_db()

    rows = db.execute(
        "SELECT * FROM audit_logs ORDER BY id DESC LIMIT 100"
    ).fetchall()

    return jsonify([dict(r) for r in rows])


@app.get("/verify-logs")
def verify_logs():

    db = get_db()

    rows = db.execute(
        "SELECT * FROM audit_logs ORDER BY id"
    ).fetchall()

    prev = "GENESIS"

    for row in rows:

        entry = f"{prev}|{row['user']}|{row['action']}|{row['result']}|{row['risk_score']}|{row['timestamp']}"

        h = hashlib.sha256(entry.encode()).hexdigest()

        if h != row["hash"]:
            return jsonify({"integrity": "TAMPERED"})

        prev = row["hash"]

    return jsonify({"integrity": "OK"})


# =====================================================
# MAIN
# =====================================================

if __name__ == "__main__":

    with app.app_context():
        init_db()

    app.run(debug=True, port=5000)