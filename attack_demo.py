"""
attack_demo.py  —  SecureBank Live Attack Demonstration
========================================================
Written for the app.py version that uses:
  - Table: logs  (columns: user, result, timestamp, riskScore, action, prev_hash, current_hash)
  - In-memory LOGIN_NONCES dict  (no nonce table in DB)
  - Endpoints: /challenge  /login  /operation-challenge  /execute-operation  /verify-logs

Usage:
    cd PasswordlessAuth          # project root
    python attack_demo.py
"""

import base64, os, secrets, sqlite3, time
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

BASE     = "http://127.0.0.1:5000"
DB_PATH  = os.path.join(os.path.dirname(__file__), "backend", "securebank.db")

# ── Colours ───────────────────────────────────────────────────────────────────
RED    = "\033[91m"; GREEN  = "\033[92m"; YELLOW = "\033[93m"
CYAN   = "\033[96m"; BOLD   = "\033[1m";  RESET  = "\033[0m"

def banner(title):
    print(f"\n{BOLD}{CYAN}{'═'*60}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'═'*60}{RESET}")

def step(msg):  print(f"  {YELLOW}▶{RESET}  {msg}")
def result(ok, msg):
    icon = f"{GREEN}✅ BLOCKED{RESET}" if ok else f"{RED}❌ VULNERABLE{RESET}"
    print(f"  {icon}  {msg}\n")

# ── Crypto helpers ────────────────────────────────────────────────────────────
def make_keypair():
    priv = rsa.generate_private_key(65537, 2048, default_backend())
    return priv, priv.public_key()

def pub_pem(pub_key):
    return pub_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

def sign(priv, nonce_b64):
    sig = priv.sign(
        base64.b64decode(nonce_b64),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256()
    )
    return base64.b64encode(sig).decode()

# ── Setup / cleanup ───────────────────────────────────────────────────────────
def setup_victim():
    username = f"victim_{secrets.token_hex(3)}"
    priv, pub = make_keypair()
    r = requests.post(f"{BASE}/register", json={"username": username, "publicKey": pub_pem(pub)})
    assert r.json()["status"] == "REGISTERED", f"Setup failed: {r.text}"
    return username, priv

def cleanup(username):
    db = sqlite3.connect(DB_PATH)
    db.execute("DELETE FROM users WHERE username=?", (username,))
    db.execute("DELETE FROM logs  WHERE user=?",     (username,))
    db.commit(); db.close()

RISK_CTX = {
    "deviceFingerprint": "demo-fp-xyz", "sessionAgeMs": 5000,
    "timezone": "Asia/Kolkata", "connectionType": "wifi",
    "mouseMovementDetected": True, "keyboardInteractionDetected": True,
    "timeOnPageMs": 3000,
}

# ══════════════════════════════════════════════════════════════════════════════
# ATTACK 1 — Login Nonce Replay
# ══════════════════════════════════════════════════════════════════════════════
def attack_1_replay_login():
    banner("ATTACK 1 — Login Nonce Replay")
    print("  Scenario: Attacker intercepts a valid (nonce, signature) pair")
    print("  and submits it a second time to hijack the session.\n")

    username, priv = setup_victim()
    try:
        step("Victim requests a challenge nonce from the server")
        nonce = requests.post(f"{BASE}/challenge", json={"username": username}).json()["nonce"]
        step(f"Victim signs the nonce with their private key")
        sig = sign(priv, nonce)

        step("Victim logs in — first use (legitimate)")
        r1 = requests.post(f"{BASE}/login", json={"username": username, "signature": sig})
        assert r1.json()["status"] == "SUCCESS", f"First login failed: {r1.json()}"
        step(f"First login result: {GREEN}SUCCESS{RESET}")

        step("ATTACKER replays the exact same (nonce, signature)")
        r2 = requests.post(f"{BASE}/login", json={"username": username, "signature": sig})
        blocked = r2.json()["status"] != "SUCCESS"
        result(blocked, f"Replay attempt returned: {r2.json()['status']}")
    finally:
        cleanup(username)

# ══════════════════════════════════════════════════════════════════════════════
# ATTACK 2 — Forged Signature (random bytes)
# ══════════════════════════════════════════════════════════════════════════════
def attack_2_forged_signature():
    banner("ATTACK 2 — Forged Signature (No Private Key)")
    print("  Scenario: Attacker knows the username but has no private key.")
    print("  They send 256 random bytes pretending it is a valid signature.\n")

    username, _ = setup_victim()
    try:
        step("Attacker requests a challenge nonce")
        nonce = requests.post(f"{BASE}/challenge", json={"username": username}).json()["nonce"]

        step("Attacker generates 256 random bytes as a fake signature")
        fake_sig = base64.b64encode(secrets.token_bytes(256)).decode()

        step("Attacker submits the forged signature")
        r = requests.post(f"{BASE}/login", json={"username": username, "signature": fake_sig})
        blocked = r.json()["status"] != "SUCCESS"
        result(blocked, f"Forgery attempt returned: {r.json()['status']}")
    finally:
        cleanup(username)

# ══════════════════════════════════════════════════════════════════════════════
# ATTACK 3 — Wrong Key (attacker uses their own valid RSA key)
# ══════════════════════════════════════════════════════════════════════════════
def attack_3_wrong_key():
    banner("ATTACK 3 — Wrong Private Key (Key Substitution)")
    print("  Scenario: Attacker has their OWN valid RSA key pair.")
    print("  They sign the victim's nonce with their own key.")
    print("  The signature is cryptographically valid — but for the wrong key.\n")

    username, _ = setup_victim()
    try:
        step("Attacker requests the victim's challenge nonce")
        nonce = requests.post(f"{BASE}/challenge", json={"username": username}).json()["nonce"]

        step("Attacker signs with THEIR OWN private key (not the victim's)")
        attacker_priv, _ = make_keypair()
        attacker_sig = sign(attacker_priv, nonce)

        step("Attacker submits a cryptographically valid — but wrong — signature")
        r = requests.post(f"{BASE}/login", json={"username": username, "signature": attacker_sig})
        blocked = r.json()["status"] != "SUCCESS"
        result(blocked, f"Wrong-key attempt returned: {r.json()['status']}")
    finally:
        cleanup(username)

# ══════════════════════════════════════════════════════════════════════════════
# ATTACK 4 — Operation Context Tampering
# ══════════════════════════════════════════════════════════════════════════════
def attack_4_context_tamper():
    banner("ATTACK 4 — Operation Context Tampering")
    print("  Scenario: Attacker gets a nonce for a $10 transfer,")
    print("  then tries to replay it with a $50,000 amount.")
    print("  The context hash bound to the nonce should catch this.\n")

    username, priv = setup_victim()
    try:
        small_ctx = {**RISK_CTX, "amount": 10}
        large_ctx = {**RISK_CTX, "amount": 50000}

        step("User gets an operation nonce for a $10 transfer")
        ch = requests.post(f"{BASE}/operation-challenge", json={
            "username": username, "operation": "TRANSFER", "context": small_ctx
        }).json()
        nonce = ch["nonce"]
        step(f"Nonce issued: {nonce[:24]}…")

        step("Attacker tries to use this nonce but with $50,000 context")
        r = requests.post(f"{BASE}/execute-operation", json={
            "username": username, "operation": "TRANSFER",
            "nonce": nonce, "context": large_ctx
        }).json()
        blocked = r.get("status") in ("DENY", "DENIED")
        result(blocked, f"Tampered context attempt returned: {r.get('status')}")
    finally:
        cleanup(username)

# ══════════════════════════════════════════════════════════════════════════════
# ATTACK 5 — Operation Nonce Replay
# ══════════════════════════════════════════════════════════════════════════════
def attack_5_operation_replay():
    banner("ATTACK 5 — Operation Nonce Replay")
    print("  Scenario: Attacker replays a used operation nonce")
    print("  to try to execute the same operation twice.\n")

    username, priv = setup_victim()
    try:
        step("User gets an operation nonce for TRANSFER")
        ch = requests.post(f"{BASE}/operation-challenge", json={
            "username": username, "operation": "TRANSFER", "context": RISK_CTX
        }).json()
        nonce = ch["nonce"]

        step("First execution — legitimate")
        r1 = requests.post(f"{BASE}/execute-operation", json={
            "username": username, "operation": "TRANSFER",
            "nonce": nonce, "context": RISK_CTX
        }).json()
        step(f"First result: {r1.get('status')}")

        step("ATTACKER replays the exact same nonce")
        r2 = requests.post(f"{BASE}/execute-operation", json={
            "username": username, "operation": "TRANSFER",
            "nonce": nonce, "context": RISK_CTX
        }).json()
        blocked = r2.get("status") in ("DENY", "DENIED")
        result(blocked, f"Replay attempt returned: {r2.get('status')}")
    finally:
        cleanup(username)

# ══════════════════════════════════════════════════════════════════════════════
# ATTACK 6 — Audit Log Tampering
# ══════════════════════════════════════════════════════════════════════════════
def attack_6_audit_tamper():
    banner("ATTACK 6 — Audit Log Tampering")
    print("  Scenario: Insider attacker directly edits the SQLite database")
    print("  to change a DENIED record to SUCCESS — hiding evidence.")
    print("  The SHA-256 hash chain should detect the mutation.\n")

    username, priv = setup_victim()
    try:
        # Do a successful login (writes LOGIN_SUCCESS to logs)
        step("Performing legitimate login to write audit entries")
        nonce = requests.post(f"{BASE}/challenge", json={"username": username}).json()["nonce"]
        requests.post(f"{BASE}/login", json={"username": username, "signature": sign(priv, nonce)})

        # Do a failed login (writes LOGIN_DENIED to logs)
        step("Performing a failed login attempt to create a DENIED record")
        requests.post(f"{BASE}/challenge", json={"username": username})
        requests.post(f"{BASE}/login", json={"username": username,
                                              "signature": base64.b64encode(b"fake").decode()})

        step("Checking integrity before tampering")
        r1 = requests.get(f"{BASE}/verify-logs")
        before = r1.json().get("integrity")
        step(f"Integrity before: {GREEN if before == 'OK' else RED}{before}{RESET}")

        if before != "OK":
            print(f"  {YELLOW}⚠  Chain was already broken before tampering.")
            print(f"     Reset the DB:  rm backend/securebank.db && python backend/app.py{RESET}\n")
            return

        # Show audit log before tampering
        db = sqlite3.connect(DB_PATH)
        rows = db.execute(
            "SELECT id, user, result, action FROM logs WHERE user=? ORDER BY id", (username,)
        ).fetchall()
        db.close()
        print(f"\n  {YELLOW}Audit entries for this user before tampering:{RESET}")
        for row in rows:
            print(f"    id={row[0]}  result={row[2]}  action={row[3]}")
        print()

        # Tamper directly in the DB
        step("ATTACKER opens SQLite and changes LOGIN_DENIED → LOGIN_SUCCESS")
        db = sqlite3.connect(DB_PATH)
        changed = db.execute(
            "UPDATE logs SET result='LOGIN_SUCCESS' WHERE user=? AND result='LOGIN_DENIED'",
            (username,)
        ).rowcount
        db.commit()

        # Show after
        rows_after = db.execute(
            "SELECT id, user, result, action FROM logs WHERE user=? ORDER BY id", (username,)
        ).fetchall()
        db.close()

        print(f"\n  {YELLOW}Audit entries after tampering:{RESET}")
        for row in rows_after:
            print(f"    id={row[0]}  result={row[2]}  action={row[3]}")
        print(f"\n  {YELLOW}Rows changed in DB: {changed}{RESET}\n")

        step("Running integrity check — did the hash chain catch it?")
        r2 = requests.get(f"{BASE}/verify-logs")
        detected = r2.json().get("integrity") == "TAMPERED"
        result(detected, f"Integrity check returned: {r2.json().get('integrity')}")

    finally:
        cleanup(username)

# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print(f"\n{BOLD}SecureBank — Live Attack Demonstration{RESET}")
    print(f"Backend: {BASE}\n")

    try:
        requests.get(f"{BASE}/logs", timeout=2)
    except Exception:
        print(f"{RED}ERROR: Backend not reachable at {BASE}{RESET}")
        print("Start it:  cd backend && python app.py")
        exit(1)

    attack_1_replay_login()
    attack_2_forged_signature()
    attack_3_wrong_key()
    attack_4_context_tamper()
    attack_5_operation_replay()
    attack_6_audit_tamper()

    print(f"\n{BOLD}{GREEN}{'═'*60}{RESET}")
    print(f"{BOLD}{GREEN}  All 6 attack demonstrations complete.{RESET}")
    print(f"{BOLD}{GREEN}{'═'*60}{RESET}\n")