"""
risk_policy.py
Server-Side Risk Policy Engine
=================================
Scores each operation request by combining:
  1. Operation base risk    — some actions are inherently higher risk
  2. Velocity signals       — rapid successive operations = suspicious
  3. Device consistency     — is the fingerprint the same as at login?
  4. Behavioural signals    — did a human actually interact with the page?
  5. Amount thresholds      — large transfers get extra scrutiny
  6. Session freshness      — old session + high-risk action = step-up

Decision mapping
────────────────
  0–39   → ALLOW     (low confidence of threat)
  40–69  → STEP_UP   (require fresh crypto re-authentication)
  70–100 → DENY      (high confidence of threat / policy hard-block)

Usage
──────
  engine = RiskPolicyEngine()
  decision = engine.evaluate(username, operation_type, context, db)
  # decision.status  ∈ {"ALLOW", "STEP_UP", "DENY"}
  # decision.score   ∈ [0, 100]
  # decision.reasons list[str]
"""

from __future__ import annotations
import time
from dataclasses import dataclass, field
from typing import Optional
import sqlite3


# ─── Decision ────────────────────────────────────────────────────────────────

@dataclass
class RiskDecision:
    status: str                        # "ALLOW" | "STEP_UP" | "DENY"
    score: int                         # 0–100
    reasons: list[str] = field(default_factory=list)


# ─── Per-Operation Base Scores ────────────────────────────────────────────────

OPERATION_BASE_RISK = {
    "LOGIN":    0,
    "READ":    10,
    "WRITE":   25,
    "TRANSFER":35,
    "DELETE":  50,
}

# Hard DENY threshold for DELETE — always force step-up at minimum
OPERATION_MINIMUM_ACTION = {
    "DELETE": "STEP_UP",
}


# ─── Engine ──────────────────────────────────────────────────────────────────

class RiskPolicyEngine:

    # ── Tunable weights ──────────────────────────────────────────────────────
    VELOCITY_WINDOW_SECONDS   = 120   # Look back 2 minutes for rapid ops
    VELOCITY_MAX_ALLOWED      = 5     # > 5 ops in window → velocity penalty
    VELOCITY_PENALTY          = 20    # Score points added per excess op

    SESSION_FRESHNESS_LIMIT   = 1800  # 30 min — after this, high-risk needs re-auth
    SESSION_STALENESS_PENALTY = 20

    LARGE_TRANSFER_THRESHOLD  = 5_000   # USD — triggers additional scrutiny
    LARGE_TRANSFER_PENALTY    = 25

    BOT_SIGNAL_PENALTY        = 30    # No mouse + no keyboard + very fast = bot

    DEVICE_MISMATCH_PENALTY   = 40    # Fingerprint changed since login

    # ── Main entry point ─────────────────────────────────────────────────────
    def evaluate(
        self,
        username: str,
        operation: str,
        context: dict,
        db: sqlite3.Connection,
    ) -> RiskDecision:

        score = 0
        reasons: list[str] = []

        # 1. Base risk for this operation type
        base = OPERATION_BASE_RISK.get(operation.upper(), 30)
        score += base
        if base:
            reasons.append(f"Base risk for {operation}: +{base}")

        # 2. Velocity check — how many ops has this user done recently?
        velocity_score = self._velocity_penalty(username, db)
        if velocity_score:
            score += velocity_score
            reasons.append(f"High operation velocity: +{velocity_score}")

        # 3. Session freshness
        freshness_score = self._session_freshness_penalty(username, db, operation)
        if freshness_score:
            score += freshness_score
            reasons.append(f"Stale session for sensitive op: +{freshness_score}")

        # 4. Device fingerprint consistency
        fp_score = self._fingerprint_check(username, context, db)
        if fp_score:
            score += fp_score
            reasons.append(f"Device fingerprint mismatch: +{fp_score}")

        # 5. Behavioural bot signals
        bot_score = self._bot_signals(context)
        if bot_score:
            score += bot_score
            reasons.append(f"Suspicious behavioural signals (possible bot): +{bot_score}")

        # 6. Large transfer amount
        amount_score = self._amount_check(context)
        if amount_score:
            score += amount_score
            reasons.append(f"High-value transfer (>${self.LARGE_TRANSFER_THRESHOLD}): +{amount_score}")

        # Cap score at 100
        score = min(score, 100)

        # Determine decision
        status = self._decide(score, operation)

        return RiskDecision(status=status, score=score, reasons=reasons)

    # ── Velocity ─────────────────────────────────────────────────────────────
    def _velocity_penalty(self, username: str, db: sqlite3.Connection) -> int:
        cutoff = time.time() - self.VELOCITY_WINDOW_SECONDS
        cur = db.execute(
            "SELECT COUNT(*) FROM audit_logs WHERE user=? AND timestamp > ?",
            (username, cutoff)
        )
        count = cur.fetchone()[0]
        if count > self.VELOCITY_MAX_ALLOWED:
            excess = count - self.VELOCITY_MAX_ALLOWED
            return min(excess * self.VELOCITY_PENALTY, 40)
        return 0

    # ── Session freshness ─────────────────────────────────────────────────────
    def _session_freshness_penalty(
        self, username: str, db: sqlite3.Connection, operation: str
    ) -> int:
        # Only penalise for high-risk operations
        if OPERATION_BASE_RISK.get(operation.upper(), 0) < 25:
            return 0
        cur = db.execute(
            "SELECT login_timestamp FROM sessions WHERE username=?", (username,)
        )
        row = cur.fetchone()
        if not row:
            return 0
        age = time.time() - row[0]
        if age > self.SESSION_FRESHNESS_LIMIT:
            return self.SESSION_STALENESS_PENALTY
        return 0

    # ── Device fingerprint ────────────────────────────────────────────────────
    def _fingerprint_check(
        self, username: str, context: dict, db: sqlite3.Connection
    ) -> int:
        incoming_fp = context.get("deviceFingerprint", "")
        cur = db.execute(
            "SELECT fingerprint FROM sessions WHERE username=?", (username,)
        )
        row = cur.fetchone()
        if not row or not row[0]:
            return 0   # No baseline recorded yet — first login
        if row[0] != incoming_fp:
            return self.DEVICE_MISMATCH_PENALTY
        return 0

    # ── Bot signals ───────────────────────────────────────────────────────────
    def _bot_signals(self, context: dict) -> int:
        no_mouse    = not context.get("mouseMovementDetected", True)
        no_keyboard = not context.get("keyboardInteractionDetected", True)
        # Less than 800ms on page = almost certainly automated
        too_fast    = context.get("timeOnPageMs", 9999) < 800

        if no_mouse and no_keyboard and too_fast:
            return self.BOT_SIGNAL_PENALTY
        if no_mouse and too_fast:
            return self.BOT_SIGNAL_PENALTY // 2
        return 0

    # ── Amount threshold ──────────────────────────────────────────────────────
    def _amount_check(self, context: dict) -> int:
        amount = context.get("amount")
        if amount and float(amount) >= self.LARGE_TRANSFER_THRESHOLD:
            return self.LARGE_TRANSFER_PENALTY
        return 0

    # ── Decision mapping ──────────────────────────────────────────────────────
    def _decide(self, score: int, operation: str) -> str:
        # Enforce operation-level minimums first
        minimum = OPERATION_MINIMUM_ACTION.get(operation.upper())
        if minimum == "STEP_UP" and score < 40:
            score = 40   # Force into STEP_UP band

        if score >= 70:
            return "DENY"
        if score >= 40:
            return "STEP_UP"
        return "ALLOW"