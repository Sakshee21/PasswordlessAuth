/**
 * riskEngine.ts
 * Client-Side Risk Context Collector
 *
 * Gathers behavioral + contextual signals BEFORE each operation request.
 * These signals are sent to the server alongside the nonce request so the
 * server's Risk Policy Engine can score them and decide: ALLOW / STEP_UP / DENY.
 *
 * ⚠️  None of these signals are individually definitive.
 *      The server combines them with historical baselines to produce a score.
 */

export interface RiskContext {
  // ── Device ──────────────────────────────────────────────────────────────
  deviceFingerprint: string;        // Same fingerprint used for key binding
  screenResolution: string;         // "1920x1080"
  timezone: string;                 // "Asia/Kolkata"
  language: string;                 // "en-US"
  platform: string;                 // "Win32" / "MacIntel"
  hardwareConcurrency: number;      // CPU core count
  colorDepth: number;

  // ── Session ──────────────────────────────────────────────────────────────
  sessionAgeMs: number;             // How long ago the user logged in
  previousOperationsCount: number;  // Actions performed this session
  lastOperationTimestamp: number | null;

  // ── Behavioural ──────────────────────────────────────────────────────────
  timeOnPageMs: number;             // How long user spent on this page (too fast = bot signal)
  mouseMovementDetected: boolean;   // Did the user move the mouse at all?
  keyboardInteractionDetected: boolean;

  // ── Network ──────────────────────────────────────────────────────────────
  connectionType: string;           // "wifi" / "4g" / "unknown" (via Navigator.connection)

  // ── Operation ────────────────────────────────────────────────────────────
  operationType: string;            // "TRANSFER" / "DELETE" / etc.
  targetResource?: string;
  amount?: number;

  // ── Timestamp ────────────────────────────────────────────────────────────
  collectedAt: string;              // ISO timestamp
}

// ─── Session State (module-level, cleared on page load) ──────────────────────
const SESSION_START = Date.now();
let operationCount = 0;
let lastOpTime: number | null = null;

export function recordOperation() {
  operationCount++;
  lastOpTime = Date.now();
}

// ─── Behavioural Probes ───────────────────────────────────────────────────────
let _mouseMovedSincePageLoad = false;
let _keyboardUsedSincePageLoad = false;
let _pageLoadTime = Date.now();

if (typeof window !== "undefined") {
  window.addEventListener("mousemove", () => { _mouseMovedSincePageLoad = true; }, { once: true });
  window.addEventListener("keydown",   () => { _keyboardUsedSincePageLoad = true; }, { once: true });
}

// ─── Public Collector ─────────────────────────────────────────────────────────
export function collectRiskContext(
  operationType: string,
  targetResource?: string,
  amount?: number
): RiskContext {
  const nav = navigator as any;

  // Device fingerprint uses same logic as deviceKey.ts
  const fingerprint = [
    nav.userAgent,
    nav.language,
    nav.hardwareConcurrency?.toString() ?? "",
    nav.platform ?? "",
    screen.width + "x" + screen.height,
    screen.colorDepth?.toString() ?? "",
    Intl.DateTimeFormat().resolvedOptions().timeZone,
  ].join("|");

  return {
    // Device
    deviceFingerprint: fingerprint,
    screenResolution: `${screen.width}x${screen.height}`,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    language: nav.language,
    platform: nav.platform ?? "unknown",
    hardwareConcurrency: nav.hardwareConcurrency ?? 0,
    colorDepth: screen.colorDepth,

    // Session
    sessionAgeMs: Date.now() - SESSION_START,
    previousOperationsCount: operationCount,
    lastOperationTimestamp: lastOpTime,

    // Behavioural
    timeOnPageMs: Date.now() - _pageLoadTime,
    mouseMovementDetected: _mouseMovedSincePageLoad,
    keyboardInteractionDetected: _keyboardUsedSincePageLoad,

    // Network
    connectionType: nav.connection?.effectiveType ?? "unknown",

    // Operation
    operationType,
    targetResource,
    amount,

    collectedAt: new Date().toISOString(),
  };
}