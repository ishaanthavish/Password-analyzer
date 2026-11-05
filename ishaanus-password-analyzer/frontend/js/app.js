/**
 * app.js – Ishaanus Password Security Analyzer  v1.1.0
 *
 * Frontend controller: handles UI interactions, calls the Flask backend,
 * and reactively updates all analysis sections.
 *
 * KEY CHANGES IN v1.1.0
 * ─────────────────────
 * RACE CONDITION FIX:
 *   An AbortController is now attached to every fetch request.  When a new
 *   debounce fires while a previous request is still in-flight, the in-flight
 *   request is cancelled before the new one starts.  This guarantees that only
 *   the result of the most recently typed password can ever appear in the UI.
 *
 * ENTROPY DISPLAY:
 *   The backend now returns both observed_entropy (Shannon, primary display)
 *   and theoretical_entropy (charset upper-bound, tooltip).  We show the
 *   observed value as the main metric because it correctly reflects character
 *   diversity (e.g. "aaaaaaa" shows 0 bits, not an inflated value).
 *
 * PRIVACY: Passwords are only sent to the local Flask server (127.0.0.1:5000).
 *          They are never transmitted to any external service.
 *          Note: Google Fonts were replaced with locally hosted WOFF2 files,
 *          so the page makes no external network calls at all.
 */

// ── Configuration ─────────────────────────────────────────────────────────────
const API_BASE    = "http://127.0.0.1:5000";
const DEBOUNCE_MS = 300;  // milliseconds to wait after last keystroke

// ── DOM References ─────────────────────────────────────────────────────────────
const passwordInput  = document.getElementById("password-input");
const toggleBtn      = document.getElementById("toggle-btn");
const eyeIcon        = document.getElementById("eye-icon");
const spinner        = document.getElementById("spinner");
const errorToast     = document.getElementById("error-toast");
const errorMsg       = document.getElementById("error-msg");
const resultsSection = document.getElementById("results-section");
const emptyState     = document.getElementById("empty-state");

// Strength meter
const strengthBadge    = document.getElementById("strength-badge");
const strengthSegments = document.querySelectorAll(".strength-segment");

// Stats
const statEntropy    = document.getElementById("stat-entropy");
const statLength     = document.getElementById("stat-length");
const statCrackOnline = document.getElementById("stat-crack-online");
const statScore      = document.getElementById("stat-score");

// Character checks
const checkUpper  = document.getElementById("check-upper");
const checkLower  = document.getElementById("check-lower");
const checkDigit  = document.getElementById("check-digit");
const checkSymbol = document.getElementById("check-symbol");
const countUpper  = document.getElementById("count-upper");
const countLower  = document.getElementById("count-lower");
const countDigit  = document.getElementById("count-digit");
const countSymbol = document.getElementById("count-symbol");

// Crack times
const crackThrottle   = document.getElementById("crack-throttle");
const crackNoThrottle = document.getElementById("crack-no-throttle");
const crackSlowHash   = document.getElementById("crack-slow-hash");
const crackFastHash   = document.getElementById("crack-fast-hash");

// Alert & recommendations
const weakAlert = document.getElementById("weak-alert");
const alertDesc = document.getElementById("alert-desc");
const recsList  = document.getElementById("recommendations-list");


// ── Strength badge styles (score 0–4) ─────────────────────────────────────────
const BADGE_STYLES = [
  { bg: "rgba(239,68,68,0.2)",   color: "#f87171", label: "Very Weak"   },
  { bg: "rgba(249,115,22,0.2)",  color: "#fb923c", label: "Weak"        },
  { bg: "rgba(245,158,11,0.2)",  color: "#fbbf24", label: "Fair"        },
  { bg: "rgba(34,197,94,0.2)",   color: "#4ade80", label: "Strong"      },
  { bg: "rgba(16,185,129,0.2)",  color: "#34d399", label: "Very Strong" },
];


// ── Show / Hide password toggle ───────────────────────────────────────────────
toggleBtn.addEventListener("click", () => {
  const isPassword = passwordInput.type === "password";
  passwordInput.type = isPassword ? "text" : "password";

  // Swap SVG icon between "eye" (show) and "eye-off" (hide)
  eyeIcon.innerHTML = isPassword
    ? /* eye-off */
      `<path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94"/>
       <path d="M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19"/>
       <line x1="1" y1="1" x2="23" y2="23"/>`
    : /* eye */
      `<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
       <circle cx="12" cy="12" r="3"/>`;
});


// ── Debounce helper ───────────────────────────────────────────────────────────
function debounce(fn, delay) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), delay);
  };
}


// ── In-flight request controller ─────────────────────────────────────────────
// RACE CONDITION FIX:
//   We track the AbortController for whatever fetch() is currently in-flight.
//   When a new debounce fires, we call .abort() on the previous controller
//   before starting the next request.  Any response from the aborted request
//   will throw an AbortError, which we catch and silently ignore.
//   This guarantees that only the response to the most-recently-typed password
//   can ever be rendered in the UI.
let _currentController = null;


// ── Main input handler (debounced) ────────────────────────────────────────────
const onPasswordInput = debounce(async (e) => {
  const password = e.target.value;

  // Clear results when input is empty
  if (!password) {
    hideResults();
    return;
  }

  // ── Cancel any in-flight request (race-condition guard) ──────────────────
  if (_currentController) {
    _currentController.abort();
    _currentController = null;
  }

  setLoading(true);
  hideError();

  // Create a fresh controller for this request
  const controller = new AbortController();
  _currentController = controller;

  try {
    const data = await analyzePassword(password, controller.signal);

    // If this controller was already replaced by a newer call, discard result.
    // (The abort() above makes this redundant but it's an extra safety net.)
    if (controller !== _currentController && _currentController !== null) {
      return;
    }

    renderResults(data);
  } catch (err) {
    if (err.name === "AbortError") {
      // This request was deliberately cancelled — do nothing.
      return;
    }
    showError(
      err.message ||
      "Could not connect to backend. Is the Flask server running on port 5000?"
    );
  } finally {
    // Only clear the spinner if this is still the active controller
    if (controller === _currentController || _currentController === null) {
      setLoading(false);
      _currentController = null;
    }
  }
}, DEBOUNCE_MS);

passwordInput.addEventListener("input", onPasswordInput);


// ── API call ──────────────────────────────────────────────────────────────────
async function analyzePassword(password, signal) {
  /**
   * POST { password } to the local Flask backend.
   *
   * @param {string} password  - The plaintext password to analyze.
   * @param {AbortSignal} signal - AbortController signal to cancel the fetch.
   *
   * Returns parsed JSON on success; throws on network error, HTTP error, or abort.
   *
   * PRIVACY: The password is sent ONLY to 127.0.0.1:5000 (this machine).
   *          No external service ever receives it.
   */
  const response = await fetch(`${API_BASE}/api/analyze`, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ password }),
    signal,          // <-- ties this fetch to the AbortController
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.error || `HTTP ${response.status}`);
  }

  return response.json();
}


// ── Render all UI sections ────────────────────────────────────────────────────
function renderResults(data) {
  const {
    score,
    label,
    // observed_entropy is the primary display value (Shannon entropy).
    // It correctly reflects character diversity; "aaaaaaa" scores 0 bits.
    observed_entropy,
    theoretical_entropy,
    length,
    categories,
    crack_times,
    is_common,
    recommendations,
    // guesses_log10 is always present (even for empty input) in v1.1.0
    guesses_log10 = 0,
  } = data;

  // Show results panel, hide empty state
  resultsSection.classList.add("visible");
  emptyState.style.display = "none";

  // ── Strength meter ───────────────────────────────────────────────────────
  updateStrengthMeter(score, label);

  // ── Stats ────────────────────────────────────────────────────────────────
  // Primary entropy display: observed (Shannon) value.
  // Tooltip shows the theoretical upper-bound for context.
  statEntropy.textContent = `${observed_entropy}`;
  statEntropy.title = (
    `Observed entropy: ${observed_entropy} bits (Shannon)\n` +
    `Theoretical max: ${theoretical_entropy} bits (charset pool)\n\n` +
    `Observed entropy reflects actual character diversity.\n` +
    `A password of all identical characters scores 0 bits here,\n` +
    `even if it has a large charset.`
  );

  statLength.textContent = length;

  statCrackOnline.textContent = crack_times.online_throttling;

  // Map score (0–4) → 0–100 % for the complexity badge
  const complexityPct = Math.round((score / 4) * 100);
  statScore.textContent = `${complexityPct}%`;
  colorizeScore(statScore, score);

  // ── Character checks ─────────────────────────────────────────────────────
  setCheck(checkUpper,  countUpper,  categories.has_uppercase, categories.uppercase_count);
  setCheck(checkLower,  countLower,  categories.has_lowercase, categories.lowercase_count);
  setCheck(checkDigit,  countDigit,  categories.has_digits,    categories.digit_count);
  setCheck(checkSymbol, countSymbol, categories.has_symbols,   categories.symbol_count);

  // ── Crack times ──────────────────────────────────────────────────────────
  crackThrottle.textContent   = crack_times.online_throttling;
  crackNoThrottle.textContent = crack_times.online_no_throttling;
  crackSlowHash.textContent   = crack_times.offline_slow_hashing;
  crackFastHash.textContent   = crack_times.offline_fast_hashing;
  colorizeCrackTimes(score);

  // ── Weak password alert ──────────────────────────────────────────────────
  if (is_common || score <= 1) {
    weakAlert.classList.add("visible");
    alertDesc.textContent = is_common
      ? "This password appears in well-known breach databases and can be cracked instantly."
      : "This password is too predictable. Attackers can crack it in seconds with common tools.";
  } else {
    weakAlert.classList.remove("visible");
  }

  // ── Recommendations ──────────────────────────────────────────────────────
  renderRecommendations(recommendations);
}


// ── Strength meter update ─────────────────────────────────────────────────────
function updateStrengthMeter(score, label) {
  const style = BADGE_STYLES[score] || BADGE_STYLES[0];
  strengthBadge.textContent      = label;
  strengthBadge.style.background = style.bg;
  strengthBadge.style.color      = style.color;

  // Light up all segments up to and including the score index
  strengthSegments.forEach((seg, i) => {
    seg.classList.toggle("active", i <= score);
  });
}


// ── Character check item ──────────────────────────────────────────────────────
function setCheck(itemEl, countEl, hasPassed, count) {
  itemEl.classList.toggle("pass", hasPassed);
  itemEl.classList.toggle("fail", !hasPassed);

  const iconEl = itemEl.querySelector(".check-icon");
  iconEl.textContent  = hasPassed ? "✓" : "✗";
  countEl.textContent = hasPassed ? `${count} found` : "Missing";
}


// ── Colorize complexity score ─────────────────────────────────────────────────
function colorizeScore(el, score) {
  const colors = ["#f87171", "#fb923c", "#fbbf24", "#4ade80", "#34d399"];
  el.style.color = colors[score] || colors[0];
}


// ── Colorize crack-time values to match strength ──────────────────────────────
function colorizeCrackTimes(score) {
  const color = BADGE_STYLES[score]?.color || "#f87171";
  [crackThrottle, crackNoThrottle, crackSlowHash, crackFastHash]
    .forEach(el => (el.style.color = color));
}


// ── Render recommendations list ───────────────────────────────────────────────
function renderRecommendations(recs) {
  recsList.innerHTML = "";
  recs.forEach((rec, i) => {
    const li = document.createElement("li");
    li.style.animationDelay = `${i * 50}ms`;
    // escapeHtml prevents XSS if a recommendation string ever contained
    // characters that could be interpreted as HTML markup.
    li.innerHTML = `<span class="rec-bullet"></span><span>${escapeHtml(rec)}</span>`;
    recsList.appendChild(li);
  });
}


// ── UI state helpers ──────────────────────────────────────────────────────────
function hideResults() {
  resultsSection.classList.remove("visible");
  weakAlert.classList.remove("visible");
  emptyState.style.display = "";
  hideError();
}

function setLoading(active) {
  spinner.classList.toggle("visible", active);
}

function showError(msg) {
  errorMsg.textContent = msg;
  errorToast.classList.add("visible");
}

function hideError() {
  errorToast.classList.remove("visible");
}


// ── XSS protection ────────────────────────────────────────────────────────────
function escapeHtml(str) {
  const map = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#x27;" };
  return str.replace(/[&<>"']/g, m => map[m]);
}
