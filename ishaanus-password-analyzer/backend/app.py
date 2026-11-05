# -*- coding: utf-8 -*-
"""
app.py – Flask application entry point for Ishaanus Password Security Analyzer.

Exposes a single API endpoint:
  POST /api/analyze  ->  { "password": "..." }  ->  analysis JSON

CORS CONFIGURATION AND LIMITATIONS
────────────────────────────────────
CORS is restricted to explicit localhost origins.  Key limitations:

  1. The "null" origin is included to allow file:// access (browsers send
     Origin: null for local files).  However, any sandboxed <iframe> also
     sends Origin: null, so this is NOT a strong security boundary.

  2. Flask-CORS does NOT support glob port wildcards (e.g. "localhost:*").
     Only the explicit ports listed in CORS_ORIGINS (or the CORS_ORIGINS
     environment variable) are allowed.

  3. This server is designed for LOCAL USE ONLY.  Do not expose it to a
     network or the public internet without proper authentication, rate
     limiting, TLS, and a production WSGI server (e.g. gunicorn).

PRIVACY: Passwords are NEVER logged, stored, or forwarded to any third party.
         They exist only in RAM for the duration of a single request.
"""

import os
import logging
from flask import Flask, request, jsonify
from flask_cors import CORS
from analyzer import analyze_password

# ── App setup ─────────────────────────────────────────────────────────────────
app = Flask(__name__)

# ── CORS origins ──────────────────────────────────────────────────────────────
# Default list covers common local dev scenarios:
#   - Browsers opening index.html via file:// send Origin: null
#   - Live-server / VS Code defaults: 5500 / 5501
#   - Any other port the user may serve the frontend from (add to env var)
#
# To override at runtime:
#   set CORS_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
#   (comma-separated, no spaces around commas)
#
_DEFAULT_ORIGINS = [
    "http://localhost:5500",
    "http://127.0.0.1:5500",
    "http://localhost:5501",
    "http://127.0.0.1:5501",
    "http://localhost:8080",
    "http://127.0.0.1:8080",
    # file:// pages send "null" – see CORS limitation note in module docstring
    "null",
]

_env_origins = os.environ.get("CORS_ORIGINS", "")
_allowed_origins = (
    [o.strip() for o in _env_origins.split(",") if o.strip()]
    if _env_origins
    else _DEFAULT_ORIGINS
)

CORS(app, resources={r"/api/*": {"origins": _allowed_origins}})

# ── Suppress werkzeug access logs ─────────────────────────────────────────────
# Werkzeug logs one line per request at INFO level.  Although it only logs
# the URL (not the POST body), we silence it to avoid any accidental future
# leakage if the logging format is ever changed.
logging.getLogger("werkzeug").setLevel(logging.ERROR)

# ── App logger (for our own messages only) ────────────────────────────────────
# We log at WARNING+ only, and we NEVER include request bodies in log messages.
app.logger.setLevel(logging.WARNING)


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Health-check / root route."""
    return jsonify({
        "status":  "ok",
        "service": "Ishaanus Password Security Analyzer",
        "version": "1.1.0",
    })


@app.route("/api/analyze", methods=["POST"])
def analyze():
    """
    Analyze a password and return a structured security report.

    Request JSON:
        { "password": "<string>" }

    Response JSON:
        {
          "score":                int   (0-4, zxcvbn scale),
          "label":                str,
          "entropy":              float (observed Shannon entropy, bits),
          "theoretical_entropy":  float (charset upper-bound, bits),
          "observed_entropy":     float (same as entropy),
          "length":               int,
          "categories":           { has_uppercase, has_lowercase, has_digits,
                                    has_symbols, ...counts },
          "crack_times":          { online_throttling, online_no_throttling,
                                    offline_slow_hashing, offline_fast_hashing },
          "is_common":            bool,
          "recommendations":      [str, ...],
          "guesses_log10":        float,
        }
    """
    # ── Parse request ─────────────────────────────────────────────────────────
    data = request.get_json(silent=True)

    if data is None:
        return jsonify({"error": "Invalid or missing JSON body"}), 400

    # Accept a missing "password" key as an empty string
    password = data.get("password", "")

    # ── Input validation ──────────────────────────────────────────────────────
    if not isinstance(password, str):
        return jsonify({"error": "password must be a string"}), 400

    # Hard cap: refuse passwords longer than 1000 chars to protect server CPU.
    # zxcvbn's complexity scales with length and can be slow on very long inputs.
    if len(password) > 1000:
        return jsonify({"error": "Password too long (maximum 1000 characters)"}), 400

    # ── Analyze ───────────────────────────────────────────────────────────────
    # We wrap the call in a try/except so that unexpected internal errors:
    #   a) return a clean JSON error (not a Werkzeug HTML traceback page)
    #   b) are logged without including the password or request body
    try:
        result = analyze_password(password)
    except Exception:
        # Log the traceback for debugging, but NOT the password.
        app.logger.exception("Unexpected error in analyze_password (password omitted)")
        return jsonify({"error": "Internal analysis error"}), 500

    return jsonify(result), 200


# ── Error handlers ────────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found"}), 404


@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed"}), 405


@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "Internal server error"}), 500


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    import io

    # Force UTF-8 output so the banner renders correctly on Windows terminals
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

    # ── Debug mode ────────────────────────────────────────────────────────────
    # debug=True enables the Werkzeug interactive browser debugger (a Python
    # REPL accessible from the browser) and auto-reloader.  This is useful
    # during development but MUST be False in any shared or deployed context.
    #
    # Control via environment variable:
    #   set FLASK_DEBUG=1   (Windows)   — enables debug + reloader
    #   export FLASK_DEBUG=1 (Unix)
    #   (unset or 0 = production-safe defaults)
    debug_mode = os.environ.get("FLASK_DEBUG", "0").strip() in ("1", "true", "yes")

    print("=" * 62)
    print("  Ishaanus - Password Security Analyzer  v1.1.0")
    print("  Backend : http://127.0.0.1:5000")
    print(f"  Debug   : {'ON  (development mode)' if debug_mode else 'OFF (production-safe)'}")
    print("  Open frontend/index.html in your browser to start.")
    print("=" * 62)

    app.run(host="127.0.0.1", port=5000, debug=debug_mode)
