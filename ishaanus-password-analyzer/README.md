# Ishaanus – Password Security Analyzer

A full-stack cybersecurity web application that analyzes password strength in
real time. Built with **Python Flask** (backend) and **HTML5/CSS3/JS** (frontend),
powered by [zxcvbn](https://github.com/dropbox/zxcvbn).

> **Privacy** — Your password is sent only to your *local* Flask server
> (`127.0.0.1:5000`). It is never logged, stored, or transmitted to any
> external service.  Fonts are locally hosted; the page makes zero external
> network calls.

> [!CAUTION]
> This application is designed for **local personal use only**.  It has not
> undergone a formal security audit and should **not** be exposed to a network
> or the public internet without additional hardening (authentication, rate
> limiting, TLS, production WSGI server).

---

## Features

| Feature | Details |
|---|---|
| Real-time analysis | 300 ms debounced API call; in-flight requests cancelled on fast typing |
| Strength meter | 5-segment animated bar (Very Weak → Very Strong) |
| Entropy score | Observed (Shannon) entropy shown; theoretical upper-bound in tooltip |
| Crack time estimates | 4 scenarios from zxcvbn; hover each card for attacker model details |
| Character checks | Uppercase / Lowercase / Numbers / Symbols with counts |
| Weak password detection | Flags known common passwords; score capped at ≤ 1 |
| Security recommendations | Personalised, actionable tips per password |
| Show / hide toggle | Eye-icon button to reveal / mask the password field |
| Privacy-first | No external calls; fonts served locally; no request logging |
| Responsive layout | Desktop, tablet, and mobile |

---

## Project Structure

```
ishaanus-password-analyzer/
├── backend/
│   ├── app.py               # Flask server + /api/analyze endpoint
│   ├── analyzer.py          # Core analysis (entropy, zxcvbn, recommendations)
│   ├── download_fonts.py    # One-time script to fetch WOFF2 font files
│   ├── requirements.txt     # Python dependencies (includes pytest)
│   └── tests/
│       ├── __init__.py
│       └── test_analyzer.py # Full pytest test suite (14 test classes, 40+ cases)
├── frontend/
│   ├── index.html           # Single-page app
│   ├── css/
│   │   └── style.css        # Dark theme, glassmorphism, animations
│   ├── fonts/               # Locally hosted WOFF2 files (created by download_fonts.py)
│   └── js/
│       └── app.js           # UI logic, AbortController fetch, rendering
├── .gitignore
└── README.md
```

---

## Setup & Running

### Prerequisites

- **Python 3.9 or higher** (tested on 3.14)
- A modern browser (Chrome, Firefox, Edge)

> **Windows note:** Use `py` instead of `python` or `python3` if the `python`
> command is not in your PATH.

---

### Step 1 — Install Python dependencies

```powershell
cd backend
py -m pip install -r requirements.txt
```

Installs: `flask`, `flask-cors`, `zxcvbn`, `pytest`.

---

### Step 2 — Download fonts (one-time)

```powershell
# From the project root:
py backend/download_fonts.py
```

Downloads Inter and JetBrains Mono as WOFF2 files into `frontend/fonts/`.
After this the page makes **no external network calls**.

---

### Step 3 — Start the Flask backend

```powershell
# From the backend/ directory:
py app.py
```

Expected output:
```
==============================================================
  Ishaanus - Password Security Analyzer  v1.1.0
  Backend : http://127.0.0.1:5000
  Debug   : OFF (production-safe)
  Open frontend/index.html in your browser to start.
==============================================================
```

---

### Step 4 — Open the frontend

Open **`frontend/index.html`** in your browser:
- **Windows:** Right-click `index.html` → *Open with* → your browser
- **macOS/Linux:** `open frontend/index.html`

The frontend connects to `http://127.0.0.1:5000` automatically.

---

## Development Mode

### Enable Flask debug mode

Debug mode activates the Werkzeug interactive debugger and auto-reloader.
**Never use it in a shared or deployed context.**

```powershell
# Windows PowerShell
$env:FLASK_DEBUG = "1"
py app.py
```

```bash
# Unix / macOS
export FLASK_DEBUG=1
python app.py
```

### Custom CORS origins

If you serve the frontend on a different port (e.g. via VS Code Live Server),
add your origin to the allowed list:

```powershell
$env:CORS_ORIGINS = "http://localhost:5500,http://127.0.0.1:5500,null"
py app.py
```

---

## Running Tests

```powershell
cd backend
py -m pytest tests/ -v
```

With coverage:

```powershell
py -m pytest tests/ -v --tb=short --cov=analyzer --cov-report=term-missing
```

The test suite covers:

| # | Test class | What it tests |
|---|---|---|
| 1 | `TestEmptyPassword` | Empty input → all zeros, all keys present, N/A crack times |
| 2 | `TestCommonPassword` | `123456` → `is_common=True`, score ≤ 1 |
| 3 | `TestAllLowercase` | Single-category entropy, uppercase recommendation |
| 4 | `TestDigitsOnly` | Digit-only charset entropy formula |
| 5 | `TestFairPassword` | Mid-range password structure |
| 6 | `TestComplexPassword` | Score 4, observed entropy ≥ 50 bits, all categories |
| 7 | `TestOverlongPassword` | 1001 chars → 400; exactly 1000 chars → 200 |
| 8 | `TestNonStringPassword` | int / list / null → 400 |
| 9 | `TestMalformedRequest` | Bad JSON → 400; missing key → empty-password result |
| 10 | `TestEntropyInvariant` | `observed ≤ theoretical` for many passwords |
| 11 | `TestCrackTimeKeys` | All 4 scenario keys present in every response |
| 12 | `TestGuessesLog10AlwaysPresent` | Key present and numeric for all inputs |
| 13 | `TestCommonPasswordScoreCap` | 8 known common passwords all have score ≤ 1 |
| 14 | `TestBoundaryLengthPassword` | Exactly 1000 chars → 200; 1001 chars → 400 |

---

## API Reference

### `POST /api/analyze`

**Request body:**
```json
{ "password": "YourPasswordHere" }
```

**Response (200 OK):**
```json
{
  "score":                3,
  "label":                "Strong",
  "entropy":              68.42,
  "observed_entropy":     68.42,
  "theoretical_entropy":  83.65,
  "length":               13,
  "categories": {
    "has_uppercase": true, "uppercase_count": 2,
    "has_lowercase": true, "lowercase_count": 6,
    "has_digits":    true, "digit_count":     3,
    "has_symbols":   true, "symbol_count":    2
  },
  "crack_times": {
    "online_throttling":    "centuries",
    "online_no_throttling": "3 years",
    "offline_slow_hashing": "5 days",
    "offline_fast_hashing": "7 minutes"
  },
  "is_common":       false,
  "recommendations": ["Great length! 16+ characters makes..."],
  "guesses_log10":   11.4
}
```

**Error responses:**

| Status | Condition |
|---|---|
| 400 | Missing/invalid JSON, non-string password, password > 1000 chars |
| 500 | Unexpected internal error (generic message, no password in body) |

---

## Entropy Explained

The app computes and returns two entropy values:

| Field | Formula | Meaning |
|---|---|---|
| `observed_entropy` | `H × length` where `H = -Σ p log₂ p` | Shannon entropy — reflects actual character diversity. `aaaaaaa` = 0 bits. **Primary display value.** |
| `theoretical_entropy` | `log₂(charset_size) × length` | Upper bound — assumes characters are drawn uniformly at random from the charset pool. Inflated for low-diversity passwords. Shown in tooltip. |

The two estimates bracket the real entropy:
`observed ≤ real ≤ theoretical`

**zxcvbn's guess estimate is different from both** — it models an intelligent
attacker using dictionaries, common patterns, and substitutions. The crack-time
values come from `guesses_log10`, not from entropy.

---

## Security & Privacy Notes

| Property | Detail |
|---|---|
| No external calls | Fonts local, no analytics, no CDN dependencies |
| No password logging | werkzeug access log set to ERROR; app logger never logs request bodies |
| Input validation | Type check + 1000-char hard cap |
| XSS protection | All recommendation text HTML-escaped before DOM insertion |
| CORS restriction | Only explicit localhost origins allowed; `null` origin included for `file://` access (known footgun — see CORS limitations in `app.py`) |
| Debug mode | OFF by default; must be explicitly enabled via `FLASK_DEBUG=1` |
| Error handling | Exceptions in `analyze_password` return generic 500 (password never logged) |

### Known Limitations

- **Local use only.** Flask's built-in server (`app.run`) is not production-ready.
  For multi-user deployment, use gunicorn + nginx + TLS.
- **CORS `null` origin** allows sandboxed iframes — not just `file://` pages.
- **Common-password list is small** (~40 entries). zxcvbn's internal dictionary
  covers hundreds of thousands of additional weak passwords.
- **No formal security audit** has been performed on this application.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | HTML5, CSS3 (Vanilla), JavaScript ES2020 |
| Backend | Python 3.9+, Flask 3.0, Flask-CORS 4.0 |
| Analysis | zxcvbn 4.4, custom entropy & heuristics |
| Fonts | Inter v4 + JetBrains Mono v2.3 (locally hosted WOFF2) |
| Tests | pytest 8+ |

---

## License

MIT — free to use, modify, and distribute.
