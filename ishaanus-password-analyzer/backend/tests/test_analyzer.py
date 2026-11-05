# -*- coding: utf-8 -*-
"""
test_analyzer.py – Automated tests for Ishaanus backend.

Run from the backend/ directory:
    py -m pytest tests/ -v

Coverage report:
    py -m pytest tests/ -v --tb=short --cov=analyzer --cov-report=term-missing

Tests cover:
  1.  Empty password
  2.  Weak / common password  (123456)
  3.  Single-category password  (all lowercase)
  4.  Single-category password  (digits only)
  5.  Fair-strength password
  6.  Strong / complex password
  7.  API: password > 1000 chars  (should return 400)
  8.  API: non-string password    (should return 400)
  9.  API: missing JSON body      (should return 400)
  10. Entropy invariant: observed <= theoretical
  11. All four crack-time scenario keys present
  12. guesses_log10 always present (even for empty password)
  13. Common-password score cap (score must be <= 1)
  14. Very long valid password (1000 chars exactly – edge case, should succeed)
"""

import sys
import os
import pytest

# ── Ensure the backend/ directory is on sys.path so analyzer can be imported
# when pytest is invoked from either the project root or the backend/ directory.
_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

from analyzer import (
    analyze_password,
    calculate_theoretical_entropy,
    calculate_observed_entropy,
    check_character_categories,
    is_common_password,
)
import app as flask_app


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def client():
    """Return a Flask test client with testing mode enabled."""
    flask_app.app.config["TESTING"] = True
    with flask_app.app.test_client() as c:
        yield c


def post_analyze(client, payload):
    """Helper: POST JSON to /api/analyze and return the response."""
    return client.post(
        "/api/analyze",
        json=payload,
        content_type="application/json",
    )


# ── Helper: assert all required response keys are present ────────────────────

REQUIRED_KEYS = {
    "score", "label", "entropy", "theoretical_entropy", "observed_entropy",
    "length", "categories", "crack_times", "is_common", "recommendations",
    "guesses_log10",
}

REQUIRED_CRACK_KEYS = {
    "online_throttling",
    "online_no_throttling",
    "offline_slow_hashing",
    "offline_fast_hashing",
}

REQUIRED_CATEGORY_KEYS = {
    "has_uppercase", "has_lowercase", "has_digits", "has_symbols",
    "uppercase_count", "lowercase_count", "digit_count", "symbol_count",
}


def assert_valid_structure(data: dict) -> None:
    """Assert that an analysis response contains all required keys."""
    missing = REQUIRED_KEYS - data.keys()
    assert not missing, f"Response missing keys: {missing}"
    assert REQUIRED_CRACK_KEYS == data["crack_times"].keys(), (
        f"crack_times keys mismatch: {data['crack_times'].keys()}"
    )
    assert REQUIRED_CATEGORY_KEYS.issubset(data["categories"].keys()), (
        "categories keys mismatch"
    )


# ═════════════════════════════════════════════════════════════════════════════
#  Test 1 – Empty password
# ═════════════════════════════════════════════════════════════════════════════

class TestEmptyPassword:
    def test_analyze_returns_valid_structure(self):
        data = analyze_password("")
        assert_valid_structure(data)

    def test_score_is_zero(self):
        assert analyze_password("")["score"] == 0

    def test_length_is_zero(self):
        assert analyze_password("")["length"] == 0

    def test_entropy_is_zero(self):
        data = analyze_password("")
        assert data["entropy"] == 0.0
        assert data["theoretical_entropy"] == 0.0
        assert data["observed_entropy"] == 0.0

    def test_guesses_log10_present(self):
        # Must be present even for empty input (regression guard)
        data = analyze_password("")
        assert "guesses_log10" in data
        assert isinstance(data["guesses_log10"], (int, float))

    def test_crack_times_all_na(self):
        crack = analyze_password("")["crack_times"]
        for key in REQUIRED_CRACK_KEYS:
            assert crack[key] == "N/A", f"Expected N/A for {key}, got {crack[key]}"

    def test_via_api(self, client):
        resp = post_analyze(client, {"password": ""})
        assert resp.status_code == 200
        data = resp.get_json()
        assert_valid_structure(data)
        assert data["length"] == 0


# ═════════════════════════════════════════════════════════════════════════════
#  Test 2 – Common / weak password
# ═════════════════════════════════════════════════════════════════════════════

class TestCommonPassword:
    PW = "123456"

    def test_is_common_flag(self):
        assert is_common_password(self.PW) is True

    def test_score_capped_at_one(self):
        """Common passwords must have score <= 1 regardless of zxcvbn result."""
        data = analyze_password(self.PW)
        assert data["score"] <= 1, f"Expected score <= 1, got {data['score']}"

    def test_is_common_in_response(self):
        assert analyze_password(self.PW)["is_common"] is True

    def test_has_recommendations(self):
        recs = analyze_password(self.PW)["recommendations"]
        assert len(recs) > 0

    def test_all_crack_times_present(self):
        crack = analyze_password(self.PW)["crack_times"]
        for key in REQUIRED_CRACK_KEYS:
            assert crack[key] != "N/A", f"crack_times.{key} should not be N/A"

    def test_via_api(self, client):
        resp = post_analyze(client, {"password": self.PW})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["is_common"] is True
        assert data["score"] <= 1


# ═════════════════════════════════════════════════════════════════════════════
#  Test 3 – Single-category: all lowercase
# ═════════════════════════════════════════════════════════════════════════════

class TestAllLowercase:
    PW = "abcdefghij"

    def test_category_flags(self):
        cats = check_character_categories(self.PW)
        assert cats["has_lowercase"] is True
        assert cats["has_uppercase"] is False
        assert cats["has_digits"] is False
        assert cats["has_symbols"] is False

    def test_theoretical_entropy_uses_26_pool(self):
        # charset_size should be 26 → theoretical = log2(26) × 10 ≈ 47.0
        te = calculate_theoretical_entropy(self.PW)
        expected = pytest.approx(47.0, abs=1.0)
        assert te == expected, f"Expected ~47 bits, got {te}"

    def test_recommendations_suggest_uppercase(self):
        recs = analyze_password(self.PW)["recommendations"]
        assert any("uppercase" in r.lower() or "A-Z" in r for r in recs)


# ═════════════════════════════════════════════════════════════════════════════
#  Test 4 – Single-category: digits only
# ═════════════════════════════════════════════════════════════════════════════

class TestDigitsOnly:
    PW = "1234567890"

    def test_has_digits_true(self):
        cats = check_character_categories(self.PW)
        assert cats["has_digits"] is True
        assert cats["has_uppercase"] is False
        assert cats["has_lowercase"] is False
        assert cats["has_symbols"] is False

    def test_theoretical_entropy_uses_10_pool(self):
        # charset_size = 10 → theoretical = log2(10) × 10 ≈ 33.2
        te = calculate_theoretical_entropy(self.PW)
        expected = pytest.approx(33.2, abs=1.0)
        assert te == expected, f"Expected ~33.2 bits, got {te}"


# ═════════════════════════════════════════════════════════════════════════════
#  Test 5 – Fair-strength password
# ═════════════════════════════════════════════════════════════════════════════

class TestFairPassword:
    PW = "BlueSky99"   # mixed case + digit, no symbol, 9 chars

    def test_score_at_least_one(self):
        data = analyze_password(self.PW)
        assert data["score"] >= 1

    def test_not_common(self):
        assert analyze_password(self.PW)["is_common"] is False

    def test_has_uppercase_and_digit(self):
        cats = analyze_password(self.PW)["categories"]
        assert cats["has_uppercase"] is True
        assert cats["has_digits"] is True


# ═════════════════════════════════════════════════════════════════════════════
#  Test 6 – Strong / complex password
# ═════════════════════════════════════════════════════════════════════════════

class TestComplexPassword:
    PW = "C0mpl3x!P@ss#99XY"  # 18 chars, all 4 categories

    def test_score_is_four(self):
        """A genuinely complex, long password should score 4 (Very Strong)."""
        data = analyze_password(self.PW)
        assert data["score"] == 4, f"Expected score 4, got {data['score']}"

    def test_all_categories_present(self):
        cats = analyze_password(self.PW)["categories"]
        assert cats["has_uppercase"] is True
        assert cats["has_lowercase"] is True
        assert cats["has_digits"]    is True
        assert cats["has_symbols"]   is True

    def test_observed_entropy_above_threshold(self):
        """A strong 18-char all-category password should have >= 50 observed bits."""
        oe = analyze_password(self.PW)["observed_entropy"]
        assert oe >= 50, f"Expected >= 50 observed bits, got {oe}"

    def test_not_common(self):
        assert analyze_password(self.PW)["is_common"] is False

    def test_crack_times_all_present(self):
        crack = analyze_password(self.PW)["crack_times"]
        for key in REQUIRED_CRACK_KEYS:
            assert crack[key] != "N/A", f"crack_times.{key} should not be N/A"


# ═════════════════════════════════════════════════════════════════════════════
#  Test 7 – API: password longer than 1000 chars → 400
# ═════════════════════════════════════════════════════════════════════════════

class TestOverlongPassword:
    def test_returns_400(self, client):
        resp = post_analyze(client, {"password": "a" * 1001})
        assert resp.status_code == 400

    def test_error_message_in_response(self, client):
        resp = post_analyze(client, {"password": "a" * 1001})
        data = resp.get_json()
        assert "error" in data

    def test_exactly_1000_chars_succeeds(self, client):
        """The boundary: exactly 1000 characters must be accepted."""
        resp = post_analyze(client, {"password": "aB1!" * 250})  # 1000 chars
        assert resp.status_code == 200


# ═════════════════════════════════════════════════════════════════════════════
#  Test 8 – API: non-string password → 400
# ═════════════════════════════════════════════════════════════════════════════

class TestNonStringPassword:
    def test_integer_returns_400(self, client):
        resp = post_analyze(client, {"password": 12345})
        assert resp.status_code == 400

    def test_null_returns_400_or_empty(self, client):
        # None is serialised as JSON null; we accept it as empty string
        # (the route treats missing key as ""), so either 200 or 400 is
        # acceptable as long as a JSON body is returned.
        resp = post_analyze(client, {"password": None})
        assert resp.status_code in (200, 400)
        assert resp.get_json() is not None

    def test_list_returns_400(self, client):
        resp = post_analyze(client, {"password": ["a", "b"]})
        assert resp.status_code == 400


# ═════════════════════════════════════════════════════════════════════════════
#  Test 9 – API: missing / malformed JSON body → 400
# ═════════════════════════════════════════════════════════════════════════════

class TestMalformedRequest:
    def test_no_body_returns_400(self, client):
        resp = client.post(
            "/api/analyze",
            data="not json",
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_missing_password_key_treated_as_empty(self, client):
        """A valid JSON object without the 'password' key is treated as empty."""
        resp = post_analyze(client, {})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["length"] == 0


# ═════════════════════════════════════════════════════════════════════════════
#  Test 10 – Entropy invariant: observed <= theoretical
# ═════════════════════════════════════════════════════════════════════════════

class TestEntropyInvariant:
    PASSWORDS = [
        "a",
        "aaaaaaa",           # all identical chars — observed should be 0
        "123456",
        "Password1!",
        "aAbBcCdDeEfF1234!@",
        "correct horse battery staple",
    ]

    @pytest.mark.parametrize("pw", PASSWORDS)
    def test_observed_le_theoretical(self, pw):
        te = calculate_theoretical_entropy(pw)
        oe = calculate_observed_entropy(pw)
        assert oe <= te + 0.01, (
            f"Password={pw!r}: observed ({oe}) > theoretical ({te})"
        )

    def test_all_identical_chars_observed_is_zero(self):
        """'aaaaaaa' has zero Shannon entropy per character."""
        oe = calculate_observed_entropy("aaaaaaa")
        assert oe == pytest.approx(0.0, abs=0.01), (
            f"Expected 0 observed entropy for all-identical chars, got {oe}"
        )

    def test_response_includes_both_fields(self):
        data = analyze_password("SomePassword1!")
        assert "theoretical_entropy" in data
        assert "observed_entropy" in data
        assert data["observed_entropy"] <= data["theoretical_entropy"] + 0.01


# ═════════════════════════════════════════════════════════════════════════════
#  Test 11 – All four crack-time keys present in every response
# ═════════════════════════════════════════════════════════════════════════════

class TestCrackTimeKeys:
    PASSWORDS = ["", "123456", "Password1!", "V3ryStr0ng!P@ssw0rd#2024"]

    @pytest.mark.parametrize("pw", PASSWORDS)
    def test_all_four_keys_present(self, pw):
        crack = analyze_password(pw)["crack_times"]
        assert REQUIRED_CRACK_KEYS == crack.keys(), (
            f"Missing or extra crack_time keys for password={pw!r}: {crack.keys()}"
        )


# ═════════════════════════════════════════════════════════════════════════════
#  Test 12 – guesses_log10 always present
# ═════════════════════════════════════════════════════════════════════════════

class TestGuessesLog10AlwaysPresent:
    PASSWORDS = ["", "abc", "123456", "StrongP@ss!99"]

    @pytest.mark.parametrize("pw", PASSWORDS)
    def test_present_and_numeric(self, pw):
        data = analyze_password(pw)
        assert "guesses_log10" in data, f"guesses_log10 missing for pw={pw!r}"
        assert isinstance(data["guesses_log10"], (int, float))


# ═════════════════════════════════════════════════════════════════════════════
#  Test 13 – Common password score cap
# ═════════════════════════════════════════════════════════════════════════════

class TestCommonPasswordScoreCap:
    COMMON = [
        "password", "123456", "qwerty", "admin", "letmein",
        "iloveyou", "monkey", "dragon",
    ]

    @pytest.mark.parametrize("pw", COMMON)
    def test_score_capped_at_one(self, pw):
        data = analyze_password(pw)
        assert data["score"] <= 1, (
            f"Common password {pw!r} has score {data['score']} (expected <= 1)"
        )
        assert data["is_common"] is True


# ═════════════════════════════════════════════════════════════════════════════
#  Test 14 – Exactly 1000-character password (boundary edge case)
# ═════════════════════════════════════════════════════════════════════════════

class TestBoundaryLengthPassword:
    def test_1000_chars_succeeds(self):
        pw = "aB1!" * 250   # exactly 1000 characters, all 4 categories
        data = analyze_password(pw)
        assert_valid_structure(data)
        assert data["length"] == 1000

    def test_1001_chars_raises_or_is_refused(self, client):
        resp = post_analyze(client, {"password": "a" * 1001})
        assert resp.status_code == 400
