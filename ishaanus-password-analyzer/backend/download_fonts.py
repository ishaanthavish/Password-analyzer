# -*- coding: utf-8 -*-
"""
download_fonts.py – Download locally hosted WOFF2 font files for Ishaanus.

Run from the project root or backend/ directory:
    py backend/download_fonts.py

Downloads:
  - Inter (variable font, all weights 300-900) from GitHub/rsms/inter
  - JetBrains Mono Regular, Medium, SemiBold from JetBrains GitHub releases

Output directory: frontend/fonts/

This script only needs to be run once.  After that, the fonts are served
locally and no network calls are made when the page is loaded.
"""

import os
import sys
import urllib.request
import urllib.error

# ── Resolve paths regardless of where the script is called from ──────────────
_SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_SCRIPT_DIR) if os.path.basename(_SCRIPT_DIR) == "backend" else _SCRIPT_DIR
_FONTS_DIR   = os.path.join(_PROJECT_ROOT, "frontend", "fonts")

# ── Font files to download ────────────────────────────────────────────────────
# Using stable, versioned release URLs from official GitHub repos.
FONTS = [
    {
        "filename": "inter-variable.woff2",
        # Inter v4.0 variable font (covers weights 100-900 in a single file)
        "url": "https://github.com/rsms/inter/raw/v4.0/docs/font-files/InterVariable.woff2",
        "description": "Inter Variable (all weights)",
    },
    {
        "filename": "jetbrains-mono-regular.woff2",
        "url": (
            "https://github.com/JetBrains/JetBrainsMono/raw/v2.304/"
            "fonts/webfonts/JetBrainsMono-Regular.woff2"
        ),
        "description": "JetBrains Mono Regular (400)",
    },
    {
        "filename": "jetbrains-mono-medium.woff2",
        "url": (
            "https://github.com/JetBrains/JetBrainsMono/raw/v2.304/"
            "fonts/webfonts/JetBrainsMono-Medium.woff2"
        ),
        "description": "JetBrains Mono Medium (500)",
    },
    {
        "filename": "jetbrains-mono-semibold.woff2",
        "url": (
            "https://github.com/JetBrains/JetBrainsMono/raw/v2.304/"
            "fonts/webfonts/JetBrainsMono-SemiBold.woff2"
        ),
        "description": "JetBrains Mono SemiBold (600)",
    },
]


def download_font(url: str, dest_path: str, description: str) -> bool:
    """Download a single font file.  Returns True on success, False on error."""
    filename = os.path.basename(dest_path)

    if os.path.exists(dest_path):
        size = os.path.getsize(dest_path)
        if size > 1000:          # sanity-check: a valid WOFF2 is at least 1 KB
            print(f"  [skip]  {filename}  ({size:,} bytes — already downloaded)")
            return True
        else:
            print(f"  [retry] {filename}  (existing file looks truncated, re-downloading)")

    print(f"  [fetch] {description}")
    print(f"          {url}")
    try:
        headers = {"User-Agent": "Ishaanus-font-downloader/1.0"}
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = resp.read()
        with open(dest_path, "wb") as f:
            f.write(data)
        print(f"  [ok]    {filename}  ({len(data):,} bytes)")
        return True
    except urllib.error.URLError as e:
        print(f"  [FAIL]  {filename}: {e}", file=sys.stderr)
        return False
    except OSError as e:
        print(f"  [FAIL]  {filename}: {e}", file=sys.stderr)
        return False


def main() -> int:
    print("=" * 60)
    print("  Ishaanus – Font Downloader")
    print(f"  Output: {_FONTS_DIR}")
    print("=" * 60)

    os.makedirs(_FONTS_DIR, exist_ok=True)

    results = []
    for font in FONTS:
        dest = os.path.join(_FONTS_DIR, font["filename"])
        ok   = download_font(font["url"], dest, font["description"])
        results.append((font["filename"], ok))

    print()
    failures = [f for f, ok in results if not ok]
    if failures:
        print(f"WARNING: {len(failures)} font(s) failed to download:")
        for f in failures:
            print(f"  - {f}")
        print()
        print("The UI will fall back to system fonts until these are resolved.")
        print("Check your internet connection and try again.")
        return 1

    print(f"All {len(results)} font files ready.")
    print("The app now serves fonts locally — no external calls on page load.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
