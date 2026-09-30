"""Best-effort screenshot of the live sandboxed app, captured with a
headless browser the moment the container is confirmed ready (see
sandbox.py's _wait_until_ready).

This is purely a "here's what we actually tested" preview for the
dashboard -- it never influences a finding, a score, or anything the risk
engine decides, and a failure here must never break the real probe. Every
call is wrapped so it can only ever return the screenshot or None, never
raise.
"""

from __future__ import annotations

_TIMEOUT_MS = 8000


def take_screenshot(url: str) -> bytes | None:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return None

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            try:
                page = browser.new_page(viewport={"width": 1280, "height": 800})
                page.goto(url, timeout=_TIMEOUT_MS, wait_until="load")
                return page.screenshot(type="png")
            finally:
                browser.close()
    except Exception:
        return None
