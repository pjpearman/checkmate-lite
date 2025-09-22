"""Utilities for scraping STIG download metadata from public.cyber.mil."""
from __future__ import annotations

import json
import logging
import os
import re
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import urljoin, urlsplit

logger = logging.getLogger(__name__)

PUBLIC_CYBER_MIL_URL = "https://public.cyber.mil/stigs/downloads/"

# Match absolute and protocol-relative URLs that end with .zip
ZIP_URL_PATTERN = re.compile(r"(?:(?:https?:)?//|/)[^\s\"'<>]+?\.zip", re.IGNORECASE)


def _iter_zip_candidates(data: object) -> Iterable[str]:
    """Recursively pull any string that resembles a .zip URL from a JSON structure."""
    if isinstance(data, dict):
        for value in data.values():
            yield from _iter_zip_candidates(value)
    elif isinstance(data, list):
        for item in data:
            yield from _iter_zip_candidates(item)
    elif isinstance(data, str):
        text = data.strip()
        if not text:
            return
        if text.lower().endswith(".zip"):
            yield text
        for match in ZIP_URL_PATTERN.finditer(text):
            yield match.group(0)


def _normalize_url(raw_url: str, base_url: str) -> Optional[str]:
    """Normalize relative and protocol-relative URLs to absolute HTTPS URLs."""
    if not raw_url:
        return None
    url = raw_url.strip()
    if not url or url.startswith("data:"):
        return None
    if url.startswith("//"):
        url = f"https:{url}"
    elif url.startswith("/"):
        url = urljoin(base_url, url)
    elif not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = urljoin(base_url, url)
    return url


def _categorize(file_name: str) -> str:
    """Best-effort classification of STIG artifact type based on filename."""
    lower_name = file_name.lower()
    if "ckl" in lower_name or "checklist" in lower_name:
        return "checklist"
    if lower_name.endswith(".ckl.zip"):
        return "checklist"
    if "benchmark" in lower_name:
        return "benchmark"
    if lower_name.endswith(".xml.zip") or "_xccdf" in lower_name:
        return "benchmark"
    if lower_name.endswith("_stig.zip") or "_stig_" in lower_name:
        return "benchmark"
    return "unknown"


def _filter_by_mode(entries: Iterable[Dict[str, str]], mode: str) -> List[Dict[str, str]]:
    filtered: List[Dict[str, str]] = []
    for entry in entries:
        category = _categorize(entry["FileName"])
        if mode == "all":
            filtered.append(entry)
        elif mode == "benchmark" and category in {"benchmark", "unknown"}:
            filtered.append(entry)
        elif mode == "checklist" and category in {"checklist", "unknown"}:
            filtered.append(entry)
    return filtered


def scrape_stigs(mode: str = "all", headful: bool = False, base_url: str = PUBLIC_CYBER_MIL_URL) -> List[Dict[str, str]]:
    """Scrape STIG download metadata from public.cyber.mil using Playwright.

    Args:
        mode: Desired artifact type ("benchmark", "checklist", or "all").
        headful: If True, launch the browser in headful mode for debugging.
        base_url: Base URL for the STIG downloads catalog.

    Returns:
        A list of dictionaries with at minimum FileName and URL keys.
    """
    normalized_mode = (mode or "all").lower()
    if normalized_mode not in {"benchmark", "checklist", "all"}:
        raise ValueError(f"Unsupported mode '{mode}'. Expected benchmark, checklist, or all.")

    try:
        from playwright.sync_api import (  # type: ignore
            TimeoutError as PlaywrightTimeoutError,
            sync_playwright,
        )
    except ImportError as exc:  # pragma: no cover - dependency missing
        raise RuntimeError(
            "Playwright is required for scraping STIG metadata. Install it with 'pip install playwright' "
            "and run 'playwright install chromium'."
        ) from exc

    entries_by_url: Dict[str, Dict[str, str]] = {}
    errors: List[Dict[str, str]] = []

    def record_candidate(raw_url: str, source: str) -> None:
        url = _normalize_url(raw_url, base_url)
        if not url or not url.lower().endswith(".zip"):
            return
        file_name = os.path.basename(urlsplit(url).path)
        if not file_name:
            return
        if url not in entries_by_url:
            logger.debug("Captured %s via %s", file_name, source)
            entries_by_url[url] = {"FileName": file_name, "URL": url}

    def capture_xhr_response(response) -> None:
        try:
            resource_type = response.request.resource_type
        except Exception:
            return
        if resource_type not in {"xhr", "fetch"}:
            return
        content_type = response.headers.get("content-type", "").lower()
        if "json" not in content_type:
            return
        try:
            payload = response.json()
        except Exception:
            try:
                payload = json.loads(response.text())
            except Exception:
                logger.debug("Skipping non-JSON XHR response: %s", response.url)
                return
        for candidate in _iter_zip_candidates(payload):
            record_candidate(candidate, "xhr")

    def crawl_dom_for_links(page) -> None:
        # Attempt to walk through pagination or load-more interactions to surface links.
        max_iterations = 25
        for _ in range(max_iterations):
            anchors: List[str] = page.eval_on_selector_all(
                "a[href$='.zip']",
                "elements => elements.map(el => el.href)",
            )
            for anchor in anchors:
                record_candidate(anchor, "dom")

            # Scroll to the bottom to trigger lazy loading if applicable.
            page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            page.wait_for_timeout(1000)

            clicked = False
            for selector in (
                "button:has-text(\"Load More\")",
                "a:has-text(\"Load More\")",
                "button:has-text(\"Next\")",
                "a:has-text(\"Next\")",
                "a[rel='next']",
            ):
                locator = page.locator(selector).first
                try:
                    if not locator.count():
                        continue
                    if not locator.is_enabled():
                        continue
                    if not locator.is_visible():
                        continue
                    locator.click(timeout=2000)
                    page.wait_for_load_state("networkidle")
                    page.wait_for_timeout(1000)
                    clicked = True
                    break
                except PlaywrightTimeoutError:
                    continue
                except Exception:
                    continue
            if not clicked:
                break

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=not headful)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        page.on("response", capture_xhr_response)

        logger.info("Navigating to %s", base_url)
        try:
            page.goto(base_url, wait_until="networkidle", timeout=90000)
        except PlaywrightTimeoutError as exc:
            logger.error("Timeout loading %s: %s", base_url, exc)
            errors.append({"Error": f"Timeout loading {base_url}: {exc}"})
        except Exception as exc:  # pragma: no cover - network failure
            logger.error("Failed to load %s: %s", base_url, exc)
            errors.append({"Error": f"Failed to load {base_url}: {exc}"})
        else:
            page.wait_for_timeout(2000)
            if not entries_by_url:
                logger.info("No XHR JSON links detected; falling back to DOM traversal")
                crawl_dom_for_links(page)
        finally:
            try:
                context.close()
            except Exception:
                logger.debug("Error closing Playwright context", exc_info=True)
            try:
                browser.close()
            except Exception:
                logger.debug("Error closing Playwright browser", exc_info=True)

    entries: List[Dict[str, str]] = sorted(entries_by_url.values(), key=lambda item: item["FileName"].lower())
    entries = _filter_by_mode(entries, normalized_mode)
    if errors and not entries:
        raise RuntimeError(errors[0]["Error"])
    return entries


def scrape_stig_file_links(
    mode: str = "all",
    headful: bool = False,
    base_url: str = PUBLIC_CYBER_MIL_URL,
) -> List[Tuple[str, str]]:
    """Return (file_name, url) tuples from :func:`scrape_stigs` results."""

    items = scrape_stigs(mode=mode, headful=headful, base_url=base_url)
    file_links: List[Tuple[str, str]] = []
    for item in items:
        file_name = item.get("FileName")
        url = item.get("URL")
        if file_name and url:
            file_links.append((file_name, url))
    return file_links


__all__ = ["scrape_stigs", "scrape_stig_file_links"]
