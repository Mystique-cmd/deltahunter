#!/usr/bin/env python3
"""enumerate_site.py

Dynamic site enumerator (headless) that discovers endpoints and then
reuses todo_analyzer.py heuristics to rank likely state-changing actions.

This is intended for legitimate security testing / bug bounty workflow.

Usage:
  python3 enumerate_site.py --base https://example.com --max-pages 30

Notes:
- Dynamic rendering via Playwright so JS-driven navigation/XHR is captured.
- Uses same-origin crawl by default.
- Captures network request/response metadata and converts it into the
  "event" schema expected by todo_analyzer.py.

Security/ethics:
- Do not target systems without authorization.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
from dataclasses import asdict
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

# todo_analyzer provides the scoring + workflow grouping logic.
import todo_analyzer


def _normalize_url(url: str) -> str:
    # Keep it simple: strip fragments; remove trailing slashes (except root)
    p = urlparse(url)
    if not p.scheme:
        return url
    path = p.path or "/"
    if path != "/" and path.endswith("/"):
        path = path[:-1]
    fragless = p._replace(fragment="").geturl()
    # If we changed only trailing slash, apply best-effort.
    if fragless != url:
        return urlparse(fragless)._replace(path=path).geturl()
    return fragless


def _same_origin(a: str, b: str) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    return (
        pa.scheme.lower() == pb.scheme.lower()
        and pa.netloc.lower() == pb.netloc.lower()
    )


async def _crawl(
    base_url: str,
    max_pages: int,
    max_depth: int,
    wait_ms: int,
    headless: bool,
    allow_cross_origin: bool,
    rate_limit_delay: float,
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Returns (events, visited_urls)."""

    try:
        from playwright.async_api import async_playwright
    except Exception as e:
        raise SystemExit(
            "Playwright is required. Install with: pip install playwright && playwright install"
        ) from e

    base_url = _normalize_url(base_url)

    base_origin = f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}"

    visited: Set[str] = set()
    queued: List[Tuple[str, int]] = [(base_url, 0)]
    events: List[Dict[str, Any]] = []
    discovered_order: List[str] = []

    # In-memory map request -> request body capture (best-effort)
    req_body_by_id: Dict[str, Any] = {}

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=headless)
        context = await browser.new_context()

        page = await context.new_page()

        async def handle_request(req):
            # Capture request details. We'll attach response later in handle_response.
            # NOTE: Avoid Playwright internal fields (e.g. req._impl_obj._requestId)
            # because they vary across Playwright versions.
            try:
                url = req.url
                method = req.method
                post_data = req.post_data
                ct = req.headers.get("content-type", "")


                key = f"{method} {url}"
                body_obj: Any = None
                if post_data:
                    # Try JSON parse
                    if "application/json" in ct.lower() or (post_data.strip().startswith("{") or post_data.strip().startswith("[")):
                        try:
                            body_obj = json.loads(post_data)
                        except Exception:
                            body_obj = post_data
                    else:
                        body_obj = post_data

                if body_obj is not None:
                    # append to queue for later association
                    req_body_by_id.setdefault(key, []).append(body_obj)
            except Exception:
                return

        async def handle_response(resp):
            try:
                req = resp.request
                method = req.method
                url = resp.url
                status = resp.status

                # Only consider same-origin by default for endpoint ranking.
                if not allow_cross_origin and not _same_origin(base_origin, url):
                    return

                path = urlparse(url).path
                key = f"{method} {url}"

                # Best-effort: response body can be large; limit size.
                body_text: Any = None
                try:
                    # Only attempt text for small-ish responses
                    # (Playwright doesn't give size until reading)
                    txt = await resp.text()
                    if txt is not None:
                        body_text = txt[:5000]
                except Exception:
                    body_text = None

                # Best-effort request body association
                request_body: Any = None
                if key in req_body_by_id and req_body_by_id[key]:
                    request_body = req_body_by_id[key].pop(0)

                events.append(
                    {
                        "method": method,
                        "url": url,
                        "path": path,
                        "request_body": request_body,
                        "response": {"status": status, "body": body_text},
                    }
                )
            except Exception:
                return

        context.on("request", lambda req: asyncio.create_task(handle_request(req)))
        context.on("response", lambda resp: asyncio.create_task(handle_response(resp)))

        async def extract_links_and_forms(current_url: str) -> List[str]:
            # Extract anchor hrefs + form actions + script src navigations.
            # Also extract values from fetch-like patterns is hard; network listeners already capture XHR.
            discovered: List[str] = []

            try:
                anchors = await page.eval_on_selector_all(
                    "a[href]", "els => els.map(e => e.getAttribute('href')).filter(Boolean)"
                )
            except Exception:
                anchors = []

            try:
                forms = await page.eval_on_selector_all(
                    "form[action]", "els => els.map(e => e.getAttribute('action')).filter(Boolean)"
                )
            except Exception:
                forms = []

            try:
                scripts = await page.eval_on_selector_all(
                    "script[src]", "els => els.map(e => e.getAttribute('src')).filter(Boolean)"
                )
            except Exception:
                scripts = []

            for h in anchors + forms + scripts:
                try:
                    u = urljoin(current_url, h)
                    u = _normalize_url(u)
                    if not allow_cross_origin:
                        if not _same_origin(base_origin, u):
                            continue
                    if u not in visited:
                        discovered.append(u)
                except Exception:
                    continue

            return discovered

        # Crawl loop
        while queued and len(visited) < max_pages:
            url, depth = queued.pop(0)
            if url in visited:
                continue
            if depth > max_depth:
                continue

            visited.add(url)
            discovered_order.append(url)

            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=30000)
            except Exception:
                # Still try to continue; dynamic pages may require longer.
                try:
                    await page.goto(url, wait_until="load", timeout=30000)
                except Exception:
                    continue

            # Let JS run / XHR fire
            try:
                await page.wait_for_timeout(wait_ms)
            except Exception:
                pass

            # Extract more URLs to crawl.
            if len(visited) < max_pages:
                try:
                    new_urls = await extract_links_and_forms(url)
                except Exception:
                    new_urls = []

                for nu in new_urls:
                    if nu not in visited:
                        queued.append((nu, depth + 1))

            if rate_limit_delay > 0:
                try:
                    await page.wait_for_timeout(int(rate_limit_delay * 1000))
                except Exception:
                    pass

        await context.close()
        await browser.close()

    return events, discovered_order


def main() -> None:
    ap = argparse.ArgumentParser(description="Dynamically enumerate a website and rank state-changing endpoints")
    ap.add_argument("--base", required=True, help="Base URL to start crawling from")
    ap.add_argument("--max-pages", type=int, default=30)
    ap.add_argument("--max-depth", type=int, default=3)
    ap.add_argument("--wait-ms", type=int, default=1200, help="Wait after each navigation for JS/XHR to fire")
    ap.add_argument("--headless", action="store_true", default=False, help="Run headless (default: headed)")
    ap.add_argument("--cross-origin", action="store_true", default=False, help="Allow crawling outside the base origin")
    ap.add_argument("--rate-limit-delay", type=float, default=0.0, help="Extra delay (seconds) between page navigations")
    ap.add_argument("--top", type=int, default=30, help="Max candidates to output")
    ap.add_argument("--output", "-o", help="Path to save the output file")
    ap.add_argument("--format", "-f", choices=["text", "json", "csv"], help="Output format (default: auto-detect from output extension, or text if printing to console)")

    args = ap.parse_args()

    base = args.base

    # Run crawler
    events, visited = asyncio.run(
        _crawl(
            base_url=base,
            max_pages=args.max_pages,
            max_depth=args.max_depth,
            wait_ms=args.wait_ms,
            headless=args.headless,
            allow_cross_origin=args.cross_origin,
            rate_limit_delay=args.rate_limit_delay,
        )
    )

    # Reuse todo_analyzer scoring
    candidates: List[todo_analyzer.CandidateEndpoint] = []
    for idx, e in enumerate(events):
        try:
            c = todo_analyzer.score_event(e, idx)
            candidates.append(c)
        except Exception:
            continue

    filtered = [c for c in candidates if c.state_changing and c.confidence >= 0.45]
    filtered.sort(key=lambda x: (-x.confidence, x.raw_event_index))

    # Determine format
    fmt = args.format
    if not fmt and args.output:
        ext = os.path.splitext(args.output)[1].lower()
        if ext == ".json":
            fmt = "json"
        elif ext == ".csv":
            fmt = "csv"
        else:
            fmt = "text"
    elif not fmt:
        fmt = "text"

    # Generate output
    if fmt == "json":
        report_content = todo_analyzer.generate_json_report(filtered, args.top, visited)
    elif fmt == "csv":
        report_content = todo_analyzer.generate_csv_report(filtered, args.top)
    else:
        report_content = todo_analyzer.generate_text_report(filtered, args.top, visited)

    # Export to file if requested
    if args.output:
        out_dir = os.path.dirname(args.output)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report_content)
            if not report_content.endswith("\n"):
                f.write("\n")
        print(todo_analyzer.generate_text_report(filtered, args.top, visited))
    else:
        print(report_content)


if __name__ == "__main__":
    main()

