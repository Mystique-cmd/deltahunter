#!/usr/bin/env python3
"""todo_analyzer.py

Prototype: State-changing endpoint analyzer for bug bounty hunting.

Input: JSON log(s) captured via proxy/crawler.

This script classifies HTTP requests/responses as likely state-changing and
outputs candidate endpoints + workflow groupings useful for race-condition
testing.

Log schema (flexible): The parser supports either:
- A JSON array of events
- Or a JSON object with key "events" containing that array

Each event may contain fields like:
- method: "POST" / "GET" / ...
- path: "/redeem-coupon" (or url)
- url: full URL
- request_body / body: JSON or string
- response: { status: 200, body: "..." }
  OR response_status / status

Because logs vary widely, the detection logic is defensive and uses heuristics.
"""

from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import dataclass, asdict
from typing import Any, Dict, Iterable, List, Optional, Tuple

# Exported for reuse by enumerate_site.py
__all__ = [
    "CandidateEndpoint",
    "classify_by_method",
    "detect_payload",
    "detect_path_keywords",
    "detect_response_change",
    "score_event",
    "group_workflows",
    "format_candidate",
]
from urllib.parse import urlparse


STATE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

PATH_KEYWORDS = [
    r"\bupdate\b",
    r"\bcreate\b",
    r"\bdelete\b",
    r"\bredeem\b",
    r"\bcheckout\b",
    r"\bapply\b",
    r"\bconfirm\b",
]

# Request body fields / value indicators to search for.
PAYLOAD_FIELD_HINTS = [
    r"\bamount\b",
    r"\bbalance\b",
    r"\bcoupon\b",
    r"\buser[_-]?id\b",
    r"\buser[_-]?ids\b",
    r"\binventory\b",
    r"\bstock\b",
    r"\bincrease\b",
    r"\bdecrease\b",
    r"\bquantity\b",
    r"\bredemption\b",
    r"\bredeem\b",
]

# Response indicators (heuristics).
RESPONSE_SIGNAL_HINTS = [
    r"new[_\- ]?id",
    r"resource[_\- ]?id",
    r"created",
    r"deleted",
    r"updated",
    r"counter",
    r"increment",
    r"decrement",
    r"status",
    r"balance",
    r"inventory",
    r"remaining",
    r"consumed",
    r"coupon",
]


@dataclass
class CandidateEndpoint:
    method: str
    path: str
    url: Optional[str]
    state_changing: bool
    confidence: float
    reasons: List[str]
    raw_event_index: int

    # Workflow-related fields
    workflow_key: Optional[str] = None
    workflow_step: Optional[str] = None


def _extract_path(event: Dict[str, Any]) -> Tuple[str, Optional[str]]:
    # Prefer explicit path
    if isinstance(event.get("path"), str) and event["path"].strip():
        return event["path"], event.get("url")

    # Fallback to URL
    url = event.get("url")
    if isinstance(url, str) and url.strip():
        try:
            parsed = urlparse(url)
            return parsed.path or url, url
        except Exception:
            return url, url

    # Last resort
    target = event.get("target")
    if isinstance(target, str) and target.strip():
        return target, event.get("url")

    return "", event.get("url")


def _normalize_method(event: Dict[str, Any]) -> str:
    m = event.get("method")
    if not isinstance(m, str):
        return ""
    return m.strip().upper()


def _stringify_body(body: Any) -> str:
    if body is None:
        return ""
    if isinstance(body, (dict, list)):
        try:
            return json.dumps(body, separators=(",", ":"), ensure_ascii=False)
        except Exception:
            return str(body)
    if isinstance(body, (str, bytes)):
        if isinstance(body, bytes):
            try:
                body = body.decode("utf-8", errors="replace")
            except Exception:
                body = repr(body)
        return body
    return str(body)


def _extract_request_body(event: Dict[str, Any]) -> Any:
    # common fields
    for key in ("request_body", "body", "requestBody", "request", "payload"):
        if key in event:
            return event.get(key)
    return None


def _extract_response_body(event: Dict[str, Any]) -> Any:
    resp = event.get("response")
    if isinstance(resp, dict):
        return resp.get("body") or resp.get("data")
    for key in ("response_body", "responseBody", "responseBody", "resp_body", "body_response"):
        if key in event:
            return event.get(key)
    return None


def _extract_response_status(event: Dict[str, Any]) -> Optional[int]:
    if isinstance(event.get("response"), dict):
        s = event["response"].get("status")
        if isinstance(s, int):
            return s
        if isinstance(s, str) and s.isdigit():
            return int(s)

    for key in ("response_status", "status", "status_code"):
        v = event.get(key)
        if isinstance(v, int):
            return v
        if isinstance(v, str) and v.isdigit():
            return int(v)
    return None


def classify_by_method(method: str) -> Tuple[bool, List[str], float]:
    reasons: List[str] = []
    if method in STATE_METHODS:
        reasons.append(f"method={method} is in POST/PUT/PATCH/DELETE")
        return True, reasons, 0.35
    if method:
        reasons.append(f"method={method} is not a typical state-changing verb")
    return False, reasons, 0.0


def detect_payload(event: Dict[str, Any]) -> Tuple[bool, List[str], float]:
    body = _extract_request_body(event)
    s = _stringify_body(body).lower()
    if not s.strip():
        return False, [], 0.0

    hit_fields: List[str] = []
    for pat in PAYLOAD_FIELD_HINTS:
        if re.search(pat, s, flags=re.IGNORECASE):
            hit_fields.append(pat)

    if not hit_fields:
        return False, [], 0.0

    # Ensure we don't match too broadly on generic words by requiring at least 1 field match.
    reasons = [
        "non-empty request body contains stateful fields (heuristic): " + ", ".join(hit_fields[:6])
    ]
    return True, reasons, 0.35


def detect_path_keywords(path: str) -> Tuple[bool, List[str], float]:
    if not path:
        return False, [], 0.0
    reasons: List[str] = []
    p = path.lower()
    hits = [kw for kw in PATH_KEYWORDS if re.search(kw, p, flags=re.IGNORECASE)]
    if hits:
        reasons.append("path keyword match: " + ", ".join(hits))
        return True, reasons, 0.25
    return False, [], 0.0


def detect_response_change(event: Dict[str, Any]) -> Tuple[bool, List[str], float]:
    resp_body = _extract_response_body(event)
    s = _stringify_body(resp_body).lower()
    status = _extract_response_status(event)

    reasons: List[str] = []
    if status is not None:
        # Avoid treating errors as state-change confirmation.
        if 200 <= status < 300:
            reasons.append(f"response status {status} indicates success")
        elif 400 <= status:
            # errors likely no state change
            return False, [f"response status {status} suggests failure; skipping response-change inference"], 0.0

    if not s.strip():
        return False, [], 0.0

    hits: List[str] = []
    for pat in RESPONSE_SIGNAL_HINTS:
        if re.search(pat, s, flags=re.IGNORECASE):
            hits.append(pat)

    if hits:
        reasons.append("response body suggests state change (heuristic): " + ", ".join(hits[:8]))
        return True, reasons, 0.30

    # Extra heuristic: presence of typical created/updated keys
    if re.search(r"\b(id|uuid)\b", s) and re.search(r"\b(created|updated|deleted)\b", s):
        reasons.append("response contains ids + created/updated/deleted tokens")
        return True, reasons, 0.25

    return False, [], 0.0


def score_event(event: Dict[str, Any], idx: int) -> CandidateEndpoint:
    method = _normalize_method(event)
    path, url = _extract_path(event)

    reasons: List[str] = []
    confidence = 0.0

    m_hit, m_reasons, m_score = classify_by_method(method)
    confidence += m_score
    reasons += m_reasons

    p_hit, p_reasons, p_score = detect_path_keywords(path)
    confidence += p_score
    reasons += p_reasons

    payload_hit, payload_reasons, payload_score = detect_payload(event)
    confidence += payload_score
    reasons += payload_reasons

    resp_hit, resp_reasons, resp_score = detect_response_change(event)
    confidence += resp_score
    reasons += resp_reasons

    # Decide state-changing: require method OR payload OR path keyword AND some response signal.
    # For race-condition candidates, response signal is particularly valuable.
    state_changing = False
    if (m_hit or p_hit or payload_hit) and (resp_hit or any("response status" in r for r in reasons)):
        state_changing = True

    # Bound confidence for readability.
    confidence = min(confidence, 1.0)

    return CandidateEndpoint(
        method=method,
        path=path,
        url=url,
        state_changing=state_changing,
        confidence=confidence,
        reasons=reasons,
        raw_event_index=idx,
    )


def group_workflows(candidates: List[CandidateEndpoint]) -> Dict[str, List[CandidateEndpoint]]:
    """Group into likely multi-step workflows.

    Heuristic workflow keys:
    - validate -> confirm -> redeem
    - add -> checkout -> confirm
    - create -> confirm

    We infer steps based on path keywords.
    """

    workflow_map: Dict[str, List[CandidateEndpoint]] = {}

    for c in candidates:
        p = (c.path or "").lower()
        key = None
        step = None

        # Validate/confirm/redeem workflow
        if any(w in p for w in ("validate", "check")):
            key = "validate→confirm→redeem"
            step = "validate"
        elif any(w in p for w in ("confirm", "approval", "finalize")):
            # Could be confirm for several flows; keep generic key.
            key = "validate→confirm→redeem"
            step = "confirm"
        elif any(w in p for w in ("redeem", "coupon")):
            key = "validate→confirm→redeem"
            step = "redeem"

        # Checkout/inventory flows
        if key is None and ("checkout" in p or "cart" in p):
            key = "checkout→inventory_update"
            step = "checkout"
        if key is None and any(w in p for w in ("inventory", "stock", "order")):
            key = "checkout→inventory_update"
            step = "inventory_update"

        # Generic create/delete
        if key is None and any(w in p for w in ("create", "register", "signup", "add")):
            key = "create_or_register"
            step = "create"
        if key is None and any(w in p for w in ("delete", "remove")):
            key = "delete_or_remove"
            step = "delete"

        # If still none, group as unassigned workflow.
        if key is None:
            key = "unassigned"
            step = "unknown"

        c.workflow_key = key
        c.workflow_step = step
        workflow_map.setdefault(key, []).append(c)

    # Sort by confidence descending within each workflow for prioritization.
    for k in list(workflow_map.keys()):
        workflow_map[k].sort(key=lambda x: (-x.confidence, x.raw_event_index))

    return workflow_map


def parse_input(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if isinstance(data.get("events"), list):
            return data["events"]
        # common alternative keys
        for k in ("logs", "requests", "traffic"):
            if isinstance(data.get(k), list):
                return data[k]
    raise ValueError("Unsupported JSON log format. Expected array or {events:[...]}.")


def format_candidate(c: CandidateEndpoint) -> str:
    sig = f"{c.method} {c.path}".strip()
    if c.url:
        sig += f" (url={c.url})"
    conf = f"confidence={c.confidence:.2f}"
    reasons = "; ".join(reasons_cleanup(c.reasons))
    return f"{sig} → {'LIKELY STATE-CHANGING' if c.state_changing else 'likely read'} [{conf}]\n  Reasons: {reasons}"


def reasons_cleanup(reasons: List[str]) -> List[str]:
    out = []
    for r in reasons:
        r = r.strip()
        if not r:
            continue
        out.append(r)
    # de-dup while preserving order
    seen = set()
    dedup = []
    for r in out:
        if r not in seen:
            dedup.append(r)
            seen.add(r)
    return dedup


def main() -> None:
    ap = argparse.ArgumentParser(description="State-changing endpoint analyzer")
    ap.add_argument("--input", required=True, help="Path to JSON traffic log")
    ap.add_argument("--top", type=int, default=30, help="Max candidates to output")
    args = ap.parse_args()

    events = parse_input(args.input)

    candidates: List[CandidateEndpoint] = []
    for idx, e in enumerate(events):
        try:
            c = score_event(e, idx)
            candidates.append(c)
        except Exception:
            # Skip malformed events
            continue

    # Keep only state-changing candidates with minimal threshold.
    filtered = [c for c in candidates if c.state_changing and c.confidence >= 0.45]
    filtered.sort(key=lambda x: (-x.confidence, x.raw_event_index))

    # Output candidate list
    print("=== Candidate state-changing endpoints (race-condition candidates) ===")
    for c in filtered[: args.top]:
        print(format_candidate(c))
        print()

    # Workflow grouping
    workflow_map = group_workflows(filtered)
    print("=== Workflow grouping ===")
    for wf_key, wf_candidates in workflow_map.items():
        if not wf_candidates:
            continue
        # Highlight only workflows with at least 2 distinct steps
        steps = {c.workflow_step for c in wf_candidates}
        if wf_key == "unassigned" and len(wf_candidates) < 2:
            continue

        print(f"\n[{wf_key}] ({len(wf_candidates)} candidates; steps={sorted(steps)})")
        for c in wf_candidates[:10]:
            print(f"  - {c.method} {c.path} (step={c.workflow_step}, confidence={c.confidence:.2f})")


if __name__ == "__main__":
    main()


