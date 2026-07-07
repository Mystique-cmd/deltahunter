# DeltaHunter

Small, heuristic Python tools for analyzing HTTP traffic and prioritizing **likely state-changing** endpoints for security testing workflows (e.g., race-condition / multi-step flow exploration).

This repository contains two scripts:

- **`todo_analyzer.py`**: Reads JSON HTTP event logs and ranks candidates using heuristic signals.
- **`enumerate_site.py`**: Crawls a site with Playwright, captures network traffic, then reuses the same heuristics to rank endpoints.

> ⚠️ Use only with explicit authorization against systems you are permitted to test. These tools are not a guarantee of correctness—results are best used for prioritization.

---

## What `todo_analyzer.py` does

`todo_analyzer.py` parses JSON “events” and scores each event for how likely it is to be **state-changing** based on:

- HTTP method (strong signals): `POST`, `PUT`, `PATCH`, `DELETE`
- Path keywords (examples): `update`, `create`, `delete`, `redeem`, `checkout`, `apply`, `confirm`
- Request body hints (examples): `amount`, `balance`, `coupon`, `user_id`, `inventory`, `stock`, `quantity`
- Response change indicators (examples): `created`, `updated`, `deleted`, `new_id`, `resource_id`, `increment`, `decrement`, `balance`, `inventory`

It then:

1. marks candidates as `state_changing == True`
2. applies a confidence filter: `confidence >= 0.45`
3. prints ranked candidates and groups them into likely workflows.

---

## How it works (inputs & schema)

The scripts are designed to be defensive: log formats vary, so keys are matched flexibly.

### Supported input for `todo_analyzer.py`

The input JSON can be either:

1) **A JSON array** of events

```json
[
  {
    "method": "POST",
    "url": "https://example.com/redeem",
    "body": {"coupon": "X"},
    "response": {"status": 200, "body": "created new_id"}
  }
]
```

2) **A JSON object** containing an `events` array

```json
{
  "events": [
    {
      "method": "POST",
      "path": "/redeem-coupon",
      "request_body": {"coupon": "X"},
      "response_status": 200,
      "response_body": {"body": "created"}
    }
  ]
}
```

### Flexible field names (common variants)

`todo_analyzer.py` tries multiple keys, such as:

- **Method**: `method`
- **Path**: `path` (preferred) or derived from `url`
- **Request body**: `request_body`, `body`, `requestBody`, `request`, `payload`
- **Response status**: `response.status` or `response_status`, `status`, `status_code`
- **Response body**: `response.body` or variants like `response_body` / `responseBody`

---

## Usage

### `todo_analyzer.py`

Basic:

```bash
python3 todo_analyzer.py --input /path/to/log.json
```

Limit output:

```bash
python3 todo_analyzer.py --input /path/to/log.json --top 30
```

CLI flags:

- `--input` (required): path to the JSON traffic log
- `--top` (default: `30`): max candidates to print

---

### Output (for `todo_analyzer.py`)

The script prints two main sections:

1. **Candidate state-changing endpoints**
   - Each entry shows: `METHOD PATH (url=...)`, confidence score, and heuristic reasons.

2. **Workflow grouping**
   - Candidates are grouped into heuristic workflow “keys” based on path keywords.
   - Example workflow keys used by the script include:
     - `validate→confirm→redeem`
     - `checkout→inventory_update`
     - `create_or_register`
     - `delete_or_remove`
     - `unassigned`

---

## Dynamic site enumeration with `enumerate_site.py`

`enumerate_site.py` crawls pages using Playwright (to capture JS-driven navigation/XHR), listens for network requests/responses, converts captured traffic into the event schema expected by `todo_analyzer.py`, and prints ranked candidates + workflow grouping.

### Requirements

- Python 3.x
- Playwright

Install Playwright:

```bash
pip install playwright
playwright install
```

### Run

```bash
python3 enumerate_site.py --base https://example.com --max-pages 30 --max-depth 3
```

CLI flags:

- `--base` (required): base URL to start crawling from
- `--max-pages` (default: `30`): upper bound on visited pages
- `--max-depth` (default: `3`): maximum crawl depth (relative to the starting page)
- `--wait-ms` (default: `1200`): wait time after navigation for JS/XHR to fire
- `--headless` (default: headed): run browser headlessly
- `--cross-origin` (default: same-origin only): allow crawling outside the base origin
- `--rate-limit-delay` (default: `0.0`): optional delay between navigations (seconds)
- `--top` (default: `30`): max ranked candidates to print

### Notes / limitations (enumeration)

- By default, it applies **same-origin only** filtering for endpoint ranking.
- Response body capture is best-effort and truncated to a maximum size (the script reads up to ~5000 characters).
- Request body association is also best-effort; mismatches can occur when requests/responses don’t pair cleanly in the log stream.

---

## Heuristics & limitations (important)

- This is **heuristic** scoring, not a ground-truth state-machine model.
- It helps prioritize endpoints for further manual verification.
- Log formats vary widely; extraction depends on the available fields (method/path/body/response signals).

---

## Project structure

- `todo_analyzer.py`: JSON parser + scoring + workflow grouping
- `enumerate_site.py`: Playwright-based crawling + network capture, then reuse scoring/grouping
- `virtualenvironment/`: local virtual environment (repo-local; optional for users)

---

## Safety & ethics

Operate only on systems where you have explicit authorization.

These scripts may produce false positives and should never be treated as definitive proof of behavior.

