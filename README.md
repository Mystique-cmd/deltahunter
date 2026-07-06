# DeltaHunter Todo Analyzer

`todo_analyzer.py` is a lightweight prototype that scans JSON HTTP traffic logs and identifies endpoints that are *likely state-changing* (useful as candidates for race-condition / workflow testing).

It applies defensive heuristics (method/path/body/response signals), assigns a confidence score, filters candidates, and also groups them into likely multi-step workflows.

## What it does

For each event in your input log, the script extracts:

- **HTTP method** (`method`)
- **Endpoint path** (`path` or derived from `url`)
- **Request body** (`request_body`, `body`, `payload`, etc.)
- **Response status/body** (`response.status`, `status_code`, `response.body`, etc.)

Then it uses these heuristic signals:

1. **State-changing HTTP verbs**
   - Treats `POST`, `PUT`, `PATCH`, `DELETE` as strong candidates.

2. **Path keyword matches** (examples)
   - `update`, `create`, `delete`, `redeem`, `checkout`, `apply`, `confirm`, etc.

3. **Request body field hints** (examples)
   - `amount`, `balance`, `coupon`, `user_id`, `inventory`, `stock`, `quantity`, etc.

4. **Response change indicators** (examples)
   - `created`, `updated`, `deleted`, `new_id`, `resource_id`, `increment`, `decrement`, `inventory`, `balance`, etc.

### Confidence + filtering

Each matching category contributes to a **confidence** score. The script marks an event as *state-changing* when:

- It matches state-changing verbs / path keywords / payload hints **and**
- It also shows response-change signals (or a successful response status signal).

Finally it filters to:

- `state_changing == True`
- `confidence >= 0.45`

## Supported input format

The script accepts JSON traffic logs in either of these shapes:

1. **A JSON array** of events

```json
[
  { "method": "POST", "url": "https://example.com/redeem", "body": {"coupon":"X"}, "response": {"status":200,"body":"created new_id"} }
]
```

2. **A JSON object** with an `events` array

```json
{
  "events": [
    { "method": "POST", "path": "/redeem-coupon", "request_body": {"coupon":"X"}, "response_status": 200, "response_body": {"body":"created"} }
  ]
}
```

### Flexible schema fields

Because log formats vary, the parser tries multiple alternative keys, for example:

- Path: `path` (preferred) or derived from `url`
- Request body: `request_body`, `body`, `requestBody`, `request`, `payload`
- Response body: `response.body`, `responseBody`, `response_body`, etc.
- Response status: `response.status`, `status_code`, `status`

## Usage

### Basic

```bash
python3 todo_analyzer.py --input /path/to/log.json
```

### Limit output

```bash
python3 todo_analyzer.py --input /path/to/log.json --top 30
```

## Output

The script prints two main sections:

1. **Candidate state-changing endpoints**
   - Shows method + path (+ URL when available)
   - Shows confidence score
   - Lists heuristic reasons

2. **Workflow grouping**
   - Groups candidates into likely multi-step flows using path keywords.
   - Example workflow keys used by the script:
     - `validate→confirm→redeem`
     - `checkout→inventory_update`
     - `create_or_register`
     - `delete_or_remove`
     - `unassigned`

## Notes / limitations

- This is **heuristic** logic, not a ground-truth state-machine model.
- It is designed to be **defensive** against inconsistent/malformed logs.
- Confidence is intended for **prioritization**, not definitive correctness.
- Response-body extraction depends on how your events represent response content.

## Requirements

- Python 3.x
- Standard library only (no external dependencies)

## Dynamic site enumeration (new)

This repo now also includes `enumerate_site.py`, which **actively crawls/enumerates a site** using a headless browser (Playwright) and ranks discovered endpoints using the same heuristics as `todo_analyzer.py`.

### Install Playwright

```bash
pip install playwright
playwright install
```

### Run

```bash
python3 enumerate_site.py --base https://example.com --max-pages 30 --max-depth 3
```

### Notes

- Default behavior is **same-origin only** when ranking endpoints.
- You must have authorization to test the target.


