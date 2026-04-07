# FastXSS Integration Guide

FastXSS can run as a standalone scanner or as a subprocess called by external tools. This document covers the integration interface.

---

## Subprocess Mode

Use `--quiet` to suppress banner, color, and progress output. Combine with `--output-format json` for machine-readable results.

```bash
fastxss -t https://target.com --output-format json -o results.json --quiet
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No vulnerabilities found |
| `1` | One or more vulnerabilities found |

```bash
fastxss -t https://target.com --output-format json --quiet
if [ $? -eq 1 ]; then
  echo "XSS vulnerabilities detected"
fi
```

---

## Pre-Crawled URLs (`--urls-file` + `--no-crawl`)

Skip FastXSS's built-in crawler and scan a list of URLs provided by an external tool.

**urls.txt** (one URL per line):
```
https://target.com/
https://target.com/login
https://target.com/search?q=test
https://target.com/profile?id=1
https://target.com/api/users
```

```bash
fastxss -t https://target.com \
  --urls-file urls.txt \
  --no-crawl \
  --output-format json \
  -o results.json \
  --quiet
```

FastXSS will:
1. Fetch each URL to get the response body
2. Extract forms and parameters from the HTML
3. Run all enabled scanners against each URL
4. Skip crawling/link discovery entirely

Lines starting with `#` are ignored.

---

## Pre-Discovered Forms (`--forms-file`)

Pass forms discovered by an external crawler. FastXSS will test them for XSS without needing to find them itself.

**forms.json** format:
```json
[
  {
    "action": "https://target.com/login",
    "method": "POST",
    "fields": [
      {
        "name": "email",
        "field_type": "email",
        "value": null,
        "required": true
      },
      {
        "name": "password",
        "field_type": "password",
        "value": null,
        "required": false
      }
    ],
    "enctype": null
  },
  {
    "action": "https://target.com/search",
    "method": "GET",
    "fields": [
      {
        "name": "q",
        "field_type": "text",
        "value": "",
        "required": false
      }
    ],
    "enctype": null
  }
]
```

```bash
fastxss -t https://target.com \
  --urls-file urls.txt \
  --forms-file forms.json \
  --no-crawl \
  --output-format json \
  --quiet
```

### FormData Schema

| Field | Type | Description |
|-------|------|-------------|
| `action` | string | Form submission URL |
| `method` | string | `GET` or `POST` |
| `fields` | array | List of form fields |
| `enctype` | string or null | Encoding type (e.g. `multipart/form-data`) |

### FormField Schema

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Field name attribute |
| `field_type` | string | Input type: `text`, `email`, `password`, `hidden`, `textarea`, etc. |
| `value` | string or null | Default value |
| `required` | bool | Whether field is required |

---

## Authentication Passthrough

Pass authentication context from the calling tool:

```bash
# Cookie-based auth
fastxss -t https://target.com --cookie "session=abc123; token=xyz" --quiet

# Bearer token (API)
fastxss -t https://target.com --bearer-token "eyJhbGciOi..." --quiet

# Custom headers
fastxss -t https://target.com --headers "X-API-Key: secret123" --quiet
```

---

## Output Formats

### JSON File (`-o results.json`)

```bash
fastxss -t https://target.com --output-format json -o results.json --quiet
```

Output is a JSON array of findings:
```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "scanner_type": "Reflected",
    "severity": "High",
    "confidence": "Confirmed",
    "url": "https://target.com/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
    "injection_point": {
      "name": "q",
      "location": "Query",
      "original_value": "test",
      "context": null
    },
    "payload": "<script>alert('fxssabcd1234')</script>",
    "evidence": "...surrounding HTML...",
    "request": {
      "method": "GET",
      "url": "https://target.com/search?q=...",
      "headers": [],
      "body": null
    },
    "response_status": 200,
    "context": "ScriptBlock",
    "timestamp": "2026-04-05T12:00:00Z"
  }
]
```

### JSON to stdout (pipe-friendly)

```bash
fastxss -t https://target.com --output-format json --quiet | jq '.'
```

When `--quiet` is set with `--output-format json` and no `-o` file, JSON is written to stdout.

### Real-Time JSON Streaming (`--json-stream`)

Findings written as JSONL (one JSON object per line) as they're discovered:

```bash
fastxss -t https://target.com --json-stream findings.jsonl --quiet &
tail -f findings.jsonl | jq .
```

Each line is a complete JSON finding object. Useful for long-running scans where you want results before the scan finishes.

### HTML Report

```bash
fastxss -t https://target.com --output-format html -o report.html
```

Self-contained dark-themed HTML with severity stats and expandable evidence.

---

## Finding Schema

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Unique finding identifier |
| `scanner_type` | string | `Reflected`, `Stored`, `Dom`, `Blind` |
| `severity` | string | `Critical`, `High`, `Medium`, `Low`, `Info` |
| `confidence` | string | `Confirmed`, `High`, `Medium`, `Low` |
| `url` | string | URL where vulnerability was found |
| `injection_point.name` | string | Parameter/field name |
| `injection_point.location` | string | `Query`, `Body`, `Header`, `Cookie`, `Fragment`, `Path` |
| `payload` | string | XSS payload that triggered the finding |
| `evidence` | string | Response excerpt around the reflection |
| `request` | object | HTTP request details (method, url, headers, body) |
| `response_status` | int | HTTP status code |
| `context` | string or null | HTML context where payload landed |
| `timestamp` | string | ISO 8601 timestamp |
| `waf_detected` | string or null | WAF name if detected |
| `csp_info` | string or null | CSP weakness summary |

---

## Typical Integration Pattern

```python
import subprocess
import json

def run_fastxss(target, urls=None, forms=None, cookie=None):
    cmd = [
        "fastxss",
        "-t", target,
        "--output-format", "json",
        "-o", "results.json",
        "--quiet",
        "--disable-dom",
        "--disable-blind",
    ]

    if urls:
        cmd += ["--urls-file", urls, "--no-crawl"]
    if forms:
        cmd += ["--forms-file", forms]
    if cookie:
        cmd += ["--cookie", cookie]

    result = subprocess.run(cmd, capture_output=True, text=True)

    findings = []
    try:
        with open("results.json") as f:
            findings = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        pass

    return {
        "has_vulns": result.returncode == 1,
        "findings": findings,
        "stderr": result.stderr,
    }
```

---

## Scanner Selection

Disable scanners you don't need for faster runs:

```bash
# Reflected only (fastest, no browser needed)
fastxss -t https://target.com --disable-dom --disable-blind --disable-stored --quiet

# Skip browser-based scanning
fastxss -t https://target.com --disable-dom --quiet

# Include everything
fastxss -t https://target.com --test-apis --test-graphql --test-crlf --waf-detect
```
