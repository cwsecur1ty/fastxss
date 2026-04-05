<div align="center">

# FastXSS

**Advanced XSS Vulnerability Scanner**

[![build](https://img.shields.io/badge/build-passing-brightgreen)]()
[![language](https://img.shields.io/badge/language-Rust-orange)](https://www.rust-lang.org/)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

Fast, cross-site scripting detection built in Rust.
Reflected, stored, DOM-based, and blind/out-of-band XSS. All in one tool.

---

</div>

## Features

- **Reflected XSS** -- Probe-first detection with context-aware payloads. Browser-verified execution confirmation.
- **Stored XSS** -- Inject via forms, revisit pages to detect persistence.
- **DOM-based XSS** -- Headless Chrome with 15+ JavaScript sink hooks.
- **Blind/OOB XSS** -- Built-in callback server with unique token tracking.
- **API & GraphQL** -- OpenAPI/Swagger spec parsing, GraphQL introspection, JSON body injection.
- **Parameter Mining** -- 200+ built-in params, JS source extraction, response-diff hidden param detection.
- **Cookie XSS** -- Cookie value reflection testing with targeted payloads.
- **Authentication** -- Form-based login with CSRF extraction, bearer token support.
- **SPA Support** -- Renders JS-heavy pages with Chrome to find React/Vue/Angular forms.
- **Resilient** -- Retry with exponential backoff, Ctrl+C cleanup, render timeouts.

## Installation

```bash
git clone https://github.com/cwsecur1ty/fastxss.git
cd fastxss
cargo build --release
```

Requires [Rust](https://rustup.rs/) 1.70+ and Chrome/Edge for DOM scanning.

## Quick Start

```bash
# Basic scan
fastxss -t https://example.com

# Reflected only (fast, no browser)
fastxss -t https://example.com --disable-dom --disable-blind --disable-stored

# Full scan with API + GraphQL discovery
fastxss -t https://example.com --test-apis --test-graphql

# HTML report
fastxss -t https://example.com --output-format html -o report.html

# Authenticated scan
fastxss -t https://example.com --auth-url https://example.com/login --auth-user admin --auth-pass secret

# With cookies
fastxss -t https://example.com --cookie "session=abc123; token=xyz"

# API token auth
fastxss -t https://api.example.com --bearer-token eyJhbGciOi...

# Through a proxy
fastxss -t https://example.com --proxy http://127.0.0.1:8080 --insecure

# Blind XSS with external callback
fastxss -t https://example.com --callback-host your-vps.com --callback-port 8844
```

## Options

**Scan Scope:**
| Flag | Description |
|------|-------------|
| `-t, --target <URL>` | Target URL *(required)* |
| `-c, --concurrency <N>` | Concurrent requests (default: 50) |
| `--crawl-depth <N>` | Max crawl depth (default: 10) |
| `--scope <DOMAINS>` | Allowed domains (comma-separated) |
| `--rate-limit <N>` | Requests/sec (default: 100) |
| `--max-retries <N>` | Retry on 429/5xx (default: 3) |
| `--respect-robots` | Honor robots.txt |

**Authentication:**
| Flag | Description |
|------|-------------|
| `--auth-url <URL>` | Login page for form-based auth |
| `--auth-user <USER>` | Login username/email |
| `--auth-pass <PASS>` | Login password |
| `--bearer-token <TOKEN>` | API bearer token |
| `--cookie <STRING>` | Cookie header value |

**Scanner Modules:**
| Flag | Description |
|------|-------------|
| `--disable-dom` | Skip DOM scanning (no Chrome) |
| `--disable-blind` | Skip blind/OOB scanning |
| `--disable-stored` | Skip stored XSS scanning |
| `--test-apis` | Probe API endpoints + parse OpenAPI specs |
| `--test-graphql` | GraphQL introspection + argument testing |

**Output:**
| Flag | Description |
|------|-------------|
| `--output-format <FMT>` | `terminal`, `json`, or `html` |
| `-o, --output-file <PATH>` | Write report to file |
| `-v` | Verbosity (`-v` info, `-vv` debug, `-vvv` trace) |

**Advanced:**
| Flag | Description |
|------|-------------|
| `--proxy <URL>` | HTTP/SOCKS5 proxy |
| `--headers <H>` | Custom headers |
| `--wordlist <PATH>` | Custom XSS payload wordlist |
| `--param-wordlist <PATH>` | Parameter mining wordlist |
| `--callback-host <HOST>` | External host for blind callbacks |
| `--callback-port <PORT>` | Callback server port (default: 8844) |
| `--insecure` | Accept invalid TLS certs |

## How It Works

```
Crawler ──> Scanner Dispatcher ──> Reflected (probe-first + browser verify)
  │              │                  Stored (inject + revisit)
  │              │                  DOM (Chrome sink hooks)
  │              │                  Blind (callback server)
  │              │
  │         Post-Scan ───────────> API Discovery (Swagger/OpenAPI)
  │                                GraphQL Introspection
  │                                Parameter Mining
  v
Reporter <── Findings Channel ──> Terminal / JSON / HTML
```

1. **Crawl** -- BFS spider discovers pages, forms, parameters, and cookies.
2. **Probe** -- Each parameter gets a canary probe. No reflection = skip (saves hundreds of requests).
3. **Target** -- Context detection (script, attribute, template literal, SVG, comment) selects relevant payloads.
4. **Verify** -- High-severity findings verified in headless Chrome for confirmed execution.
5. **Discover** -- API probing, GraphQL introspection, and hidden parameter mining expand attack surface.
6. **Report** -- Deduplicated, severity-rated findings with CSP header analysis.

## Legal

This tool is intended for **authorized security testing only**. Always obtain written permission before scanning any target.

## License

[MIT](LICENSE)
