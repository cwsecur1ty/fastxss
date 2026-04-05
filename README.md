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

- **Reflected XSS** -- Probe-first detection with context-aware payload selection. Tests query parameters, form fields, and HTTP headers.
- **Stored XSS** -- Injects payloads via forms, then revisits pages to detect persistence.
- **DOM-based XSS** -- Headless Chrome with JavaScript sink hooking (innerHTML, document.write, eval, jQuery, and 15+ more sinks).
- **Blind/OOB XSS** -- Built-in callback server with unique token tracking. Confirmed callbacks rated Critical.
- **Execution Verification** -- Optionally confirms reflected XSS actually executes in a real browser, not just reflects.
- **SPA Support** -- Renders pages with headless Chrome to discover React/Vue/Angular forms invisible in raw HTML.
- **Smart Crawling** -- Async BFS crawler with sitemap parsing, robots.txt support, and scope enforcement.
- **Retry & Resilience** -- Automatic retry with exponential backoff on 429/503. Respects Retry-After headers.
- **Graceful Shutdown** -- Ctrl+C cleanly kills Chrome processes, cleans temp dirs, and exits.

## Installation

**Prerequisites:** [Rust](https://rustup.rs/) 1.70+ and Google Chrome or Microsoft Edge (for DOM scanning).

```bash
git clone https://github.com/cwsecur1ty/fastxss.git
cd fastxss
cargo build --release
```

Binary at `target/release/fastxss` (or `fastxss.exe` on Windows).

## Quick Start

```bash
# Basic scan
fastxss --target https://example.com

# Fast reflected-only scan (no browser needed)
fastxss --target https://example.com --disable-dom --disable-blind --disable-stored

# Full scan with HTML report
fastxss --target https://example.com --output-format html -o report.html

# Authenticated scan
fastxss --target https://example.com --cookie "session=abc123"

# Through a proxy
fastxss --target https://example.com --proxy http://127.0.0.1:8080

# Blind XSS with external callback
fastxss --target https://example.com --callback-host your-server.com --callback-port 8844
```

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `-t, --target <URL>` | required | Target URL to scan |
| `-c, --concurrency <N>` | 50 | Max concurrent requests |
| `--crawl-depth <N>` | 10 | Maximum crawl depth |
| `--scope <DOMAINS>` | target domain | Comma-separated allowed domains |
| `--output-format <FMT>` | terminal | Output: `json`, `html`, or `terminal` |
| `-o, --output-file <PATH>` | -- | Write report to file |
| `--proxy <URL>` | -- | HTTP/SOCKS5 proxy |
| `--headers <H>` | -- | Custom headers: `"Key: Value,Key2: Val2"` |
| `--cookie <COOKIE>` | -- | Cookie string |
| `--wordlist <PATH>` | built-in | Custom payload wordlist |
| `--callback-port <PORT>` | 8844 | Blind XSS callback port |
| `--callback-host <HOST>` | 127.0.0.1 | External host for blind XSS |
| `--rate-limit <N>` | 100 | Max requests per second |
| `--max-retries <N>` | 3 | Retry attempts on transient errors |
| `--delay-ms <MS>` | 0 | Delay between requests |
| `--respect-robots` | false | Honor robots.txt |
| `--disable-dom` | false | Skip DOM-based scanning |
| `--disable-blind` | false | Skip blind XSS scanning |
| `--disable-stored` | false | Skip stored XSS scanning |
| `--timeout-secs <N>` | 30 | Request timeout |
| `--insecure` | false | Accept invalid TLS certs |
| `--blind-wait-secs <N>` | 10 | Wait for blind callbacks after scan |
| `-v` | warn | Increase verbosity (up to `-vvv`) |

## How It Works

```
                    +---> Reflected Scanner (probe-first + browser verification)
                    |
Crawler -----> Scanner Dispatcher ---> Stored Scanner
  |                 |
  |                 +---> DOM Scanner (headless Chrome + sink hooks)
  |                 |
  v                 +---> Blind Scanner --> Callback Server
Reporter <------- Findings Channel
```

1. **Crawl** -- Async BFS spider discovers pages, forms, and parameters. Sitemap and JS-embedded URLs are extracted.
2. **Probe** -- Each parameter gets a single canary probe. No reflection? Skip it entirely. Saves hundreds of requests.
3. **Target** -- Detect HTML context (attribute, script string, template literal, tag body, comment, SVG) and send only relevant payloads.
4. **Verify** -- High-severity findings optionally verified via headless Chrome to confirm actual JavaScript execution.
5. **Report** -- Findings are deduplicated, severity-rated (with CSP header analysis), and output to terminal, JSON, or HTML.

## Payloads

| File | Count | Purpose |
|------|-------|---------|
| `reflected.txt` | 120+ | Event handlers, tag breaking, attribute injection, filter bypasses |
| `stored.txt` | 60+ | Persistent contexts, markdown/BBCode, mXSS |
| `dom.txt` | 55+ | Sink/source pairs, template injection, prototype pollution |
| `blind.txt` | 50+ | Fetch/Image/XHR callbacks, data exfiltration, delayed payloads |
| `polyglot.txt` | 20+ | Multi-context breakers |

Custom wordlists: `--wordlist <path>`

## Output Formats

**Terminal** (default) -- Color-coded findings with severity, URL, parameter, and payload.

**JSON** -- `fastxss -t https://example.com --output-format json -o results.json`

**HTML** -- Self-contained dark-themed report with expandable evidence sections.

## Legal

This tool is intended for **authorized security testing only**. Always obtain written permission before scanning any target. Unauthorized scanning may violate laws in your jurisdiction.

## License

[MIT](LICENSE)
