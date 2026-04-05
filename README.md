# fastxss

A fast, comprehensive XSS vulnerability scanner built in Rust.

Detects reflected, stored, DOM-based, and blind/out-of-band cross-site scripting vulnerabilities across web applications. Designed for authorized penetration testing and security auditing.

---

## Features

- **Reflected XSS** - Probe-first detection with context-aware payload selection. Tests query parameters, form fields, and HTTP headers.
- **Stored XSS** - Injects payloads via forms, then revisits pages to detect persistence.
- **DOM-based XSS** - Headless Chrome with JavaScript sink hooking (innerHTML, document.write, eval, etc.).
- **Blind/OOB XSS** - Built-in callback server with unique token tracking. Confirmed callbacks = Critical severity.
- **SPA/JS Form Detection** - Renders pages with headless Chrome to find React/Vue/Angular forms invisible in raw HTML.
- **Smart Crawling** - Async BFS crawler with link extraction, sitemap parsing, robots.txt support, and scope enforcement.
- **Fast** - Concurrent scanning with probe-first reflection testing. Skips non-reflecting parameters immediately.

## Installation

### Prerequisites

- [Rust](https://rustup.rs/) (1.70+)
- Google Chrome or Microsoft Edge (for DOM-based scanning)

### Build from source

```bash
git clone https://github.com/cwsecur1ty/fastxss.git
cd fastxss
cargo build --release
```

The binary will be at `target/release/fastxss` (or `fastxss.exe` on Windows).

### Verify installation

```bash
./target/release/fastxss --help
```

## Usage

### Basic scan

```bash
fastxss --target https://example.com
```

### Full scan with HTML report

```bash
fastxss --target https://example.com --output-format html -o report.html
```

### Fast scan (reflected only, no browser)

```bash
fastxss --target https://example.com --disable-dom --disable-blind --disable-stored
```

### Authenticated scan

```bash
fastxss --target https://example.com --cookie "session=abc123; token=xyz"
```

### With proxy

```bash
fastxss --target https://example.com --proxy http://127.0.0.1:8080
```

### Blind XSS with external callback

```bash
fastxss --target https://example.com --callback-host your-server.com --callback-port 8844
```

### Verbose output

```bash
fastxss --target https://example.com -v      # info
fastxss --target https://example.com -vv     # debug
fastxss --target https://example.com -vvv    # trace (includes browser messages)
```

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `-t, --target <URL>` | required | Target URL to scan |
| `-c, --concurrency <N>` | 50 | Max concurrent requests |
| `--crawl-depth <N>` | 10 | Maximum crawl depth |
| `--scope <DOMAINS>` | target domain | Comma-separated allowed domains |
| `--output-format <FMT>` | terminal | Output: `json`, `html`, or `terminal` |
| `-o, --output-file <PATH>` | - | Write report to file |
| `--proxy <URL>` | - | HTTP/SOCKS5 proxy |
| `--headers <H>` | - | Custom headers: `"Key: Value,Key2: Val2"` |
| `--cookie <COOKIE>` | - | Cookie string |
| `--wordlist <PATH>` | built-in | Custom payload wordlist |
| `--callback-port <PORT>` | 8844 | Blind XSS callback port |
| `--callback-host <HOST>` | 127.0.0.1 | External host for blind XSS |
| `--rate-limit <N>` | 100 | Max requests per second |
| `--delay-ms <MS>` | 0 | Delay between requests |
| `--respect-robots` | false | Honor robots.txt |
| `--disable-dom` | false | Skip DOM-based scanning |
| `--disable-blind` | false | Skip blind XSS scanning |
| `--disable-stored` | false | Skip stored XSS scanning |
| `--timeout-secs <N>` | 30 | Request timeout |
| `--insecure` | false | Accept invalid TLS certs |
| `--blind-wait-secs <N>` | 10 | Wait for blind callbacks after scan |
| `-v` | warn | Increase verbosity (up to -vvv) |

## How It Works

```
                    +---> Reflected Scanner (probe-first)
                    |
Crawler -----> Scanner Dispatcher ---> Stored Scanner
  |                 |
  |                 +---> DOM Scanner (headless Chrome)
  |                 |
  v                 +---> Blind Scanner --> Callback Server
Reporter <------- Findings Channel
```

1. **Crawl** - Async BFS spider discovers pages, forms, and parameters. Sitemap and JS-embedded URLs are extracted.
2. **Probe** - Each parameter gets a single canary probe. If it doesn't reflect, skip it entirely (saves hundreds of requests).
3. **Target** - For reflecting parameters, detect the HTML context (attribute, script, tag body, comment) and send only relevant payloads.
4. **Render** - Pages likely to have JS-rendered forms are loaded in headless Chrome. Standalone `<input>` elements (React/SPA pattern) are detected even without `<form>` tags.
5. **Report** - Findings are deduplicated, severity-rated, and output to terminal, JSON, or a self-contained HTML report.

## Payloads

Built-in payload categories:

| File | Count | Purpose |
|------|-------|---------|
| `reflected.txt` | 120+ | Event handlers, tag breaking, attribute injection, filter bypasses |
| `stored.txt` | 60+ | Persistent contexts, markdown/BBCode, mXSS |
| `dom.txt` | 55+ | Sink/source pairs, template injection, prototype pollution |
| `blind.txt` | 50+ | Fetch/Image/XHR callbacks, data exfiltration, delayed payloads |
| `polyglot.txt` | 20+ | Multi-context breakers |

Custom wordlists can be provided with `--wordlist <path>`.

## Output Formats

### Terminal (default)
Color-coded findings with severity, URL, parameter, and payload.

### JSON
```bash
fastxss --target https://example.com --output-format json -o results.json
```

### HTML
Self-contained dark-themed report with expandable evidence sections.
```bash
fastxss --target https://example.com --output-format html -o report.html
```

## Legal

This tool is intended for authorized security testing only. Always obtain written permission before scanning any target. Unauthorized scanning may violate laws in your jurisdiction.

## License

[LICENSE](LICENSE)
