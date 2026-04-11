# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

FastXSS is a Rust CLI XSS vulnerability scanner covering reflected, stored, DOM-based, and blind/OOB XSS, plus API/GraphQL probing, parameter mining, and CSP/WAF analysis. Intended for authorized security testing only.

## Build & Run

```bash
cargo build --release                        # release binary at target/release/fastxss
cargo run -- -t https://example.com          # dev run
cargo check                                  # fast type-check
cargo clippy --all-targets -- -D warnings    # lint
cargo test                                   # run all tests
cargo test <name>                            # run a single test by name substring
```

Requires Rust 1.70+ and Chrome/Edge on PATH for DOM scanning (chromiumoxide drives it). Use `--disable-dom` to skip browser init when iterating without a browser installed.

## Architecture

`main.rs` is the orchestrator. The rest of `src/` is organized by concern; each subdir has a `mod.rs` that re-exports its public surface. The flow is a three-stage async pipeline wired with tokio `mpsc` channels:

1. **Crawl stage** (`crawler/`) — `Spider` (BFS) or `--no-crawl` feeder emits `CrawlResult`s into `crawl_tx`. Each `CrawlResult` bundles the URL, HTTP method, response body/status, extracted `FormData`, and `InjectionPoint`s (query/body/header/cookie/path/fragment). Forms come from `crawler::forms`; URL params from `crawler::params`.
2. **Scan stage** — `main.rs` reads from `crawl_rx` and fans each page out to up to `concurrency.min(10)` page-level workers. Each worker optionally re-renders the page via `DomScanner` (only if the raw HTML has form hints and no server-rendered forms), then dispatches to all enabled scanners concurrently. Findings are sent through `finding_tx`.
3. **Post-scan discovery** — after crawl+scan finishes, `main.rs` runs `ParamMiner`, `ApiDiscovery`, `GraphqlDiscovery`, and `CrlfScanner` in parallel against the root target. Their findings go through the same channel.

A dedicated `collection_handle` task drains `finding_rx`, prints to terminal (unless `--quiet`), optionally JSONL-streams via `--json-stream`, and builds a `FindingCollection` for the final JSON/HTML report. Process exit code is `1` iff any finding was recorded — this contract is relied on by integrators (see `INTEGRATION.md`).

### Scanner trait

All scanners implement `scanner::traits::Scanner` (`async fn scan(&self, target, engine, client) -> Vec<Finding>`). Living implementations:

- `ReflectedScanner` — probe-first: sends a canary, skips the param if it never reflects, then picks context-aware payloads from `PayloadEngine`. When constructed via `with_dom_verifier`, high-severity findings are re-run in a headless browser to upgrade confidence to `Confirmed`.
- `StoredScanner` — injects via POST forms, then re-fetches linked pages to detect persistence. Uses rotating field tokens to avoid false positives from reflected echoes on the submit response itself.
- `DomScanner` — drives chromiumoxide, installs 15+ JS sink hooks, and correlates taint from sources (`location.hash`, `document.referrer`, …) to sinks.
- `BlindScanner` — embeds unique per-injection tokens; matched against hits recorded by the `callback::server` axum server (`TokenTracker` maps token → original injection context).
- `CrlfScanner`, `WafDetector`, `csp` analysis — auxiliary checks invoked from the post-scan phase or at startup.

Key types in `scanner/traits.rs`: `CrawlResult`, `InjectionPoint` (+ `ParamLocation`), `HtmlContext` (drives context-aware payload selection — `ScriptBlock`, `AttributeValue`, `TemplateLiteral`, `SvgContext`, `UnquotedAttributeValue`, etc.), `Finding`, `Severity`, `Confidence`.

### Payloads

`payloads/engine.rs` (`PayloadEngine`) is the single source of payloads. It loads per-category lists (`payloads/*.txt` — `reflected.txt`, `stored.txt`, `dom.txt`, `blind.txt`, `polyglot.txt`, `waf_bypass.txt`, `mxss.txt`, `crlf.txt`) and selects from them based on the detected `HtmlContext`. `--wordlist` overrides the built-in reflected list. When adding or editing categories, mirror the change in both the category text file and any code that indexes into the engine.

### HTTP / session / rate limit

`http/client.rs` wraps `reqwest` with retry (exponential backoff on 429/5xx up to `--max-retries`), gzip/brotli, cookies, SOCKS proxy, and TLS skip via `--insecure`. `http/rate_limiter.rs` uses `governor` for global RPS. `http/session.rs::SessionManager` handles CSRF-aware form login at startup and then the shared cookie jar carries auth for the whole scan.

### Reporting

`reporter/finding.rs::FindingCollection` dedupes and sorts. `terminal.rs`, `json.rs`, and `html.rs` are the three output sinks; JSON is also the stdout format when `--quiet --output-format json` is set without `-o`. The `Finding` struct is a stable public contract — external tools consume it (see `INTEGRATION.md`), so changing field names or enum variants is a breaking change for integrators.

## Integration contract (do not break casually)

- Exit codes: `0` = clean, `1` = findings, `130` = Ctrl+C. Integrators script on these.
- `--quiet` must suppress banner, colors, and all non-finding stdout chatter.
- `--urls-file` + `--no-crawl` and `--forms-file` are the documented injection points for external crawlers. `FormData` / `FormField` JSON shapes are documented in `INTEGRATION.md` and must stay in sync with the `serde::Deserialize` impls in `scanner/traits.rs`.
- `--json-stream <path>` writes JSONL in real time and is expected to be tail-followable.

## Conventions

- `#![allow(dead_code)]` is set in `main.rs` — don't remove it without a full sweep; several scanner helpers are held for upcoming modules (see `ROADMAP.md`).
- Scanners are constructed once and shared as `Arc<T>`; `DomScanner` additionally lives behind a `Mutex` because the chromiumoxide handle needs exclusive access for shutdown. Preserve that wrapping if you add new entry points.
- Add new scanners by implementing `Scanner` and wiring them into `main.rs`'s fan-out in the page worker (for per-page scanners) or the post-scan `discovery_handles` vec (for target-level scanners).
