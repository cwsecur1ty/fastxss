# fastxss Development Roadmap

## Current State (v0.1.0)
Working scanner with reflected, stored, DOM-based, and blind XSS detection. Probe-first optimization, async crawler, headless Chrome rendering, context-aware payloads.

---

## Phase 1: Reliability & Accuracy (v0.2.0)
*Goal: Reduce false negatives, fix detection gaps, stabilize Chrome*

### 1.1 Chrome Process Safety
- [ ] Implement `Drop` for `DomScanner` to kill Chrome on exit
- [ ] Add render timeout (configurable, default 5s) to prevent hangs
- [ ] Pool browser tabs instead of open/close per page
- [ ] Clean up temp user data dirs on exit
- [ ] Graceful Ctrl+C handler that kills child Chrome processes

### 1.2 Improved Context Detection
- [ ] Handle nested contexts (`<script>var x = "<img>";</script>`)
- [ ] Handle template literals in JS context
- [ ] Handle HTML5 custom elements
- [ ] Improve attribute name extraction for edge cases (multiple `=`, empty attrs)
- [ ] Add context detection for JSON responses, XML, SVG

### 1.3 Execution Verification
- [ ] For reflected XSS: verify payload is in executable position (not just reflected)
- [ ] Use headless browser to confirm reflected payloads actually execute
- [ ] Distinguish HTML-encoded reflection from raw reflection
- [ ] Add confidence scoring based on filter bypass difficulty

### 1.4 Additional JS Sink Hooks
- [ ] `insertAdjacentHTML`
- [ ] `element.append()`, `element.prepend()`
- [ ] jQuery `.append()`, `.prepend()`, `.after()`, `.before()`, `.replaceWith()`
- [ ] Angular `ng-bind-html`, `$sce.trustAsHtml()`
- [ ] Vue `v-html`
- [ ] React `dangerouslySetInnerHTML`

### 1.5 Better Error Handling
- [ ] Log all network errors with context (URL, method, error type)
- [ ] Retry on transient errors (429, 503, connection reset)
- [ ] Timeout handling per-request with configurable default
- [ ] Graceful degradation when Chrome crashes mid-scan

---

## Phase 2: Discovery & Coverage (v0.3.0)
*Goal: Find more attack surface, discover hidden parameters and endpoints*

### 2.1 Parameter Mining
- [ ] Brute-force hidden parameter discovery from wordlist (500+ common params)
- [ ] Response diff-based parameter detection (inject param, compare response length/content)
- [ ] Extract parameter names from JavaScript source code
- [ ] Extract parameter names from HTML comments
- [ ] Extract parameter names from error messages

### 2.2 API Endpoint Discovery
- [ ] Auto-detect `/api/`, `/v1/`, `/graphql`, `/rest/` paths
- [ ] Parse OpenAPI/Swagger specs if found (`/swagger.json`, `/openapi.yaml`)
- [ ] GraphQL introspection query to discover all fields/arguments
- [ ] Test JSON body injection (not just form-encoded POST)
- [ ] Test multipart form data

### 2.3 Authentication Support
- [ ] Multi-step login flow (fill form, submit, capture session)
- [ ] Bearer token / API key header support
- [ ] Session validation (detect when session expires, re-authenticate)
- [ ] Cookie jar persistence across scan

### 2.4 Advanced Crawling
- [ ] JavaScript route discovery (parse React Router, Vue Router configs)
- [ ] SPA hash-based route testing
- [ ] Extract URLs from `fetch()`, `XMLHttpRequest`, `axios` calls in JS
- [ ] Follow `<meta http-equiv="refresh">` redirects
- [ ] Parse `<base href>` for relative URL resolution
- [ ] Sitemap index file support

### 2.5 Cookie-Based XSS
- [ ] Test cookie reflection (set cookie, check if value appears in response)
- [ ] Cookie injection via URL parameters (`?lang=en; inject=<script>`)
- [ ] HTTPOnly/Secure/SameSite flag reporting

---

## Phase 3: Evasion & Bypass (v0.4.0)
*Goal: Bypass WAFs and filters, detect more sophisticated XSS*

### 3.1 WAF Detection & Adaptation
- [ ] Detect WAF presence (403 patterns, rate limiting, Cloudflare/Akamai headers)
- [ ] Adaptive payload selection based on WAF type
- [ ] Automatic rate reduction when WAF detected
- [ ] WAF fingerprinting (ModSecurity, Cloudflare, AWS WAF, etc.)

### 3.2 CSP Analysis
- [ ] Parse Content-Security-Policy headers
- [ ] Identify `unsafe-inline`, `unsafe-eval` directives
- [ ] Report CSP bypasses (JSONP endpoints, CDN allowlisting)
- [ ] Extract nonces from page source for nonce-based CSP bypass
- [ ] Test `<meta>` tag CSP override

### 3.3 Advanced Encoding Chains
- [ ] Double/triple encoding detection and testing
- [ ] Charset-based bypass (UTF-7, UTF-16, UTF-32)
- [ ] Unicode normalization bypass (NFD/NFC/NFKD/NFKC)
- [ ] HTML entity + URL encoding combinations
- [ ] Backslash escape chain testing

### 3.4 Filter Bypass Intelligence
- [ ] Adaptive mutation: if `<script>` blocked, try `<ScRiPt>`, `<scr<script>ipt>`, etc.
- [ ] Tag mutation engine: generate novel tag variations
- [ ] Attribute mutation: `onmouseover` → `ONMOUSEOVER` → `OnMouseOver`
- [ ] Automatic detection of what's being filtered (blacklist analysis)
- [ ] Protocol-relative bypass (`//attacker.com` instead of `http://`)

### 3.5 CRLF Injection → XSS
- [ ] Test `\r\n` injection in all header positions
- [ ] Response splitting payload injection
- [ ] Header injection to set arbitrary Content-Type
- [ ] HTTP/2 CRLF variants

### 3.6 Mutation XSS (mXSS)
- [ ] Test payloads that mutate through browser HTML parser
- [ ] DOMPurify bypass payloads
- [ ] Sanitizer-specific bypass testing (detect sanitizer, target it)

---

## Phase 4: Reporting & UX (v0.5.0)
*Goal: Professional reports, better user experience*

### 4.1 Enhanced Reporting
- [ ] CVSS v3.1 scoring per finding
- [ ] CVSS vector string in output
- [ ] Remediation advice per finding type and context
- [ ] CWE-79 classification
- [ ] OWASP Top 10 mapping

### 4.2 Report Improvements
- [ ] Interactive HTML report with filtering/sorting
- [ ] Request/response pair evidence (full HTTP, not truncated)
- [ ] Screenshot evidence for DOM XSS findings
- [ ] Scan duration and performance metrics
- [ ] Technology fingerprint summary

### 4.3 Progress & Real-Time Output
- [ ] Progress bar with ETA (pages crawled/total, injection points tested)
- [ ] Real-time finding streaming to JSON file (append mode)
- [ ] Scan statistics dashboard (requests/sec, findings/min)

### 4.4 Config File Support
- [ ] `fastxss.toml` config file for persistent settings
- [ ] Profile/preset system (e.g., `--profile aggressive`, `--profile stealth`)
- [ ] Scope exclusion patterns (regex/glob for paths to skip)
- [ ] Per-target override configs

### 4.5 Resume & Checkpoint
- [ ] Save scan state to disk periodically
- [ ] `--resume <scan-id>` to continue interrupted scans
- [ ] Partial result recovery on crash

### 4.6 Scan Comparison
- [ ] `--baseline <prev-report.json>` to diff against previous scan
- [ ] New/fixed/unchanged finding classification
- [ ] Regression detection for CI/CD integration

---

## Phase 5: Advanced Detection (v0.6.0)
*Goal: Catch sophisticated XSS in modern applications*

### 5.1 Prototype Pollution → XSS
- [ ] Systematic `__proto__` and `constructor.prototype` testing
- [ ] Detect prototype pollution sinks (innerHTML, src, href set from polluted props)
- [ ] Framework-specific gadget chains (jQuery, Lodash)

### 5.2 Server-Side Template Injection (SSTI)
- [ ] Detect template engines (Jinja2, ERB, Twig, Pug, Handlebars)
- [ ] Engine-specific payloads
- [ ] Blind SSTI detection via timing/callbacks

### 5.3 PostMessage XSS
- [ ] Enumerate `window.addEventListener('message')` handlers
- [ ] Test origin validation bypass
- [ ] Inject via `postMessage()` from headless browser

### 5.4 Service Worker XSS
- [ ] Detect service worker registration
- [ ] Test SW cache poisoning
- [ ] SW scope-based XSS

### 5.5 DNS Rebinding for Blind XSS
- [ ] DNS exfiltration channel for blind XSS detection
- [ ] Works through strict firewalls that block HTTP callbacks

---

## Phase 6: Enterprise & Scale (v1.0.0)
*Goal: Production-ready for enterprise security teams*

### 6.1 Distributed Scanning
- [ ] Multi-worker architecture with task queue
- [ ] Result aggregation from multiple agents
- [ ] Central coordinator for scan management

### 6.2 CI/CD Integration
- [ ] GitHub Actions integration
- [ ] Exit code based on severity threshold
- [ ] SARIF output format for GitHub Code Scanning
- [ ] JUnit XML output for Jenkins
- [ ] GitLab SAST report format

### 6.3 API Mode
- [ ] REST API server mode for programmatic scanning
- [ ] Webhook notifications for findings
- [ ] Scan queue management
- [ ] Multi-tenant support

### 6.4 Plugin System
- [ ] Custom scanner plugin interface (trait-based)
- [ ] Custom payload generators
- [ ] Custom sink definitions for DOM scanning
- [ ] Community payload packs

### 6.5 Compliance
- [ ] PCI DSS XSS testing requirements
- [ ] SOC 2 evidence generation
- [ ] Audit trail logging

---

## Quick Wins (Can Be Done Anytime)

| Improvement | Effort | Impact |
|---|---|---|
| Add `--exclude` flag for path patterns | Small | Medium |
| Config file support (`fastxss.toml`) | Small | High |
| Progress bar with `indicatif` (already a dep) | Small | High |
| Add scan duration to summary | Tiny | Medium |
| JSONP callback injection testing | Small | Medium |
| Retry on 429/503 with backoff | Small | High |
| Test `X-Forwarded-Host` header reflection | Tiny | Medium |
| Add `--json-stream` for real-time JSON output | Medium | High |
| Multipart form data support | Medium | Medium |
| GraphQL introspection | Medium | High |

---

## Metrics to Track

- **Detection rate** against OWASP XSS test cases
- **False positive rate** on clean applications
- **Scan speed** (pages/sec, payloads/sec)
- **Coverage** (% of injection points tested)
- **Time to first finding**
