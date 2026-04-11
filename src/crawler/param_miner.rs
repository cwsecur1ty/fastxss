use anyhow::Result;
use regex::Regex;
use std::path::Path;
use tokio::sync::Semaphore;
use std::sync::Arc;
use tracing::{debug, info, warn};
use url::Url;

use crate::http::client::HttpClient;
use crate::scanner::traits::{InjectionPoint, ParamLocation};

/// How a mined param was detected — used for noise suppression when the
/// len-diff signal goes off on every candidate (volatile pages).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DetectionSignal {
    /// Canary string was reflected in the response — high confidence.
    Reflection,
    /// Response length changed beyond the noise threshold — lower confidence.
    LengthDiff,
}

const BUILTIN_PARAMS: &[&str] = &[
    // Common
    "q", "s", "search", "query", "keyword", "term", "id", "page", "p", "num",
    "url", "uri", "path", "redirect", "next", "redir", "return", "returnUrl",
    "goto", "target", "dest", "destination", "continue", "forward", "ref",
    // Auth/session
    "token", "csrf", "nonce", "state", "code", "session", "sid", "auth",
    "username", "user", "email", "login", "password",
    // Data
    "name", "title", "body", "content", "text", "msg", "message", "comment",
    "description", "bio", "about", "note", "value", "val", "data", "input",
    "payload", "json", "xml", "html",
    // Display
    "view", "template", "tpl", "theme", "layout", "render", "format", "mode",
    "type", "action", "cmd", "command", "do", "func", "function", "method",
    "op", "operation", "task", "step",
    // Navigation
    "category", "cat", "tag", "sort", "order", "dir", "filter", "limit",
    "offset", "skip", "from", "to", "start", "end", "min", "max",
    "lang", "locale", "language", "country", "region",
    // Debug/test
    "debug", "test", "dev", "staging", "preview", "draft", "admin", "verbose",
    "trace", "log", "error", "err", "status", "info", "version",
    // API
    "api_key", "apikey", "key", "secret", "client_id", "client_secret",
    "access_token", "refresh_token", "grant_type",
    // File
    "file", "filename", "upload", "download", "attachment", "image", "img",
    "src", "source", "link", "href",
    // Callback/redirect
    "callback", "cb", "webhook", "notify", "ping", "return_url", "success_url",
    "cancel_url", "error_url", "redirect_uri", "oauth_callback",
    // Misc
    "color", "size", "width", "height", "x", "y", "lat", "lng", "zoom",
    "config", "settings", "options", "prefs", "preferences",
    "include", "require", "import", "load", "fetch", "get", "post",
    "edit", "update", "delete", "create", "add", "remove", "save",
    "submit", "confirm", "verify", "validate", "check", "process",
    // Framework-specific
    "controller", "action", "module", "plugin", "extension", "component",
    "route", "handler", "endpoint", "resource", "model", "table",
    "_method", "_token", "__RequestVerificationToken",
    // Encoding/format
    "encoding", "charset", "content_type", "accept", "output",
    "response_type", "grant", "scope", "audience",
];

pub struct ParamMiner {
    client: HttpClient,
    semaphore: Arc<Semaphore>,
    custom_params: Vec<String>,
    max_results: usize,
}

impl ParamMiner {
    pub fn new(
        client: HttpClient,
        concurrency: usize,
        custom_wordlist: Option<&Path>,
        max_results: usize,
    ) -> Self {
        let mut custom_params = Vec::new();
        if let Some(path) = custom_wordlist {
            if let Ok(contents) = std::fs::read_to_string(path) {
                custom_params = contents
                    .lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .collect();
            }
        }
        Self {
            client,
            semaphore: Arc::new(Semaphore::new(concurrency.min(20))),
            custom_params,
            max_results,
        }
    }

    /// Mine hidden parameters on a page.
    ///
    /// Uses a stabilised baseline: fetches the page 3 times to measure the natural
    /// length variance (timestamps, CSRF rotation, ads, analytics) and derives a
    /// dynamic length-diff threshold of `max(250, 5σ)`. Canary reflection is the
    /// high-signal path; length-diff is treated as best-effort.
    ///
    /// If the length-diff signal fires on an implausibly large share of candidates
    /// the result is treated as noise and only canary-reflection hits are kept.
    pub async fn mine(&self, base_url: &Url) -> Vec<InjectionPoint> {
        // Stabilised baseline — fetch 3x to measure natural variance
        let mut baseline_bodies: Vec<String> = Vec::with_capacity(3);
        for _ in 0..3 {
            let resp = match self.client.get(base_url.as_str()).await {
                Ok(r) => r,
                Err(_) => continue,
            };
            if let Ok(body) = resp.text().await {
                baseline_bodies.push(body);
            }
        }
        if baseline_bodies.is_empty() {
            return Vec::new();
        }

        let lengths: Vec<usize> = baseline_bodies.iter().map(|b| b.len()).collect();
        let mean = lengths.iter().sum::<usize>() as f64 / lengths.len() as f64;
        let variance = lengths
            .iter()
            .map(|&l| (l as f64 - mean).powi(2))
            .sum::<f64>()
            / lengths.len() as f64;
        let stddev = variance.sqrt();
        // 5σ catches real param-induced changes above natural noise; 250-byte floor
        // prevents false negatives on perfectly-stable pages.
        let len_threshold = ((stddev * 5.0) as usize).max(250);
        let baseline_len = lengths[0];

        if stddev > 50.0 {
            debug!(
                "Baseline for {} is noisy (σ={:.0} bytes) — len-diff threshold raised to {} bytes",
                base_url, stddev, len_threshold
            );
        }

        // Extract params from JS source of the first baseline
        let body = &baseline_bodies[0];
        let js_params = extract_params_from_js(body);

        // Combine all candidate params, dedup
        let mut seen = std::collections::HashSet::new();
        let mut all_params: Vec<String> = Vec::new();

        // JS-extracted params first (highest signal)
        for p in &js_params {
            if seen.insert(p.clone()) {
                all_params.push(p.clone());
            }
        }
        // Then builtin list
        for p in BUILTIN_PARAMS {
            let s = p.to_string();
            if seen.insert(s.clone()) {
                all_params.push(s);
            }
        }
        // Custom wordlist
        for p in &self.custom_params {
            if seen.insert(p.clone()) {
                all_params.push(p.clone());
            }
        }

        // Skip params already in the URL
        let existing: std::collections::HashSet<String> = base_url
            .query_pairs()
            .map(|(k, _)| k.to_string())
            .collect();

        let total_candidates = all_params
            .iter()
            .filter(|p| !existing.contains(*p))
            .count();

        // Test all candidates concurrently
        let mut handles = Vec::new();
        for param in all_params {
            if existing.contains(&param) {
                continue;
            }

            let permit = self.semaphore.clone().acquire_owned().await.unwrap();
            let client = self.client.clone();
            let url = base_url.clone();
            let baseline = baseline_len;
            let threshold = len_threshold;

            handles.push(tokio::spawn(async move {
                let _permit = permit;
                test_param_static(&client, &url, &param, baseline, threshold).await
            }));
        }

        let mut hits: Vec<(InjectionPoint, DetectionSignal)> = Vec::new();
        for handle in handles {
            if let Ok(Some(hit)) = handle.await {
                hits.push(hit);
            }
        }

        // Noise suppression: if length-diff fires on > 25% of candidates, the
        // page is volatile and those results are almost certainly false positives.
        // Keep only canary-reflection hits in that case.
        let len_diff_count = hits
            .iter()
            .filter(|(_, sig)| *sig == DetectionSignal::LengthDiff)
            .count();
        let noise_ceiling = (total_candidates / 4).max(20);
        let noisy = len_diff_count > noise_ceiling;
        if noisy {
            warn!(
                "Parameter mining on {} flagged {} len-diff hits out of {} candidates — \
                 treating as noise, keeping only reflection hits",
                base_url, len_diff_count, total_candidates
            );
        }

        let mut discovered: Vec<InjectionPoint> = hits
            .into_iter()
            .filter(|(_, sig)| !noisy || *sig == DetectionSignal::Reflection)
            .map(|(point, _)| point)
            .collect();

        // Hard cap — the reflected scanner tests each of these serially per payload,
        // so unbounded growth here blows up the total scan time.
        if discovered.len() > self.max_results {
            debug!(
                "Capping mined params from {} to {} on {}",
                discovered.len(),
                self.max_results,
                base_url
            );
            discovered.truncate(self.max_results);
        }

        if !discovered.is_empty() {
            info!(
                "Parameter mining found {} hidden params on {}",
                discovered.len(),
                base_url
            );
        }

        discovered
    }

}

async fn test_param_static(
    client: &HttpClient,
    base_url: &Url,
    param: &str,
    baseline_len: usize,
    len_threshold: usize,
) -> Option<(InjectionPoint, DetectionSignal)> {
    let canary = "fxssmine1337";
    let mut test_url = base_url.clone();
    test_url.query_pairs_mut().append_pair(param, canary);

    let resp = client.get(test_url.as_str()).await.ok()?;
    let body = resp.text().await.ok()?;

    let make_point = || InjectionPoint {
        name: param.to_string(),
        location: ParamLocation::Query,
        original_value: None,
        context: None,
    };

    // Primary signal: canary reflects in response (high confidence)
    if body.contains(canary) {
        debug!("Hidden param found (reflects): '{}' on {}", param, base_url);
        return Some((make_point(), DetectionSignal::Reflection));
    }

    // Secondary signal: length delta above the stabilised threshold
    let test_len = body.len();
    let len_diff = (test_len as isize - baseline_len as isize).unsigned_abs();
    if len_diff > len_threshold {
        debug!(
            "Hidden param candidate (len diff {} > {}): '{}' on {}",
            len_diff, len_threshold, param, base_url
        );
        return Some((make_point(), DetectionSignal::LengthDiff));
    }

    None
}

/// Extract parameter names from JavaScript source code
pub fn extract_params_from_js(js_source: &str) -> Vec<String> {
    let mut params = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Match URL query params: ?param= or &param=
    let url_param_re = Regex::new(r#"[?&](\w{2,30})="#).unwrap();
    for cap in url_param_re.captures_iter(js_source) {
        if let Some(m) = cap.get(1) {
            let p = m.as_str().to_string();
            if seen.insert(p.clone()) {
                params.push(p);
            }
        }
    }

    // Match URLSearchParams.get("param")
    let get_re = Regex::new(r#"\.get\(\s*['"](\w{2,30})['"]\s*\)"#).unwrap();
    for cap in get_re.captures_iter(js_source) {
        if let Some(m) = cap.get(1) {
            let p = m.as_str().to_string();
            if seen.insert(p.clone()) {
                params.push(p);
            }
        }
    }

    // Match params["name"] or params.name patterns
    let bracket_re = Regex::new(r#"params?\[['"](\w{2,30})['"]\]"#).unwrap();
    for cap in bracket_re.captures_iter(js_source) {
        if let Some(m) = cap.get(1) {
            let p = m.as_str().to_string();
            if seen.insert(p.clone()) {
                params.push(p);
            }
        }
    }

    // Match request.body.param or req.query.param
    let dot_re = Regex::new(r#"(?:req|request)\.(?:body|query|params)\.(\w{2,30})"#).unwrap();
    for cap in dot_re.captures_iter(js_source) {
        if let Some(m) = cap.get(1) {
            let p = m.as_str().to_string();
            if seen.insert(p.clone()) {
                params.push(p);
            }
        }
    }

    params
}

/// Extract parameter names from HTML comments
pub fn extract_params_from_comments(html: &str) -> Vec<String> {
    let mut params = Vec::new();
    let comment_re = Regex::new(r"<!--(.*?)-->").unwrap();
    let param_re = Regex::new(r#"(\w{2,30})\s*="#).unwrap();

    for cap in comment_re.captures_iter(html) {
        if let Some(comment) = cap.get(1) {
            for param_cap in param_re.captures_iter(comment.as_str()) {
                if let Some(m) = param_cap.get(1) {
                    params.push(m.as_str().to_string());
                }
            }
        }
    }

    params
}
