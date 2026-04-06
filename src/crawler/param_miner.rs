use anyhow::Result;
use regex::Regex;
use std::path::Path;
use tokio::sync::Semaphore;
use std::sync::Arc;
use tracing::{debug, info};
use url::Url;

use crate::http::client::HttpClient;
use crate::scanner::traits::{InjectionPoint, ParamLocation};

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
}

impl ParamMiner {
    pub fn new(client: HttpClient, concurrency: usize, custom_wordlist: Option<&Path>) -> Self {
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
        }
    }

    /// Mine hidden parameters on a page by comparing response sizes
    pub async fn mine(&self, base_url: &Url) -> Vec<InjectionPoint> {
        // Get baseline response + extract JS params in one fetch
        let resp = match self.client.get(base_url.as_str()).await {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        let body = match resp.text().await {
            Ok(b) => b,
            Err(_) => return Vec::new(),
        };
        let baseline_len = body.len();

        // Extract params from JS source
        let js_params = extract_params_from_js(&body);

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

            handles.push(tokio::spawn(async move {
                let _permit = permit;
                test_param_static(&client, &url, &param, baseline).await
            }));
        }

        let mut discovered = Vec::new();
        for handle in handles {
            if let Ok(Some(point)) = handle.await {
                discovered.push(point);
            }
        }

        if !discovered.is_empty() {
            info!("Parameter mining found {} hidden params on {}", discovered.len(), base_url);
        }

        discovered
    }

    async fn get_response_length(&self, url: &str) -> Option<usize> {
        let resp = self.client.get(url).await.ok()?;
        let body = resp.text().await.ok()?;
        Some(body.len())
    }

    async fn test_param(&self, base_url: &Url, param: &str, baseline_len: usize) -> Option<InjectionPoint> {
        test_param_static(&self.client, base_url, param, baseline_len).await
    }
}

async fn test_param_static(
    client: &HttpClient,
    base_url: &Url,
    param: &str,
    baseline_len: usize,
) -> Option<InjectionPoint> {
    let canary = "fxssmine1337";
    let mut test_url = base_url.clone();
    test_url.query_pairs_mut().append_pair(param, canary);

    let resp = client.get(test_url.as_str()).await.ok()?;
    let body = resp.text().await.ok()?;
    let test_len = body.len();

    // If response length differs significantly OR canary appears in response
    let len_diff = (test_len as isize - baseline_len as isize).unsigned_abs();
    let reflects = body.contains(canary);

    if reflects || len_diff > 50 {
        debug!(
            "Hidden param found: '{}' on {} (len diff: {}, reflects: {})",
            param, base_url, len_diff, reflects
        );
        return Some(InjectionPoint {
            name: param.to_string(),
            location: ParamLocation::Query,
            original_value: None,
            context: None,
        });
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
