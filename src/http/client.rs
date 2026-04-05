use anyhow::{Context, Result};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

use crate::config::Config;
use crate::http::rate_limiter::RateLimiter;

#[derive(Clone)]
pub struct HttpClient {
    client: reqwest::Client,
    rate_limiter: Arc<RateLimiter>,
    delay_ms: u64,
    max_retries: u32,
}

impl HttpClient {
    pub fn new(config: &Config) -> Result<Self> {
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .cookie_store(true)
            .redirect(reqwest::redirect::Policy::limited(10))
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");

        if config.insecure {
            builder = builder.danger_accept_invalid_certs(true);
        }

        if let Some(ref proxy_url) = config.proxy {
            let proxy = reqwest::Proxy::all(proxy_url)
                .context("Invalid proxy URL")?;
            builder = builder.proxy(proxy);
        }

        let mut default_headers = HeaderMap::new();
        for header_str in &config.headers {
            if let Some((key, value)) = header_str.split_once(':') {
                let name = HeaderName::from_bytes(key.trim().as_bytes())
                    .context("Invalid header name")?;
                let val = HeaderValue::from_str(value.trim())
                    .context("Invalid header value")?;
                default_headers.insert(name, val);
            }
        }

        if let Some(ref cookie) = config.cookie {
            default_headers.insert(
                reqwest::header::COOKIE,
                HeaderValue::from_str(cookie).context("Invalid cookie value")?,
            );
        }

        if let Some(ref token) = config.bearer_token {
            default_headers.insert(
                reqwest::header::AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {}", token))
                    .context("Invalid bearer token")?,
            );
        }

        if !default_headers.is_empty() {
            builder = builder.default_headers(default_headers);
        }

        let client = builder.build().context("Failed to build HTTP client")?;
        let rate_limiter = Arc::new(RateLimiter::new(config.rate_limit));

        Ok(Self {
            client,
            rate_limiter,
            delay_ms: config.delay_ms,
            max_retries: config.max_retries,
        })
    }

    /// Execute a request with retry logic and exponential backoff.
    /// The `build_request` closure is called on each attempt to create a fresh RequestBuilder.
    async fn execute_with_retry(
        &self,
        build_request: impl Fn() -> reqwest::RequestBuilder,
    ) -> Result<reqwest::Response> {
        let mut last_err = None;

        for attempt in 0..=self.max_retries {
            if attempt > 0 {
                let delay = Duration::from_millis(500 * 2u64.pow(attempt - 1));
                debug!("Retry attempt {}/{} after {}ms", attempt, self.max_retries, delay.as_millis());
                tokio::time::sleep(delay).await;
            }

            self.rate_limiter.wait().await;
            if self.delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(self.delay_ms)).await;
            }

            match build_request().send().await {
                Ok(resp) if is_retryable_status(resp.status()) => {
                    let status = resp.status();
                    // Respect Retry-After header on 429
                    if let Some(wait) = parse_retry_after(resp.headers()) {
                        debug!("Server returned {}, Retry-After: {}s", status, wait.as_secs());
                        tokio::time::sleep(wait).await;
                    }
                    last_err = Some(anyhow::anyhow!("HTTP {} (retryable)", status));
                    if attempt == self.max_retries {
                        // Return the response on final attempt even if retryable status
                        // so caller can inspect the body/headers
                        // Need to re-send since we consumed this response
                        self.rate_limiter.wait().await;
                        if let Ok(final_resp) = build_request().send().await {
                            return Ok(final_resp);
                        }
                    }
                    continue;
                }
                Ok(resp) => return Ok(resp),
                Err(e) if is_retryable_error(&e) && attempt < self.max_retries => {
                    debug!("Request error (retryable): {}", e);
                    last_err = Some(e.into());
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("Max retries exceeded")))
    }

    pub async fn get(&self, url: &str) -> Result<reqwest::Response> {
        let url = url.to_string();
        self.execute_with_retry(|| self.client.get(&url)).await
    }

    pub async fn post_form(
        &self,
        url: &str,
        form_data: &HashMap<String, String>,
    ) -> Result<reqwest::Response> {
        let url = url.to_string();
        let data = form_data.clone();
        self.execute_with_retry(|| self.client.post(&url).form(&data)).await
    }

    pub async fn post_json(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> Result<reqwest::Response> {
        let url = url.to_string();
        let data = body.clone();
        self.execute_with_retry(|| self.client.post(&url).json(&data)).await
    }

    pub async fn request(
        &self,
        method: &str,
        url: &str,
        headers: Option<&[(String, String)]>,
        body: Option<&str>,
    ) -> Result<reqwest::Response> {
        let method_parsed: reqwest::Method = method.parse()?;
        let url = url.to_string();
        let headers_owned: Option<Vec<(String, String)>> = headers.map(|h| h.to_vec());
        let body_owned: Option<String> = body.map(|b| b.to_string());

        self.execute_with_retry(|| {
            let mut req = self.client.request(method_parsed.clone(), &url);
            if let Some(ref hdrs) = headers_owned {
                for (k, v) in hdrs {
                    req = req.header(k.as_str(), v.as_str());
                }
            }
            if let Some(ref b) = body_owned {
                req = req.body(b.clone());
            }
            req
        })
        .await
    }

    pub fn inner(&self) -> &reqwest::Client {
        &self.client
    }
}

fn is_retryable_status(status: reqwest::StatusCode) -> bool {
    matches!(status.as_u16(), 429 | 500 | 502 | 503 | 504)
}

fn is_retryable_error(e: &reqwest::Error) -> bool {
    e.is_timeout() || e.is_connect() || e.is_request()
}

fn parse_retry_after(headers: &HeaderMap) -> Option<Duration> {
    headers
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs)
}
