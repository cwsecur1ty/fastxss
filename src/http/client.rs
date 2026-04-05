use anyhow::{Context, Result};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::config::Config;
use crate::http::rate_limiter::RateLimiter;

#[derive(Clone)]
pub struct HttpClient {
    client: reqwest::Client,
    rate_limiter: Arc<RateLimiter>,
    delay_ms: u64,
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

        if !default_headers.is_empty() {
            builder = builder.default_headers(default_headers);
        }

        let client = builder.build().context("Failed to build HTTP client")?;
        let rate_limiter = Arc::new(RateLimiter::new(config.rate_limit));

        Ok(Self {
            client,
            rate_limiter,
            delay_ms: config.delay_ms,
        })
    }

    pub async fn get(&self, url: &str) -> Result<reqwest::Response> {
        self.rate_limiter.wait().await;
        if self.delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(self.delay_ms)).await;
        }
        let resp = self.client.get(url).send().await?;
        Ok(resp)
    }

    pub async fn post_form(
        &self,
        url: &str,
        form_data: &HashMap<String, String>,
    ) -> Result<reqwest::Response> {
        self.rate_limiter.wait().await;
        if self.delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(self.delay_ms)).await;
        }
        let resp = self.client.post(url).form(form_data).send().await?;
        Ok(resp)
    }

    pub async fn request(
        &self,
        method: &str,
        url: &str,
        headers: Option<&[(String, String)]>,
        body: Option<&str>,
    ) -> Result<reqwest::Response> {
        self.rate_limiter.wait().await;
        if self.delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(self.delay_ms)).await;
        }

        let method = method.parse::<reqwest::Method>()?;
        let mut req = self.client.request(method, url);

        if let Some(hdrs) = headers {
            for (k, v) in hdrs {
                req = req.header(k.as_str(), v.as_str());
            }
        }

        if let Some(b) = body {
            req = req.body(b.to_string());
        }

        let resp = req.send().await?;
        Ok(resp)
    }

    pub fn inner(&self) -> &reqwest::Client {
        &self.client
    }
}
