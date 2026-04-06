use tracing::{debug, info};

use crate::http::client::HttpClient;
use crate::utils::url::set_query_param;

#[derive(Debug, Clone)]
pub struct WafResult {
    pub detected: bool,
    pub waf_type: Option<String>,
    pub confidence: f32,
}

impl WafResult {
    pub fn none() -> Self {
        Self {
            detected: false,
            waf_type: None,
            confidence: 0.0,
        }
    }

    pub fn summary(&self) -> String {
        if self.detected {
            format!(
                "{} (confidence: {:.0}%)",
                self.waf_type.as_deref().unwrap_or("Unknown WAF"),
                self.confidence * 100.0
            )
        } else {
            "None detected".to_string()
        }
    }
}

pub struct WafDetector {
    client: HttpClient,
}

impl WafDetector {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    /// Detect WAF by sending a known-bad payload and analyzing the response
    pub async fn detect(&self, target_url: &url::Url) -> WafResult {
        // Phase 1: Check baseline response headers for WAF signatures
        let baseline_result = self.check_headers(target_url).await;
        if baseline_result.detected {
            return baseline_result;
        }

        // Phase 2: Send a malicious payload and check if it's blocked
        let test_url = set_query_param(target_url, "fxsswaftest", "<script>alert(1)</script>");
        match self.client.get(test_url.as_str()).await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let headers = resp.headers().clone();
                let body = resp.text().await.unwrap_or_default();

                // Check response for WAF indicators
                self.analyze_response(status, &headers, &body)
            }
            Err(_) => WafResult::none(),
        }
    }

    async fn check_headers(&self, target_url: &url::Url) -> WafResult {
        let resp = match self.client.get(target_url.as_str()).await {
            Ok(r) => r,
            Err(_) => return WafResult::none(),
        };

        let headers = resp.headers();

        // Cloudflare
        if headers.contains_key("cf-ray") || headers.contains_key("cf-cache-status") {
            return WafResult {
                detected: true,
                waf_type: Some("Cloudflare".to_string()),
                confidence: 0.95,
            };
        }

        // Akamai
        if headers.get("server").and_then(|v| v.to_str().ok()).map_or(false, |s| s.contains("AkamaiGHost")) {
            return WafResult {
                detected: true,
                waf_type: Some("Akamai".to_string()),
                confidence: 0.9,
            };
        }

        // Sucuri
        if headers.contains_key("x-sucuri-id") || headers.contains_key("x-sucuri-cache") {
            return WafResult {
                detected: true,
                waf_type: Some("Sucuri".to_string()),
                confidence: 0.95,
            };
        }

        // AWS WAF / CloudFront
        if headers.contains_key("x-amzn-requestid") || headers.contains_key("x-amz-cf-id") {
            return WafResult {
                detected: true,
                waf_type: Some("AWS WAF/CloudFront".to_string()),
                confidence: 0.7,
            };
        }

        // Imperva / Incapsula
        if headers.contains_key("x-iinfo") || headers.get("set-cookie").and_then(|v| v.to_str().ok()).map_or(false, |s| s.contains("incap_ses") || s.contains("visid_incap")) {
            return WafResult {
                detected: true,
                waf_type: Some("Imperva/Incapsula".to_string()),
                confidence: 0.9,
            };
        }

        // F5 BIG-IP
        if headers.get("server").and_then(|v| v.to_str().ok()).map_or(false, |s| s.contains("BIG-IP") || s.contains("BigIP")) {
            return WafResult {
                detected: true,
                waf_type: Some("F5 BIG-IP".to_string()),
                confidence: 0.9,
            };
        }

        WafResult::none()
    }

    fn analyze_response(
        &self,
        status: u16,
        headers: &reqwest::header::HeaderMap,
        body: &str,
    ) -> WafResult {
        let body_lower = body.to_lowercase();

        // Cloudflare block page
        if body_lower.contains("attention required") && body_lower.contains("cloudflare") {
            return WafResult {
                detected: true,
                waf_type: Some("Cloudflare".to_string()),
                confidence: 0.95,
            };
        }

        // ModSecurity
        if body_lower.contains("modsecurity") || body_lower.contains("mod_security") {
            return WafResult {
                detected: true,
                waf_type: Some("ModSecurity".to_string()),
                confidence: 0.9,
            };
        }

        // AWS WAF
        if status == 403 && body_lower.contains("request blocked") {
            return WafResult {
                detected: true,
                waf_type: Some("AWS WAF".to_string()),
                confidence: 0.7,
            };
        }

        // Imperva
        if body_lower.contains("incapsula incident") || body_lower.contains("imperva") {
            return WafResult {
                detected: true,
                waf_type: Some("Imperva".to_string()),
                confidence: 0.9,
            };
        }

        // Sucuri
        if body_lower.contains("sucuri website firewall") {
            return WafResult {
                detected: true,
                waf_type: Some("Sucuri".to_string()),
                confidence: 0.95,
            };
        }

        // Wordfence
        if body_lower.contains("wordfence") || body_lower.contains("generated by wordfence") {
            return WafResult {
                detected: true,
                waf_type: Some("Wordfence".to_string()),
                confidence: 0.9,
            };
        }

        // Generic WAF detection (403 on payload but 200 on baseline)
        if status == 403 || status == 406 || status == 501 {
            debug!("Potential WAF: got {} on payload test", status);
            return WafResult {
                detected: true,
                waf_type: Some("Unknown WAF".to_string()),
                confidence: 0.5,
            };
        }

        WafResult::none()
    }
}
