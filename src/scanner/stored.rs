use async_trait::async_trait;
use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::debug;

use crate::http::client::HttpClient;
use crate::payloads::engine::PayloadEngine;
use crate::scanner::context::detect_context;
use crate::scanner::traits::*;

pub struct StoredScanner {
    injected_canaries: Arc<DashMap<String, StoredInjectionRecord>>,
}

#[derive(Debug, Clone)]
pub(crate) struct StoredInjectionRecord {
    injection_url: String,
    injection_point: InjectionPoint,
    payload: String,
}

impl StoredScanner {
    pub fn new() -> Self {
        Self {
            injected_canaries: Arc::new(DashMap::new()),
        }
    }

    pub fn canaries(&self) -> Arc<DashMap<String, StoredInjectionRecord>> {
        self.injected_canaries.clone()
    }
}

#[async_trait]
impl Scanner for StoredScanner {
    fn name(&self) -> &'static str {
        "Stored XSS Scanner"
    }

    fn scanner_type(&self) -> ScannerType {
        ScannerType::Stored
    }

    async fn scan(
        &self,
        target: &CrawlResult,
        payload_engine: &PayloadEngine,
        http_client: &HttpClient,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Phase 1: Inject payloads via forms — rotate across ALL eligible fields
        // Test both POST and GET forms (GET can store via search history, logs, etc.)
        for form in &target.forms {

            let injectable_fields: Vec<&FormField> = form
                .fields
                .iter()
                .filter(|f| {
                    matches!(
                        f.field_type.as_str(),
                        "text" | "textarea" | "hidden" | "email" | "search" | "url" | "tel"
                    )
                })
                .collect();

            let payloads = payload_engine.stored_payloads(None);

            // Test each injectable field with a payload (rotate fields, not just first)
            for (i, target_field) in injectable_fields.iter().enumerate() {
                let gp = match payloads.get(i % payloads.len().max(1)) {
                    Some(p) => p,
                    None => continue,
                };

                let mut form_data = HashMap::new();
                for field in &form.fields {
                    if field.name == target_field.name {
                        form_data.insert(field.name.clone(), gp.payload.clone());
                    } else {
                        form_data.insert(
                            field.name.clone(),
                            field.value.clone().unwrap_or_else(|| "test".to_string()),
                        );
                    }
                }

                let submit_result = if form.method == "GET" {
                    let mut url = match url::Url::parse(&form.action) {
                        Ok(u) => u,
                        Err(_) => continue,
                    };
                    for (k, v) in &form_data {
                        url.query_pairs_mut().append_pair(k, v);
                    }
                    http_client.get(url.as_str()).await
                } else {
                    http_client.post_form(&form.action, &form_data).await
                };
                if let Ok(_resp) = submit_result {
                    self.injected_canaries.insert(
                        gp.canary.clone(),
                        StoredInjectionRecord {
                            injection_url: form.action.clone(),
                            injection_point: InjectionPoint {
                                name: target_field.name.clone(),
                                location: ParamLocation::Body,
                                original_value: None,
                                context: None,
                            },
                            payload: gp.payload.clone(),
                        },
                    );
                }
            }
        }

        // Phase 2: Revisit the page with cache-busting to check for stored payloads
        // Add cache-busting param + headers to avoid CDN/browser cached responses
        let revisit_url = {
            let mut u = target.url.clone();
            u.query_pairs_mut().append_pair("_fxss_nocache", &format!("{}", std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()));
            u
        };
        let cache_headers = vec![
            ("Cache-Control".to_string(), "no-cache, no-store".to_string()),
            ("Pragma".to_string(), "no-cache".to_string()),
        ];
        if let Ok(resp) = http_client.request("GET", revisit_url.as_str(), Some(&cache_headers), None).await {
            if let Ok(body) = resp.text().await {
                for entry in self.injected_canaries.iter() {
                    let canary = entry.key();
                    let record = entry.value();

                    if let Some(canary_pos) = body.find(canary.as_str()) {
                        let context = detect_context(&body, canary_pos);
                        let evidence = extract_evidence(&body, canary_pos, 100);

                        debug!(
                            "Stored XSS found: canary {} on page {} (injected via {})",
                            canary, target.url, record.injection_url
                        );

                        findings.push(Finding::new(
                            ScannerType::Stored,
                            Severity::High,
                            Confidence::High,
                            target.url.to_string(),
                            record.injection_point.clone(),
                            record.payload.clone(),
                            evidence,
                            RequestRecord {
                                method: "POST".to_string(),
                                url: record.injection_url.clone(),
                                headers: Vec::new(),
                                body: None,
                            },
                            200,
                            Some(context),
                        ));
                    }
                }
            }
        }

        findings
    }
}

fn extract_evidence(body: &str, pos: usize, window: usize) -> String {
    let start = pos.saturating_sub(window);
    let end = (pos + window).min(body.len());
    body[start..end].to_string()
}
