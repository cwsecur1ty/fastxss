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

        // Phase 1: Inject payloads via forms (POST forms are primary stored XSS vectors)
        for form in &target.forms {
            if form.method != "POST" {
                continue;
            }

            let payloads = payload_engine.stored_payloads(None);

            for gp in payloads.iter().take(3) {
                let mut form_data = HashMap::new();
                let mut injected_field = None;

                for field in &form.fields {
                    if field.field_type == "text"
                        || field.field_type == "textarea"
                        || field.field_type == "hidden"
                    {
                        if injected_field.is_none() {
                            form_data.insert(field.name.clone(), gp.payload.clone());
                            injected_field = Some(field.name.clone());
                        } else {
                            form_data.insert(
                                field.name.clone(),
                                field.value.clone().unwrap_or_else(|| "test".to_string()),
                            );
                        }
                    } else {
                        form_data.insert(
                            field.name.clone(),
                            field.value.clone().unwrap_or_else(|| "test".to_string()),
                        );
                    }
                }

                if let Some(field_name) = injected_field {
                    if let Ok(_resp) = http_client.post_form(&form.action, &form_data).await {
                        self.injected_canaries.insert(
                            gp.canary.clone(),
                            StoredInjectionRecord {
                                injection_url: form.action.clone(),
                                injection_point: InjectionPoint {
                                    name: field_name,
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
        }

        // Phase 2: Revisit the page to check for stored payloads
        if let Ok(resp) = http_client.get(target.url.as_str()).await {
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
