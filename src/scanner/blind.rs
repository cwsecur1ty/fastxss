use async_trait::async_trait;
use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::debug;

use crate::http::client::HttpClient;
use crate::payloads::engine::PayloadEngine;
use crate::scanner::traits::*;

pub struct BlindScanner {
    callback_url: String,
    token_map: Arc<DashMap<String, BlindInjectionRecord>>,
}

#[derive(Debug, Clone)]
pub struct BlindInjectionRecord {
    pub url: String,
    pub injection_point: InjectionPoint,
    pub payload: String,
}

impl BlindScanner {
    pub fn new(callback_host: &str, callback_port: u16) -> Self {
        Self {
            callback_url: format!("http://{}:{}", callback_host, callback_port),
            token_map: Arc::new(DashMap::new()),
        }
    }

    pub fn token_map(&self) -> Arc<DashMap<String, BlindInjectionRecord>> {
        self.token_map.clone()
    }
}

#[async_trait]
impl Scanner for BlindScanner {
    fn name(&self) -> &'static str {
        "Blind/OOB XSS Scanner"
    }

    fn scanner_type(&self) -> ScannerType {
        ScannerType::Blind
    }

    async fn scan(
        &self,
        target: &CrawlResult,
        payload_engine: &PayloadEngine,
        http_client: &HttpClient,
    ) -> Vec<Finding> {
        let payloads = payload_engine.blind_payloads(&self.callback_url);

        // Inject blind payloads into all form fields
        for form in &target.forms {
            for gp in payloads.iter().take(15) {
                let mut form_data = HashMap::new();

                for field in &form.fields {
                    if field.field_type == "text"
                        || field.field_type == "textarea"
                        || field.field_type == "hidden"
                        || field.field_type == "email"
                        || field.field_type == "search"
                    {
                        form_data.insert(field.name.clone(), gp.payload.clone());
                    } else {
                        form_data.insert(
                            field.name.clone(),
                            field.value.clone().unwrap_or_else(|| "test".to_string()),
                        );
                    }
                }

                // Track this injection
                for field in &form.fields {
                    self.token_map.insert(
                        gp.canary.clone(),
                        BlindInjectionRecord {
                            url: form.action.clone(),
                            injection_point: InjectionPoint {
                                name: field.name.clone(),
                                location: ParamLocation::Body,
                                original_value: None,
                                context: None,
                            },
                            payload: gp.payload.clone(),
                        },
                    );
                }

                // Submit the form
                let result = if form.method == "POST" {
                    http_client.post_form(&form.action, &form_data).await
                } else {
                    let mut url = match url::Url::parse(&form.action) {
                        Ok(u) => u,
                        Err(_) => continue,
                    };
                    for (k, v) in &form_data {
                        url.query_pairs_mut().append_pair(k, v);
                    }
                    http_client.get(url.as_str()).await
                };

                if result.is_ok() {
                    debug!(
                        "Blind XSS payload injected at {} with canary {}",
                        form.action, gp.canary
                    );
                }
            }
        }

        // Inject via query parameters
        for point in &target.params {
            if point.location == ParamLocation::Query {
                for gp in payloads.iter().take(10) {
                    let test_url =
                        crate::utils::url::set_query_param(&target.url, &point.name, &gp.payload);

                    self.token_map.insert(
                        gp.canary.clone(),
                        BlindInjectionRecord {
                            url: test_url.to_string(),
                            injection_point: point.clone(),
                            payload: gp.payload.clone(),
                        },
                    );

                    let _ = http_client.get(test_url.as_str()).await;
                }
            }
        }

        // Inject via headers
        for gp in payloads.iter().take(10) {
            let headers = vec![
                ("User-Agent".to_string(), gp.payload.clone()),
                ("Referer".to_string(), gp.payload.clone()),
                ("X-Forwarded-For".to_string(), gp.payload.clone()),
            ];

            self.token_map.insert(
                gp.canary.clone(),
                BlindInjectionRecord {
                    url: target.url.to_string(),
                    injection_point: InjectionPoint {
                        name: "Header".to_string(),
                        location: ParamLocation::Header,
                        original_value: None,
                        context: None,
                    },
                    payload: gp.payload.clone(),
                },
            );

            let _ = http_client
                .request("GET", target.url.as_str(), Some(&headers), None)
                .await;
        }

        // Findings from blind XSS come through the callback server, not here
        Vec::new()
    }
}
