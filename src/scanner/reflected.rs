use async_trait::async_trait;
use std::collections::HashMap;
use tracing::{debug, info};

use crate::http::client::HttpClient;
use crate::payloads::engine::{GeneratedPayload, PayloadEngine};
use crate::scanner::context::{detect_context, is_executable_context};
use crate::scanner::traits::*;
use crate::utils::url::set_query_param;

pub struct ReflectedScanner;

impl ReflectedScanner {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Scanner for ReflectedScanner {
    fn name(&self) -> &'static str {
        "Reflected XSS Scanner"
    }

    fn scanner_type(&self) -> ScannerType {
        ScannerType::Reflected
    }

    async fn scan(
        &self,
        target: &CrawlResult,
        payload_engine: &PayloadEngine,
        http_client: &HttpClient,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for injection_point in &target.params {
            let point_findings = match injection_point.location {
                ParamLocation::Query => {
                    self.scan_query_param(target, injection_point, payload_engine, http_client)
                        .await
                }
                ParamLocation::Body => {
                    self.scan_body_param(target, injection_point, payload_engine, http_client)
                        .await
                }
                ParamLocation::Header => {
                    self.scan_header(target, injection_point, payload_engine, http_client)
                        .await
                }
                _ => Vec::new(),
            };
            findings.extend(point_findings);
        }

        findings
    }
}

impl ReflectedScanner {
    /// Phase 1: Send a canary probe to check if the parameter reflects at all.
    /// Phase 2: If it reflects, detect context and send targeted payloads.
    async fn scan_query_param(
        &self,
        target: &CrawlResult,
        point: &InjectionPoint,
        engine: &PayloadEngine,
        client: &HttpClient,
    ) -> Vec<Finding> {
        // Phase 1: Reflection probe
        let probe = engine.reflection_probe();
        let probe_url = set_query_param(&target.url, &point.name, &probe.payload);
        let resp = match client.get(probe_url.as_str()).await {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };

        let status = resp.status().as_u16();
        let body = match resp.text().await {
            Ok(b) => b,
            Err(_) => return Vec::new(),
        };

        let canary_pos = match body.find(&probe.canary) {
            Some(pos) => pos,
            None => return Vec::new(), // Param doesn't reflect - skip entirely
        };

        // Phase 2: Param reflects! Detect context and send targeted payloads
        let context = detect_context(&body, canary_pos);
        info!(
            "Reflection found in param '{}' on {} (context: {:?})",
            point.name,
            target.url,
            context_name(&context)
        );

        let payloads = engine.reflected_payloads_for_context(&context);
        let mut findings = Vec::new();

        for gp in &payloads {
            let test_url = set_query_param(&target.url, &point.name, &gp.payload);
            let resp = match client.get(test_url.as_str()).await {
                Ok(r) => r,
                Err(_) => continue,
            };

            let resp_status = resp.status().as_u16();
            let resp_body = match resp.text().await {
                Ok(b) => b,
                Err(_) => continue,
            };

            if let Some(pos) = resp_body.find(&gp.canary) {
                let resp_context = detect_context(&resp_body, pos);
                let (severity, confidence) = assess_reflected_severity(&resp_body, gp, &resp_context);

                debug!(
                    "Reflected XSS: {} param '{}' [{}]",
                    target.url, point.name, severity
                );

                let evidence = extract_evidence(&resp_body, pos, 100);

                findings.push(Finding::new(
                    ScannerType::Reflected,
                    severity,
                    confidence,
                    test_url.to_string(),
                    point.clone(),
                    gp.payload.clone(),
                    evidence,
                    RequestRecord {
                        method: "GET".to_string(),
                        url: test_url.to_string(),
                        headers: Vec::new(),
                        body: None,
                    },
                    resp_status,
                    Some(resp_context),
                ));

                // Found one confirmed payload, stop testing this param
                break;
            }
        }

        // If no targeted payloads worked but reflection exists, report as info
        if findings.is_empty() {
            findings.push(Finding::new(
                ScannerType::Reflected,
                Severity::Low,
                Confidence::Low,
                probe_url.to_string(),
                point.clone(),
                probe.payload,
                extract_evidence(&body, canary_pos, 100),
                RequestRecord {
                    method: "GET".to_string(),
                    url: probe_url.to_string(),
                    headers: Vec::new(),
                    body: None,
                },
                status,
                Some(context),
            ));
        }

        findings
    }

    async fn scan_body_param(
        &self,
        target: &CrawlResult,
        point: &InjectionPoint,
        engine: &PayloadEngine,
        client: &HttpClient,
    ) -> Vec<Finding> {
        let form = match target.forms.iter().find(|f| {
            f.fields.iter().any(|field| field.name == point.name)
        }) {
            Some(f) => f,
            None => return Vec::new(),
        };

        // Phase 1: Reflection probe via form submission
        let probe = engine.reflection_probe();
        let mut form_data = HashMap::new();
        for field in &form.fields {
            if field.name == point.name {
                form_data.insert(field.name.clone(), probe.payload.clone());
            } else {
                form_data.insert(
                    field.name.clone(),
                    field.value.clone().unwrap_or_else(|| "test".to_string()),
                );
            }
        }

        let resp = if form.method == "POST" {
            client.post_form(&form.action, &form_data).await
        } else {
            let mut url = match url::Url::parse(&form.action) {
                Ok(u) => u,
                Err(_) => return Vec::new(),
            };
            for (k, v) in &form_data {
                url.query_pairs_mut().append_pair(k, v);
            }
            client.get(url.as_str()).await
        };

        let resp = match resp {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };

        let status = resp.status().as_u16();
        let body = match resp.text().await {
            Ok(b) => b,
            Err(_) => return Vec::new(),
        };

        let canary_pos = match body.find(&probe.canary) {
            Some(pos) => pos,
            None => return Vec::new(),
        };

        // Phase 2: Context-targeted payloads
        let context = detect_context(&body, canary_pos);
        info!(
            "Reflection found in form field '{}' on {} (context: {:?})",
            point.name,
            form.action,
            context_name(&context)
        );

        let payloads = engine.reflected_payloads_for_context(&context);
        let mut findings = Vec::new();

        for gp in &payloads {
            let mut test_data = HashMap::new();
            for field in &form.fields {
                if field.name == point.name {
                    test_data.insert(field.name.clone(), gp.payload.clone());
                } else {
                    test_data.insert(
                        field.name.clone(),
                        field.value.clone().unwrap_or_else(|| "test".to_string()),
                    );
                }
            }

            let resp = if form.method == "POST" {
                client.post_form(&form.action, &test_data).await
            } else {
                let mut url = match url::Url::parse(&form.action) {
                    Ok(u) => u,
                    Err(_) => continue,
                };
                for (k, v) in &test_data {
                    url.query_pairs_mut().append_pair(k, v);
                }
                client.get(url.as_str()).await
            };

            let resp = match resp {
                Ok(r) => r,
                Err(_) => continue,
            };

            let resp_status = resp.status().as_u16();
            let resp_body = match resp.text().await {
                Ok(b) => b,
                Err(_) => continue,
            };

            if let Some(pos) = resp_body.find(&gp.canary) {
                let resp_context = detect_context(&resp_body, pos);
                let (severity, confidence) = assess_reflected_severity(&resp_body, gp, &resp_context);
                let evidence = extract_evidence(&resp_body, pos, 100);

                findings.push(Finding::new(
                    ScannerType::Reflected,
                    severity,
                    confidence,
                    form.action.clone(),
                    point.clone(),
                    gp.payload.clone(),
                    evidence,
                    RequestRecord {
                        method: form.method.clone(),
                        url: form.action.clone(),
                        headers: Vec::new(),
                        body: Some(serde_json::to_string(&test_data).unwrap_or_default()),
                    },
                    resp_status,
                    Some(resp_context),
                ));

                break;
            }
        }

        findings
    }

    async fn scan_header(
        &self,
        target: &CrawlResult,
        point: &InjectionPoint,
        engine: &PayloadEngine,
        client: &HttpClient,
    ) -> Vec<Finding> {
        // Phase 1: Probe header reflection
        let probe = engine.reflection_probe();
        let headers = vec![(point.name.clone(), probe.payload.clone())];

        let resp = match client
            .request("GET", target.url.as_str(), Some(&headers), None)
            .await
        {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };

        let status = resp.status().as_u16();
        let body = match resp.text().await {
            Ok(b) => b,
            Err(_) => return Vec::new(),
        };

        let canary_pos = match body.find(&probe.canary) {
            Some(pos) => pos,
            None => return Vec::new(), // Header doesn't reflect
        };

        // Phase 2: targeted payloads
        let context = detect_context(&body, canary_pos);
        let payloads = engine.reflected_payloads_for_context(&context);
        let mut findings = Vec::new();

        for gp in payloads.iter().take(10) {
            let headers = vec![(point.name.clone(), gp.payload.clone())];

            let resp = match client
                .request("GET", target.url.as_str(), Some(&headers), None)
                .await
            {
                Ok(r) => r,
                Err(_) => continue,
            };

            let resp_status = resp.status().as_u16();
            let resp_body = match resp.text().await {
                Ok(b) => b,
                Err(_) => continue,
            };

            if let Some(pos) = resp_body.find(&gp.canary) {
                let resp_context = detect_context(&resp_body, pos);
                let (severity, confidence) = assess_reflected_severity(&resp_body, gp, &resp_context);
                let evidence = extract_evidence(&resp_body, pos, 100);

                findings.push(Finding::new(
                    ScannerType::Reflected,
                    severity,
                    confidence,
                    target.url.to_string(),
                    point.clone(),
                    gp.payload.clone(),
                    evidence,
                    RequestRecord {
                        method: "GET".to_string(),
                        url: target.url.to_string(),
                        headers,
                        body: None,
                    },
                    resp_status,
                    Some(resp_context),
                ));

                break;
            }
        }

        findings
    }
}

fn assess_reflected_severity(
    body: &str,
    payload: &GeneratedPayload,
    context: &HtmlContext,
) -> (Severity, Confidence) {
    let full_payload_reflected = body.contains(&payload.raw_payload);

    match context {
        HtmlContext::ScriptBlock => {
            if full_payload_reflected {
                (Severity::High, Confidence::High)
            } else {
                (Severity::Medium, Confidence::Medium)
            }
        }
        HtmlContext::AttributeValue { attr, .. } if attr.starts_with("on") => {
            if full_payload_reflected {
                (Severity::High, Confidence::High)
            } else {
                (Severity::Medium, Confidence::Medium)
            }
        }
        HtmlContext::AttributeValue { attr, .. }
            if attr == "href" || attr == "src" || attr == "action" =>
        {
            (Severity::Medium, Confidence::Medium)
        }
        HtmlContext::Plain => {
            if full_payload_reflected {
                (Severity::Medium, Confidence::Medium)
            } else {
                (Severity::Low, Confidence::Low)
            }
        }
        HtmlContext::Comment => (Severity::Low, Confidence::Low),
        _ => {
            if is_executable_context(context) {
                (Severity::Medium, Confidence::Medium)
            } else {
                (Severity::Low, Confidence::Low)
            }
        }
    }
}

fn extract_evidence(body: &str, pos: usize, window: usize) -> String {
    let start = pos.saturating_sub(window);
    let end = (pos + window).min(body.len());
    body[start..end].to_string()
}

fn context_name(ctx: &HtmlContext) -> &'static str {
    match ctx {
        HtmlContext::AttributeValue { .. } => "attribute",
        HtmlContext::TagBody { .. } => "tag_body",
        HtmlContext::ScriptBlock => "script",
        HtmlContext::StyleBlock => "style",
        HtmlContext::Comment => "comment",
        HtmlContext::Url => "url",
        HtmlContext::Plain => "plain",
    }
}
