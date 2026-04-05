use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info};

use crate::http::client::HttpClient;
use crate::payloads::engine::{GeneratedPayload, PayloadEngine};
use crate::scanner::context::{detect_context, is_executable_context};
use crate::scanner::dom::DomScanner;
use crate::scanner::traits::*;
use crate::utils::url::set_query_param;

pub struct ReflectedScanner {
    dom_verifier: Option<Arc<Mutex<DomScanner>>>,
}

impl ReflectedScanner {
    pub fn new() -> Self {
        Self { dom_verifier: None }
    }

    pub fn with_dom_verifier(dom: Arc<Mutex<DomScanner>>) -> Self {
        Self {
            dom_verifier: Some(dom),
        }
    }
}

/// Security-relevant response headers
struct ResponseMeta {
    has_csp: bool,
    csp_blocks_inline: bool,
    has_xss_protection: bool,
}

fn extract_response_meta(headers: &reqwest::header::HeaderMap) -> ResponseMeta {
    let csp = headers
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let has_csp = !csp.is_empty();
    let csp_blocks_inline = has_csp
        && !csp.contains("unsafe-inline")
        && (csp.contains("script-src") || csp.contains("default-src"));

    let xss_prot = headers
        .get("x-xss-protection")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let has_xss_protection = xss_prot.starts_with('1');

    ResponseMeta {
        has_csp,
        csp_blocks_inline,
        has_xss_protection,
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
                ParamLocation::Cookie => {
                    self.scan_cookie(target, injection_point, payload_engine, http_client)
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
            let resp_meta = extract_response_meta(resp.headers());
            let resp_body = match resp.text().await {
                Ok(b) => b,
                Err(_) => continue,
            };

            if let Some(pos) = resp_body.find(&gp.canary) {
                let resp_context = detect_context(&resp_body, pos);
                let (mut severity, mut confidence) =
                    assess_reflected_severity(&resp_body, gp, &resp_context, Some(&resp_meta));

                // Browser-based execution verification for high-severity findings
                if severity >= Severity::Medium {
                    if let Some(ref dom) = self.dom_verifier {
                        let guard = dom.lock().await;
                        if guard.is_available() {
                            if guard.verify_execution(test_url.as_str()).await {
                                severity = Severity::High;
                                confidence = Confidence::Confirmed;
                                info!("Execution CONFIRMED for {} param '{}'", target.url, point.name);
                            }
                        }
                    }
                }

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

                break;
            }
        }

        // If no targeted payloads worked but reflection exists, report as low
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
                let (severity, confidence) = assess_reflected_severity(&resp_body, gp, &resp_context, None);
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
                let (severity, confidence) = assess_reflected_severity(&resp_body, gp, &resp_context, None);
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

    async fn scan_cookie(
        &self,
        target: &CrawlResult,
        point: &InjectionPoint,
        engine: &PayloadEngine,
        client: &HttpClient,
    ) -> Vec<Finding> {
        // Phase 1: Probe cookie reflection
        let probe = engine.reflection_probe();
        let cookie_header = format!("{}={}", point.name, probe.payload);
        let headers = vec![("Cookie".to_string(), cookie_header.clone())];

        let resp = match client
            .request("GET", target.url.as_str(), Some(&headers), None)
            .await
        {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };

        let _status = resp.status().as_u16();
        let body = match resp.text().await {
            Ok(b) => b,
            Err(_) => return Vec::new(),
        };

        let canary_pos = match body.find(&probe.canary) {
            Some(pos) => pos,
            None => return Vec::new(),
        };

        // Phase 2: targeted payloads
        let context = detect_context(&body, canary_pos);
        info!(
            "Cookie reflection found: '{}' on {} (context: {:?})",
            point.name,
            target.url,
            context_name(&context)
        );

        let payloads = engine.reflected_payloads_for_context(&context);
        let mut findings = Vec::new();

        for gp in payloads.iter().take(10) {
            let cookie_val = format!("{}={}", point.name, gp.payload);
            let headers = vec![("Cookie".to_string(), cookie_val)];

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
                let (severity, confidence) =
                    assess_reflected_severity(&resp_body, gp, &resp_context, None);
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
                        headers: vec![("Cookie".to_string(), format!("{}=<payload>", point.name))],
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
    meta: Option<&ResponseMeta>,
) -> (Severity, Confidence) {
    let full_payload_reflected = body.contains(&payload.raw_payload);

    let (mut severity, mut confidence) = match context {
        HtmlContext::ScriptBlock | HtmlContext::ScriptString { .. } | HtmlContext::TemplateLiteral => {
            if full_payload_reflected {
                (Severity::High, Confidence::High)
            } else {
                (Severity::Medium, Confidence::Medium)
            }
        }
        HtmlContext::AttributeValue { attr, .. } | HtmlContext::UnquotedAttributeValue { attr, .. }
            if attr.starts_with("on") =>
        {
            if full_payload_reflected {
                (Severity::High, Confidence::High)
            } else {
                (Severity::Medium, Confidence::Medium)
            }
        }
        HtmlContext::AttributeValue { attr, .. } | HtmlContext::UnquotedAttributeValue { attr, .. }
            if attr == "href" || attr == "src" || attr == "action" =>
        {
            (Severity::Medium, Confidence::Medium)
        }
        HtmlContext::SvgContext => (Severity::High, Confidence::High),
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
    };

    // Downgrade if CSP blocks inline scripts
    if let Some(meta) = meta {
        if meta.csp_blocks_inline && severity == Severity::High {
            severity = Severity::Medium;
            confidence = Confidence::Medium;
        }
    }

    (severity, confidence)
}

fn extract_evidence(body: &str, pos: usize, window: usize) -> String {
    let start = pos.saturating_sub(window);
    let end = (pos + window).min(body.len());
    body[start..end].to_string()
}

fn context_name(ctx: &HtmlContext) -> &'static str {
    match ctx {
        HtmlContext::AttributeValue { .. } => "attribute",
        HtmlContext::UnquotedAttributeValue { .. } => "unquoted_attr",
        HtmlContext::TagBody { .. } => "tag_body",
        HtmlContext::ScriptBlock => "script",
        HtmlContext::ScriptString { .. } => "script_string",
        HtmlContext::TemplateLiteral => "template_literal",
        HtmlContext::StyleBlock => "style",
        HtmlContext::Comment => "comment",
        HtmlContext::SvgContext => "svg",
        HtmlContext::Url => "url",
        HtmlContext::Plain => "plain",
    }
}
