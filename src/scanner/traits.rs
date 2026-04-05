use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::fmt;
use uuid::Uuid;

use crate::http::client::HttpClient;
use crate::payloads::engine::PayloadEngine;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum ScannerType {
    Reflected,
    Stored,
    Dom,
    Blind,
}

impl fmt::Display for ScannerType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScannerType::Reflected => write!(f, "Reflected"),
            ScannerType::Stored => write!(f, "Stored"),
            ScannerType::Dom => write!(f, "DOM-based"),
            ScannerType::Blind => write!(f, "Blind/OOB"),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum Confidence {
    Confirmed,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum ParamLocation {
    Query,
    Body,
    Header,
    Fragment,
    Cookie,
    Path,
}

#[derive(Debug, Clone, Serialize)]
pub enum HtmlContext {
    AttributeValue {
        tag: String,
        attr: String,
        quote: char,
    },
    TagBody {
        tag: String,
    },
    ScriptBlock,
    StyleBlock,
    Comment,
    Url,
    Plain,
}

#[derive(Debug, Clone, Serialize)]
pub struct InjectionPoint {
    pub name: String,
    pub location: ParamLocation,
    pub original_value: Option<String>,
    pub context: Option<HtmlContext>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FormData {
    pub action: String,
    pub method: String,
    pub fields: Vec<FormField>,
    pub enctype: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FormField {
    pub name: String,
    pub field_type: String,
    pub value: Option<String>,
    pub required: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CrawlResult {
    pub url: url::Url,
    pub method: String,
    pub params: Vec<InjectionPoint>,
    pub response_body: String,
    pub response_status: u16,
    pub forms: Vec<FormData>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RequestRecord {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub id: Uuid,
    pub scanner_type: ScannerType,
    pub severity: Severity,
    pub confidence: Confidence,
    pub url: String,
    pub injection_point: InjectionPoint,
    pub payload: String,
    pub evidence: String,
    pub request: RequestRecord,
    pub response_status: u16,
    pub context: Option<HtmlContext>,
    pub timestamp: DateTime<Utc>,
}

impl Finding {
    pub fn new(
        scanner_type: ScannerType,
        severity: Severity,
        confidence: Confidence,
        url: String,
        injection_point: InjectionPoint,
        payload: String,
        evidence: String,
        request: RequestRecord,
        response_status: u16,
        context: Option<HtmlContext>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            scanner_type,
            severity,
            confidence,
            url,
            injection_point,
            payload,
            evidence,
            request,
            response_status,
            context,
            timestamp: Utc::now(),
        }
    }
}

#[async_trait]
pub trait Scanner: Send + Sync {
    fn name(&self) -> &'static str;
    fn scanner_type(&self) -> ScannerType;

    async fn scan(
        &self,
        target: &CrawlResult,
        payload_engine: &PayloadEngine,
        http_client: &HttpClient,
    ) -> Vec<Finding>;
}
