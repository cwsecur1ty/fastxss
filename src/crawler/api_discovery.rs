use anyhow::Result;
use tracing::{debug, info};
use url::Url;

use crate::http::client::HttpClient;
use crate::scanner::traits::{CrawlResult, FormData, InjectionPoint, ParamLocation};

const API_PATHS: &[&str] = &[
    "/api",
    "/api/",
    "/api/v1",
    "/api/v1/",
    "/api/v2",
    "/api/v2/",
    "/v1",
    "/v1/",
    "/v2",
    "/v2/",
    "/rest",
    "/rest/",
    "/graphql",
    "/gql",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/openapi.json",
    "/openapi.yaml",
    "/api-docs",
    "/api-docs/",
    "/api/swagger.json",
    "/api/openapi.json",
    "/_api",
    "/api/health",
    "/api/status",
    "/api/info",
    "/api/version",
];

pub struct ApiDiscovery {
    client: HttpClient,
}

impl ApiDiscovery {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    /// Probe common API paths and return discovered endpoints
    pub async fn discover(&self, base_url: &Url) -> Vec<DiscoveredEndpoint> {
        let mut endpoints = Vec::new();
        let scheme = base_url.scheme();
        let host = base_url.host_str().unwrap_or("");
        let port = base_url
            .port()
            .map(|p| format!(":{}", p))
            .unwrap_or_default();
        let base = format!("{}://{}{}", scheme, host, port);

        for path in API_PATHS {
            let url = format!("{}{}", base, path);
            match self.client.get(&url).await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    if status == 200 || status == 301 || status == 302 {
                        let content_type = resp
                            .headers()
                            .get("content-type")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_string();
                        let body = resp.text().await.unwrap_or_default();

                        debug!("API endpoint found: {} ({})", url, status);

                        // Try to parse as Swagger/OpenAPI
                        if path.contains("swagger") || path.contains("openapi") {
                            if let Ok(spec_endpoints) = parse_openapi_spec(&body, &base) {
                                info!(
                                    "Parsed OpenAPI spec: {} endpoints found",
                                    spec_endpoints.len()
                                );
                                endpoints.extend(spec_endpoints);
                                continue;
                            }
                        }

                        endpoints.push(DiscoveredEndpoint {
                            url: url.clone(),
                            method: "GET".to_string(),
                            content_type,
                            params: Vec::new(),
                            is_json_api: body.starts_with('{') || body.starts_with('['),
                        });
                    }
                }
                Err(_) => continue,
            }
        }

        if !endpoints.is_empty() {
            info!(
                "API discovery found {} endpoints on {}",
                endpoints.len(),
                base
            );
        }

        endpoints
    }
}

#[derive(Debug, Clone)]
pub struct DiscoveredEndpoint {
    pub url: String,
    pub method: String,
    pub content_type: String,
    pub params: Vec<InjectionPoint>,
    pub is_json_api: bool,
}

impl DiscoveredEndpoint {
    pub fn to_crawl_result(&self) -> CrawlResult {
        CrawlResult {
            url: Url::parse(&self.url).unwrap_or_else(|_| Url::parse("http://localhost").unwrap()),
            method: self.method.clone(),
            params: self.params.clone(),
            response_body: String::new(),
            response_status: 200,
            forms: Vec::new(),
        }
    }
}

/// Parse an OpenAPI/Swagger JSON spec and extract endpoints with parameters
fn parse_openapi_spec(json_str: &str, base_url: &str) -> Result<Vec<DiscoveredEndpoint>> {
    let spec: serde_json::Value = serde_json::from_str(json_str)?;
    let mut endpoints = Vec::new();

    let paths = spec
        .get("paths")
        .and_then(|p| p.as_object())
        .ok_or_else(|| anyhow::anyhow!("No paths in spec"))?;

    for (path, methods) in paths {
        let methods_obj = match methods.as_object() {
            Some(m) => m,
            None => continue,
        };

        for (method, operation) in methods_obj {
            if !["get", "post", "put", "patch", "delete"].contains(&method.as_str()) {
                continue;
            }

            let mut params = Vec::new();

            // Extract parameters
            if let Some(parameters) = operation.get("parameters").and_then(|p| p.as_array()) {
                for param in parameters {
                    let name = param.get("name").and_then(|n| n.as_str()).unwrap_or("");
                    let location = param.get("in").and_then(|l| l.as_str()).unwrap_or("query");

                    if name.is_empty() {
                        continue;
                    }

                    let param_loc = match location {
                        "query" => ParamLocation::Query,
                        "header" => ParamLocation::Header,
                        "path" => ParamLocation::Path,
                        "cookie" => ParamLocation::Cookie,
                        _ => ParamLocation::Query,
                    };

                    params.push(InjectionPoint {
                        name: name.to_string(),
                        location: param_loc,
                        original_value: None,
                        context: None,
                    });
                }
            }

            // Extract request body properties (for POST/PUT/PATCH)
            if let Some(req_body) = operation.get("requestBody") {
                if let Some(content) = req_body.get("content") {
                    if let Some(json_schema) = content.get("application/json") {
                        if let Some(props) = json_schema
                            .pointer("/schema/properties")
                            .and_then(|p| p.as_object())
                        {
                            for (prop_name, _) in props {
                                params.push(InjectionPoint {
                                    name: prop_name.clone(),
                                    location: ParamLocation::Body,
                                    original_value: None,
                                    context: None,
                                });
                            }
                        }
                    }
                }
            }

            let url = format!("{}{}", base_url, path);
            endpoints.push(DiscoveredEndpoint {
                url,
                method: method.to_uppercase(),
                content_type: "application/json".to_string(),
                params,
                is_json_api: true,
            });
        }
    }

    Ok(endpoints)
}
