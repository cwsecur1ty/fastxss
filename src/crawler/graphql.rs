use anyhow::Result;
use serde_json::{json, Value};
use tracing::{debug, info, warn};

use crate::http::client::HttpClient;
use crate::scanner::traits::{InjectionPoint, ParamLocation};

const INTROSPECTION_QUERY: &str = r#"{"query":"{ __schema { queryType { name } mutationType { name } types { name kind fields { name args { name type { name kind ofType { name kind } } } } } } }"}"#;

pub struct GraphqlDiscovery {
    client: HttpClient,
}

impl GraphqlDiscovery {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    /// Attempt GraphQL introspection on a URL and extract injectable arguments
    pub async fn introspect(&self, graphql_url: &str) -> Vec<GraphqlField> {
        let mut fields = Vec::new();

        // Try introspection query
        let query: Value = serde_json::from_str(INTROSPECTION_QUERY).unwrap();
        let resp = match self.client.post_json(graphql_url, &query).await {
            Ok(r) => r,
            Err(e) => {
                debug!("GraphQL introspection failed at {}: {}", graphql_url, e);
                return fields;
            }
        };

        let body = match resp.text().await {
            Ok(b) => b,
            Err(_) => return fields,
        };

        let result: Value = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(_) => {
                debug!("GraphQL response not valid JSON");
                return fields;
            }
        };

        // Check for introspection data
        let types = match result.pointer("/data/__schema/types") {
            Some(Value::Array(types)) => types,
            _ => {
                debug!("No introspection data found (may be disabled)");
                return fields;
            }
        };

        info!("GraphQL introspection successful at {}", graphql_url);

        for type_obj in types {
            let type_name = type_obj
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("");
            let type_kind = type_obj
                .get("kind")
                .and_then(|k| k.as_str())
                .unwrap_or("");

            // Skip internal types
            if type_name.starts_with("__") || type_kind == "SCALAR" || type_kind == "ENUM" {
                continue;
            }

            let type_fields = match type_obj.get("fields").and_then(|f| f.as_array()) {
                Some(f) => f,
                None => continue,
            };

            for field in type_fields {
                let field_name = field
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("");
                let args = match field.get("args").and_then(|a| a.as_array()) {
                    Some(a) => a,
                    None => continue,
                };

                if args.is_empty() {
                    continue;
                }

                let mut injectable_args = Vec::new();
                for arg in args {
                    let arg_name = arg.get("name").and_then(|n| n.as_str()).unwrap_or("");
                    let arg_type = get_type_name(arg.get("type"));

                    // Only inject into String-like arguments
                    if is_injectable_type(&arg_type) {
                        injectable_args.push(GraphqlArg {
                            name: arg_name.to_string(),
                            type_name: arg_type,
                        });
                    }
                }

                if !injectable_args.is_empty() {
                    debug!(
                        "GraphQL field: {}.{} with {} injectable args",
                        type_name,
                        field_name,
                        injectable_args.len()
                    );
                    fields.push(GraphqlField {
                        type_name: type_name.to_string(),
                        field_name: field_name.to_string(),
                        args: injectable_args,
                    });
                }
            }
        }

        info!(
            "GraphQL discovery: {} injectable fields found",
            fields.len()
        );
        fields
    }

    /// Generate XSS test queries for discovered fields
    pub fn generate_test_queries(
        &self,
        fields: &[GraphqlField],
        payload: &str,
    ) -> Vec<(String, String)> {
        let mut queries = Vec::new();

        for field in fields {
            for arg in &field.args {
                let query = format!(
                    r#"{{ {field}({arg}: "{payload}") {{ __typename }} }}"#,
                    field = field.field_name,
                    arg = arg.name,
                    payload = payload.replace('"', "\\\""),
                );

                let body = json!({
                    "query": query
                });

                queries.push((
                    arg.name.clone(),
                    body.to_string(),
                ));
            }
        }

        queries
    }

    /// Convert GraphQL fields into injection points for the scanner pipeline
    pub fn fields_to_injection_points(&self, fields: &[GraphqlField]) -> Vec<InjectionPoint> {
        let mut points = Vec::new();
        for field in fields {
            for arg in &field.args {
                points.push(InjectionPoint {
                    name: format!("{}.{}", field.field_name, arg.name),
                    location: ParamLocation::Body,
                    original_value: None,
                    context: None,
                });
            }
        }
        points
    }
}

#[derive(Debug, Clone)]
pub struct GraphqlField {
    pub type_name: String,
    pub field_name: String,
    pub args: Vec<GraphqlArg>,
}

#[derive(Debug, Clone)]
pub struct GraphqlArg {
    pub name: String,
    pub type_name: String,
}

fn get_type_name(type_val: Option<&Value>) -> String {
    match type_val {
        Some(t) => {
            if let Some(name) = t.get("name").and_then(|n| n.as_str()) {
                return name.to_string();
            }
            if let Some(of_type) = t.get("ofType") {
                return get_type_name(Some(of_type));
            }
            "Unknown".to_string()
        }
        None => "Unknown".to_string(),
    }
}

fn is_injectable_type(type_name: &str) -> bool {
    matches!(
        type_name,
        "String" | "ID" | "Text" | "URL" | "Email" | "Unknown"
    )
}
