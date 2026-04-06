use url::Url;

pub fn normalize_url(raw: &str) -> anyhow::Result<Url> {
    let trimmed = raw.trim().trim_end_matches('#');
    let with_scheme = if !trimmed.contains("://") {
        format!("https://{trimmed}")
    } else {
        trimmed.to_string()
    };
    let mut parsed = Url::parse(&with_scheme)?;
    // Remove default port
    if parsed.port() == Some(80) && parsed.scheme() == "http" {
        let _ = parsed.set_port(None);
    }
    if parsed.port() == Some(443) && parsed.scheme() == "https" {
        let _ = parsed.set_port(None);
    }
    // Remove trailing slash for consistency (but keep root "/")
    let path = parsed.path().to_string();
    if path.len() > 1 && path.ends_with('/') {
        parsed.set_path(&path[..path.len() - 1]);
    }
    // Remove fragment
    parsed.set_fragment(None);
    Ok(parsed)
}

pub fn is_in_scope(url: &Url, target: &Url, extra_scope: &[String]) -> bool {
    let target_host = target.host_str().unwrap_or("");
    let url_host = url.host_str().unwrap_or("");

    if url_host == target_host {
        return true;
    }

    for scope_domain in extra_scope {
        let domain = scope_domain.trim().trim_start_matches('.');
        if url_host == domain || url_host.ends_with(&format!(".{domain}")) {
            return true;
        }
    }

    false
}

pub fn is_excluded(url: &Url, exclude_patterns: &[String]) -> bool {
    let path = url.path().to_lowercase();
    let full = url.as_str().to_lowercase();
    for pattern in exclude_patterns {
        let p = pattern.to_lowercase();
        if path.contains(&p) || full.contains(&p) {
            return true;
        }
    }
    false
}

pub fn is_same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme() && a.host_str() == b.host_str() && a.port() == b.port()
}

pub fn extract_query_params(url: &Url) -> Vec<(String, String)> {
    url.query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

pub fn set_query_param(url: &Url, key: &str, value: &str) -> Url {
    let mut new_url = url.clone();
    let mut pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let mut found = false;
    for pair in &mut pairs {
        if pair.0 == key {
            pair.1 = value.to_string();
            found = true;
            break;
        }
    }
    if !found {
        pairs.push((key.to_string(), value.to_string()));
    }

    {
        let mut query = new_url.query_pairs_mut();
        query.clear();
        for (k, v) in &pairs {
            query.append_pair(k, v);
        }
    }
    new_url
}

pub fn is_static_resource(url: &Url) -> bool {
    let path = url.path().to_lowercase();
    let static_extensions = [
        ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
        ".ttf", ".eot", ".mp3", ".mp4", ".webm", ".webp", ".pdf", ".zip", ".tar", ".gz",
        ".map", ".min.js", ".min.css",
    ];
    static_extensions.iter().any(|ext| path.ends_with(ext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_url() {
        let url = normalize_url("example.com/path/").unwrap();
        assert_eq!(url.as_str(), "https://example.com/path");

        let url = normalize_url("http://example.com:80/test").unwrap();
        assert_eq!(url.as_str(), "http://example.com/test");
    }

    #[test]
    fn test_scope_check() {
        let target = Url::parse("https://example.com").unwrap();
        let in_scope = Url::parse("https://example.com/page").unwrap();
        let out_scope = Url::parse("https://other.com/page").unwrap();
        let sub = Url::parse("https://sub.allowed.com/page").unwrap();

        assert!(is_in_scope(&in_scope, &target, &[]));
        assert!(!is_in_scope(&out_scope, &target, &[]));
        assert!(is_in_scope(&sub, &target, &["allowed.com".to_string()]));
    }

    #[test]
    fn test_set_query_param() {
        let url = Url::parse("https://example.com/search?q=test&page=1").unwrap();
        let modified = set_query_param(&url, "q", "payload");
        assert!(modified.as_str().contains("q=payload"));
        assert!(modified.as_str().contains("page=1"));
    }

    #[test]
    fn test_is_static_resource() {
        let static_url = Url::parse("https://example.com/style.css").unwrap();
        let html_url = Url::parse("https://example.com/page.html").unwrap();
        assert!(is_static_resource(&static_url));
        assert!(!is_static_resource(&html_url));
    }
}
