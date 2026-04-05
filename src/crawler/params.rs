use url::Url;

use crate::scanner::traits::{InjectionPoint, ParamLocation};

pub fn extract_url_params(url: &Url) -> Vec<InjectionPoint> {
    url.query_pairs()
        .map(|(key, value)| InjectionPoint {
            name: key.to_string(),
            location: ParamLocation::Query,
            original_value: Some(value.to_string()),
            context: None,
        })
        .collect()
}

pub fn common_param_names() -> Vec<&'static str> {
    vec![
        "q", "s", "search", "query", "keyword", "id", "page", "url", "redirect", "next",
        "redir", "return", "returnUrl", "goto", "target", "dest", "destination", "rurl",
        "redirect_uri", "continue", "path", "file", "ref", "callback", "cb", "data",
        "input", "name", "user", "username", "email", "msg", "message", "text", "comment",
        "title", "body", "content", "value", "val", "param", "arg", "type", "action",
        "view", "template", "lang", "locale", "category", "cat", "tag", "sort", "order",
        "filter", "limit", "offset", "from", "to", "start", "end", "token", "error",
        "err", "debug", "test", "preview",
    ]
}

pub fn extract_header_injection_points() -> Vec<InjectionPoint> {
    let injectable_headers = vec![
        "Referer",
        "User-Agent",
        "X-Forwarded-For",
        "X-Forwarded-Host",
        "X-Original-URL",
        "X-Rewrite-URL",
        "Origin",
    ];

    injectable_headers
        .into_iter()
        .map(|h| InjectionPoint {
            name: h.to_string(),
            location: ParamLocation::Header,
            original_value: None,
            context: None,
        })
        .collect()
}
