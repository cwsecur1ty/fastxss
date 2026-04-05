use anyhow::Result;
use regex::Regex;
use url::Url;

use crate::http::client::HttpClient;

pub async fn fetch_sitemap_urls(client: &HttpClient, base_url: &Url) -> Vec<Url> {
    let mut urls = Vec::new();

    let sitemap_url = format!("{}://{}/sitemap.xml", base_url.scheme(), base_url.host_str().unwrap_or(""));
    if let Ok(resp) = client.get(&sitemap_url).await {
        if let Ok(body) = resp.text().await {
            urls.extend(extract_urls_from_sitemap(&body, base_url));
        }
    }

    urls
}

fn extract_urls_from_sitemap(xml: &str, base_url: &Url) -> Vec<Url> {
    let loc_re = Regex::new(r"<loc>\s*(.*?)\s*</loc>").unwrap();
    loc_re
        .captures_iter(xml)
        .filter_map(|cap| {
            let url_str = cap.get(1)?.as_str();
            Url::parse(url_str).ok()
        })
        .filter(|u| u.host_str() == base_url.host_str())
        .collect()
}

pub async fn fetch_robots_txt(client: &HttpClient, base_url: &Url) -> Result<Option<String>> {
    let robots_url = format!("{}://{}/robots.txt", base_url.scheme(), base_url.host_str().unwrap_or(""));
    match client.get(&robots_url).await {
        Ok(resp) if resp.status().is_success() => Ok(Some(resp.text().await?)),
        _ => Ok(None),
    }
}

pub fn parse_disallowed_paths(robots_txt: &str) -> Vec<String> {
    let mut disallowed = Vec::new();
    let mut in_all_agents = false;

    for line in robots_txt.lines() {
        let line = line.trim();
        if line.starts_with("User-agent:") {
            let agent = line.strip_prefix("User-agent:").unwrap().trim();
            in_all_agents = agent == "*";
        } else if in_all_agents && line.starts_with("Disallow:") {
            if let Some(path) = line.strip_prefix("Disallow:") {
                let path = path.trim();
                if !path.is_empty() {
                    disallowed.push(path.to_string());
                }
            }
        }
    }

    disallowed
}

pub fn is_path_allowed(path: &str, disallowed_paths: &[String]) -> bool {
    !disallowed_paths.iter().any(|d| path.starts_with(d))
}
