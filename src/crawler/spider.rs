use anyhow::Result;
use dashmap::DashSet;
use regex::Regex;
use scraper::{Html, Selector};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, Semaphore};
use tracing::{debug, info, warn};
use url::Url;

use crate::config::Config;
use crate::crawler::forms;
use crate::crawler::params;
use crate::crawler::sitemap;
use crate::http::client::HttpClient;
use crate::scanner::traits::CrawlResult;
use crate::utils::url::{is_excluded, is_in_scope, is_static_resource, normalize_url};

pub struct Spider {
    config: Arc<Config>,
    client: HttpClient,
    visited: Arc<DashSet<String>>,
    semaphore: Arc<Semaphore>,
    disallowed_paths: Vec<String>,
}

impl Spider {
    pub fn new(config: Arc<Config>, client: HttpClient) -> Self {
        let concurrency = config.concurrency;
        Self {
            config,
            client,
            visited: Arc::new(DashSet::new()),
            semaphore: Arc::new(Semaphore::new(concurrency)),
            disallowed_paths: Vec::new(),
        }
    }

    pub async fn crawl(&mut self, tx: mpsc::Sender<CrawlResult>) -> Result<()> {
        let target_url = normalize_url(&self.config.target)?;

        // Fetch robots.txt if respecting it
        if self.config.respect_robots {
            if let Ok(Some(robots)) = sitemap::fetch_robots_txt(&self.client, &target_url).await {
                self.disallowed_paths = sitemap::parse_disallowed_paths(&robots);
            }
        }

        // Channel-based queue for discovered URLs
        let (queue_tx, mut queue_rx) = mpsc::channel::<(Url, usize)>(10000);

        // Seed with sitemap URLs
        let sitemap_urls = sitemap::fetch_sitemap_urls(&self.client, &target_url).await;
        info!("Sitemap returned {} URLs", sitemap_urls.len());
        for url in sitemap_urls {
            let _ = queue_tx.send((url, 0)).await;
        }

        // Add the target URL
        let _ = queue_tx.send((target_url.clone(), 0)).await;

        // Track in-flight crawl tasks
        let active_tasks = Arc::new(AtomicU32::new(0));

        let visited = self.visited.clone();
        let semaphore = self.semaphore.clone();
        let client = self.client.clone();
        let config = self.config.clone();
        let target = target_url.clone();
        let disallowed = self.disallowed_paths.clone();

        // We'll drop our queue_tx at the end so the receiver eventually closes
        let feeder_qtx = queue_tx.clone();
        drop(queue_tx);

        let active = active_tasks.clone();

        let processor = tokio::spawn(async move {
            while let Some((url, depth)) = queue_rx.recv().await {
                let url_str = url.to_string();

                if visited.contains(&url_str) {
                    continue;
                }
                if depth > config.crawl_depth {
                    continue;
                }
                if is_static_resource(&url) {
                    continue;
                }
                if !is_in_scope(&url, &target, &config.scope) {
                    continue;
                }
                if is_excluded(&url, &config.exclude) {
                    debug!("Skipping excluded path: {}", url.path());
                    continue;
                }
                if config.respect_robots
                    && !sitemap::is_path_allowed(url.path(), &disallowed)
                {
                    debug!("Skipping disallowed path: {}", url.path());
                    continue;
                }

                visited.insert(url_str);

                let permit = match semaphore.clone().acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => continue,
                };

                let client = client.clone();
                let tx = tx.clone();
                let qtx = feeder_qtx.clone();
                let target = target.clone();
                let scope = config.scope.clone();
                let exclude = config.exclude.clone();
                let max_depth = config.crawl_depth;
                let visited = visited.clone();
                let active = active.clone();

                active.fetch_add(1, Ordering::SeqCst);

                tokio::spawn(async move {
                    let _permit = permit;

                    match crawl_page(&client, &url).await {
                        Ok((crawl_result, discovered_urls)) => {
                            info!(
                                "Crawled {} - {} params, {} forms, {} links",
                                url,
                                crawl_result.params.len(),
                                crawl_result.forms.len(),
                                discovered_urls.len()
                            );

                            let _ = tx.send(crawl_result).await;

                            for discovered in discovered_urls {
                                let ds = discovered.to_string();
                                if !visited.contains(&ds)
                                    && is_in_scope(&discovered, &target, &scope)
                                    && !is_static_resource(&discovered)
                                    && !is_excluded(&discovered, &exclude)
                                    && depth + 1 <= max_depth
                                {
                                    let _ = qtx.send((discovered, depth + 1)).await;
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Failed to crawl {}: {}", url, e);
                        }
                    }

                    active.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });

        // Wait for processing to complete
        // The queue_rx closes when all queue_tx clones are dropped.
        // Each crawl task holds a qtx clone, so the queue stays open while tasks run.
        // But the processor loop also holds feeder_qtx via the spawned tasks.
        // We need to wait until active tasks drain AND queue is empty.
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            let count = active_tasks.load(Ordering::SeqCst);
            if count == 0 {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                if active_tasks.load(Ordering::SeqCst) == 0 {
                    break;
                }
            }
        }

        // Drop feeder to let processor finish
        // (processor will exit when queue_rx closes, which happens when all qtx clones drop)
        // The spawned tasks hold qtx clones, but they've all completed (active == 0)
        // So the only remaining qtx is inside the processor's `feeder_qtx` — but we moved it in.
        // Just abort the processor since all work is done.
        processor.abort();

        info!(
            "Crawling complete. {} unique URLs visited.",
            self.visited.len()
        );

        Ok(())
    }
}

async fn crawl_page(client: &HttpClient, url: &Url) -> Result<(CrawlResult, Vec<Url>)> {
    let resp = client.get(url.as_str()).await?;
    let status = resp.status().as_u16();
    let body = resp.text().await?;

    // Extract forms
    let page_forms = forms::extract_forms(&body, url);
    let mut injection_points = forms::forms_to_injection_points(&page_forms);

    // Extract URL parameters
    injection_points.extend(params::extract_url_params(url));

    // Extract header injection points
    injection_points.extend(params::extract_header_injection_points());

    // Extract links for further crawling
    let discovered = extract_links(&body, url);

    let crawl_result = CrawlResult {
        url: url.clone(),
        method: "GET".to_string(),
        params: injection_points,
        response_body: body,
        response_status: status,
        forms: page_forms,
    };

    Ok((crawl_result, discovered))
}

fn extract_links(html: &str, base_url: &Url) -> Vec<Url> {
    let mut urls = Vec::new();
    let document = Html::parse_document(html);

    // Extract <a href="...">
    if let Ok(selector) = Selector::parse("a[href]") {
        for element in document.select(&selector) {
            if let Some(href) = element.value().attr("href") {
                if let Some(url) = resolve_url(href, base_url) {
                    urls.push(url);
                }
            }
        }
    }

    // Extract <form action="...">
    if let Ok(selector) = Selector::parse("form[action]") {
        for element in document.select(&selector) {
            if let Some(action) = element.value().attr("action") {
                if let Some(url) = resolve_url(action, base_url) {
                    urls.push(url);
                }
            }
        }
    }

    // Extract <iframe src="...">
    if let Ok(selector) = Selector::parse("iframe[src]") {
        for element in document.select(&selector) {
            if let Some(src) = element.value().attr("src") {
                if let Some(url) = resolve_url(src, base_url) {
                    urls.push(url);
                }
            }
        }
    }

    // Extract URLs from JavaScript
    let js_url_re =
        Regex::new(r#"(?:href|src|action|url|location)\s*[=:]\s*['"]([^'"]+)['"]"#).unwrap();
    for cap in js_url_re.captures_iter(html) {
        if let Some(url_match) = cap.get(1) {
            if let Some(url) = resolve_url(url_match.as_str(), base_url) {
                urls.push(url);
            }
        }
    }

    // Deduplicate
    urls.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    urls.dedup_by(|a, b| a.as_str() == b.as_str());

    urls
}

fn resolve_url(href: &str, base_url: &Url) -> Option<Url> {
    let href = href.trim();

    if href.is_empty()
        || href.starts_with("javascript:")
        || href.starts_with("mailto:")
        || href.starts_with("tel:")
        || href.starts_with("data:")
        || href.starts_with('#')
    {
        return None;
    }

    base_url.join(href).ok().map(|mut u| {
        u.set_fragment(None);
        u
    })
}
