#![allow(dead_code)]

mod callback;
mod config;
mod crawler;
mod http;
mod payloads;
mod reporter;
mod scanner;
mod utils;

use anyhow::Result;
use clap::Parser;
use colored::*;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::callback::server::start_callback_server;
use crate::callback::token::TokenTracker;
use crate::config::{Config, OutputFormat};
use crate::crawler::api_discovery::ApiDiscovery;
use crate::crawler::graphql::GraphqlDiscovery;
use crate::crawler::param_miner::ParamMiner;
use crate::crawler::spider::Spider;
use crate::http::client::HttpClient;
use crate::http::session::SessionManager;
use crate::payloads::engine::PayloadEngine;
use crate::reporter::finding::FindingCollection;
use crate::reporter::terminal;
use crate::scanner::blind::BlindScanner;
use crate::scanner::crlf::CrlfScanner;
use crate::scanner::dom::DomScanner;
use crate::scanner::reflected::ReflectedScanner;
use crate::scanner::stored::StoredScanner;
use crate::scanner::traits::{CrawlResult, Finding, Scanner};
use crate::scanner::waf::WafDetector;

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::parse();

    // Setup logging - filter out noisy chromiumoxide messages
    let filter = match config.verbose {
        0 => "warn,chromiumoxide=off",
        1 => "info,chromiumoxide=off",
        2 => "debug,chromiumoxide=off",
        _ => "trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(filter))
        .init();

    if !config.quiet {
        terminal::print_banner();
        terminal::print_scan_start(&config.target);
    }

    let scan_start = std::time::Instant::now();
    let quiet = config.quiet;
    let config = Arc::new(config);

    // Build HTTP client
    let http_client = HttpClient::new(&config)?;

    // Authenticate if configured
    if config.auth_url.is_some() {
        let mut session = SessionManager::new();
        println!("{} Authenticating...", "[*]".bright_blue());
        if let Err(e) = session.authenticate(&http_client, &config).await {
            eprintln!("{} Authentication failed: {}", "[!]".bright_red(), e);
        } else if session.is_authenticated() {
            println!("{} Authentication successful", "[+]".bright_green());
        }
    }

    // WAF detection
    let waf_result = if config.waf_detect {
        println!("{} Detecting WAF...", "[*]".bright_blue());
        let detector = WafDetector::new(http_client.clone());
        let target_url = crate::utils::url::normalize_url(&config.target)?;
        let result = detector.detect(&target_url).await;
        if result.detected {
            println!(
                "{} WAF detected: {}",
                "[!]".bright_yellow(),
                result.summary().bright_yellow()
            );
        } else {
            println!("{} No WAF detected", "[+]".bright_green());
        }
        Some(result)
    } else {
        None
    };

    // Build payload engine
    let payload_engine = Arc::new(PayloadEngine::new(
        config.wordlist.as_deref(),
    ));

    // Channels for findings
    let (finding_tx, mut finding_rx) = mpsc::channel::<Finding>(1000);

    // Initialize scanners
    let stored_scanner = Arc::new(StoredScanner::new());

    // DOM scanner (optional) — wrapped in Mutex for shutdown access
    let dom_scanner: Option<Arc<Mutex<DomScanner>>> = if !config.disable_dom {
        println!("{} Initializing headless browser for DOM analysis...", "[*]".bright_blue());
        Some(Arc::new(Mutex::new(DomScanner::new().await)))
    } else {
        None
    };

    // Reflected scanner — optionally wired to DOM verifier
    let reflected_scanner = Arc::new(if let Some(ref dom) = dom_scanner {
        ReflectedScanner::with_dom_verifier(dom.clone())
    } else {
        ReflectedScanner::new()
    });

    // Blind scanner + callback server (optional)
    let mut callback_server_handle = None;
    let blind_scanner: Option<Arc<BlindScanner>> = if !config.disable_blind {
        let callback_host = config
            .callback_host
            .clone()
            .unwrap_or_else(|| "127.0.0.1".to_string());
        let scanner = Arc::new(BlindScanner::new(&callback_host, config.callback_port));
        let token_map = scanner.token_map();
        let tracker = Arc::new(TokenTracker::new(token_map));

        let cb_tx = finding_tx.clone();
        let cb_port = config.callback_port;
        let cb_tracker = tracker.clone();

        let handle = tokio::spawn(async move {
            if let Err(e) = start_callback_server(cb_port, cb_tracker, cb_tx).await {
                // Ignore "address in use" on shutdown
                if !e.to_string().contains("address") {
                    eprintln!("Callback server error: {}", e);
                }
            }
        });
        callback_server_handle = Some(handle);

        println!(
            "{} Callback server started on port {}",
            "[*]".bright_blue(),
            config.callback_port.to_string().bright_yellow()
        );

        Some(scanner)
    } else {
        None
    };

    // Ctrl+C signal handler for graceful shutdown
    let shutdown_dom = dom_scanner.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            eprintln!("\n{} Ctrl+C received, shutting down...", "[!]".bright_red());
            if let Some(dom) = shutdown_dom {
                dom.lock().await.shutdown().await;
            }
            // Give a moment for cleanup
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            std::process::exit(130);
        }
    });

    // Crawl channel
    let (crawl_tx, mut crawl_rx) = mpsc::channel(500);

    // Load external forms if provided
    let external_forms: Vec<crate::scanner::traits::FormData> = if let Some(ref forms_path) = config.forms_file {
        match std::fs::read_to_string(forms_path) {
            Ok(json) => serde_json::from_str(&json).unwrap_or_else(|e| {
                eprintln!("Failed to parse forms file: {}", e);
                Vec::new()
            }),
            Err(e) => {
                eprintln!("Failed to read forms file: {}", e);
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };

    // Start crawler or feed from --urls-file
    let crawler_config = config.clone();
    let crawler_client = http_client.clone();
    let crawler_handle = if config.no_crawl {
        // No-crawl mode: feed URLs from file or just the target
        let tx = crawl_tx.clone();
        let client = crawler_client.clone();
        let external_forms = external_forms.clone();
        tokio::spawn(async move {
            let urls: Vec<String> = if let Some(ref urls_path) = crawler_config.urls_file {
                match std::fs::read_to_string(urls_path) {
                    Ok(content) => content
                        .lines()
                        .map(|l| l.trim().to_string())
                        .filter(|l| !l.is_empty() && !l.starts_with('#'))
                        .collect(),
                    Err(e) => {
                        eprintln!("Failed to read URLs file: {}", e);
                        vec![crawler_config.target.clone()]
                    }
                }
            } else {
                vec![crawler_config.target.clone()]
            };

            for url_str in &urls {
                let url = match crate::utils::url::normalize_url(url_str) {
                    Ok(u) => u,
                    Err(_) => continue,
                };

                // Fetch each URL to get response body for context detection
                let resp = match client.get(url.as_str()).await {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();

                // Extract forms from HTML + merge external forms for this URL
                let mut page_forms = crate::crawler::forms::extract_forms(&body, &url);
                for ext_form in &external_forms {
                    if ext_form.action == url.as_str() || ext_form.action.starts_with(url.as_str()) {
                        page_forms.push(ext_form.clone());
                    }
                }
                // If no URL-specific match, add all external forms to first URL
                if page_forms.is_empty() && !external_forms.is_empty() && url_str == &urls[0] {
                    page_forms.extend(external_forms.clone());
                }

                let mut params = crate::crawler::forms::forms_to_injection_points(&page_forms);
                params.extend(crate::crawler::params::extract_url_params(&url));

                let crawl_result = crate::scanner::traits::CrawlResult {
                    url,
                    method: "GET".to_string(),
                    params,
                    response_body: body,
                    response_status: status,
                    forms: page_forms,
                };
                let _ = tx.send(crawl_result).await;
            }
        })
    } else {
        // Normal crawl mode
        tokio::spawn(async move {
            let mut spider = Spider::new(crawler_config, crawler_client);
            if let Err(e) = spider.crawl(crawl_tx).await {
                eprintln!("Crawler error: {}", e);
            }
        })
    };

    // Process crawl results - scan pages concurrently
    let scan_config = config.clone();
    let scan_finding_tx = finding_tx.clone();
    let scan_semaphore = Arc::new(tokio::sync::Semaphore::new(config.concurrency.min(10)));
    let pages_scanned = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let scan_dom_scanner = dom_scanner.clone();
    let progress = Arc::new(terminal::create_progress_bar());

    // Clone for post-scan discovery phase
    let discovery_client = http_client.clone();
    let discovery_reflected = reflected_scanner.clone();
    let discovery_engine = payload_engine.clone();

    let scan_handle = tokio::spawn({
        let pages_scanned = pages_scanned.clone();
        let dom_scanner = scan_dom_scanner;
        let progress = progress.clone();
        async move {
            let mut page_handles = Vec::new();

            while let Some(crawl_result) = crawl_rx.recv().await {
                let permit = scan_semaphore.clone().acquire_owned().await.unwrap();
                let dom = dom_scanner.clone();
                let reflected = reflected_scanner.clone();
                let stored = stored_scanner.clone();
                let blind = blind_scanner.clone();
                let engine = payload_engine.clone();
                let client = http_client.clone();
                let tx = scan_finding_tx.clone();
                let pb = progress.clone();
                let config = scan_config.clone();
                let pages = pages_scanned.clone();

                page_handles.push(tokio::spawn(async move {
                    let _permit = permit;
                    let mut crawl_result = crawl_result;

                    // Only render pages likely to have forms (has input-like content hints)
                    let should_render = crawl_result.forms.is_empty()
                        && (crawl_result.response_body.contains("input")
                            || crawl_result.response_body.contains("login")
                            || crawl_result.response_body.contains("signup")
                            || crawl_result.response_body.contains("search")
                            || crawl_result.response_body.contains("contact")
                            || crawl_result.response_body.contains("form")
                            || crawl_result.response_body.contains("submit"));

                    if should_render {
                        if let Some(ref dom) = dom {
                            let dom_guard = dom.lock().await;
                            if dom_guard.is_available() {
                                if let Some(rendered_html) =
                                    dom_guard.render_page(crawl_result.url.as_str()).await
                                {
                                    let js_forms = crate::crawler::forms::extract_forms(
                                        &rendered_html,
                                        &crawl_result.url,
                                    );
                                    if !js_forms.is_empty() {
                                        let js_points =
                                            crate::crawler::forms::forms_to_injection_points(
                                                &js_forms,
                                            );
                                        crawl_result.forms = js_forms;
                                        crawl_result.params.extend(js_points);
                                        crawl_result.response_body = rendered_html;
                                    }
                                }
                            }
                        }
                    }

                    let real_params = crawl_result
                        .params
                        .iter()
                        .filter(|p| {
                            !matches!(
                                p.location,
                                crate::scanner::traits::ParamLocation::Header
                            )
                        })
                        .count();
                    terminal::print_scan_page(
                        crawl_result.url.as_str(),
                        real_params,
                        crawl_result.forms.len(),
                    );

                    let crawl_result = Arc::new(crawl_result);
                    let mut scan_handles = Vec::new();

                    // Reflected XSS
                    {
                        let scanner = reflected.clone();
                        let target = crawl_result.clone();
                        let engine = engine.clone();
                        let client = client.clone();
                        let tx = tx.clone();
                        scan_handles.push(tokio::spawn(async move {
                            let findings = scanner.scan(&target, &engine, &client).await;
                            for f in findings {
                                let _ = tx.send(f).await;
                            }
                        }));
                    }

                    // Stored XSS
                    if !config.disable_stored {
                        let scanner = stored.clone();
                        let target = crawl_result.clone();
                        let engine = engine.clone();
                        let client = client.clone();
                        let tx = tx.clone();
                        scan_handles.push(tokio::spawn(async move {
                            let findings = scanner.scan(&target, &engine, &client).await;
                            for f in findings {
                                let _ = tx.send(f).await;
                            }
                        }));
                    }

                    // DOM XSS
                    if let Some(ref dom) = dom {
                        let scanner = dom.clone();
                        let target = crawl_result.clone();
                        let engine = engine.clone();
                        let client = client.clone();
                        let tx = tx.clone();
                        scan_handles.push(tokio::spawn(async move {
                            let guard = scanner.lock().await;
                            let findings = guard.scan(&target, &engine, &client).await;
                            for f in findings {
                                let _ = tx.send(f).await;
                            }
                        }));
                    }

                    // Blind XSS
                    if let Some(ref blind) = blind {
                        let scanner = blind.clone();
                        let target = crawl_result.clone();
                        let engine = engine.clone();
                        let client = client.clone();
                        scan_handles.push(tokio::spawn(async move {
                            let _ = scanner.scan(&target, &engine, &client).await;
                        }));
                    }

                    for h in scan_handles {
                        let _ = h.await;
                    }

                    pages.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    pb.inc(1);
                }));
            }

            // Wait for all page scans to finish
            for h in page_handles {
                let _ = h.await;
            }
        }
    });

    // Wait for crawler to finish
    let _ = crawler_handle.await;
    // Wait for scanners to finish
    let _ = scan_handle.await;

    let total_pages = pages_scanned.load(std::sync::atomic::Ordering::Relaxed);
    progress.finish_and_clear();
    println!(
        "{} Crawl+scan complete. {} pages scanned.",
        "[+]".bright_green(),
        total_pages.to_string().bright_white()
    );

    // === Post-Scan Discovery Phase (parallel) ===
    let target_url = crate::utils::url::normalize_url(&config.target)?;
    println!("{} Running post-scan discovery...", "[*]".bright_blue());

    let mut discovery_handles: Vec<tokio::task::JoinHandle<Vec<Finding>>> = Vec::new();

    // Parameter Mining (always runs)
    {
        let client = discovery_client.clone();
        let reflected = discovery_reflected.clone();
        let engine = discovery_engine.clone();
        let url = target_url.clone();
        let concurrency = config.concurrency;
        let wordlist = config.param_wordlist.clone();
        let max_mined = config.max_mined_params;

        discovery_handles.push(tokio::spawn(async move {
            let miner = ParamMiner::new(client.clone(), concurrency, wordlist.as_deref(), max_mined);
            let mined = miner.mine(&url).await;
            if mined.is_empty() {
                return Vec::new();
            }
            println!(
                "{} Found {} hidden parameters",
                "[+]".bright_green(),
                mined.len().to_string().bright_yellow()
            );
            println!(
                "{} Testing {} mined params for reflection...",
                "[*]".bright_blue(),
                mined.len().to_string().bright_yellow()
            );
            let mined_count = mined.len();
            let crawl = crate::scanner::traits::CrawlResult {
                url: url.clone(),
                method: "GET".to_string(),
                params: mined,
                response_body: String::new(),
                response_status: 200,
                forms: Vec::new(),
            };
            let findings = reflected.scan(&crawl, &engine, &client).await;
            println!(
                "{} Mined-param scan complete ({} params tested, {} findings)",
                "[+]".bright_green(),
                mined_count.to_string().bright_white(),
                findings.len().to_string().bright_white()
            );
            findings
        }));
    }

    // API Discovery
    if config.test_apis {
        let client = discovery_client.clone();
        let reflected = discovery_reflected.clone();
        let engine = discovery_engine.clone();
        let url = target_url.clone();

        discovery_handles.push(tokio::spawn(async move {
            let api = ApiDiscovery::new(client.clone());
            let endpoints = api.discover(&url).await;
            let mut all_findings = Vec::new();
            for ep in &endpoints {
                println!(
                    "{} API: {} {} ({})",
                    "[>]".bright_cyan(),
                    ep.method.bright_white(),
                    ep.url.bright_blue(),
                    if ep.is_json_api { "JSON" } else { "HTML" }
                );
                let crawl = ep.to_crawl_result();
                all_findings.extend(reflected.scan(&crawl, &engine, &client).await);
            }
            all_findings
        }));
    }

    // GraphQL Discovery
    if config.test_graphql {
        let client = discovery_client.clone();
        let url = target_url.clone();

        discovery_handles.push(tokio::spawn(async move {
            let gql = GraphqlDiscovery::new(client);
            let graphql_urls = [
                format!("{}/graphql", url.as_str().trim_end_matches('/')),
                format!("{}/gql", url.as_str().trim_end_matches('/')),
                format!("{}/api/graphql", url.as_str().trim_end_matches('/')),
            ];
            for gql_url in &graphql_urls {
                let fields = gql.introspect(gql_url).await;
                if !fields.is_empty() {
                    println!(
                        "{} GraphQL: {} injectable fields at {}",
                        "[>]".bright_cyan(),
                        fields.len().to_string().bright_yellow(),
                        gql_url.bright_blue()
                    );
                }
            }
            Vec::new()
        }));
    }

    // CRLF Testing
    if config.test_crlf {
        let client = discovery_client.clone();
        let engine = discovery_engine.clone();
        let url = target_url.clone();

        discovery_handles.push(tokio::spawn(async move {
            let crlf = CrlfScanner::new();
            let probe = crate::scanner::traits::CrawlResult {
                url: url.clone(),
                method: "GET".to_string(),
                params: crate::crawler::params::extract_url_params(&url),
                response_body: String::new(),
                response_status: 200,
                forms: Vec::new(),
            };
            let findings = crlf.scan(&probe, &engine, &client).await;
            for f in &findings {
                println!(
                    "{} {} CRLF: {}",
                    "[!]".bright_red(),
                    f.severity.to_string().bright_red(),
                    f.evidence.bright_white()
                );
            }
            findings
        }));
    }

    // Collect all discovery findings
    for handle in discovery_handles {
        if let Ok(findings) = handle.await {
            for f in findings {
                let _ = finding_tx.send(f).await;
            }
        }
    }

    // Drop finding_tx so receiver can finish
    drop(finding_tx);

    // Wait for blind XSS callbacks
    if !config.disable_blind && config.blind_wait_secs > 0 {
        println!(
            "\n{} Waiting {} seconds for blind XSS callbacks...",
            "[*]".bright_blue(),
            config.blind_wait_secs.to_string().bright_yellow()
        );
        tokio::time::sleep(std::time::Duration::from_secs(config.blind_wait_secs)).await;
    }

    // Abort the callback server so its finding_tx drops and the receiver can finish
    if let Some(handle) = callback_server_handle {
        handle.abort();
    }

    // Collect all findings (with optional real-time JSON streaming)
    let json_stream_path = config.json_stream.clone();
    let collection_handle = tokio::spawn(async move {
        use std::io::Write;

        let mut stream_file = json_stream_path.as_ref().and_then(|path| {
            std::fs::File::create(path)
                .map_err(|e| eprintln!("Failed to create JSON stream file: {}", e))
                .ok()
        });

        let mut collection = FindingCollection::new();
        while let Some(finding) = finding_rx.recv().await {
            if !quiet {
                terminal::print_finding(&finding);
            }

            // Stream to JSONL file in real-time
            if let Some(ref mut f) = stream_file {
                if let Ok(json) = serde_json::to_string(&finding) {
                    let _ = writeln!(f, "{}", json);
                    let _ = f.flush();
                }
            }

            collection.add(finding);
        }
        collection
    });

    let collection = collection_handle.await?;
    let finding_count = collection.count();

    // Print summary (unless quiet)
    if !quiet {
        terminal::print_summary(&collection, scan_start.elapsed());
    }

    // Write output
    if let Some(ref output_path) = config.output_file {
        match config.output_format {
            OutputFormat::Json => {
                reporter::json::write_json_report(&collection, output_path)?;
                if !quiet {
                    println!(
                        "{} JSON report written to {}",
                        "[+]".bright_green(),
                        output_path.display().to_string().bright_white()
                    );
                }
            }
            OutputFormat::Html => {
                reporter::html::write_html_report(&collection, output_path)?;
                if !quiet {
                    println!(
                        "{} HTML report written to {}",
                        "[+]".bright_green(),
                        output_path.display().to_string().bright_white()
                    );
                }
            }
            OutputFormat::Terminal => {
                // Already printed to terminal
            }
        }
    }

    // In quiet+json mode with no output file, write JSON to stdout
    if quiet && config.output_file.is_none() && matches!(config.output_format, OutputFormat::Json) {
        let json = serde_json::to_string_pretty(collection.as_slice())?;
        println!("{}", json);
    }

    // Clean up browser
    if let Some(ref dom) = dom_scanner {
        dom.lock().await.shutdown().await;
    }

    info!("Scan complete. Found {} potential XSS vulnerabilities.", finding_count);

    // Exit code: 0 = no vulns, 1 = vulns found
    if finding_count > 0 {
        std::process::exit(1);
    }

    Ok(())
}
