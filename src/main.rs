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
use crate::crawler::spider::Spider;
use crate::http::client::HttpClient;
use crate::payloads::engine::PayloadEngine;
use crate::reporter::finding::FindingCollection;
use crate::reporter::terminal;
use crate::scanner::blind::BlindScanner;
use crate::scanner::dom::DomScanner;
use crate::scanner::reflected::ReflectedScanner;
use crate::scanner::stored::StoredScanner;
use crate::scanner::traits::{Finding, Scanner};

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

    terminal::print_banner();
    terminal::print_scan_start(&config.target);

    let config = Arc::new(config);

    // Build HTTP client
    let http_client = HttpClient::new(&config)?;

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

    // Start crawler
    let crawler_config = config.clone();
    let crawler_client = http_client.clone();
    let crawler_handle = tokio::spawn(async move {
        let mut spider = Spider::new(crawler_config, crawler_client);
        if let Err(e) = spider.crawl(crawl_tx).await {
            eprintln!("Crawler error: {}", e);
        }
    });

    // Process crawl results - scan pages concurrently
    let scan_config = config.clone();
    let scan_finding_tx = finding_tx.clone();
    let scan_semaphore = Arc::new(tokio::sync::Semaphore::new(config.concurrency.min(10)));
    let pages_scanned = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let scan_dom_scanner = dom_scanner.clone();

    let scan_handle = tokio::spawn({
        let pages_scanned = pages_scanned.clone();
        let dom_scanner = scan_dom_scanner;
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
                }));
            }

            // Wait for all page scans to finish
            for h in page_handles {
                let _ = h.await;
            }
        }
    });

    // Drop our copy of finding_tx so the receiver knows when scanners are done
    drop(finding_tx);

    // Wait for crawler to finish
    let _ = crawler_handle.await;
    // Wait for scanners to finish
    let _ = scan_handle.await;

    println!(
        "\n{} Scanning complete. {} pages scanned.",
        "[+]".bright_green(),
        pages_scanned.load(std::sync::atomic::Ordering::Relaxed).to_string().bright_white()
    );

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

    // Collect all findings
    let collection_handle = tokio::spawn(async move {
        let mut collection = FindingCollection::new();
        while let Some(finding) = finding_rx.recv().await {
            terminal::print_finding(&finding);
            collection.add(finding);
        }
        collection
    });

    let collection = collection_handle.await?;

    // Print summary
    terminal::print_summary(&collection);

    // Write output
    if let Some(ref output_path) = config.output_file {
        match config.output_format {
            OutputFormat::Json => {
                reporter::json::write_json_report(&collection, output_path)?;
                println!(
                    "{} JSON report written to {}",
                    "[+]".bright_green(),
                    output_path.display().to_string().bright_white()
                );
            }
            OutputFormat::Html => {
                reporter::html::write_html_report(&collection, output_path)?;
                println!(
                    "{} HTML report written to {}",
                    "[+]".bright_green(),
                    output_path.display().to_string().bright_white()
                );
            }
            OutputFormat::Terminal => {
                // Already printed to terminal
            }
        }
    }

    // Clean up browser
    if let Some(ref dom) = dom_scanner {
        dom.lock().await.shutdown().await;
    }

    info!("Scan complete. Found {} potential XSS vulnerabilities.", collection.count());

    Ok(())
}
