use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::HeaderMap,
    routing::get,
    Router,
};
use chrono::Utc;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, debug};

use crate::callback::token::{CallbackHit, TokenTracker};
use crate::scanner::traits::*;

#[derive(Clone)]
struct AppState {
    tracker: Arc<TokenTracker>,
    finding_tx: mpsc::Sender<Finding>,
}

pub async fn start_callback_server(
    port: u16,
    tracker: Arc<TokenTracker>,
    finding_tx: mpsc::Sender<Finding>,
) -> anyhow::Result<()> {
    let state = AppState {
        tracker,
        finding_tx,
    };

    let app = Router::new()
        .route("/c/{token}", get(handle_callback))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Callback server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

async fn handle_callback(
    Path(token): Path<String>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> &'static str {
    debug!("Callback received for token: {}", token);

    if let Some(record) = state.tracker.lookup(&token) {
        let user_agent = headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let query_str = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("&");

        let hit = CallbackHit {
            canary: token.clone(),
            source_ip: addr.ip().to_string(),
            user_agent: user_agent.clone(),
            timestamp: Utc::now(),
            query_params: query_str.clone(),
            record: record.clone(),
        };

        state.tracker.record_hit(hit);

        let evidence = format!(
            "Blind XSS callback received! Source IP: {}, User-Agent: {}, Params: {}",
            addr.ip(),
            user_agent.as_deref().unwrap_or("unknown"),
            if query_str.is_empty() { "none" } else { &query_str }
        );

        let finding = Finding::new(
            ScannerType::Blind,
            Severity::Critical,
            Confidence::Confirmed,
            record.url.clone(),
            record.injection_point.clone(),
            record.payload.clone(),
            evidence,
            RequestRecord {
                method: "GET".to_string(),
                url: format!("/c/{}", token),
                headers: Vec::new(),
                body: None,
            },
            200,
            None,
        );

        let _ = state.finding_tx.send(finding).await;

        info!(
            "BLIND XSS CONFIRMED! Callback from {} for injection at {}",
            addr.ip(),
            record.url
        );
    }

    // Return a 1x1 transparent GIF
    ""
}
