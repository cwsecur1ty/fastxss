use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Clone, ValueEnum)]
pub enum OutputFormat {
    Json,
    Html,
    Terminal,
}

#[derive(Parser, Debug, Clone)]
#[command(
    name = "fastxss",
    version,
    about = "Fast XSS vulnerability scanner",
    long_about = None,
    after_help = "\x1b[1mEXAMPLES:\x1b[0m
  fastxss -t https://example.com                              Basic scan
  fastxss -t https://example.com --disable-dom --disable-blind  Reflected only (fast)
  fastxss -t https://example.com --test-apis --test-graphql   Include API scanning
  fastxss -t https://example.com --output-format html -o report.html
  fastxss -t https://example.com --cookie \"session=abc123\"
  fastxss -t https://example.com --auth-url https://example.com/login --auth-user admin --auth-pass secret
  fastxss -t https://example.com --proxy http://127.0.0.1:8080 --insecure"
)]
pub struct Config {
    // ── Target ──────────────────────────────────────────────
    /// Target URL to scan
    #[arg(short, long)]
    pub target: String,

    // ── Scan Scope ──────────────────────────────────────────
    /// Max concurrent requests [default: 50]
    #[arg(short, long, default_value = "50")]
    pub concurrency: usize,

    /// Max crawl depth [default: 10]
    #[arg(long, default_value = "10")]
    pub crawl_depth: usize,

    /// Allowed domains (comma-separated)
    #[arg(long, value_delimiter = ',')]
    pub scope: Vec<String>,

    /// Requests per second limit [default: 100]
    #[arg(long, default_value = "100")]
    pub rate_limit: u32,

    /// Delay between requests (ms) [default: 0]
    #[arg(long, default_value = "0")]
    pub delay_ms: u64,

    /// Request timeout (seconds) [default: 30]
    #[arg(long, default_value = "30")]
    pub timeout_secs: u64,

    /// Retry attempts on 429/5xx errors [default: 3]
    #[arg(long, default_value = "3")]
    pub max_retries: u32,

    /// Honor robots.txt
    #[arg(long)]
    pub respect_robots: bool,

    // ── Authentication ──────────────────────────────────────
    /// Login page URL for form-based auth
    #[arg(long, help_heading = "Authentication")]
    pub auth_url: Option<String>,

    /// Login username/email
    #[arg(long, help_heading = "Authentication")]
    pub auth_user: Option<String>,

    /// Login password
    #[arg(long, help_heading = "Authentication")]
    pub auth_pass: Option<String>,

    /// Bearer token (adds Authorization header)
    #[arg(long, help_heading = "Authentication")]
    pub bearer_token: Option<String>,

    /// Cookie string to include
    #[arg(long, help_heading = "Authentication")]
    pub cookie: Option<String>,

    // ── Scanner Modules ─────────────────────────────────────
    /// Skip DOM-based XSS (no headless browser)
    #[arg(long, help_heading = "Scanners")]
    pub disable_dom: bool,

    /// Skip blind/OOB XSS
    #[arg(long, help_heading = "Scanners")]
    pub disable_blind: bool,

    /// Skip stored XSS
    #[arg(long, help_heading = "Scanners")]
    pub disable_stored: bool,

    /// Probe API endpoints (/api/, /swagger.json, etc.)
    #[arg(long, help_heading = "Scanners")]
    pub test_apis: bool,

    /// Run GraphQL introspection + argument testing
    #[arg(long, help_heading = "Scanners")]
    pub test_graphql: bool,

    // ── Output ──────────────────────────────────────────────
    /// Output format: json, html, terminal [default: terminal]
    #[arg(long, default_value = "terminal", help_heading = "Output")]
    pub output_format: OutputFormat,

    /// Write report to file
    #[arg(short, long, help_heading = "Output")]
    pub output_file: Option<PathBuf>,

    /// Verbosity (-v info, -vv debug, -vvv trace)
    #[arg(short, long, action = clap::ArgAction::Count, help_heading = "Output")]
    pub verbose: u8,

    // ── Advanced ────────────────────────────────────────────
    /// HTTP/SOCKS5 proxy
    #[arg(long, help_heading = "Advanced")]
    pub proxy: Option<String>,

    /// Custom headers ("Key: Value", comma-separated)
    #[arg(long, value_delimiter = ',', help_heading = "Advanced")]
    pub headers: Vec<String>,

    /// Custom XSS payload wordlist
    #[arg(long, help_heading = "Advanced")]
    pub wordlist: Option<PathBuf>,

    /// Parameter mining wordlist
    #[arg(long, help_heading = "Advanced")]
    pub param_wordlist: Option<PathBuf>,

    /// Blind XSS callback port [default: 8844]
    #[arg(long, default_value = "8844", help_heading = "Advanced")]
    pub callback_port: u16,

    /// External host for blind XSS callbacks
    #[arg(long, help_heading = "Advanced")]
    pub callback_host: Option<String>,

    /// Blind callback wait time (seconds) [default: 10]
    #[arg(long, default_value = "10", help_heading = "Advanced")]
    pub blind_wait_secs: u64,

    /// Accept invalid TLS certificates
    #[arg(long, help_heading = "Advanced")]
    pub insecure: bool,
}
