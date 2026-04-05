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
    about = "Fast, comprehensive XSS vulnerability scanner",
    long_about = "A Rust-based XSS scanner supporting reflected, stored, DOM-based, and blind/out-of-band XSS detection."
)]
pub struct Config {
    /// Target URL to scan
    #[arg(short, long)]
    pub target: String,

    /// Maximum concurrent requests
    #[arg(short, long, default_value = "50")]
    pub concurrency: usize,

    /// Maximum crawl depth
    #[arg(long, default_value = "10")]
    pub crawl_depth: usize,

    /// Comma-separated allowed domains for scope restriction
    #[arg(long, value_delimiter = ',')]
    pub scope: Vec<String>,

    /// Output format
    #[arg(long, default_value = "terminal")]
    pub output_format: OutputFormat,

    /// Output file path
    #[arg(short, long)]
    pub output_file: Option<PathBuf>,

    /// HTTP/SOCKS5 proxy URL
    #[arg(long)]
    pub proxy: Option<String>,

    /// Custom headers (format: "Key: Value"), can be repeated
    #[arg(long, value_delimiter = ',')]
    pub headers: Vec<String>,

    /// Cookie string to include with requests
    #[arg(long)]
    pub cookie: Option<String>,

    /// Login URL for authenticated scanning
    #[arg(long)]
    pub auth_url: Option<String>,

    /// Custom payload wordlist path
    #[arg(long)]
    pub wordlist: Option<PathBuf>,

    /// Blind XSS callback server port
    #[arg(long, default_value = "8844")]
    pub callback_port: u16,

    /// External host/IP for blind XSS callbacks
    #[arg(long)]
    pub callback_host: Option<String>,

    /// Maximum requests per second
    #[arg(long, default_value = "100")]
    pub rate_limit: u32,

    /// Honor robots.txt rules
    #[arg(long)]
    pub respect_robots: bool,

    /// Delay between requests in milliseconds
    #[arg(long, default_value = "0")]
    pub delay_ms: u64,

    /// Skip DOM-based XSS scanning (no headless browser)
    #[arg(long)]
    pub disable_dom: bool,

    /// Skip blind/OOB XSS scanning
    #[arg(long)]
    pub disable_blind: bool,

    /// Skip stored XSS scanning
    #[arg(long)]
    pub disable_stored: bool,

    /// Request timeout in seconds
    #[arg(long, default_value = "30")]
    pub timeout_secs: u64,

    /// Increase verbosity (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Accept invalid TLS certificates (for testing environments)
    #[arg(long)]
    pub insecure: bool,

    /// Wait time in seconds for blind XSS callbacks after scanning completes
    #[arg(long, default_value = "10")]
    pub blind_wait_secs: u64,
}
