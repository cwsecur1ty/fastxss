use colored::*;

use crate::reporter::finding::FindingCollection;
use crate::scanner::traits::{Finding, Severity};

pub fn print_banner() {
    println!(
        "{}",
        r#"
    dMMMMMP .aMMMb  .dMMMb dMMMMMMP dMP dMP .dMMMb  .dMMMb 
   dMP     dMP"dMP dMP" VP   dMP   dMK.dMP dMP" VP dMP" VP 
  dMMMP   dMMMMMP  VMMMb    dMP   .dMMMK"  VMMMb   VMMMb   
 dMP     dMP dMP dP .dMP   dMP   dMP"AMF dP .dMP dP .dMP   
dMP     dMP dMP  VMMMP"   dMP   dMP dMP  VMMMP"  VMMMP"    
                                                           
    "#
        .bright_red()
    );
    println!("{}", "  Fast XSS Vulnerability Scanner".bright_white());
    println!();
}

pub fn print_scan_start(target: &str) {
    println!(
        "{} Target: {}",
        "[*]".bright_blue(),
        target.bright_white()
    );
}

pub fn print_crawl_status(pages_found: usize) {
    print!(
        "\r{} Scanning... {} pages processed",
        "[*]".bright_blue(),
        pages_found.to_string().bright_yellow()
    );
    use std::io::Write;
    let _ = std::io::stdout().flush();
}

pub fn print_scan_page(url: &str, params: usize, forms: usize) {
    println!(
        "{} {} ({} params, {} forms)",
        "[>]".bright_cyan(),
        truncate_str(url, 80).bright_white(),
        params.to_string().bright_yellow(),
        forms.to_string().bright_yellow()
    );
}

pub fn print_finding(finding: &Finding) {
    let severity_colored = match finding.severity {
        Severity::Critical => finding.severity.to_string().bright_red().bold(),
        Severity::High => finding.severity.to_string().bright_magenta(),
        Severity::Medium => finding.severity.to_string().bright_yellow(),
        Severity::Low => finding.severity.to_string().bright_cyan(),
        Severity::Info => finding.severity.to_string().bright_white(),
    };

    println!();
    println!(
        "{} {} {} {}",
        "[!]".bright_red(),
        severity_colored,
        finding.scanner_type.to_string().bright_white(),
        "XSS Found!".bright_red().bold()
    );
    println!(
        "    {} {}",
        "URL:".bright_white(),
        finding.url.bright_blue()
    );
    println!(
        "    {} {} ({})",
        "Param:".bright_white(),
        finding.injection_point.name.bright_yellow(),
        format!("{:?}", finding.injection_point.location).bright_white()
    );
    println!(
        "    {} {}",
        "Payload:".bright_white(),
        truncate_str(&finding.payload, 120).bright_green()
    );
    println!(
        "    {} {}",
        "Confidence:".bright_white(),
        format!("{:?}", finding.confidence).bright_white()
    );
}

pub fn print_summary(collection: &FindingCollection) {
    let counts = collection.count_by_severity();

    println!();
    println!("{}", "=".repeat(60).bright_white());
    println!("{}", " Scan Summary".bright_white().bold());
    println!("{}", "=".repeat(60).bright_white());
    println!(
        "  Total findings: {}",
        collection.count().to_string().bright_white().bold()
    );

    if counts.critical > 0 {
        println!(
            "  {} Critical: {}",
            "[!]".bright_red(),
            counts.critical.to_string().bright_red().bold()
        );
    }
    if counts.high > 0 {
        println!(
            "  {} High: {}",
            "[!]".bright_magenta(),
            counts.high.to_string().bright_magenta()
        );
    }
    if counts.medium > 0 {
        println!(
            "  {} Medium: {}",
            "[*]".bright_yellow(),
            counts.medium.to_string().bright_yellow()
        );
    }
    if counts.low > 0 {
        println!(
            "  {} Low: {}",
            "[-]".bright_cyan(),
            counts.low.to_string().bright_cyan()
        );
    }
    if counts.info > 0 {
        println!(
            "  {} Info: {}",
            "[i]".bright_white(),
            counts.info.to_string().bright_white()
        );
    }
    println!("{}", "=".repeat(60).bright_white());
}

fn truncate_str(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max])
    }
}
