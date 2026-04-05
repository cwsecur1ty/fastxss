use anyhow::Result;
use std::path::Path;

use crate::reporter::finding::FindingCollection;
use crate::scanner::traits::Severity;

pub fn write_html_report(collection: &FindingCollection, output_path: &Path) -> Result<()> {
    let html = generate_html(collection);
    std::fs::write(output_path, html)?;
    Ok(())
}

fn generate_html(collection: &FindingCollection) -> String {
    let counts = collection.count_by_severity();
    let findings = collection.sorted();

    let mut rows = String::new();
    for (i, f) in findings.iter().enumerate() {
        let severity_class = match f.severity {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        };

        let payload_escaped = html_escape(&f.payload);
        let evidence_escaped = html_escape(&f.evidence);
        let url_escaped = html_escape(&f.url);

        rows.push_str(&format!(
            r#"<tr>
                <td>{}</td>
                <td class="severity {severity_class}">{}</td>
                <td>{}</td>
                <td><a href="{}" target="_blank">{}</a></td>
                <td>{} ({:?})</td>
                <td><code>{}</code></td>
                <td>
                    <details>
                        <summary>View</summary>
                        <pre>{}</pre>
                    </details>
                </td>
            </tr>"#,
            i + 1,
            f.severity,
            f.scanner_type,
            url_escaped,
            truncate(&url_escaped, 60),
            f.injection_point.name,
            f.injection_point.location,
            truncate(&payload_escaped, 80),
            evidence_escaped,
        ));
    }

    format!(
        r#"<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>fastxss Scan Report</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #1a1a2e; color: #e0e0e0; margin: 0; padding: 20px; }}
h1 {{ color: #ff4444; text-align: center; }}
.summary {{ display: flex; gap: 20px; justify-content: center; margin: 20px 0; }}
.stat {{ background: #16213e; padding: 15px 25px; border-radius: 8px; text-align: center; }}
.stat .count {{ font-size: 2em; font-weight: bold; }}
.stat.critical .count {{ color: #ff4444; }}
.stat.high .count {{ color: #ff66aa; }}
.stat.medium .count {{ color: #ffaa00; }}
.stat.low .count {{ color: #00cccc; }}
.stat.info .count {{ color: #888; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
th {{ background: #16213e; padding: 12px; text-align: left; }}
td {{ padding: 10px; border-bottom: 1px solid #333; }}
tr:hover {{ background: #16213e; }}
.severity {{ font-weight: bold; padding: 4px 8px; border-radius: 4px; }}
.critical {{ color: #ff4444; }}
.high {{ color: #ff66aa; }}
.medium {{ color: #ffaa00; }}
.low {{ color: #00cccc; }}
.info {{ color: #888; }}
a {{ color: #4da6ff; }}
code {{ background: #0a0a1a; padding: 2px 6px; border-radius: 3px; font-size: 0.9em; }}
pre {{ background: #0a0a1a; padding: 10px; border-radius: 5px; overflow-x: auto; font-size: 0.85em; white-space: pre-wrap; word-break: break-all; }}
details summary {{ cursor: pointer; color: #4da6ff; }}
</style>
</head>
<body>
<h1>fastxss Scan Report</h1>
<div class="summary">
    <div class="stat critical"><div class="count">{}</div>Critical</div>
    <div class="stat high"><div class="count">{}</div>High</div>
    <div class="stat medium"><div class="count">{}</div>Medium</div>
    <div class="stat low"><div class="count">{}</div>Low</div>
    <div class="stat info"><div class="count">{}</div>Info</div>
</div>
<table>
<thead>
<tr><th>#</th><th>Severity</th><th>Type</th><th>URL</th><th>Parameter</th><th>Payload</th><th>Evidence</th></tr>
</thead>
<tbody>
{rows}
</tbody>
</table>
</body>
</html>"#,
        counts.critical, counts.high, counts.medium, counts.low, counts.info,
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max])
    }
}
