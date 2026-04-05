use crate::scanner::traits::{HtmlContext, Severity, Confidence, ScannerType};

pub fn assess_severity(
    scanner_type: &ScannerType,
    context: Option<&HtmlContext>,
    payload_reflected_fully: bool,
) -> (Severity, Confidence) {
    match scanner_type {
        ScannerType::Blind => (Severity::Critical, Confidence::Confirmed),
        ScannerType::Stored => {
            if payload_reflected_fully {
                (Severity::High, Confidence::High)
            } else {
                (Severity::Medium, Confidence::Medium)
            }
        }
        ScannerType::Dom => (Severity::High, Confidence::Confirmed),
        ScannerType::Reflected => {
            match context {
                Some(HtmlContext::ScriptBlock) => {
                    if payload_reflected_fully {
                        (Severity::High, Confidence::High)
                    } else {
                        (Severity::Medium, Confidence::Medium)
                    }
                }
                Some(HtmlContext::AttributeValue { attr, .. }) if attr.starts_with("on") => {
                    (Severity::High, Confidence::High)
                }
                Some(HtmlContext::AttributeValue { attr, .. })
                    if attr == "href" || attr == "src" =>
                {
                    (Severity::Medium, Confidence::Medium)
                }
                Some(HtmlContext::Plain) if payload_reflected_fully => {
                    (Severity::Medium, Confidence::Medium)
                }
                Some(HtmlContext::Comment) => (Severity::Low, Confidence::Low),
                _ => (Severity::Low, Confidence::Low),
            }
        }
    }
}
