use crate::scanner::traits::HtmlContext;

/// Count quotes in a string, ignoring escaped ones (preceded by \)
fn count_unescaped(s: &str, target: char) -> usize {
    let bytes = s.as_bytes();
    let mut count = 0;
    for i in 0..bytes.len() {
        if bytes[i] == target as u8 {
            let escaped = if i > 0 {
                let mut backslashes = 0;
                let mut j = i - 1;
                loop {
                    if bytes[j] == b'\\' {
                        backslashes += 1;
                    } else {
                        break;
                    }
                    if j == 0 { break; }
                    j -= 1;
                }
                backslashes % 2 == 1
            } else {
                false
            };
            if !escaped {
                count += 1;
            }
        }
    }
    count
}

const SVG_ELEMENTS: &[&str] = &[
    "svg", "animate", "animatemotion", "animatetransform", "set", "use",
    "foreignobject",
];

pub fn detect_context(html: &str, canary_pos: usize) -> HtmlContext {
    let before = &html[..canary_pos];

    // Check non-executable contexts first (noscript, textarea, title, xmp)
    // Content inside these tags renders as text, not HTML
    for tag in &["textarea", "noscript", "title", "xmp", "iframe", "noframes"] {
        let open_tag = format!("<{}", tag);
        let close_tag = format!("</{}", tag);
        let last_open = before.rfind(&open_tag);
        let last_close = before.rfind(&close_tag);
        if let Some(open) = last_open {
            if last_close.map_or(true, |close| close < open) {
                return HtmlContext::Plain; // Content is text, not executable
            }
        }
    }

    // Check if inside a script block
    let last_script_open = before.rfind("<script");
    let last_script_close = before.rfind("</script");
    if let Some(open) = last_script_open {
        if last_script_close.map_or(true, |close| close < open) {
            if let Some(tag_end) = html[open..].find('>') {
                let script_body = &before[open + tag_end + 1..];
                return detect_script_subcontext(script_body);
            }
            return HtmlContext::ScriptBlock;
        }
    }

    // Check if inside a style block
    let last_style_open = before.rfind("<style");
    let last_style_close = before.rfind("</style");
    if let Some(open) = last_style_open {
        if last_style_close.map_or(true, |close| close < open) {
            return HtmlContext::StyleBlock;
        }
    }

    // Check if inside an HTML comment
    let last_comment_open = before.rfind("<!--");
    let last_comment_close = before.rfind("-->");
    if let Some(open) = last_comment_open {
        if last_comment_close.map_or(true, |close| close < open) {
            return HtmlContext::Comment;
        }
    }

    // Check if inside a tag
    let last_lt = before.rfind('<');
    let last_gt = before.rfind('>');
    if let Some(lt_pos) = last_lt {
        if last_gt.map_or(true, |gt_pos| gt_pos < lt_pos) {
            let tag_content = &before[lt_pos..];

            let tag_name = tag_content
                .trim_start_matches('<')
                .trim_start_matches('/')
                .split(|c: char| c.is_whitespace() || c == '/' || c == '>')
                .next()
                .unwrap_or("")
                .to_lowercase();

            // Check for SVG context
            if SVG_ELEMENTS.contains(&tag_name.as_str()) {
                if let Some(attr_ctx) = detect_attribute_context(tag_content, &tag_name) {
                    return attr_ctx;
                }
                return HtmlContext::SvgContext;
            }

            // Check if inside an attribute value
            if let Some(attr_ctx) = detect_attribute_context(tag_content, &tag_name) {
                return attr_ctx;
            }

            return HtmlContext::TagBody { tag: tag_name };
        }
    }

    HtmlContext::Plain
}

fn detect_attribute_context(tag_content: &str, tag_name: &str) -> Option<HtmlContext> {
    let in_double_quote = count_unescaped(tag_content, '"') % 2 == 1;
    let in_single_quote = count_unescaped(tag_content, '\'') % 2 == 1;

    if in_double_quote || in_single_quote {
        let quote = if in_double_quote { '"' } else { '\'' };
        let attr_name = extract_current_attr(tag_content, quote);
        return Some(HtmlContext::AttributeValue {
            tag: tag_name.to_string(),
            attr: attr_name,
            quote,
        });
    }

    // Check for unquoted attribute: <input value=CANARY
    // The canary position is right at the boundary, so tag_content may end with "="
    // or have a short unquoted value after it
    let trimmed = tag_content.trim_end();
    if let Some(eq_pos) = trimmed.rfind('=') {
        let after_eq = trimmed[eq_pos + 1..].trim_start();
        // Either empty (canary is right after =) or has content with no quotes
        let is_unquoted = after_eq.is_empty()
            || (!after_eq.starts_with('"')
                && !after_eq.starts_with('\'')
                && !after_eq.contains(char::is_whitespace));

        if is_unquoted {
            let before_eq = trimmed[..eq_pos].trim_end();
            let attr = before_eq
                .rsplit(|c: char| c.is_whitespace())
                .next()
                .unwrap_or("")
                .to_lowercase();
            if !attr.is_empty() && attr.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
                return Some(HtmlContext::UnquotedAttributeValue {
                    tag: tag_name.to_string(),
                    attr,
                });
            }
        }
    }

    None
}

fn detect_script_subcontext(script_body: &str) -> HtmlContext {
    // Check backtick (template literal)
    if count_unescaped(script_body, '`') % 2 == 1 {
        return HtmlContext::TemplateLiteral;
    }
    // Check double-quoted JS string
    if count_unescaped(script_body, '"') % 2 == 1 {
        return HtmlContext::ScriptString { quote: '"' };
    }
    // Check single-quoted JS string
    if count_unescaped(script_body, '\'') % 2 == 1 {
        return HtmlContext::ScriptString { quote: '\'' };
    }
    HtmlContext::ScriptBlock
}

fn extract_current_attr(tag_content: &str, quote: char) -> String {
    let quote_str = quote.to_string();
    if let Some(last_quote_pos) = tag_content.rfind(&quote_str) {
        let before_quote = &tag_content[..last_quote_pos];
        if let Some(eq_pos) = before_quote.rfind('=') {
            let before_eq = before_quote[..eq_pos].trim_end();
            let attr = before_eq
                .rsplit(|c: char| c.is_whitespace())
                .next()
                .unwrap_or("");
            return attr.to_lowercase();
        }
    }
    String::new()
}

pub fn is_executable_context(context: &HtmlContext) -> bool {
    match context {
        HtmlContext::ScriptBlock
        | HtmlContext::ScriptString { .. }
        | HtmlContext::TemplateLiteral
        | HtmlContext::SvgContext => true,
        HtmlContext::AttributeValue { attr, .. }
        | HtmlContext::UnquotedAttributeValue { attr, .. } => {
            attr.starts_with("on") || attr == "href" || attr == "src" || attr == "action"
        }
        _ => false,
    }
}

pub fn is_dangerous_attribute(attr: &str) -> bool {
    attr.starts_with("on")
        || attr == "href"
        || attr == "src"
        || attr == "action"
        || attr == "formaction"
        || attr == "data"
        || attr == "srcdoc"
        || attr == "style"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_script_context() {
        let html = r#"<script>var x = CANARY;</script>"#;
        let pos = html.find("CANARY").unwrap();
        assert!(matches!(detect_context(html, pos), HtmlContext::ScriptBlock));
    }

    #[test]
    fn test_detect_script_string_double() {
        let html = r#"<script>var x = "CANARY";</script>"#;
        let pos = html.find("CANARY").unwrap();
        match detect_context(html, pos) {
            HtmlContext::ScriptString { quote } => assert_eq!(quote, '"'),
            other => panic!("Expected ScriptString, got {:?}", other),
        }
    }

    #[test]
    fn test_detect_script_string_single() {
        let html = r#"<script>var x = 'CANARY';</script>"#;
        let pos = html.find("CANARY").unwrap();
        match detect_context(html, pos) {
            HtmlContext::ScriptString { quote } => assert_eq!(quote, '\''),
            other => panic!("Expected ScriptString, got {:?}", other),
        }
    }

    #[test]
    fn test_detect_template_literal() {
        let html = "<script>var x = `hello ${CANARY}`;</script>";
        let pos = html.find("CANARY").unwrap();
        assert!(matches!(detect_context(html, pos), HtmlContext::TemplateLiteral));
    }

    #[test]
    fn test_detect_attribute_context() {
        let html = r#"<input value="CANARY">"#;
        let pos = html.find("CANARY").unwrap();
        match detect_context(html, pos) {
            HtmlContext::AttributeValue { tag, attr, quote } => {
                assert_eq!(tag, "input");
                assert_eq!(attr, "value");
                assert_eq!(quote, '"');
            }
            other => panic!("Expected AttributeValue, got {:?}", other),
        }
    }

    #[test]
    fn test_detect_unquoted_attribute() {
        let html = "<input value=CANARY>";
        let pos = html.find("CANARY").unwrap();
        match detect_context(html, pos) {
            HtmlContext::UnquotedAttributeValue { tag, attr } => {
                assert_eq!(tag, "input");
                assert_eq!(attr, "value");
            }
            other => panic!("Expected UnquotedAttributeValue, got {:?}", other),
        }
    }

    #[test]
    fn test_detect_escaped_quotes() {
        let html = r#"<input value="he said \"hello\" CANARY">"#;
        let pos = html.find("CANARY").unwrap();
        match detect_context(html, pos) {
            HtmlContext::AttributeValue { attr, .. } => assert_eq!(attr, "value"),
            other => panic!("Expected AttributeValue, got {:?}", other),
        }
    }

    #[test]
    fn test_detect_comment_context() {
        let html = "<!-- CANARY -->";
        let pos = html.find("CANARY").unwrap();
        assert!(matches!(detect_context(html, pos), HtmlContext::Comment));
    }

    #[test]
    fn test_detect_plain_context() {
        let html = "<div>CANARY</div>";
        let pos = html.find("CANARY").unwrap();
        assert!(matches!(detect_context(html, pos), HtmlContext::Plain));
    }

    #[test]
    fn test_detect_svg_attribute() {
        let html = "<svg onload=CANARY>";
        let pos = html.find("CANARY").unwrap();
        match detect_context(html, pos) {
            HtmlContext::UnquotedAttributeValue { tag, attr } => {
                assert_eq!(tag, "svg");
                assert_eq!(attr, "onload");
            }
            other => panic!("Expected UnquotedAttributeValue, got {:?}", other),
        }
    }

    #[test]
    fn test_detect_style_context() {
        let html = "<style>.cls { background: CANARY; }</style>";
        let pos = html.find("CANARY").unwrap();
        assert!(matches!(detect_context(html, pos), HtmlContext::StyleBlock));
    }

    #[test]
    fn test_count_unescaped() {
        assert_eq!(count_unescaped(r#"hello "world""#, '"'), 2);
        assert_eq!(count_unescaped(r#"hello \"world\""#, '"'), 0);
        assert_eq!(count_unescaped(r#""test""#, '"'), 2);
        assert_eq!(count_unescaped("no quotes", '"'), 0);
    }

    #[test]
    fn test_executable_contexts() {
        assert!(is_executable_context(&HtmlContext::ScriptBlock));
        assert!(is_executable_context(&HtmlContext::ScriptString { quote: '"' }));
        assert!(is_executable_context(&HtmlContext::TemplateLiteral));
        assert!(is_executable_context(&HtmlContext::SvgContext));
        assert!(is_executable_context(&HtmlContext::AttributeValue {
            tag: "div".into(), attr: "onclick".into(), quote: '"'
        }));
        assert!(!is_executable_context(&HtmlContext::Plain));
        assert!(!is_executable_context(&HtmlContext::Comment));
    }
}
