use crate::scanner::traits::HtmlContext;

pub fn detect_context(html: &str, canary_pos: usize) -> HtmlContext {
    let before = &html[..canary_pos];

    // Check if inside a script block
    let last_script_open = before.rfind("<script");
    let last_script_close = before.rfind("</script");
    if let Some(open) = last_script_open {
        if last_script_close.map_or(true, |close| close < open) {
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

    // Check if inside a tag attribute
    let last_lt = before.rfind('<');
    let last_gt = before.rfind('>');
    if let Some(lt_pos) = last_lt {
        if last_gt.map_or(true, |gt_pos| gt_pos < lt_pos) {
            // We're inside a tag
            let tag_content = &before[lt_pos..];

            // Extract tag name
            let tag_name = tag_content
                .trim_start_matches('<')
                .split(|c: char| c.is_whitespace() || c == '/' || c == '>')
                .next()
                .unwrap_or("")
                .to_lowercase();

            // Check if inside an attribute value
            let in_double_quote = tag_content.matches('"').count() % 2 == 1;
            let in_single_quote = tag_content.matches('\'').count() % 2 == 1;

            if in_double_quote || in_single_quote {
                // Find the attribute name
                let quote = if in_double_quote { '"' } else { '\'' };
                let attr_name = extract_current_attr(tag_content, quote);
                return HtmlContext::AttributeValue {
                    tag: tag_name,
                    attr: attr_name,
                    quote,
                };
            }

            return HtmlContext::TagBody { tag: tag_name };
        }
    }

    HtmlContext::Plain
}

fn extract_current_attr(tag_content: &str, quote: char) -> String {
    // Walk backwards from the end to find the last attribute name before the open quote
    let quote_str = quote.to_string();
    if let Some(last_quote_pos) = tag_content.rfind(&quote_str) {
        let before_quote = &tag_content[..last_quote_pos];
        // Look for pattern: attr_name=
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
        HtmlContext::ScriptBlock => true,
        HtmlContext::AttributeValue { attr, .. } => {
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
        let html = r#"<script>var x = "CANARY";</script>"#;
        let pos = html.find("CANARY").unwrap();
        assert!(matches!(detect_context(html, pos), HtmlContext::ScriptBlock));
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
}
