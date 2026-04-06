use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};

const ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'<')
    .add(b'>')
    .add(b'&')
    .add(b'\'')
    .add(b'/')
    .add(b'(')
    .add(b')')
    .add(b';');

pub fn url_encode(input: &str) -> String {
    utf8_percent_encode(input, ENCODE_SET).to_string()
}

pub fn double_url_encode(input: &str) -> String {
    // First encode, then manually encode % signs in the result
    let first = url_encode(input);
    first.replace('%', "%25")
}

pub fn html_entity_encode(input: &str) -> String {
    input
        .chars()
        .map(|c| match c {
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '"' => "&quot;".to_string(),
            '\'' => "&#x27;".to_string(),
            '&' => "&amp;".to_string(),
            _ => c.to_string(),
        })
        .collect()
}

pub fn html_numeric_encode(input: &str) -> String {
    input.chars().map(|c| format!("&#{};", c as u32)).collect()
}

pub fn js_unicode_escape(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_string()
            } else {
                format!("\\u{:04x}", c as u32)
            }
        })
        .collect()
}

pub fn mixed_case(input: &str) -> String {
    input
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 0 {
                c.to_uppercase().to_string()
            } else {
                c.to_lowercase().to_string()
            }
        })
        .collect()
}

pub fn null_byte_inject(input: &str) -> String {
    format!("%00{input}")
}

pub fn base64_encode(input: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(input.as_bytes())
}

#[derive(Debug, Clone, Copy)]
pub enum EncodingType {
    None,
    UrlEncode,
    DoubleUrlEncode,
    HtmlEntity,
    HtmlNumeric,
    HtmlHexEntity,
    JsUnicode,
    CssEscape,
    UnicodeFullwidth,
    MixedCase,
    NullByte,
}

/// CSS escape encoding (\3c for <)
pub fn css_escape(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_string()
            } else {
                format!("\\{:x} ", c as u32)
            }
        })
        .collect()
}

/// Unicode fullwidth character substitution
pub fn unicode_fullwidth(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_ascii() && (c as u32) >= 0x21 && (c as u32) <= 0x7E {
                char::from_u32(c as u32 + 0xFEE0).unwrap_or(c)
            } else {
                c
            }
        })
        .collect()
}

/// HTML hex entity encoding (&#x3c; for <)
pub fn html_hex_entity_encode(input: &str) -> String {
    input.chars().map(|c| format!("&#x{:x};", c as u32)).collect()
}

pub fn apply_encoding(input: &str, encoding: EncodingType) -> String {
    match encoding {
        EncodingType::None => input.to_string(),
        EncodingType::UrlEncode => url_encode(input),
        EncodingType::DoubleUrlEncode => double_url_encode(input),
        EncodingType::HtmlEntity => html_entity_encode(input),
        EncodingType::HtmlNumeric => html_numeric_encode(input),
        EncodingType::HtmlHexEntity => html_hex_entity_encode(input),
        EncodingType::JsUnicode => js_unicode_escape(input),
        EncodingType::CssEscape => css_escape(input),
        EncodingType::UnicodeFullwidth => unicode_fullwidth(input),
        EncodingType::MixedCase => mixed_case(input),
        EncodingType::NullByte => null_byte_inject(input),
    }
}

pub fn all_encodings() -> Vec<EncodingType> {
    vec![
        EncodingType::None,
        EncodingType::UrlEncode,
        EncodingType::DoubleUrlEncode,
        EncodingType::HtmlEntity,
        EncodingType::MixedCase,
    ]
}

// === Encoding Chains ===

/// A chain of encodings applied in sequence (left to right)
#[derive(Debug, Clone)]
pub struct EncodingChain {
    pub steps: Vec<EncodingType>,
    pub name: String,
}

impl EncodingChain {
    pub fn apply(&self, input: &str) -> String {
        let mut result = input.to_string();
        for step in &self.steps {
            result = apply_encoding(&result, *step);
        }
        result
    }
}

/// Predefined encoding chains for WAF bypass
pub fn evasion_chains() -> Vec<EncodingChain> {
    vec![
        EncodingChain {
            steps: vec![EncodingType::HtmlEntity, EncodingType::UrlEncode],
            name: "HTML→URL".to_string(),
        },
        EncodingChain {
            steps: vec![EncodingType::UrlEncode, EncodingType::HtmlEntity],
            name: "URL→HTML".to_string(),
        },
        EncodingChain {
            steps: vec![EncodingType::MixedCase, EncodingType::UrlEncode],
            name: "MixedCase→URL".to_string(),
        },
        EncodingChain {
            steps: vec![EncodingType::HtmlHexEntity],
            name: "HexEntity".to_string(),
        },
        EncodingChain {
            steps: vec![EncodingType::HtmlNumeric],
            name: "NumericEntity".to_string(),
        },
        EncodingChain {
            steps: vec![EncodingType::JsUnicode],
            name: "JSUnicode".to_string(),
        },
        EncodingChain {
            steps: vec![EncodingType::UnicodeFullwidth],
            name: "Fullwidth".to_string(),
        },
        EncodingChain {
            steps: vec![EncodingType::NullByte, EncodingType::UrlEncode],
            name: "NullByte→URL".to_string(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_encode() {
        assert_eq!(url_encode("<script>"), "%3Cscript%3E");
    }

    #[test]
    fn test_double_url_encode() {
        let result = double_url_encode("<");
        assert_eq!(result, "%253C");
    }

    #[test]
    fn test_html_entity_encode() {
        assert_eq!(html_entity_encode("<>\""), "&lt;&gt;&quot;");
    }

    #[test]
    fn test_js_unicode() {
        let result = js_unicode_escape("<");
        assert_eq!(result, "\\u003c");
    }

    #[test]
    fn test_mixed_case() {
        assert_eq!(mixed_case("script"), "ScRiPt");
    }
}
