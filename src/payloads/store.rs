use std::path::Path;

const REFLECTED_PAYLOADS: &str = include_str!("../../payloads/reflected.txt");
const STORED_PAYLOADS: &str = include_str!("../../payloads/stored.txt");
const DOM_PAYLOADS: &str = include_str!("../../payloads/dom.txt");
const BLIND_PAYLOADS: &str = include_str!("../../payloads/blind.txt");
const POLYGLOT_PAYLOADS: &str = include_str!("../../payloads/polyglot.txt");

pub struct PayloadStore {
    pub reflected: Vec<String>,
    pub stored: Vec<String>,
    pub dom: Vec<String>,
    pub blind: Vec<String>,
    pub polyglot: Vec<String>,
    pub custom: Vec<String>,
}

impl PayloadStore {
    pub fn load(custom_wordlist: Option<&Path>) -> Self {
        let mut store = Self {
            reflected: parse_payload_file(REFLECTED_PAYLOADS),
            stored: parse_payload_file(STORED_PAYLOADS),
            dom: parse_payload_file(DOM_PAYLOADS),
            blind: parse_payload_file(BLIND_PAYLOADS),
            polyglot: parse_payload_file(POLYGLOT_PAYLOADS),
            custom: Vec::new(),
        };

        if let Some(path) = custom_wordlist {
            if let Ok(contents) = std::fs::read_to_string(path) {
                store.custom = parse_payload_file(&contents);
            }
        }

        store
    }

    pub fn all_reflected(&self) -> Vec<&str> {
        let mut payloads: Vec<&str> = self.reflected.iter().map(|s| s.as_str()).collect();
        payloads.extend(self.polyglot.iter().map(|s| s.as_str()));
        payloads.extend(self.custom.iter().map(|s| s.as_str()));
        payloads
    }

    pub fn all_stored(&self) -> Vec<&str> {
        let mut payloads: Vec<&str> = self.stored.iter().map(|s| s.as_str()).collect();
        payloads.extend(self.polyglot.iter().map(|s| s.as_str()));
        payloads.extend(self.custom.iter().map(|s| s.as_str()));
        payloads
    }

    pub fn all_dom(&self) -> Vec<&str> {
        let mut payloads: Vec<&str> = self.dom.iter().map(|s| s.as_str()).collect();
        payloads.extend(self.custom.iter().map(|s| s.as_str()));
        payloads
    }

    pub fn all_blind(&self) -> Vec<&str> {
        let mut payloads: Vec<&str> = self.blind.iter().map(|s| s.as_str()).collect();
        payloads.extend(self.custom.iter().map(|s| s.as_str()));
        payloads
    }
}

fn parse_payload_file(contents: &str) -> Vec<String> {
    contents
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect()
}
