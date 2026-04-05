use rand::Rng;
use std::path::Path;

use crate::payloads::encoder::{self, EncodingType};
use crate::payloads::store::PayloadStore;
use crate::scanner::traits::HtmlContext;

pub struct PayloadEngine {
    store: PayloadStore,
}

#[derive(Debug, Clone)]
pub struct GeneratedPayload {
    pub canary: String,
    pub payload: String,
    pub raw_payload: String,
    pub encoding: EncodingType,
}

impl PayloadEngine {
    pub fn new(custom_wordlist: Option<&Path>) -> Self {
        Self {
            store: PayloadStore::load(custom_wordlist),
        }
    }

    pub fn generate_canary() -> String {
        let mut rng = rand::thread_rng();
        let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyz0123456789".chars().collect();
        let canary: String = (0..8).map(|_| chars[rng.gen_range(0..chars.len())]).collect();
        format!("fxss{canary}")
    }

    /// Generate a single canary-only probe to test if a parameter reflects at all.
    /// This is much cheaper than sending all payloads.
    pub fn reflection_probe(&self) -> GeneratedPayload {
        let canary = Self::generate_canary();
        GeneratedPayload {
            canary: canary.clone(),
            payload: canary.clone(),
            raw_payload: canary,
            encoding: EncodingType::None,
        }
    }

    /// Generate targeted payloads based on detected context. Much smaller set than full expansion.
    pub fn reflected_payloads_for_context(&self, context: &HtmlContext) -> Vec<GeneratedPayload> {
        let all = self.store.all_reflected();
        let filtered = self.select_payloads_for_context(Some(context), &all);
        // Only use None encoding for targeted payloads - context already tells us what works
        filtered
            .iter()
            .map(|p| {
                let canary = Self::generate_canary();
                let with_canary = p.replace("{{CANARY}}", &canary);
                GeneratedPayload {
                    canary,
                    payload: with_canary.clone(),
                    raw_payload: with_canary,
                    encoding: EncodingType::None,
                }
            })
            .collect()
    }

    /// Full payload set with encodings - used as fallback when context is unknown
    pub fn reflected_payloads(&self, context: Option<&HtmlContext>) -> Vec<GeneratedPayload> {
        let base_payloads = self.select_payloads_for_context(context, &self.store.all_reflected());
        // Limit to top payloads with minimal encodings for speed
        let top_payloads: Vec<&str> = base_payloads.into_iter().take(20).collect();
        self.expand_with_encodings(&top_payloads)
    }

    pub fn stored_payloads(&self, context: Option<&HtmlContext>) -> Vec<GeneratedPayload> {
        let base_payloads = self.select_payloads_for_context(context, &self.store.all_stored());
        let top_payloads: Vec<&str> = base_payloads.into_iter().take(10).collect();
        self.expand_with_encodings(&top_payloads)
    }

    pub fn dom_payloads(&self) -> Vec<GeneratedPayload> {
        self.store
            .all_dom()
            .into_iter()
            .map(|p| {
                let canary = Self::generate_canary();
                let payload = p.replace("{{CANARY}}", &canary);
                GeneratedPayload {
                    canary,
                    payload: payload.clone(),
                    raw_payload: payload,
                    encoding: EncodingType::None,
                }
            })
            .collect()
    }

    pub fn blind_payloads(&self, callback_url: &str) -> Vec<GeneratedPayload> {
        self.store
            .all_blind()
            .into_iter()
            .map(|p| {
                let canary = Self::generate_canary();
                let payload = p
                    .replace("{{CALLBACK}}", callback_url)
                    .replace("{{CANARY}}", &canary);
                GeneratedPayload {
                    canary,
                    payload: payload.clone(),
                    raw_payload: payload,
                    encoding: EncodingType::None,
                }
            })
            .collect()
    }

    fn select_payloads_for_context<'a>(
        &self,
        context: Option<&HtmlContext>,
        all_payloads: &[&'a str],
    ) -> Vec<&'a str> {
        match context {
            Some(HtmlContext::AttributeValue { quote, .. }) => {
                let break_char = match quote {
                    '"' => "\"",
                    '\'' => "'",
                    _ => "\"",
                };
                all_payloads
                    .iter()
                    .filter(|p| {
                        p.contains(break_char)
                            || p.contains("onmouseover")
                            || p.contains("onfocus")
                            || p.contains("autofocus")
                    })
                    .copied()
                    .collect()
            }
            Some(HtmlContext::ScriptBlock) => all_payloads
                .iter()
                .filter(|p| {
                    p.contains("</script>") || p.contains("alert") || p.contains("eval")
                })
                .copied()
                .collect(),
            Some(HtmlContext::Comment) => all_payloads
                .iter()
                .filter(|p| p.contains("-->"))
                .copied()
                .collect(),
            _ => all_payloads.to_vec(),
        }
    }

    fn expand_with_encodings(&self, base_payloads: &[&str]) -> Vec<GeneratedPayload> {
        let encodings = encoder::all_encodings();
        let mut result = Vec::new();

        for payload in base_payloads {
            let canary = Self::generate_canary();
            let with_canary = payload.replace("{{CANARY}}", &canary);

            for &encoding in &encodings {
                let encoded = encoder::apply_encoding(&with_canary, encoding);
                result.push(GeneratedPayload {
                    canary: canary.clone(),
                    payload: encoded,
                    raw_payload: with_canary.clone(),
                    encoding,
                });
            }
        }

        result
    }
}
