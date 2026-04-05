use chrono::{DateTime, Utc};
use dashmap::DashMap;
use std::sync::Arc;

use crate::scanner::blind::BlindInjectionRecord;

#[derive(Debug, Clone)]
pub struct CallbackHit {
    pub canary: String,
    pub source_ip: String,
    pub user_agent: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub query_params: String,
    pub record: BlindInjectionRecord,
}

pub struct TokenTracker {
    token_map: Arc<DashMap<String, BlindInjectionRecord>>,
    hits: Arc<DashMap<String, CallbackHit>>,
}

impl TokenTracker {
    pub fn new(token_map: Arc<DashMap<String, BlindInjectionRecord>>) -> Self {
        Self {
            token_map,
            hits: Arc::new(DashMap::new()),
        }
    }

    pub fn lookup(&self, canary: &str) -> Option<BlindInjectionRecord> {
        self.token_map.get(canary).map(|r| r.value().clone())
    }

    pub fn record_hit(&self, hit: CallbackHit) {
        self.hits.insert(hit.canary.clone(), hit);
    }

    pub fn get_hits(&self) -> Vec<CallbackHit> {
        self.hits.iter().map(|r| r.value().clone()).collect()
    }
}
