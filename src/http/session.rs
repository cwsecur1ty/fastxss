use anyhow::Result;
use std::collections::HashMap;

use crate::http::client::HttpClient;

pub struct SessionManager {
    authenticated: bool,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            authenticated: false,
        }
    }

    pub async fn authenticate(
        &mut self,
        client: &HttpClient,
        auth_url: &str,
        credentials: &HashMap<String, String>,
    ) -> Result<()> {
        let _resp = client.post_form(auth_url, credentials).await?;
        self.authenticated = true;
        Ok(())
    }

    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }
}
