use anyhow::{Context, Result};
use scraper::{Html, Selector};
use std::collections::HashMap;
use tracing::{debug, info, warn};

use crate::config::Config;
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

    /// Authenticate by navigating to the login page, extracting the form,
    /// filling in credentials, and submitting.
    pub async fn authenticate(
        &mut self,
        client: &HttpClient,
        config: &Config,
    ) -> Result<()> {
        let auth_url = match &config.auth_url {
            Some(url) => url.clone(),
            None => return Ok(()),
        };

        let username = config.auth_user.as_deref().unwrap_or("");
        let password = config.auth_pass.as_deref().unwrap_or("");

        if username.is_empty() && password.is_empty() {
            warn!("--auth-url set but no --auth-user/--auth-pass provided");
            return Ok(());
        }

        info!("Authenticating at {}", auth_url);

        // Step 1: Fetch the login page
        let resp = client.get(&auth_url).await
            .context("Failed to fetch login page")?;
        let body = resp.text().await?;

        // Step 2: Extract the login form
        let document = Html::parse_document(&body);
        let form_selector = Selector::parse("form").unwrap();
        let input_selector = Selector::parse("input").unwrap();

        let mut form_action = auth_url.clone();
        let mut form_method = "POST".to_string();
        let mut form_data = HashMap::new();

        if let Some(form_el) = document.select(&form_selector).next() {
            if let Some(action) = form_el.value().attr("action") {
                if !action.is_empty() && action != "#" {
                    if let Ok(base) = url::Url::parse(&auth_url) {
                        if let Ok(resolved) = base.join(action) {
                            form_action = resolved.to_string();
                        }
                    }
                }
            }
            if let Some(method) = form_el.value().attr("method") {
                form_method = method.to_uppercase();
            }

            for input_el in form_el.select(&input_selector) {
                let name = match input_el.value().attr("name") {
                    Some(n) if !n.is_empty() => n.to_string(),
                    _ => continue,
                };

                let field_type = input_el.value().attr("type").unwrap_or("text").to_lowercase();
                let default_value = input_el.value().attr("value").unwrap_or("").to_string();

                match field_type.as_str() {
                    "password" => {
                        form_data.insert(name, password.to_string());
                    }
                    "email" | "text" => {
                        if !form_data.values().any(|v| v == username) {
                            form_data.insert(name, username.to_string());
                        } else {
                            form_data.insert(name, default_value);
                        }
                    }
                    "hidden" => {
                        form_data.insert(name, default_value);
                        debug!("Hidden field preserved (CSRF/token)");
                    }
                    "submit" | "button" => {
                        if !default_value.is_empty() {
                            form_data.insert(name, default_value);
                        }
                    }
                    _ => {
                        form_data.insert(name, default_value);
                    }
                }
            }
        }

        if form_data.is_empty() {
            form_data.insert("email".to_string(), username.to_string());
            form_data.insert("username".to_string(), username.to_string());
            form_data.insert("password".to_string(), password.to_string());
        }

        debug!("Submitting login to {} ({} fields)", form_action, form_data.len());

        let resp = if form_method == "POST" {
            client.post_form(&form_action, &form_data).await?
        } else {
            let mut url = url::Url::parse(&form_action)?;
            for (k, v) in &form_data {
                url.query_pairs_mut().append_pair(k, v);
            }
            client.get(url.as_str()).await?
        };

        let status = resp.status();
        if status.is_success() || status.is_redirection() {
            self.authenticated = true;
            info!("Authentication successful ({})", status);
        } else {
            warn!("Authentication may have failed ({})", status);
        }

        Ok(())
    }

    pub async fn validate_session(&self, client: &HttpClient, target_url: &str) -> bool {
        if let Ok(resp) = client.get(target_url).await {
            let url = resp.url().to_string();
            if resp.status().as_u16() == 401 || resp.status().as_u16() == 403 {
                return false;
            }
            let login_indicators = ["login", "signin", "sign-in", "auth/login"];
            for indicator in &login_indicators {
                if url.contains(indicator) && !target_url.contains(indicator) {
                    return false;
                }
            }
            return true;
        }
        false
    }

    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }
}
