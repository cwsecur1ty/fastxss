use async_trait::async_trait;
use chromiumoxide::browser::{Browser, BrowserConfig};
use chromiumoxide::cdp::browser_protocol::page::AddScriptToEvaluateOnNewDocumentParams;
use futures::StreamExt;
use std::path::PathBuf;
use std::time::Duration;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::http::client::HttpClient;
use crate::payloads::engine::PayloadEngine;
use crate::scanner::traits::*;

const SINK_HOOK_SCRIPT: &str = r#"
(function() {
    window.__fxss_findings = [];

    // Hook document.write
    const origWrite = document.write.bind(document);
    document.write = function(s) {
        if (typeof s === 'string' && s.match(/fxss[a-z0-9]{8}/)) {
            window.__fxss_findings.push({sink: 'document.write', value: s});
        }
        return origWrite(s);
    };

    // Hook innerHTML setter
    const origInnerHTMLDesc = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
    if (origInnerHTMLDesc && origInnerHTMLDesc.set) {
        Object.defineProperty(Element.prototype, 'innerHTML', {
            set: function(val) {
                if (typeof val === 'string' && val.match(/fxss[a-z0-9]{8}/)) {
                    window.__fxss_findings.push({sink: 'innerHTML', value: val, element: this.tagName});
                }
                return origInnerHTMLDesc.set.call(this, val);
            },
            get: origInnerHTMLDesc.get,
            configurable: true
        });
    }

    // Hook outerHTML setter
    const origOuterHTMLDesc = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');
    if (origOuterHTMLDesc && origOuterHTMLDesc.set) {
        Object.defineProperty(Element.prototype, 'outerHTML', {
            set: function(val) {
                if (typeof val === 'string' && val.match(/fxss[a-z0-9]{8}/)) {
                    window.__fxss_findings.push({sink: 'outerHTML', value: val});
                }
                return origOuterHTMLDesc.set.call(this, val);
            },
            get: origOuterHTMLDesc.get,
            configurable: true
        });
    }

    // Hook eval
    const origEval = window.eval;
    window.eval = function(s) {
        if (typeof s === 'string' && s.match(/fxss[a-z0-9]{8}/)) {
            window.__fxss_findings.push({sink: 'eval', value: s});
        }
        return origEval(s);
    };

    // Hook Function constructor
    const origFunction = Function;
    window.Function = function() {
        const args = Array.from(arguments);
        const body = args[args.length - 1];
        if (typeof body === 'string' && body.match(/fxss[a-z0-9]{8}/)) {
            window.__fxss_findings.push({sink: 'Function', value: body});
        }
        return origFunction.apply(this, args);
    };

    // Hook setTimeout/setInterval with string args
    const origSetTimeout = window.setTimeout;
    window.setTimeout = function(fn, delay) {
        if (typeof fn === 'string' && fn.match(/fxss[a-z0-9]{8}/)) {
            window.__fxss_findings.push({sink: 'setTimeout', value: fn});
        }
        return origSetTimeout.apply(this, arguments);
    };

    const origSetInterval = window.setInterval;
    window.setInterval = function(fn, delay) {
        if (typeof fn === 'string' && fn.match(/fxss[a-z0-9]{8}/)) {
            window.__fxss_findings.push({sink: 'setInterval', value: fn});
        }
        return origSetInterval.apply(this, arguments);
    };

    // Hook jQuery .html() and other jQuery sinks if available
    if (typeof jQuery !== 'undefined') {
        ['html', 'append', 'prepend', 'after', 'before', 'replaceWith'].forEach(function(method) {
            var orig = jQuery.fn[method];
            if (orig) {
                jQuery.fn[method] = function(val) {
                    if (typeof val === 'string' && val.match(/fxss[a-z0-9]{8}/)) {
                        window.__fxss_findings.push({sink: 'jQuery.' + method, value: val});
                    }
                    return orig.apply(this, arguments);
                };
            }
        });
    }

    // Hook insertAdjacentHTML
    var origInsertAdjacentHTML = Element.prototype.insertAdjacentHTML;
    Element.prototype.insertAdjacentHTML = function(position, text) {
        if (typeof text === 'string' && text.match(/fxss[a-z0-9]{8}/)) {
            window.__fxss_findings.push({sink: 'insertAdjacentHTML', value: text, element: this.tagName});
        }
        return origInsertAdjacentHTML.call(this, position, text);
    };

    // Hook Element.append / prepend (when called with strings)
    ['append', 'prepend'].forEach(function(method) {
        var orig = Element.prototype[method];
        if (orig) {
            Element.prototype[method] = function() {
                for (var i = 0; i < arguments.length; i++) {
                    if (typeof arguments[i] === 'string' && arguments[i].match(/fxss[a-z0-9]{8}/)) {
                        window.__fxss_findings.push({sink: 'Element.' + method, value: arguments[i]});
                    }
                }
                return orig.apply(this, arguments);
            };
        }
    });

    // Hook location.assign / location.replace
    ['assign', 'replace'].forEach(function(method) {
        var orig = location[method];
        if (orig) {
            location[method] = function(url) {
                if (typeof url === 'string' && url.match(/fxss[a-z0-9]{8}/)) {
                    window.__fxss_findings.push({sink: 'location.' + method, value: url});
                }
                return orig.call(location, url);
            };
        }
    });

    // Hook window.open
    var origWindowOpen = window.open;
    window.open = function(url) {
        if (typeof url === 'string' && url.match(/fxss[a-z0-9]{8}/)) {
            window.__fxss_findings.push({sink: 'window.open', value: url});
        }
        return origWindowOpen.apply(this, arguments);
    };

    // Hook setAttribute for dangerous attributes (src, href, on*)
    var origSetAttribute = Element.prototype.setAttribute;
    Element.prototype.setAttribute = function(name, value) {
        if (typeof value === 'string' && value.match(/fxss[a-z0-9]{8}/)) {
            var dangerous = ['src', 'href', 'action', 'formaction', 'data', 'srcdoc'];
            if (dangerous.indexOf(name.toLowerCase()) !== -1 || name.toLowerCase().startsWith('on')) {
                window.__fxss_findings.push({sink: 'setAttribute(' + name + ')', value: value, element: this.tagName});
            }
        }
        return origSetAttribute.call(this, name, value);
    };
})();
"#;

pub struct DomScanner {
    browser: Option<Browser>,
    handler_handle: Option<JoinHandle<()>>,
    user_data_dir: Option<PathBuf>,
}

impl DomScanner {
    pub async fn new() -> Self {
        match launch_browser().await {
            Ok((browser, handler_handle, user_data_dir)) => Self {
                browser: Some(browser),
                handler_handle: Some(handler_handle),
                user_data_dir: Some(user_data_dir),
            },
            Err(e) => {
                warn!("Failed to launch headless browser: {}. DOM scanning disabled.", e);
                Self {
                    browser: None,
                    handler_handle: None,
                    user_data_dir: None,
                }
            }
        }
    }

    pub fn is_available(&self) -> bool {
        self.browser.is_some()
    }

    /// Gracefully shut down the browser, clean up handler task and temp directory.
    pub async fn shutdown(&mut self) {
        // Drop the browser to trigger Chrome close
        if let Some(browser) = self.browser.take() {
            drop(browser);
            info!("Browser closed");
        }

        // Abort the handler task
        if let Some(handle) = self.handler_handle.take() {
            handle.abort();
        }

        // Clean up temp user data directory
        if let Some(ref dir) = self.user_data_dir {
            if dir.exists() {
                match tokio::fs::remove_dir_all(dir).await {
                    Ok(_) => debug!("Cleaned up temp dir: {}", dir.display()),
                    Err(e) => debug!("Failed to clean temp dir {}: {}", dir.display(), e),
                }
            }
        }
        self.user_data_dir = None;
    }

    /// Render a page with JS and extract the full HTML (including JS-rendered forms).
    /// Times out after 5 seconds to prevent hangs.
    pub async fn render_page(&self, url: &str) -> Option<String> {
        let browser = self.browser.as_ref()?;

        tokio::time::timeout(Duration::from_secs(5), async {
            let page = browser.new_page(url).await.ok()?;
            tokio::time::sleep(Duration::from_millis(1000)).await;
            let html = page
                .evaluate("document.documentElement.outerHTML")
                .await
                .ok()?
                .into_value::<String>()
                .ok()?;
            let _ = page.close().await;
            Some(html)
        })
        .await
        .unwrap_or(None)
    }

    /// Verify that a payload URL actually triggers JavaScript execution.
    /// Returns true if alert/confirm/prompt was called.
    pub async fn verify_execution(&self, url: &str) -> bool {
        let browser = match &self.browser {
            Some(b) => b,
            None => return false,
        };

        let result = tokio::time::timeout(Duration::from_secs(8), async {
            let page = match browser.new_page("about:blank").await {
                Ok(p) => p,
                Err(_) => return false,
            };

            // Override alert/confirm/prompt to set a flag
            let hook = AddScriptToEvaluateOnNewDocumentParams::new(
                r#"
                window.__fxss_executed = false;
                window.alert = function() { window.__fxss_executed = true; };
                window.confirm = function() { window.__fxss_executed = true; return true; };
                window.prompt = function() { window.__fxss_executed = true; return ''; };
                "#.to_string()
            );
            if page.execute(hook).await.is_err() {
                let _ = page.close().await;
                return false;
            }

            if page.goto(url).await.is_err() {
                let _ = page.close().await;
                return false;
            }

            tokio::time::sleep(Duration::from_millis(2000)).await;

            let executed = page
                .evaluate("window.__fxss_executed === true")
                .await
                .ok()
                .and_then(|v| v.into_value::<bool>().ok())
                .unwrap_or(false);

            let _ = page.close().await;
            executed
        })
        .await
        .unwrap_or(false);

        result
    }
}

async fn launch_browser() -> anyhow::Result<(Browser, JoinHandle<()>, PathBuf)> {
    // Create a unique user data dir to avoid conflicts with running Chrome instances
    let user_data_dir = std::env::temp_dir()
        .join(format!("fastxss-chrome-{}", std::process::id()));

    let mut builder = BrowserConfig::builder()
        .no_sandbox()
        .new_headless_mode()
        .window_size(1920, 1080)
        .user_data_dir(&user_data_dir)
        .arg("--disable-gpu")
        .arg("--disable-dev-shm-usage")
        .arg("--disable-extensions")
        .arg("--disable-background-networking")
        .arg("--disable-default-apps")
        .arg("--disable-sync")
        .arg("--no-first-run");

    // Try to find Chrome/Edge on Windows
    if cfg!(target_os = "windows") {
        let chrome_paths = [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
            r"C:\Program Files\Chromium\Application\chrome.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        ];
        for path in &chrome_paths {
            if std::path::Path::new(path).exists() {
                info!("Using browser: {}", path);
                builder = builder.chrome_executable(path);
                break;
            }
        }
    }

    let config = builder
        .build()
        .map_err(|e| anyhow::anyhow!("Browser config error: {}", e))?;

    let (browser, mut handler) = Browser::launch(config).await?;

    // Spawn handler in background — keep the handle for cleanup
    let handler_handle = tokio::spawn(async move {
        while let Some(event) = handler.next().await {
            let _ = event;
        }
    });

    Ok((browser, handler_handle, user_data_dir))
}

#[async_trait]
impl Scanner for DomScanner {
    fn name(&self) -> &'static str {
        "DOM-based XSS Scanner"
    }

    fn scanner_type(&self) -> ScannerType {
        ScannerType::Dom
    }

    async fn scan(
        &self,
        target: &CrawlResult,
        payload_engine: &PayloadEngine,
        _http_client: &HttpClient,
    ) -> Vec<Finding> {
        let browser = match &self.browser {
            Some(b) => b,
            None => return Vec::new(),
        };

        let mut findings = Vec::new();
        let payloads = payload_engine.dom_payloads();

        for gp in payloads.iter().take(10) {
            // Test via location.hash
            let hash_url = format!("{}#{}", target.url, gp.payload);
            if let Some(finding) = self.test_url(browser, &hash_url, &gp.canary, target, &gp.payload, "location.hash").await {
                findings.push(finding);
                break;
            }

            // Test via query parameter (if the page reads from it)
            let search_url = if target.url.as_str().contains('?') {
                format!("{}&fxss={}", target.url, gp.payload)
            } else {
                format!("{}?fxss={}", target.url, gp.payload)
            };
            if let Some(finding) = self.test_url(browser, &search_url, &gp.canary, target, &gp.payload, "location.search").await {
                findings.push(finding);
                break;
            }
        }

        findings
    }
}

impl DomScanner {
    async fn test_url(
        &self,
        browser: &Browser,
        url: &str,
        canary: &str,
        target: &CrawlResult,
        payload: &str,
        source: &str,
    ) -> Option<Finding> {
        // Wrap entire operation in a 10-second timeout
        tokio::time::timeout(Duration::from_secs(10), async {
            let page = match browser.new_page("about:blank").await {
                Ok(p) => p,
                Err(_) => return None,
            };

            // Inject sink monitoring script before page loads
            let script_params = AddScriptToEvaluateOnNewDocumentParams::new(SINK_HOOK_SCRIPT.to_string());
            if page.execute(script_params).await.is_err() {
                let _ = page.close().await;
                return None;
            }

            // Navigate to the test URL
            if page.goto(url).await.is_err() {
                let _ = page.close().await;
                return None;
            }

            // Wait for page to settle
            tokio::time::sleep(Duration::from_millis(1500)).await;

            // Check for findings
            let result = page
                .evaluate("JSON.stringify(window.__fxss_findings || [])")
                .await;

            let _ = page.close().await;

            match result {
                Ok(val) => {
                    let json_str = val.into_value::<String>().unwrap_or_default();
                    if let Ok(dom_findings) = serde_json::from_str::<Vec<DomFinding>>(&json_str) {
                        for df in dom_findings {
                            if df.value.contains(canary) {
                                debug!(
                                    "DOM XSS found: {} -> {} on {}",
                                    source, df.sink, target.url
                                );

                                return Some(Finding::new(
                                    ScannerType::Dom,
                                    Severity::High,
                                    Confidence::Confirmed,
                                    url.to_string(),
                                    InjectionPoint {
                                        name: source.to_string(),
                                        location: ParamLocation::Fragment,
                                        original_value: None,
                                        context: None,
                                    },
                                    payload.to_string(),
                                    format!("Source: {}, Sink: {}, Value: {}", source, df.sink, truncate(&df.value, 200)),
                                    RequestRecord {
                                        method: "GET".to_string(),
                                        url: url.to_string(),
                                        headers: Vec::new(),
                                        body: None,
                                    },
                                    target.response_status,
                                    Some(HtmlContext::ScriptBlock),
                                ));
                            }
                        }
                    }
                    None
                }
                Err(_) => None,
            }
        })
        .await
        .unwrap_or(None)
    }
}

#[derive(serde::Deserialize)]
struct DomFinding {
    sink: String,
    value: String,
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        s
    } else {
        &s[..max]
    }
}
