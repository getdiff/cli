//! Daemon configuration sync from the platform.
//!
//! Periodically fetches `GET /v1/daemon-config` to get the current mode
//! (observe vs enforce), policies, and available secrets. Fetches credentials
//! for providers listed in the secrets array and caches them with a TTL.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::config::PolicyConfig;
use crate::policy::PolicyEvaluator;
use crate::proxy::GatewayState;

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// Response from `GET /v1/daemon-config`.
#[derive(Debug, Clone, Deserialize)]
pub struct DaemonConfigResponse {
    pub org_id: String,
    pub mode: String, // "enforce" or "observe"
    #[serde(default)]
    pub policies: Vec<PlatformPolicy>,
    #[serde(default)]
    pub secrets: Vec<String>,
}

/// A single policy from the platform, keyed by provider name.
#[derive(Debug, Clone, Deserialize)]
pub struct PlatformPolicy {
    pub provider: String,
    #[serde(flatten)]
    pub rules: PolicyConfig,
}

// ---------------------------------------------------------------------------
// In-memory platform state
// ---------------------------------------------------------------------------

/// Cached credential with TTL tracking.
pub struct CachedCredential {
    pub value: String,
    pub fetched_at: Instant,
}

/// Platform-synced configuration held in `GatewayState.platform`.
pub struct PlatformConfig {
    /// Org ID resolved from the CLI token by the platform.
    pub org_id: Option<String>,
    /// Gateway mode: "enforce" or "observe".
    pub mode: String,
    /// Policy evaluators keyed by provider name, from the platform.
    pub policies: HashMap<String, PolicyEvaluator>,
    /// Provider names that have secrets available on the platform.
    pub secret_providers: Vec<String>,
    /// Cached credentials keyed by provider name.
    pub credentials: HashMap<String, CachedCredential>,
}

impl Default for PlatformConfig {
    fn default() -> Self {
        Self {
            org_id: None,
            mode: "observe".to_string(),
            policies: HashMap::new(),
            secret_providers: Vec::new(),
            credentials: HashMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const CREDENTIAL_TTL: Duration = Duration::from_secs(300); // 5 minutes
const SYNC_INTERVAL: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// Platform API calls
// ---------------------------------------------------------------------------

/// Fetch daemon config from the platform.
async fn fetch_daemon_config(
    client: &reqwest::Client,
    control_plane_url: &str,
    api_token: &str,
) -> Result<DaemonConfigResponse, String> {
    let url = format!(
        "{}/v1/daemon-config",
        control_plane_url.trim_end_matches('/')
    );

    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", api_token))
        .send()
        .await
        .map_err(|e| format!("daemon-config fetch failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!(
            "daemon-config fetch failed: HTTP {}",
            resp.status()
        ));
    }

    resp.json::<DaemonConfigResponse>()
        .await
        .map_err(|e| format!("daemon-config parse failed: {}", e))
}

/// Fetch a credential for a provider from the platform secret store.
async fn fetch_credential(
    client: &reqwest::Client,
    control_plane_url: &str,
    api_token: &str,
    org_id: &str,
    provider: &str,
) -> Result<String, String> {
    let url = format!(
        "{}/v1/orgs/{}/secrets/{}",
        control_plane_url.trim_end_matches('/'),
        org_id,
        provider
    );

    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", api_token))
        .send()
        .await
        .map_err(|e| format!("credential fetch for {} failed: {}", provider, e))?;

    if !resp.status().is_success() {
        return Err(format!(
            "credential fetch for {} failed: HTTP {}",
            provider,
            resp.status()
        ));
    }

    #[derive(Deserialize)]
    struct SecretResponse {
        value: String,
    }

    let body = resp
        .json::<SecretResponse>()
        .await
        .map_err(|e| format!("credential parse for {} failed: {}", provider, e))?;

    Ok(body.value)
}

// ---------------------------------------------------------------------------
// Sync loop
// ---------------------------------------------------------------------------

/// Spawn the background daemon config sync loop. Does nothing if the control
/// plane URL or API token is empty.
pub fn spawn_config_sync(state: Arc<GatewayState>, control_plane_url: String, api_token: String) {
    if control_plane_url.is_empty() || api_token.is_empty() {
        return;
    }

    tokio::spawn(async move {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();

        // Short delay before first sync to let startup complete.
        tokio::time::sleep(Duration::from_secs(2)).await;

        loop {
            if let Err(e) = sync_once(&client, &control_plane_url, &api_token, &state).await {
                eprintln!("[gateway] config sync: {}", e);
            }
            tokio::time::sleep(SYNC_INTERVAL).await;
        }
    });
}

/// Run one sync cycle: fetch config, apply policies, refresh credentials.
async fn sync_once(
    client: &reqwest::Client,
    control_plane_url: &str,
    api_token: &str,
    state: &Arc<GatewayState>,
) -> Result<(), String> {
    let config = fetch_daemon_config(client, control_plane_url, api_token).await?;
    apply_daemon_config(state, &config);

    // Fetch credentials for providers listed in secrets.
    let org_id = config.org_id.clone();
    for provider in &config.secrets {
        let should_fetch = {
            let platform = state.platform.read().unwrap();
            match platform.credentials.get(provider) {
                Some(cached) => cached.fetched_at.elapsed() > CREDENTIAL_TTL,
                None => true,
            }
        };

        if should_fetch {
            match fetch_credential(client, control_plane_url, api_token, &org_id, provider).await {
                Ok(value) => {
                    // Update platform credential cache.
                    {
                        let mut platform = state.platform.write().unwrap();
                        platform.credentials.insert(
                            provider.clone(),
                            CachedCredential {
                                value: value.clone(),
                                fetched_at: Instant::now(),
                            },
                        );
                    }
                    // Also update the ProviderEntry credential for path-prefix mode.
                    {
                        let mut providers = state.providers.write().unwrap();
                        if let Some(entry) = providers.get_mut(provider) {
                            entry.credential = value;
                            entry.credential_env_var = Some("platform_secret".to_string());
                        }
                    }
                    eprintln!("[gateway] synced credential for {}", provider);
                }
                Err(e) => {
                    eprintln!("[gateway] {}", e);
                }
            }
        }
    }

    // Remove cached credentials for providers no longer in secrets list.
    {
        let mut platform = state.platform.write().unwrap();
        platform
            .credentials
            .retain(|k, _| config.secrets.contains(k));
    }

    Ok(())
}

/// Apply a daemon config response to the gateway state.
fn apply_daemon_config(state: &GatewayState, config: &DaemonConfigResponse) {
    // Update platform config.
    {
        let mut platform = state.platform.write().unwrap();
        platform.org_id = Some(config.org_id.clone());
        platform.mode = config.mode.clone();
        platform.secret_providers = config.secrets.clone();

        // Build policy evaluators from platform policies.
        let mut policies = HashMap::new();
        for p in &config.policies {
            policies.insert(p.provider.clone(), PolicyEvaluator::new(p.rules.clone()));
        }
        platform.policies = policies;
    }

    // Update path-prefix proxy provider evaluators with platform policies.
    if !config.policies.is_empty() {
        let mut providers = state.providers.write().unwrap();
        for p in &config.policies {
            if let Some(entry) = providers.get_mut(&p.provider) {
                entry.evaluator = PolicyEvaluator::new(p.rules.clone());
            }
        }
    }

    eprintln!(
        "[gateway] synced config: mode={}, policies={}, secrets={}",
        config.mode,
        config.policies.len(),
        config.secrets.len()
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_daemon_config() {
        let json = r#"{
            "org_id": "47ed9240-abcd-1234-5678-000000000000",
            "mode": "enforce",
            "policies": [
                {
                    "provider": "github",
                    "blocked_methods": ["DELETE"],
                    "blocked_paths": ["/repos/*/git/refs/heads/main"]
                },
                {
                    "provider": "stripe",
                    "allowed_methods": ["GET"],
                    "max_amount_cents": 5000
                }
            ],
            "secrets": ["github", "stripe"]
        }"#;

        let config: DaemonConfigResponse = serde_json::from_str(json).unwrap();
        assert_eq!(config.org_id, "47ed9240-abcd-1234-5678-000000000000");
        assert_eq!(config.mode, "enforce");
        assert_eq!(config.policies.len(), 2);
        assert_eq!(config.policies[0].provider, "github");
        assert_eq!(config.policies[0].rules.blocked_methods, vec!["DELETE"]);
        assert_eq!(
            config.policies[0].rules.blocked_paths,
            vec!["/repos/*/git/refs/heads/main"]
        );
        assert_eq!(config.policies[1].provider, "stripe");
        assert_eq!(config.policies[1].rules.max_amount_cents, Some(5000));
        assert_eq!(config.secrets, vec!["github", "stripe"]);
    }

    #[test]
    fn test_deserialize_daemon_config_observe() {
        let json = r#"{
            "org_id": "org-123",
            "mode": "observe",
            "policies": [],
            "secrets": []
        }"#;

        let config: DaemonConfigResponse = serde_json::from_str(json).unwrap();
        assert_eq!(config.mode, "observe");
        assert!(config.policies.is_empty());
        assert!(config.secrets.is_empty());
    }

    #[test]
    fn test_platform_config_default() {
        let pc = PlatformConfig::default();
        assert_eq!(pc.mode, "observe");
        assert!(pc.org_id.is_none());
        assert!(pc.policies.is_empty());
        assert!(pc.credentials.is_empty());
    }
}
