//! E2E envelope credential sync for the local proxy.
//!
//! Milestone 2 of the credential MVP (spec: product/specs/0-idea/credential-mvp/
//! in the diff monorepo). The daemon:
//!
//! 1. Loads (or generates + enrolls) a P-256 device key at
//!    `~/.config/diff/device_key.json`.
//! 2. Syncs the user's injection mappings from the Diff app
//!    (`GET /api/v1/credentials/injection-mappings`).
//! 3. Fetches each mapped credential's ciphertext envelope
//!    (`GET /api/v1/credentials/:id/envelope`) and unwraps the DEK with the
//!    device key — the server only ever sees ciphertext.
//! 4. Caches plaintext in `GatewayState.platform.credentials` (in-memory,
//!    TTL-bounded), the same cache the forward proxy injects from. Plaintext
//!    is never written to disk or logs.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use crate::daemon_config::CachedCredential;
use crate::proxy::GatewayState;

const SYNC_INTERVAL: Duration = Duration::from_secs(60);
const CREDENTIAL_TTL: Duration = Duration::from_secs(300);

// ---------------------------------------------------------------------------
// Device key storage
// ---------------------------------------------------------------------------

/// Device key file at `~/.config/diff/device_key.json` (0600).
/// `kid` is empty until the key is enrolled with the platform.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceKeyFile {
    #[serde(default)]
    pub kid: String,
    /// base64url 32-byte P-256 scalar.
    pub private_scalar: String,
    /// base64url 65-byte uncompressed SEC1 public key.
    pub public_key: String,
}

pub fn device_key_path() -> PathBuf {
    dirs::config_dir()
        .or_else(|| dirs::home_dir().map(|h| h.join(".config")))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("diff")
        .join("device_key.json")
}

fn write_secure_file(path: &std::path::Path, contents: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Load the device key file, or generate a fresh keypair (not yet enrolled).
pub fn load_or_create_device_key(path: &std::path::Path) -> Result<DeviceKeyFile, String> {
    if let Ok(contents) = std::fs::read_to_string(path)
        && let Ok(key) = serde_json::from_str::<DeviceKeyFile>(&contents)
    {
        return Ok(key);
    }
    let (scalar, public) = getdiff_envelope::generate_keypair();
    let key = DeviceKeyFile {
        kid: String::new(),
        private_scalar: URL_SAFE_NO_PAD.encode(&scalar),
        public_key: URL_SAFE_NO_PAD.encode(&public),
    };
    let contents = serde_json::to_string_pretty(&key).map_err(|e| e.to_string())?;
    write_secure_file(path, contents.as_bytes()).map_err(|e| format!("writing device key: {e}"))?;
    Ok(key)
}

fn save_device_key(path: &std::path::Path, key: &DeviceKeyFile) -> Result<(), String> {
    let contents = serde_json::to_string_pretty(key).map_err(|e| e.to_string())?;
    write_secure_file(path, contents.as_bytes()).map_err(|e| format!("writing device key: {e}"))
}

// ---------------------------------------------------------------------------
// Wire types (Diff app credential API)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct EnrollResponse {
    kid: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InjectionMapping {
    #[serde(rename = "credentialId")]
    pub credential_id: String,
    #[serde(rename = "envName")]
    pub env_name: String,
    pub provider: Option<String>,
}

#[derive(Debug, Deserialize)]
struct EnvelopeResponse {
    envelope: getdiff_envelope::Envelope,
}

// ---------------------------------------------------------------------------
// Platform API calls
// ---------------------------------------------------------------------------

fn api_url(app_url: &str, path: &str) -> String {
    format!("{}{}", app_url.trim_end_matches('/'), path)
}

/// Enroll the device public key. Returns the platform-assigned kid.
pub async fn enroll_device_key(
    client: &reqwest::Client,
    app_url: &str,
    api_token: &str,
    public_key_b64: &str,
) -> Result<String, String> {
    let hostname = gethostname::gethostname().to_string_lossy().to_string();
    let resp = client
        .post(api_url(app_url, "/api/v1/credentials/device-keys"))
        .header("Authorization", format!("Bearer {api_token}"))
        .json(&serde_json::json!({
            "name": format!("{hostname} getdiff daemon"),
            "role": "device",
            "publicKey": public_key_b64,
        }))
        .send()
        .await
        .map_err(|e| format!("device key enrollment failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!(
            "device key enrollment failed: HTTP {}",
            resp.status()
        ));
    }
    let body = resp
        .json::<EnrollResponse>()
        .await
        .map_err(|e| format!("device key enrollment parse failed: {e}"))?;
    Ok(body.kid)
}

async fn fetch_mappings(
    client: &reqwest::Client,
    app_url: &str,
    api_token: &str,
) -> Result<Vec<InjectionMapping>, String> {
    let resp = client
        .get(api_url(app_url, "/api/v1/credentials/injection-mappings"))
        .header("Authorization", format!("Bearer {api_token}"))
        .send()
        .await
        .map_err(|e| format!("mapping sync failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("mapping sync failed: HTTP {}", resp.status()));
    }
    resp.json::<Vec<InjectionMapping>>()
        .await
        .map_err(|e| format!("mapping parse failed: {e}"))
}

async fn fetch_envelope(
    client: &reqwest::Client,
    app_url: &str,
    api_token: &str,
    credential_id: &str,
) -> Result<getdiff_envelope::Envelope, String> {
    let resp = client
        .get(api_url(
            app_url,
            &format!("/api/v1/credentials/{credential_id}/envelope"),
        ))
        .header("Authorization", format!("Bearer {api_token}"))
        .send()
        .await
        .map_err(|e| format!("envelope fetch for {credential_id} failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!(
            "envelope fetch for {credential_id} failed: HTTP {}",
            resp.status()
        ));
    }
    let body = resp
        .json::<EnvelopeResponse>()
        .await
        .map_err(|e| format!("envelope parse for {credential_id} failed: {e}"))?;
    Ok(body.envelope)
}

// ---------------------------------------------------------------------------
// Sync
// ---------------------------------------------------------------------------

fn holder_from_file(key: &DeviceKeyFile) -> Result<getdiff_envelope::KeyHolder, String> {
    Ok(getdiff_envelope::KeyHolder {
        kid: key.kid.clone(),
        private_scalar: URL_SAFE_NO_PAD
            .decode(&key.private_scalar)
            .map_err(|e| format!("bad device key scalar: {e}"))?,
    })
}

/// Ensure the device key exists and is enrolled. Returns the ready-to-use key.
pub async fn ensure_enrolled_device_key(
    client: &reqwest::Client,
    app_url: &str,
    api_token: &str,
    path: &std::path::Path,
) -> Result<DeviceKeyFile, String> {
    let mut key = load_or_create_device_key(path)?;
    if key.kid.is_empty() {
        let kid = enroll_device_key(client, app_url, api_token, &key.public_key).await?;
        key.kid = kid;
        save_device_key(path, &key)?;
        eprintln!(
            "[gateway] enrolled device key {} for credential injection",
            key.kid
        );
    }
    Ok(key)
}

/// One credential sync cycle: mappings -> envelopes -> decrypt -> cache.
/// Returns the number of credentials cached.
pub async fn sync_envelope_credentials(
    client: &reqwest::Client,
    app_url: &str,
    api_token: &str,
    device_key: &DeviceKeyFile,
    state: &Arc<GatewayState>,
) -> Result<usize, String> {
    let mappings = fetch_mappings(client, app_url, api_token).await?;
    let holder = holder_from_file(device_key)?;

    // Which providers need a (re)fetch?
    let mut wanted: HashMap<String, String> = HashMap::new(); // provider -> credential_id
    for mapping in &mappings {
        let Some(provider) = mapping.provider.clone() else {
            continue;
        };
        wanted.insert(provider, mapping.credential_id.clone());
    }

    let stale: Vec<(String, String)> = {
        let platform = state.platform.read().unwrap();
        wanted
            .iter()
            .filter(|(provider, _)| match platform.credentials.get(*provider) {
                Some(cached) => cached.fetched_at.elapsed() > CREDENTIAL_TTL,
                None => true,
            })
            .map(|(p, c)| (p.clone(), c.clone()))
            .collect()
    };

    let mut synced = 0;
    for (provider, credential_id) in stale {
        let envelope = match fetch_envelope(client, app_url, api_token, &credential_id).await {
            Ok(e) => e,
            Err(e) => {
                eprintln!("[gateway] {e}");
                continue;
            }
        };
        let plaintext = match getdiff_envelope::open(&envelope, &holder) {
            Ok(p) => p,
            Err(getdiff_envelope::EnvelopeError::NoWrap) => {
                eprintln!(
                    "[gateway] credential {credential_id}: no wrap for this device key \
                     (kid {}) — re-stage or promote the credential to this device",
                    holder.kid
                );
                continue;
            }
            Err(e) => {
                eprintln!("[gateway] credential {credential_id}: decrypt failed: {e}");
                continue;
            }
        };
        let value = match String::from_utf8(plaintext) {
            Ok(v) => v,
            Err(_) => {
                eprintln!("[gateway] credential {credential_id}: value is not UTF-8; skipping");
                continue;
            }
        };
        {
            let mut platform = state.platform.write().unwrap();
            platform.credentials.insert(
                provider.clone(),
                CachedCredential {
                    value,
                    fetched_at: Instant::now(),
                },
            );
        }
        eprintln!("[gateway] synced envelope credential for {provider} (client-side decrypt)");
        synced += 1;
    }

    // Drop cached credentials whose mapping disappeared, unless the legacy
    // daemon-config sync also owns that provider.
    {
        let mut platform = state.platform.write().unwrap();
        let legacy = platform.secret_providers.clone();
        platform
            .credentials
            .retain(|provider, _| wanted.contains_key(provider) || legacy.contains(provider));
    }

    Ok(synced)
}

/// Initial sync + background loop. No-op when the app URL or token is empty.
pub async fn initial_sync(state: &Arc<GatewayState>, app_url: &str, api_token: &str) {
    if app_url.is_empty() || api_token.is_empty() {
        return;
    }
    let client = build_client();
    let key =
        match ensure_enrolled_device_key(&client, app_url, api_token, &device_key_path()).await {
            Ok(k) => k,
            Err(e) => {
                eprintln!("[gateway] envelope credentials disabled: {e}");
                return;
            }
        };
    if let Err(e) = sync_envelope_credentials(&client, app_url, api_token, &key, state).await {
        eprintln!("[gateway] initial envelope credential sync failed: {e}");
    }
}

/// Spawn the background envelope credential sync loop.
pub fn spawn_sync(state: Arc<GatewayState>, app_url: String, api_token: String) {
    if app_url.is_empty() || api_token.is_empty() {
        return;
    }
    tokio::spawn(async move {
        let client = build_client();
        let key =
            match ensure_enrolled_device_key(&client, &app_url, &api_token, &device_key_path())
                .await
            {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("[gateway] envelope credentials disabled: {e}");
                    return;
                }
            };
        loop {
            tokio::time::sleep(SYNC_INTERVAL).await;
            if let Err(e) =
                sync_envelope_credentials(&client, &app_url, &api_token, &key, &state).await
            {
                eprintln!("[gateway] envelope credential sync: {e}");
            }
        }
    });
}

fn build_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

/// Read the Diff app server URL: `DIFF_SERVER` env var, then config.json.
pub fn read_app_url() -> String {
    if let Ok(url) = std::env::var("DIFF_SERVER")
        && !url.is_empty()
    {
        return url;
    }
    let config_path = dirs::config_dir()
        .or_else(|| dirs::home_dir().map(|h| h.join(".config")))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("diff")
        .join("config.json");
    if let Ok(contents) = std::fs::read_to_string(&config_path)
        && let Ok(json) = serde_json::from_str::<serde_json::Value>(&contents)
        && let Some(server) = json.get("server").and_then(|v| v.as_str())
    {
        return server.to_string();
    }
    String::new()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_key_create_and_reload_is_stable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("device_key.json");
        let first = load_or_create_device_key(&path).unwrap();
        assert!(first.kid.is_empty());
        assert!(!first.private_scalar.is_empty());
        let second = load_or_create_device_key(&path).unwrap();
        assert_eq!(first.private_scalar, second.private_scalar);
        assert_eq!(first.public_key, second.public_key);
    }

    #[cfg(unix)]
    #[test]
    fn device_key_file_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("device_key.json");
        load_or_create_device_key(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn holder_round_trips_with_generated_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("device_key.json");
        let mut key = load_or_create_device_key(&path).unwrap();
        key.kid = "kid-test".to_string();

        let recipient = getdiff_envelope::Recipient {
            kid: key.kid.clone(),
            role: "device".to_string(),
            public_key: URL_SAFE_NO_PAD.decode(&key.public_key).unwrap(),
        };
        let envelope = getdiff_envelope::seal(b"sk_live_test_value", &[recipient]).unwrap();
        let holder = holder_from_file(&key).unwrap();
        assert_eq!(
            getdiff_envelope::open(&envelope, &holder).unwrap(),
            b"sk_live_test_value"
        );
    }

    #[test]
    fn mapping_deserializes_from_app_response() {
        let json = r#"[{
            "id": "m1",
            "credentialId": "cred-1",
            "envName": "STRIPE_SECRET_KEY",
            "scope": "session",
            "sessionId": "s1",
            "repoPath": null,
            "provider": "stripe",
            "label": "Stripe live key",
            "createdAt": "2026-07-07T00:00:00.000Z"
        }]"#;
        let mappings: Vec<InjectionMapping> = serde_json::from_str(json).unwrap();
        assert_eq!(mappings[0].credential_id, "cred-1");
        assert_eq!(mappings[0].env_name, "STRIPE_SECRET_KEY");
        assert_eq!(mappings[0].provider.as_deref(), Some("stripe"));
    }
}
