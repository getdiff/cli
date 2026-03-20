use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

/// Config file stored at ~/.config/diff/config.json
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    pub token: String,
    pub server: String,
    pub email: String,
    pub org_id: String,
}

/// Returns the path to the config file.
pub fn config_path() -> PathBuf {
    dirs::config_dir()
        .or_else(|| dirs::home_dir().map(|h| h.join(".config")))
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .map(|h| PathBuf::from(h).join(".config"))
        })
        .unwrap_or_else(|| PathBuf::from("."))
        .join("diff")
        .join("config.json")
}

/// Reads the config file. Returns None if it doesn't exist.
pub fn read_config() -> Option<Config> {
    let path = config_path();
    let contents = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&contents).ok()
}

/// Writes the config file with restrictive permissions (0600 on Unix).
pub fn write_config(config: &Config) -> Result<()> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let contents = serde_json::to_string_pretty(config)?;
    write_secure_file(&path, contents.as_bytes())?;
    eprintln!("Config saved to {}", path.display());
    Ok(())
}

fn write_secure_file(path: &std::path::Path, contents: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("config path has no parent directory"))?;
    let temp_path = parent.join(format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("config"),
        uuid::Uuid::new_v4()
    ));

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temp_path)?;
        file.write_all(contents)?;
        file.sync_all()?;
    }

    #[cfg(not(unix))]
    {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp_path)?;
        file.write_all(contents)?;
        file.sync_all()?;
    }

    std::fs::rename(&temp_path, path)?;
    Ok(())
}

/// Run the browser-based login flow.
/// 1. Start a local HTTP server on a random port
/// 2. Open the browser to {server}/cli-auth?port={port}
/// 3. Wait for the callback with the token
/// 4. Write config and return
pub async fn login(server: &str) -> Result<()> {
    // Bind to a random port
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let state = uuid::Uuid::new_v4().to_string();

    let auth_url = format!(
        "{}/cli-auth?port={}&state={}",
        server.trim_end_matches('/'),
        port,
        state
    );

    eprintln!("Opening browser to authorize...");
    eprintln!("  {}", auth_url);

    if open::that(&auth_url).is_err() {
        eprintln!("\nCouldn't open browser automatically. Please open this URL:");
        eprintln!("  {}", auth_url);
    }

    eprintln!("\nWaiting for authorization...");

    // Wait for the callback (with timeout)
    let result = tokio::time::timeout(
        Duration::from_secs(120),
        wait_for_callback(listener, &state),
    )
    .await;

    match result {
        Ok(Ok((token, email, org_id))) => {
            let config = Config {
                token,
                server: server.to_string(),
                email: email.clone(),
                org_id,
            };
            write_config(&config)?;
            eprintln!("\nLogged in as {}", email);
            Ok(())
        }
        Ok(Err(e)) => bail!("Login failed: {}", e),
        Err(_) => bail!("Login timed out after 120 seconds"),
    }
}

/// Response from the /api/v1/cli-auth/verify endpoint.
#[derive(Deserialize)]
struct VerifyResponse {
    email: String,
    org_id: String,
}

/// Run headless login with a pre-existing token.
pub async fn login_with_token(server: &str, token: &str) -> Result<()> {
    // Verify the token by calling the server
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
    let url = format!("{}/api/v1/cli-auth/verify", server.trim_end_matches('/'));
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await?;

    if !response.status().is_success() {
        bail!("Invalid token (HTTP {})", response.status());
    }

    let verified: VerifyResponse = response.json().await?;

    let config = Config {
        token: token.to_string(),
        server: server.to_string(),
        email: verified.email.clone(),
        org_id: verified.org_id,
    };
    write_config(&config)?;
    eprintln!("Logged in as {}", verified.email);
    Ok(())
}

/// Waits for a single HTTP request to the callback server.
/// Extracts token, email, and org_id from the callback request.
/// Validates the state parameter to prevent CSRF.
async fn wait_for_callback(
    listener: TcpListener,
    expected_state: &str,
) -> Result<(String, String, String)> {
    let (mut stream, _) = listener.accept().await?;

    // Read the HTTP request
    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await?;
    let request = String::from_utf8_lossy(&buf[..n]);

    // Parse the request line to get the path
    let first_line = request.lines().next().unwrap_or("");
    let path = first_line.split_whitespace().nth(1).unwrap_or("/");

    let params = parse_callback_params(path, &request);

    let callback_state = params.get("state").cloned().unwrap_or_default();
    let token = params.get("token").cloned().unwrap_or_default();
    let email = params.get("email").cloned().unwrap_or_default();
    let org_id = params.get("org_id").cloned().unwrap_or_default();

    let body = if callback_state == expected_state && !token.is_empty() {
        "<html><body><h2>Authorized!</h2><p>You can close this tab and return to your terminal.</p></body></html>"
    } else {
        "<html><body><h2>Authorization failed</h2><p>Return to your terminal to see the error and try again.</p></body></html>"
    };
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;

    if callback_state != expected_state {
        bail!("State parameter mismatch. Please try logging in again.");
    }

    if token.is_empty() {
        bail!("No token received in callback");
    }

    Ok((token, email, org_id))
}

fn parse_callback_params(path: &str, request: &str) -> std::collections::HashMap<String, String> {
    let query = path.split('?').nth(1).unwrap_or("");
    let mut params = parse_form_encoded(query);

    let body = request
        .split("\r\n\r\n")
        .nth(1)
        .or_else(|| request.split("\n\n").nth(1))
        .unwrap_or("")
        .trim_matches(char::from(0));

    if body.is_empty() {
        return params;
    }

    if let Ok(json) = serde_json::from_str::<serde_json::Value>(body)
        && let Some(object) = json.as_object()
    {
        for key in ["state", "token", "email", "org_id"] {
            if let Some(value) = object.get(key).and_then(|value| value.as_str()) {
                params.insert(key.to_string(), value.to_string());
            }
        }
        return params;
    }

    for (key, value) in parse_form_encoded(body) {
        params.insert(key, value);
    }

    params
}

fn parse_form_encoded(input: &str) -> std::collections::HashMap<String, String> {
    input
        .split('&')
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            Some((
                parts.next()?.to_string(),
                urldecode(parts.next().unwrap_or("")),
            ))
        })
        .collect()
}

/// Simple URL decoding (handles %XX and +).
fn urldecode(s: &str) -> String {
    let mut result = String::new();
    let mut chars = s.bytes();
    while let Some(b) = chars.next() {
        match b {
            b'%' => {
                let hi = chars.next().unwrap_or(b'0');
                let lo = chars.next().unwrap_or(b'0');
                let hex = format!("{}{}", hi as char, lo as char);
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte as char);
                }
            }
            b'+' => result.push(' '),
            _ => result.push(b as char),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::{parse_callback_params, write_secure_file};

    #[test]
    fn callback_prefers_json_body_values() {
        let request = "POST /callback?state=query-state HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\r\n{\"state\":\"body-state\",\"token\":\"secret\",\"email\":\"user@example.com\",\"org_id\":\"org_123\"}";
        let params = parse_callback_params("/callback?state=query-state", request);

        assert_eq!(params.get("state").map(String::as_str), Some("body-state"));
        assert_eq!(params.get("token").map(String::as_str), Some("secret"));
    }

    #[test]
    fn callback_supports_form_encoded_body() {
        let request = "POST /callback HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nstate=abc&token=secret&email=user%40example.com&org_id=org_123";
        let params = parse_callback_params("/callback", request);

        assert_eq!(
            params.get("email").map(String::as_str),
            Some("user@example.com")
        );
        assert_eq!(params.get("org_id").map(String::as_str), Some("org_123"));
    }

    #[test]
    fn write_secure_file_persists_contents() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let path = temp.path().join("config.json");
        write_secure_file(&path, br#"{"token":"secret"}"#).expect("config written");

        let contents = std::fs::read_to_string(&path).expect("config readable");
        assert_eq!(contents, r#"{"token":"secret"}"#);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mode = std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
}
