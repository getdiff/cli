use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use crate::auth;
use crate::redact::Redactor;

const DETECTOR_CACHE_TTL: Duration = Duration::from_secs(60 * 15);

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DetectorPack {
    pub version: String,
    pub fetched_at: String,
    #[serde(default)]
    pub rules: Vec<DetectorRule>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DetectorRule {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub severity: String,
    pub pattern: String,
    pub marker: String,
    #[serde(default)]
    pub flags: Option<String>,
}

pub async fn load_redactor(server: &str, api_key: &str) -> Result<(Redactor, Option<String>)> {
    let mut redactor = Redactor::new();
    let pack = load_detector_pack(server, api_key).await?;

    if let Some(pack) = &pack {
        for rule in &pack.rules {
            redactor.add_pattern(
                &rule.marker,
                &pattern_with_flags(&rule.pattern, rule.flags.as_deref()),
            )?;
        }
    }

    Ok((redactor, pack.map(|value| value.version)))
}

async fn load_detector_pack(server: &str, api_key: &str) -> Result<Option<DetectorPack>> {
    if let Some(cached) = read_cached_pack_if_fresh(server)? {
        return Ok(Some(cached));
    }

    match fetch_detector_pack(server, api_key).await {
        Ok(pack) => {
            write_cached_pack(server, &pack)?;
            Ok(Some(pack))
        }
        Err(error) => {
            if let Some(cached) = read_cached_pack(server)? {
                eprintln!("Using cached detector pack after refresh failed: {}", error);
                Ok(Some(cached))
            } else {
                eprintln!(
                    "Detector pack refresh failed, continuing with built-in detectors: {}",
                    error
                );
                Ok(None)
            }
        }
    }
}

async fn fetch_detector_pack(server: &str, api_key: &str) -> Result<DetectorPack> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
    let url = format!("{}/api/v1/security/detectors", server.trim_end_matches('/'));
    let response = client
        .get(url)
        .header("Authorization", format!("Bearer {}", api_key))
        .send()
        .await?;

    if !response.status().is_success() {
        anyhow::bail!("HTTP {}", response.status());
    }

    Ok(response.json().await?)
}

fn cache_path(server: &str) -> PathBuf {
    let cache_file = format!("detectors-{}.json", cache_key(server));
    auth::config_path()
        .parent()
        .map(|parent| parent.join(cache_file.clone()))
        .unwrap_or_else(|| PathBuf::from(cache_file))
}

fn read_cached_pack_if_fresh(server: &str) -> Result<Option<DetectorPack>> {
    let path = cache_path(server);
    let metadata = match std::fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(_) => return Ok(None),
    };
    let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
    let age = SystemTime::now()
        .duration_since(modified)
        .unwrap_or(Duration::ZERO);
    if age > DETECTOR_CACHE_TTL {
        return Ok(None);
    }
    read_cached_pack(server)
}

fn read_cached_pack(server: &str) -> Result<Option<DetectorPack>> {
    let path = cache_path(server);
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(_) => return Ok(None),
    };
    match serde_json::from_str(&contents) {
        Ok(pack) => Ok(Some(pack)),
        Err(_) => Ok(None),
    }
}

fn write_cached_pack(server: &str, pack: &DetectorPack) -> Result<()> {
    let path = cache_path(server);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(pack)?)?;
    Ok(())
}

fn pattern_with_flags(pattern: &str, flags: Option<&str>) -> String {
    let supported: String = flags
        .unwrap_or("")
        .chars()
        .filter(|flag| matches!(flag, 'i' | 'm' | 's'))
        .collect();
    if supported.is_empty() {
        pattern.to_string()
    } else {
        format!("(?{}){}", supported, pattern)
    }
}

fn cache_key(server: &str) -> String {
    let normalized = server.trim().trim_end_matches('/').to_ascii_lowercase();
    let mut hasher = DefaultHasher::new();
    normalized.hash(&mut hasher);
    let hash = hasher.finish();
    let slug: String = normalized
        .chars()
        .map(|ch| match ch {
            'a'..='z' | '0'..='9' => ch,
            _ => '-',
        })
        .collect();
    let slug = slug.trim_matches('-');
    let slug = if slug.is_empty() { "default" } else { slug };
    format!("{}-{:016x}", slug, hash)
}

#[cfg(test)]
mod tests {
    use super::{cache_path, pattern_with_flags};

    #[test]
    fn composes_inline_regex_flags() {
        assert_eq!(
            pattern_with_flags("CUST-[0-9]+", Some("im")),
            "(?im)CUST-[0-9]+"
        );
    }

    #[test]
    fn namespaces_cache_by_server() {
        let a = cache_path("https://example.com");
        let b = cache_path("https://example.org");

        assert_ne!(a, b);
        assert!(
            a.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("detectors-")
        );
    }
}
