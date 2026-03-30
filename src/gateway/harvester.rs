use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;

/// Represents a credential observed in a proxied request.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedCredential {
    pub provider: String,
    pub fingerprint: String,
    /// "bearer", "basic", "api_key_header", "api_key_query"
    #[serde(rename = "type")]
    pub cred_type: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub request_count: usize,
    /// The actual credential value -- stored temporarily in memory.
    /// Never serialized to JSON.
    #[serde(skip)]
    pub value: String,
}

/// Summary statistics about observed credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarvestStats {
    pub total_providers: usize,
    pub total_credentials: usize,
    pub total_requests: usize,
}

/// Observes credentials in transit and records them.
pub struct Harvester {
    inner: Mutex<HashMap<String, ObservedCredential>>,
}

impl Harvester {
    /// Creates a new credential harvester.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Checks if the given headers/query contain a credential and records it.
    /// Returns the observed credential (or None if none found).
    pub fn observe(
        &self,
        provider: &str,
        headers: &HashMap<String, String>,
        raw_query: &str,
    ) -> Option<ObservedCredential> {
        let (cred_type, cred_value) = detect_credential(headers, raw_query);
        if cred_value.is_empty() {
            return None;
        }

        let fp = fingerprint(&cred_value);
        let now = Utc::now();

        let mut observed = self.inner.lock().unwrap();

        if let Some(existing) = observed.get_mut(&fp) {
            existing.last_seen = now;
            existing.request_count += 1;
            return Some(existing.clone());
        }

        let oc = ObservedCredential {
            provider: provider.to_string(),
            fingerprint: fp.clone(),
            cred_type,
            first_seen: now,
            last_seen: now,
            request_count: 1,
            value: cred_value,
        };
        observed.insert(fp, oc.clone());
        Some(oc)
    }

    /// Returns all observed credentials (without the raw values).
    pub fn list(&self) -> Vec<ObservedCredential> {
        let observed = self.inner.lock().unwrap();
        observed
            .values()
            .map(|oc| ObservedCredential {
                provider: oc.provider.clone(),
                fingerprint: oc.fingerprint.clone(),
                cred_type: oc.cred_type.clone(),
                first_seen: oc.first_seen,
                last_seen: oc.last_seen,
                request_count: oc.request_count,
                value: String::new(), // Never expose raw value in list.
            })
            .collect()
    }

    /// Returns the raw credential value for a given fingerprint.
    /// Used when the user decides to harvest (store in vault).
    #[allow(dead_code)]
    pub fn get_value(&self, fp: &str) -> Option<String> {
        let observed = self.inner.lock().unwrap();
        observed.get(fp).map(|oc| oc.value.clone())
    }

    /// Returns summary statistics.
    pub fn stats(&self) -> HarvestStats {
        let observed = self.inner.lock().unwrap();
        let mut providers = std::collections::HashSet::new();
        let mut total_requests = 0;

        for oc in observed.values() {
            providers.insert(oc.provider.clone());
            total_requests += oc.request_count;
        }

        HarvestStats {
            total_providers: providers.len(),
            total_credentials: observed.len(),
            total_requests,
        }
    }
}

/// Checks headers and query params for credentials.
/// Returns (credential_type, credential_value), or empty strings if none found.
fn detect_credential(headers: &HashMap<String, String>, raw_query: &str) -> (String, String) {
    // Check Authorization header (case-insensitive key lookup).
    if let Some(auth) = get_header_case_insensitive(headers, "authorization") {
        let lower = auth.to_lowercase();
        if lower.starts_with("bearer ") {
            return ("bearer".to_string(), auth[7..].trim().to_string());
        }
        if lower.starts_with("basic ") {
            return ("basic".to_string(), auth[6..].trim().to_string());
        }
        if lower.starts_with("token ") {
            // GitHub-style token auth.
            return ("bearer".to_string(), auth[6..].trim().to_string());
        }
    }

    // Check common API key headers.
    for hdr in &["X-API-Key", "Api-Key", "X-Auth-Token"] {
        if let Some(v) = get_header_case_insensitive(headers, hdr)
            && !v.is_empty()
        {
            return ("api_key_header".to_string(), v);
        }
    }

    // Check query parameters.
    if !raw_query.is_empty()
        && let Ok(params) = serde_urlencoded::from_str::<Vec<(String, String)>>(raw_query)
    {
        for key in &["api_key", "key", "token", "access_token"] {
            if let Some((_, v)) = params.iter().find(|(k, _)| k == key)
                && !v.is_empty()
            {
                return ("api_key_query".to_string(), v.clone());
            }
        }
    }

    (String::new(), String::new())
}

/// Case-insensitive header lookup.
fn get_header_case_insensitive(headers: &HashMap<String, String>, name: &str) -> Option<String> {
    let lower = name.to_lowercase();
    for (k, v) in headers {
        if k.to_lowercase() == lower {
            return Some(v.clone());
        }
    }
    None
}

/// Returns the first 12 hex characters of the SHA-256 hash of the value.
pub fn fingerprint(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let hash = hasher.finalize();
    // 6 bytes = 12 hex chars.
    format!(
        "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        hash[0], hash[1], hash[2], hash[3], hash[4], hash[5]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with(key: &str, value: &str) -> HashMap<String, String> {
        let mut h = HashMap::new();
        h.insert(key.to_string(), value.to_string());
        h
    }

    #[test]
    fn test_bearer_token() {
        let h = Harvester::new();
        let headers = headers_with("Authorization", "Bearer ghp_abc123def456");
        let oc = h.observe("github", &headers, "");
        assert!(oc.is_some());
        let oc = oc.unwrap();
        assert_eq!(oc.cred_type, "bearer");
        assert_eq!(oc.provider, "github");
        assert_eq!(oc.request_count, 1);
    }

    #[test]
    fn test_basic_auth() {
        let h = Harvester::new();
        let headers = headers_with("Authorization", "Basic dXNlcjpwYXNz");
        let oc = h.observe("stripe", &headers, "");
        assert!(oc.is_some());
        assert_eq!(oc.unwrap().cred_type, "basic");
    }

    #[test]
    fn test_api_key_header() {
        let h = Harvester::new();
        let headers = headers_with("X-API-Key", "sk_test_abc123");
        let oc = h.observe("stripe", &headers, "");
        assert!(oc.is_some());
        assert_eq!(oc.unwrap().cred_type, "api_key_header");
    }

    #[test]
    fn test_query_parameter_key() {
        let h = Harvester::new();
        let headers = HashMap::new();
        let oc = h.observe("stripe", &headers, "api_key=sk_test_query123");
        assert!(oc.is_some());
        assert_eq!(oc.unwrap().cred_type, "api_key_query");
    }

    #[test]
    fn test_no_credential() {
        let h = Harvester::new();
        let headers = headers_with("Content-Type", "application/json");
        let oc = h.observe("github", &headers, "");
        assert!(oc.is_none());
    }

    #[test]
    fn test_same_credential_increments() {
        let h = Harvester::new();
        let headers = headers_with("Authorization", "Bearer ghp_repeat_token");

        let oc1 = h.observe("github", &headers, "").unwrap();
        assert_eq!(oc1.request_count, 1);

        let oc2 = h.observe("github", &headers, "").unwrap();
        assert_eq!(oc2.request_count, 2);

        // Should still be just one credential in the list.
        let list = h.list();
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn test_fingerprint_consistent() {
        let fp1 = fingerprint("my-secret-token");
        let fp2 = fingerprint("my-secret-token");
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 12);
    }

    #[test]
    fn test_different_credentials_different_fingerprints() {
        let fp1 = fingerprint("token-aaa");
        let fp2 = fingerprint("token-bbb");
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_list_omits_raw_values() {
        let h = Harvester::new();
        let headers = headers_with("Authorization", "Bearer secret-value-123");
        h.observe("github", &headers, "");

        let list = h.list();
        assert_eq!(list.len(), 1);
        assert!(list[0].value.is_empty());
        assert!(!list[0].fingerprint.is_empty());
    }

    #[test]
    fn test_get_value_by_fingerprint() {
        let h = Harvester::new();
        let headers = headers_with("Authorization", "Bearer retrieve-me-token");
        let oc = h.observe("github", &headers, "").unwrap();

        let val = h.get_value(&oc.fingerprint);
        assert!(val.is_some());
        assert_eq!(val.unwrap(), "retrieve-me-token");

        // Unknown fingerprint returns None.
        assert!(h.get_value("nonexistent").is_none());
    }

    #[test]
    fn test_github_token_style() {
        let h = Harvester::new();
        let headers = headers_with("Authorization", "token ghp_github_style");
        let oc = h.observe("github", &headers, "").unwrap();
        assert_eq!(oc.cred_type, "bearer");

        let val = h.get_value(&oc.fingerprint).unwrap();
        assert_eq!(val, "ghp_github_style");
    }

    #[test]
    fn test_stats() {
        let h = Harvester::new();

        // Add credentials for two providers.
        let gh = headers_with("Authorization", "Bearer gh-tok");
        h.observe("github", &gh, "");
        h.observe("github", &gh, ""); // same cred, second request

        let st = headers_with("X-API-Key", "sk_stripe");
        h.observe("stripe", &st, "");

        let stats = h.stats();
        assert_eq!(stats.total_providers, 2);
        assert_eq!(stats.total_credentials, 2);
        assert_eq!(stats.total_requests, 3);
    }
}
