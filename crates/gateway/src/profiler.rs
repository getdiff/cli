use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

/// Tracks agent behavior patterns for sessions.
pub struct Profiler {
    inner: Mutex<HashMap<String, BehaviorProfile>>,
}

/// Tracks the behavior of a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorProfile {
    pub session_id: String,
    pub started_at: DateTime<Utc>,
    pub providers: HashMap<String, ProviderProfile>,
    pub total_requests: usize,
}

/// Tracks behavior for a specific provider within a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderProfile {
    pub provider: String,
    pub operations: HashMap<String, usize>,
    pub methods: HashMap<String, usize>,
    pub total_requests: usize,
    pub first_request: DateTime<Utc>,
    pub last_request: DateTime<Utc>,
    pub blocked_count: usize,
    pub unique_paths: HashMap<String, usize>,
}

/// A suggested policy based on observed behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySuggestion {
    pub provider: String,
    #[serde(rename = "type")]
    pub suggestion_type: String,
    pub description: String,
    pub confidence: String,
}

impl Profiler {
    /// Creates a new behavior profiler.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Records a request in the behavior profile.
    pub fn record(
        &self,
        session_id: &str,
        provider: &str,
        operation: &str,
        method: &str,
        path: &str,
        decision: &str,
    ) {
        let now = Utc::now();
        let mut profiles = self.inner.lock().unwrap();

        let bp = profiles
            .entry(session_id.to_string())
            .or_insert_with(|| BehaviorProfile {
                session_id: session_id.to_string(),
                started_at: now,
                providers: HashMap::new(),
                total_requests: 0,
            });

        bp.total_requests += 1;

        let pp = bp
            .providers
            .entry(provider.to_string())
            .or_insert_with(|| ProviderProfile {
                provider: provider.to_string(),
                operations: HashMap::new(),
                methods: HashMap::new(),
                total_requests: 0,
                first_request: now,
                last_request: now,
                blocked_count: 0,
                unique_paths: HashMap::new(),
            });

        pp.total_requests += 1;
        pp.last_request = now;

        if !operation.is_empty() {
            *pp.operations.entry(operation.to_string()).or_insert(0) += 1;
        }
        if !method.is_empty() {
            *pp.methods.entry(method.to_string()).or_insert(0) += 1;
        }
        if !path.is_empty() {
            const MAX_UNIQUE_PATHS: usize = 1000;
            if pp.unique_paths.len() < MAX_UNIQUE_PATHS || pp.unique_paths.contains_key(path) {
                *pp.unique_paths.entry(path.to_string()).or_insert(0) += 1;
            }
        }
        if decision == "denied" {
            pp.blocked_count += 1;
        }
    }

    /// Returns the behavior profile for a session.
    pub fn get_profile(&self, session_id: &str) -> Option<BehaviorProfile> {
        let profiles = self.inner.lock().unwrap();
        profiles.get(session_id).cloned()
    }

    /// Analyzes a behavior profile and suggests policies.
    pub fn suggest_policies(&self, session_id: &str) -> Option<Vec<PolicySuggestion>> {
        let profiles = self.inner.lock().unwrap();
        let bp = profiles.get(session_id)?;

        // Copy provider data under lock, then release.
        let providers: HashMap<String, ProviderProfile> = bp.providers.clone();
        drop(profiles);

        let mut suggestions = Vec::new();

        for (prov_name, pp) in &providers {
            // Suggest method restriction if only read methods were used.
            let mut methods: Vec<String> = pp.methods.keys().cloned().collect();
            methods.sort();
            let all_read_only =
                !methods.is_empty() && methods.iter().all(|m| m == "GET" || m == "HEAD");

            if all_read_only {
                suggestions.push(PolicySuggestion {
                    provider: prov_name.clone(),
                    suggestion_type: "restrict_methods".to_string(),
                    description: format!(
                        "Agent only used {:?} methods. Suggest allowed_methods: {:?}",
                        methods, methods
                    ),
                    confidence: "high".to_string(),
                });
            }

            // Suggest operation restriction if a small set of operations was used.
            let mut ops: Vec<String> = pp.operations.keys().cloned().collect();
            ops.sort();
            if !ops.is_empty() && ops.len() <= 10 {
                suggestions.push(PolicySuggestion {
                    provider: prov_name.clone(),
                    suggestion_type: "restrict_operations".to_string(),
                    description: format!(
                        "Agent used {} operations: {:?}. Suggest allowed_operations: {:?}",
                        ops.len(),
                        ops,
                        ops
                    ),
                    confidence: "medium".to_string(),
                });
            }

            // Note if requests were blocked.
            if pp.blocked_count > 0 {
                suggestions.push(PolicySuggestion {
                    provider: prov_name.clone(),
                    suggestion_type: "blocked_activity".to_string(),
                    description: format!(
                        "{} requests were blocked by policy. Current policy is enforcing restrictions.",
                        pp.blocked_count
                    ),
                    confidence: "high".to_string(),
                });
            }

            // Suggest reviewing paths if many unique paths accessed.
            if pp.unique_paths.len() > 20 {
                suggestions.push(PolicySuggestion {
                    provider: prov_name.clone(),
                    suggestion_type: "review_paths".to_string(),
                    description: format!(
                        "Agent accessed {} unique paths. Consider reviewing the path list for unnecessary access.",
                        pp.unique_paths.len()
                    ),
                    confidence: "low".to_string(),
                });
            }
        }

        Some(suggestions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_session() {
        let p = Profiler::new();
        p.record("sess-1", "github", "get_user", "GET", "/user", "allowed");

        let bp = p.get_profile("sess-1");
        assert!(bp.is_some());
        let bp = bp.unwrap();
        assert_eq!(bp.session_id, "sess-1");
        assert_eq!(bp.total_requests, 1);
    }

    #[test]
    fn test_multiple_records() {
        let p = Profiler::new();
        p.record("sess-1", "github", "get_user", "GET", "/user", "allowed");
        p.record(
            "sess-1",
            "github",
            "list_repos",
            "GET",
            "/user/repos",
            "allowed",
        );
        p.record(
            "sess-1",
            "stripe",
            "list_charges",
            "GET",
            "/v1/charges",
            "allowed",
        );

        let bp = p.get_profile("sess-1").unwrap();
        assert_eq!(bp.total_requests, 3);
        assert_eq!(bp.providers.len(), 2);
    }

    #[test]
    fn test_operations_counted_per_provider() {
        let p = Profiler::new();
        p.record("sess-1", "github", "get_user", "GET", "/user", "allowed");
        p.record("sess-1", "github", "get_user", "GET", "/user", "allowed");
        p.record(
            "sess-1",
            "github",
            "list_repos",
            "GET",
            "/user/repos",
            "allowed",
        );

        let bp = p.get_profile("sess-1").unwrap();
        let gh = &bp.providers["github"];
        assert_eq!(gh.operations["get_user"], 2);
        assert_eq!(gh.operations["list_repos"], 1);
    }

    #[test]
    fn test_methods_counted() {
        let p = Profiler::new();
        p.record("sess-1", "github", "get_user", "GET", "/user", "allowed");
        p.record(
            "sess-1",
            "github",
            "list_repos",
            "GET",
            "/user/repos",
            "allowed",
        );
        p.record(
            "sess-1",
            "github",
            "create_issue",
            "POST",
            "/repos/o/r/issues",
            "allowed",
        );

        let bp = p.get_profile("sess-1").unwrap();
        let gh = &bp.providers["github"];
        assert_eq!(gh.methods["GET"], 2);
        assert_eq!(gh.methods["POST"], 1);
    }

    #[test]
    fn test_blocked_count() {
        let p = Profiler::new();
        p.record("sess-1", "github", "get_user", "GET", "/user", "allowed");
        p.record(
            "sess-1",
            "github",
            "create_issue",
            "POST",
            "/repos/o/r/issues",
            "denied",
        );
        p.record(
            "sess-1",
            "github",
            "delete_repo",
            "DELETE",
            "/repos/o/r",
            "denied",
        );

        let bp = p.get_profile("sess-1").unwrap();
        let gh = &bp.providers["github"];
        assert_eq!(gh.blocked_count, 2);
    }

    #[test]
    fn test_suggest_method_restriction() {
        let p = Profiler::new();
        // Only GET requests.
        p.record("sess-1", "github", "get_user", "GET", "/user", "allowed");
        p.record(
            "sess-1",
            "github",
            "list_repos",
            "GET",
            "/user/repos",
            "allowed",
        );

        let suggestions = p.suggest_policies("sess-1").unwrap();
        let found = suggestions
            .iter()
            .any(|s| s.suggestion_type == "restrict_methods" && s.provider == "github");
        assert!(
            found,
            "expected restrict_methods suggestion for read-only agent"
        );

        // Check confidence.
        let s = suggestions
            .iter()
            .find(|s| s.suggestion_type == "restrict_methods")
            .unwrap();
        assert_eq!(s.confidence, "high");
    }

    #[test]
    fn test_suggest_operation_restriction() {
        let p = Profiler::new();
        p.record(
            "sess-1",
            "stripe",
            "list_charges",
            "GET",
            "/v1/charges",
            "allowed",
        );
        p.record(
            "sess-1",
            "stripe",
            "get_charge",
            "GET",
            "/v1/charges/ch_1",
            "allowed",
        );

        let suggestions = p.suggest_policies("sess-1").unwrap();
        let found = suggestions
            .iter()
            .any(|s| s.suggestion_type == "restrict_operations" && s.provider == "stripe");
        assert!(found, "expected restrict_operations suggestion");
    }

    #[test]
    fn test_multiple_sessions() {
        let p = Profiler::new();
        p.record("sess-1", "github", "get_user", "GET", "/user", "allowed");
        p.record(
            "sess-2",
            "stripe",
            "list_charges",
            "GET",
            "/v1/charges",
            "allowed",
        );

        let bp1 = p.get_profile("sess-1").unwrap();
        let bp2 = p.get_profile("sess-2").unwrap();

        assert_eq!(bp1.total_requests, 1);
        assert_eq!(bp2.total_requests, 1);

        assert!(!bp1.providers.contains_key("stripe"));
        assert!(!bp2.providers.contains_key("github"));
    }

    #[test]
    fn test_unknown_session() {
        let p = Profiler::new();
        assert!(p.get_profile("nonexistent").is_none());
        assert!(p.suggest_policies("nonexistent").is_none());
    }
}
