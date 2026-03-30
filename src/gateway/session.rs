use crate::gateway::policy::PolicyEvaluator;
use std::collections::HashMap;

/// Holds the session identity and provider-specific state.
/// Used when the control plane pushes dynamic sessions at runtime.
#[allow(dead_code)]
#[derive(Debug)]
pub struct SessionContext {
    pub session_id: String,
    pub learning_mode: bool,
    pub providers: HashMap<String, ProviderSession>,
}

/// Bundles the resolved credential, policy evaluator, and upstream URL
/// for a single provider within a session.
#[allow(dead_code)]
#[derive(Debug)]
pub struct ProviderSession {
    pub provider: String,
    pub upstream: String,
    pub credential: String,
    pub policy: PolicyEvaluator,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::config::PolicyConfig;

    #[test]
    fn test_session_context_creation() {
        let mut providers = HashMap::new();
        providers.insert(
            "github".to_string(),
            ProviderSession {
                provider: "github".to_string(),
                upstream: "https://api.github.com".to_string(),
                credential: "ghp_test".to_string(),
                policy: PolicyEvaluator::new(PolicyConfig {
                    allowed_methods: vec!["GET".to_string()],
                    ..Default::default()
                }),
            },
        );

        let ctx = SessionContext {
            session_id: "sess-001".to_string(),
            learning_mode: false,
            providers,
        };

        assert_eq!(ctx.session_id, "sess-001");
        assert!(!ctx.learning_mode);
        assert!(ctx.providers.contains_key("github"));
    }

    #[test]
    fn test_provider_session_policy_evaluation() {
        let ps = ProviderSession {
            provider: "github".to_string(),
            upstream: "https://api.github.com".to_string(),
            credential: "ghp_test".to_string(),
            policy: PolicyEvaluator::new(PolicyConfig {
                allowed_methods: vec!["GET".to_string()],
                blocked_methods: vec!["DELETE".to_string()],
                ..Default::default()
            }),
        };

        let d = ps.policy.evaluate("GET", "/user", "", &HashMap::new());
        assert!(d.allowed);

        let d = ps.policy.evaluate("DELETE", "/user", "", &HashMap::new());
        assert!(!d.allowed);
    }
}
