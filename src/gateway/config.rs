use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Top-level gateway configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GatewayConfig {
    pub session: SessionConfig,
    pub providers: HashMap<String, ProviderConfig>,
    #[serde(default)]
    pub intersection_policies: Vec<IntersectionPolicyConfig>,
}

/// Identifies the current session.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SessionConfig {
    pub id: String,
    #[serde(default)]
    pub learning_mode: bool,
    /// Agent type for profiling (e.g., "coding", "support", "research").
    /// The platform groups behavior profiles by this field.
    #[serde(default)]
    pub agent_type: Option<String>,
    /// Project identifier for scoping.
    #[serde(default)]
    pub project_id: Option<String>,
    /// Environment label: "laptop", "sandbox", "ci", "staging", "production".
    #[serde(default)]
    pub environment: Option<String>,
}

/// Defines a single upstream provider.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProviderConfig {
    pub upstream: String,
    pub credential: CredentialConfig,
    #[serde(default)]
    pub policies: PolicyConfig,
    /// Optional config-driven adapter definition. When present, a GenericAdapter
    /// is created instead of using the built-in hard-coded adapter.
    #[serde(default)]
    pub adapter: Option<crate::gateway::adapter::generic::AdapterConfig>,
}

/// Describes how to obtain credentials for a provider.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CredentialConfig {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub env_var: String,
}

/// Allow/block rules for methods, paths, operations, and parameters.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct PolicyConfig {
    #[serde(default)]
    pub allowed_methods: Vec<String>,
    #[serde(default)]
    pub blocked_methods: Vec<String>,
    #[serde(default)]
    pub allowed_paths: Vec<String>,
    #[serde(default)]
    pub blocked_paths: Vec<String>,
    #[serde(default)]
    pub allowed_operations: Vec<String>,
    #[serde(default)]
    pub blocked_operations: Vec<String>,
    pub max_amount_cents: Option<i64>,
    pub daily_limit_cents: Option<i64>,
    #[serde(default)]
    pub allowed_recipients: Vec<String>,
    #[serde(default)]
    pub blocked_recipients: Vec<String>,
    pub max_recipients_per_message: Option<usize>,
    #[serde(default)]
    pub allowed_currencies: Vec<String>,
}

/// Defines a cross-capability policy in YAML config.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IntersectionPolicyConfig {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub when: IntersectionWhen,
    pub then: HashMap<String, PolicyConfig>,
}

/// Defines when an intersection activates.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IntersectionWhen {
    pub all_of: Vec<CapabilityMatcher>,
}

/// Matches a capability in the session.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CapabilityMatcher {
    pub provider: String,
    #[serde(default)]
    pub capability: Option<String>,
}

/// Load reads a YAML config file from the given path and returns the parsed config.
pub fn load(path: &str) -> anyhow::Result<GatewayConfig> {
    let content = std::fs::read_to_string(path)?;
    let config: GatewayConfig = serde_yaml::from_str(&content)?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_YAML: &str = r#"
session:
  id: "demo-session-001"
  learning_mode: false

providers:
  github:
    upstream: "https://api.github.com"
    credential:
      type: "bearer"
      env_var: "GATEWAY_GITHUB_TOKEN"
    policies:
      allowed_methods: ["GET", "HEAD"]
      allowed_paths:
        - "/user"
        - "/user/repos"
        - "/repos/*"
        - "/repos/*/*"
        - "/rate_limit"
      blocked_paths:
        - "/repos/*/*/issues"
      blocked_methods: ["POST", "PUT", "DELETE", "PATCH"]

  stripe:
    upstream: "https://api.stripe.com"
    credential:
      type: "bearer"
      env_var: "GATEWAY_STRIPE_KEY"
    policies:
      allowed_methods: ["GET", "POST"]
      blocked_methods: ["DELETE"]
      allowed_operations:
        - "list_charges"
        - "get_charge"
        - "create_charge"
        - "list_customers"
        - "get_customer"
        - "create_customer"
      blocked_operations:
        - "create_transfer"
        - "get_balance"
      max_amount_cents: 5000
      allowed_currencies: ["usd"]

  gmail:
    upstream: "https://gmail.googleapis.com"
    credential:
      type: "bearer"
      env_var: "GATEWAY_GMAIL_TOKEN"
    policies:
      allowed_methods: ["GET", "POST"]
      blocked_methods: ["DELETE"]
      allowed_operations:
        - "send_email"
        - "list_messages"
        - "get_message"
        - "list_labels"
      blocked_operations:
        - "delete_message"
        - "modify_message"
      allowed_recipients:
        - "*@acme.com"
      max_recipients_per_message: 5

intersection_policies:
  - name: "prevent-mass-email"
    description: "When agent has email + payment data, restrict email volume"
    when:
      all_of:
        - provider: gmail
        - provider: stripe
    then:
      gmail:
        max_recipients_per_message: 3
  - name: "payment-data-restriction"
    description: "When agent has payment + email, lower charge caps"
    when:
      all_of:
        - provider: stripe
        - provider: gmail
    then:
      stripe:
        max_amount_cents: 1000
"#;

    #[test]
    fn test_deserialize_config() {
        let config: GatewayConfig = serde_yaml::from_str(TEST_YAML).unwrap();
        assert_eq!(config.session.id, "demo-session-001");
        assert!(!config.session.learning_mode);
        assert_eq!(config.providers.len(), 3);
    }

    #[test]
    fn test_github_provider_config() {
        let config: GatewayConfig = serde_yaml::from_str(TEST_YAML).unwrap();
        let github = config.providers.get("github").unwrap();
        assert_eq!(github.upstream, "https://api.github.com");
        assert_eq!(github.credential.cred_type, "bearer");
        assert_eq!(github.credential.env_var, "GATEWAY_GITHUB_TOKEN");
        assert_eq!(github.policies.allowed_methods, vec!["GET", "HEAD"]);
        assert_eq!(
            github.policies.blocked_methods,
            vec!["POST", "PUT", "DELETE", "PATCH"]
        );
        assert!(github.policies.allowed_paths.contains(&"/user".to_string()));
        assert!(github
            .policies
            .blocked_paths
            .contains(&"/repos/*/*/issues".to_string()));
    }

    #[test]
    fn test_stripe_provider_config() {
        let config: GatewayConfig = serde_yaml::from_str(TEST_YAML).unwrap();
        let stripe = config.providers.get("stripe").unwrap();
        assert_eq!(stripe.upstream, "https://api.stripe.com");
        assert_eq!(stripe.policies.max_amount_cents, Some(5000));
        assert_eq!(stripe.policies.allowed_currencies, vec!["usd"]);
        assert!(stripe
            .policies
            .blocked_operations
            .contains(&"create_transfer".to_string()));
    }

    #[test]
    fn test_gmail_provider_config() {
        let config: GatewayConfig = serde_yaml::from_str(TEST_YAML).unwrap();
        let gmail = config.providers.get("gmail").unwrap();
        assert_eq!(gmail.upstream, "https://gmail.googleapis.com");
        assert_eq!(gmail.policies.max_recipients_per_message, Some(5));
        assert_eq!(
            gmail.policies.allowed_recipients,
            vec!["*@acme.com"]
        );
    }

    #[test]
    fn test_intersection_policies() {
        let config: GatewayConfig = serde_yaml::from_str(TEST_YAML).unwrap();
        assert_eq!(config.intersection_policies.len(), 2);

        let first = &config.intersection_policies[0];
        assert_eq!(first.name, "prevent-mass-email");
        assert_eq!(first.when.all_of.len(), 2);
        assert_eq!(first.when.all_of[0].provider, "gmail");
        assert_eq!(first.when.all_of[1].provider, "stripe");
        let gmail_then = first.then.get("gmail").unwrap();
        assert_eq!(gmail_then.max_recipients_per_message, Some(3));

        let second = &config.intersection_policies[1];
        assert_eq!(second.name, "payment-data-restriction");
        let stripe_then = second.then.get("stripe").unwrap();
        assert_eq!(stripe_then.max_amount_cents, Some(1000));
    }
}
