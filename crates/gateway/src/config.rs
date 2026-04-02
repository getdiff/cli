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
    /// Environment label: "laptop", "sandbox", "ci", "staging", "production".
    #[serde(default)]
    pub environment: Option<String>,
    /// Deprecated: org_id is derived from the CLI token by the platform.
    /// If set in YAML, a deprecation warning is logged at startup.
    /// Also accepts the old name "project_id" from existing configs.
    #[serde(default, alias = "project_id")]
    pub org_id: Option<String>,
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
    pub adapter: Option<crate::adapter::generic::AdapterConfig>,
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

/// Built-in hostname → provider name mapping for the transparent forward proxy.
/// Known hostnames get friendly provider names; unknown hostnames use the raw
/// hostname as the provider name. All traffic is observed regardless.
pub const KNOWN_HOSTS: &[(&str, &str)] = &[
    ("api.github.com", "github"),
    ("api.stripe.com", "stripe"),
    ("gmail.googleapis.com", "gmail"),
    ("slack.com", "slack"),
    ("api.openai.com", "openai"),
    ("api.anthropic.com", "anthropic"),
    ("api2.cursor.sh", "cursor"),
    ("api3.cursor.sh", "cursor"),
    ("http-intake.logs.us5.datadoghq.com", "datadog"),
];

/// Resolve a hostname to a provider name. Returns the friendly name for known
/// hosts, or the raw hostname for unknown hosts.
pub fn provider_for_host(hostname: &str) -> String {
    for &(host, provider) in KNOWN_HOSTS {
        if hostname == host {
            return provider.to_string();
        }
    }
    // AWS Bedrock pattern: *.amazonaws.com containing "bedrock"
    if hostname.ends_with(".amazonaws.com") && hostname.contains("bedrock") {
        return "aws-bedrock".to_string();
    }
    hostname.to_string()
}

/// Built-in provider registry: name → (upstream URL, conventional env var).
/// Used for backward-compatible path-prefix proxy mode.
const BUILTIN_PROVIDERS: &[(&str, &str, &str)] = &[
    ("github", "https://api.github.com", "GITHUB_TOKEN"),
    ("stripe", "https://api.stripe.com", "STRIPE_API_KEY"),
    ("gmail", "https://gmail.googleapis.com", "GMAIL_TOKEN"),
    ("slack", "https://slack.com/api", "SLACK_TOKEN"),
    ("openai", "https://api.openai.com", "OPENAI_API_KEY"),
    (
        "anthropic",
        "https://api.anthropic.com",
        "ANTHROPIC_API_KEY",
    ),
];

/// Build a default `GatewayConfig` for zero-config startup.
///
/// All built-in providers are registered with empty (observe-only) policies,
/// learning mode is enabled, and environment is auto-detected.
pub fn default_config(agent_type: Option<String>, environment: Option<String>) -> GatewayConfig {
    let env = environment.unwrap_or_else(|| {
        if std::env::var("CI").unwrap_or_default() == "true" {
            "ci".to_string()
        } else {
            "local".to_string()
        }
    });

    let session_id = format!("gateway-{}", &uuid::Uuid::new_v4().to_string()[..8]);

    let mut providers = HashMap::new();
    for &(name, upstream, env_var) in BUILTIN_PROVIDERS {
        providers.insert(
            name.to_string(),
            ProviderConfig {
                upstream: upstream.to_string(),
                credential: CredentialConfig {
                    cred_type: "bearer".to_string(),
                    env_var: env_var.to_string(),
                },
                policies: PolicyConfig::default(),
                adapter: None,
            },
        );
    }

    GatewayConfig {
        session: SessionConfig {
            id: session_id,
            learning_mode: true,
            agent_type: Some(agent_type.unwrap_or_else(|| "default".to_string())),
            environment: Some(env),
            org_id: None,
        },
        providers,
        intersection_policies: Vec::new(),
    }
}

/// Merge a YAML config on top of defaults. YAML values override defaults;
/// additional providers in YAML are added; providers only in defaults are kept.
pub fn merge_with_defaults(mut defaults: GatewayConfig, overrides: GatewayConfig) -> GatewayConfig {
    // Session: override takes precedence for all fields.
    defaults.session.id = overrides.session.id;
    defaults.session.learning_mode = overrides.session.learning_mode;
    if overrides.session.agent_type.is_some() {
        defaults.session.agent_type = overrides.session.agent_type;
    }
    if overrides.session.environment.is_some() {
        defaults.session.environment = overrides.session.environment;
    }
    if overrides.session.org_id.is_some() {
        defaults.session.org_id = overrides.session.org_id;
    }

    // Providers: YAML providers override defaults by name; defaults are kept.
    for (name, provider) in overrides.providers {
        defaults.providers.insert(name, provider);
    }

    // Intersection policies come entirely from overrides if present.
    if !overrides.intersection_policies.is_empty() {
        defaults.intersection_policies = overrides.intersection_policies;
    }

    defaults
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_YAML: &str = r#"
session:
  id: "demo-session-001"
  learning_mode: false
  agent_type: "coding"
  project_id: "proj-test"
  environment: "sandbox"

providers:
  github:
    upstream: "https://api.github.com"
    credential:
      type: "bearer"
      env_var: "GATEWAY_GITHUB_TOKEN"
    adapter:
      host: "api.github.com"
      body_format: "json"
      operations:
        - match: { method: "GET", path: "/user" }
          name: "get_user"
        - match: { method: "GET", path: "/user/repos" }
          name: "list_repos"
        - match: { method: "GET", path: "/repos/*/*" }
          name: "get_repo"
        - match: { method: "GET", path: "/repos/*/*/issues" }
          name: "list_issues"
        - match: { method: "GET", path: "/rate_limit" }
          name: "rate_limit"
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
    adapter:
      host: "api.stripe.com"
      body_format: "form"
      operations:
        - match: { method: "POST", path: "/v1/charges" }
          name: "create_charge"
          extract:
            - { param: "amount", field: "amount", type: "integer" }
            - { param: "currency", field: "currency" }
        - match: { method: "GET", path: "/v1/charges" }
          name: "list_charges"
        - match: { method: "GET", path: "/v1/charges/*" }
          name: "get_charge"
        - match: { method: "POST", path: "/v1/customers" }
          name: "create_customer"
        - match: { method: "GET", path: "/v1/customers" }
          name: "list_customers"
        - match: { method: "GET", path: "/v1/customers/*" }
          name: "get_customer"
        - match: { method: "POST", path: "/v1/transfers" }
          name: "create_transfer"
        - match: { method: "GET", path: "/v1/balance" }
          name: "get_balance"
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
    adapter:
      host: "gmail.googleapis.com"
      body_format: "gmail_mime"
      operations:
        - match: { method: "POST", path: "/gmail/v1/users/me/messages/send" }
          name: "send_email"
        - match: { method: "GET", path: "/gmail/v1/users/me/messages" }
          name: "list_messages"
        - match: { method: "GET", path: "/gmail/v1/users/me/messages/*" }
          name: "get_message"
        - match: { method: "GET", path: "/gmail/v1/users/me/labels" }
          name: "list_labels"
        - match: { method: "DELETE", path: "/gmail/v1/users/me/messages/*" }
          name: "delete_message"
        - match: { method: "POST", path: "/gmail/v1/users/me/messages/*/modify" }
          name: "modify_message"
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
        assert_eq!(config.session.agent_type, Some("coding".to_string()));
        // project_id in YAML is aliased to org_id.
        assert_eq!(config.session.org_id, Some("proj-test".to_string()));
        assert_eq!(config.session.environment, Some("sandbox".to_string()));
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
        assert!(
            github
                .policies
                .blocked_paths
                .contains(&"/repos/*/*/issues".to_string())
        );
        // Verify adapter block is present.
        let adapter = github.adapter.as_ref().unwrap();
        assert_eq!(adapter.host, "api.github.com");
        assert_eq!(adapter.body_format, "json");
        assert!(!adapter.operations.is_empty());
    }

    #[test]
    fn test_stripe_provider_config() {
        let config: GatewayConfig = serde_yaml::from_str(TEST_YAML).unwrap();
        let stripe = config.providers.get("stripe").unwrap();
        assert_eq!(stripe.upstream, "https://api.stripe.com");
        assert_eq!(stripe.policies.max_amount_cents, Some(5000));
        assert_eq!(stripe.policies.allowed_currencies, vec!["usd"]);
        assert!(
            stripe
                .policies
                .blocked_operations
                .contains(&"create_transfer".to_string())
        );
        let adapter = stripe.adapter.as_ref().unwrap();
        assert_eq!(adapter.host, "api.stripe.com");
        assert_eq!(adapter.body_format, "form");
        assert!(adapter.operations.len() >= 6);
    }

    #[test]
    fn test_gmail_provider_config() {
        let config: GatewayConfig = serde_yaml::from_str(TEST_YAML).unwrap();
        let gmail = config.providers.get("gmail").unwrap();
        assert_eq!(gmail.upstream, "https://gmail.googleapis.com");
        assert_eq!(gmail.policies.max_recipients_per_message, Some(5));
        assert_eq!(gmail.policies.allowed_recipients, vec!["*@acme.com"]);
        let adapter = gmail.adapter.as_ref().unwrap();
        assert_eq!(adapter.host, "gmail.googleapis.com");
        assert_eq!(adapter.body_format, "gmail_mime");
        assert!(adapter.operations.len() >= 4);
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

    #[test]
    fn test_provider_for_host_known() {
        assert_eq!(provider_for_host("api.github.com"), "github");
        assert_eq!(provider_for_host("api.stripe.com"), "stripe");
        assert_eq!(provider_for_host("api.openai.com"), "openai");
        assert_eq!(provider_for_host("api.anthropic.com"), "anthropic");
        assert_eq!(provider_for_host("gmail.googleapis.com"), "gmail");
        assert_eq!(provider_for_host("slack.com"), "slack");
    }

    #[test]
    fn test_provider_for_host_unknown() {
        assert_eq!(
            provider_for_host("custom-api.example.com"),
            "custom-api.example.com"
        );
    }

    #[test]
    fn test_provider_for_host_bedrock() {
        assert_eq!(
            provider_for_host("bedrock-runtime.us-east-1.amazonaws.com"),
            "aws-bedrock"
        );
    }

    #[test]
    fn test_provider_for_host_non_bedrock_aws() {
        assert_eq!(
            provider_for_host("s3.us-east-1.amazonaws.com"),
            "s3.us-east-1.amazonaws.com"
        );
    }

    #[test]
    fn test_default_config() {
        // Pass explicit environment to avoid dependency on CI env var.
        let config = default_config(None, Some("test".to_string()));
        assert!(config.session.learning_mode);
        assert_eq!(config.session.agent_type, Some("default".to_string()));
        assert_eq!(config.session.environment, Some("test".to_string()));
        assert_eq!(config.providers.len(), 6);
        assert!(config.providers.contains_key("github"));
        assert!(config.providers.contains_key("anthropic"));
    }

    #[test]
    fn test_default_config_with_overrides() {
        let config = default_config(Some("research".to_string()), Some("ci".to_string()));
        assert_eq!(config.session.agent_type, Some("research".to_string()));
        assert_eq!(config.session.environment, Some("ci".to_string()));
    }

    #[test]
    fn test_merge_with_defaults() {
        let defaults = default_config(None, None);
        let yaml = r#"
session:
  id: "custom-session"
  learning_mode: false
  agent_type: "coding"
providers:
  github:
    upstream: "https://github.enterprise.com/api/v3"
    credential:
      type: "bearer"
      env_var: "GHE_TOKEN"
    policies:
      allowed_methods: ["GET"]
"#;
        let overrides: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
        let merged = merge_with_defaults(defaults, overrides);

        // Session overrides.
        assert_eq!(merged.session.id, "custom-session");
        assert!(!merged.session.learning_mode);
        assert_eq!(merged.session.agent_type, Some("coding".to_string()));

        // GitHub was overridden with enterprise URL.
        let github = merged.providers.get("github").unwrap();
        assert_eq!(github.upstream, "https://github.enterprise.com/api/v3");
        assert_eq!(github.credential.env_var, "GHE_TOKEN");

        // Other default providers are still present.
        assert!(merged.providers.contains_key("stripe"));
        assert!(merged.providers.contains_key("openai"));
    }
}
