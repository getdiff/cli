pub mod generic;

use std::collections::HashMap;

/// A parsed API operation extracted from an HTTP request.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ParsedOperation {
    pub provider: String,
    pub operation: String,
    pub method: String,
    pub path: String,
    pub parameters: HashMap<String, serde_json::Value>,
}

/// Trait for provider-specific request parsing and credential injection.
#[allow(dead_code)]
pub trait ProviderAdapter: Send + Sync {
    /// Returns the provider identifier (e.g., "github").
    fn name(&self) -> &str;

    /// Returns true if this adapter handles the given host.
    fn match_host(&self, host: &str) -> bool;

    /// Interprets an HTTP method + path + body into a structured operation.
    fn parse_request(&self, method: &str, path: &str, body: &[u8]) -> ParsedOperation;

    /// Returns the credential header name and value for injection.
    fn credential_header(&self, credential: &str) -> (String, String);
}

/// Registry of provider adapters, built from config.
pub struct Registry {
    adapters: Vec<Box<dyn ProviderAdapter>>,
}

impl Registry {
    /// Creates a registry from provider configs. Each provider with an `adapter`
    /// block gets a config-driven generic adapter. Providers without an `adapter`
    /// block get no adapter (requests still route, but operations aren't parsed).
    pub fn from_config(providers: &HashMap<String, crate::config::ProviderConfig>) -> Self {
        let mut adapters: Vec<Box<dyn ProviderAdapter>> = Vec::new();

        for (name, cfg) in providers {
            if let Some(ref adapter_cfg) = cfg.adapter {
                adapters.push(Box::new(generic::GenericAdapter::new(
                    name,
                    adapter_cfg.clone(),
                )));
            }
        }

        Self { adapters }
    }

    /// Returns the first adapter whose match_host returns true for the given host.
    #[allow(dead_code)]
    pub fn find(&self, host: &str) -> Option<&dyn ProviderAdapter> {
        self.adapters
            .iter()
            .find(|a| a.match_host(host))
            .map(|a| a.as_ref())
    }

    /// Returns the adapter matching the given provider name.
    pub fn find_by_name(&self, name: &str) -> Option<&dyn ProviderAdapter> {
        self.adapters
            .iter()
            .find(|a| a.name() == name)
            .map(|a| a.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::generic::{AdapterConfig, FieldExtraction, OperationDef, RequestMatcher};
    use crate::config::{CredentialConfig, PolicyConfig, ProviderConfig};

    fn test_providers() -> HashMap<String, ProviderConfig> {
        let mut providers = HashMap::new();
        providers.insert(
            "stripe".to_string(),
            ProviderConfig {
                upstream: "https://api.stripe.com".to_string(),
                credential: CredentialConfig {
                    cred_type: "bearer".to_string(),
                    env_var: "TEST".to_string(),
                },
                policies: PolicyConfig::default(),
                adapter: Some(AdapterConfig {
                    host: "api.stripe.com".to_string(),
                    body_format: "form".to_string(),
                    operations: vec![OperationDef {
                        matcher: RequestMatcher {
                            method: Some("POST".into()),
                            path: "/v1/charges".into(),
                        },
                        name: "create_charge".into(),
                        extract: vec![FieldExtraction {
                            param: "amount".into(),
                            field: "amount".into(),
                            field_type: "integer".into(),
                        }],
                    }],
                }),
            },
        );
        providers
    }

    #[test]
    fn test_registry_from_config() {
        let providers = test_providers();
        let reg = Registry::from_config(&providers);
        assert!(reg.find_by_name("stripe").is_some());
        assert!(reg.find_by_name("unknown").is_none());
    }

    #[test]
    fn test_registry_find_by_host() {
        let providers = test_providers();
        let reg = Registry::from_config(&providers);
        assert!(reg.find("api.stripe.com").is_some());
        assert!(reg.find("api.github.com").is_none());
    }

    #[test]
    fn test_registry_parses_request() {
        let providers = test_providers();
        let reg = Registry::from_config(&providers);
        let adapter = reg.find_by_name("stripe").unwrap();
        let op = adapter.parse_request("POST", "/v1/charges", b"amount=3000&currency=usd");
        assert_eq!(op.operation, "create_charge");
        assert_eq!(op.parameters["amount"], serde_json::json!(3000));
    }

    #[test]
    fn test_registry_skips_providers_without_adapter() {
        let mut providers = HashMap::new();
        providers.insert(
            "bare".to_string(),
            ProviderConfig {
                upstream: "https://example.com".to_string(),
                credential: CredentialConfig {
                    cred_type: "bearer".to_string(),
                    env_var: "TEST".to_string(),
                },
                policies: PolicyConfig::default(),
                adapter: None,
            },
        );
        let reg = Registry::from_config(&providers);
        assert!(reg.find_by_name("bare").is_none());
    }
}
