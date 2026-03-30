use crate::gateway::config::PolicyConfig;
use std::collections::HashMap;

/// Checks requests against a set of policy rules.
#[derive(Debug)]
pub struct PolicyEvaluator {
    config: PolicyConfig,
}

/// The result of a policy evaluation.
#[derive(Debug, Clone)]
pub struct Decision {
    pub allowed: bool,
    pub reason: String,
    pub matched_rule: String,
}

impl PolicyEvaluator {
    /// Creates a policy evaluator from the given policy config.
    pub fn new(config: PolicyConfig) -> Self {
        Self { config }
    }

    /// Returns a reference to the underlying policy config.
    #[allow(dead_code)]
    pub fn config(&self) -> &PolicyConfig {
        &self.config
    }

    /// Checks whether a request with the given method, path, operation,
    /// and parameters is allowed.
    ///
    /// Evaluation order:
    ///  1. blocked_methods: deny if method is in the list
    ///  2. allowed_methods: deny if list is non-empty and method is not in the list
    ///  3. blocked_paths: deny if path matches any pattern
    ///  4. allowed_paths: if non-empty, allow only if path matches; deny otherwise
    ///  5. blocked_operations: deny if operation is in the list
    ///  6. allowed_operations: if non-empty, deny if operation is not in the list
    ///  7. Parameter constraints (amount, currency, recipients, etc.)
    ///  8. Default: allow
    pub fn evaluate(
        &self,
        method: &str,
        path: &str,
        operation: &str,
        params: &HashMap<String, serde_json::Value>,
    ) -> Decision {
        let upper_method = method.to_uppercase();

        // 1. Check blocked methods.
        for m in &self.config.blocked_methods {
            if m.eq_ignore_ascii_case(&upper_method) {
                return Decision {
                    allowed: false,
                    reason: format!("method {} is blocked", upper_method),
                    matched_rule: format!("blocked_methods: {}", m),
                };
            }
        }

        // 2. Check allowed methods (if non-empty, method must be in list).
        if !self.config.allowed_methods.is_empty() {
            let found = self
                .config
                .allowed_methods
                .iter()
                .any(|m| m.eq_ignore_ascii_case(&upper_method));
            if !found {
                return Decision {
                    allowed: false,
                    reason: format!("method {} is not in allowed_methods", upper_method),
                    matched_rule: "allowed_methods".to_string(),
                };
            }
        }

        // 3. Check blocked paths.
        for pattern in &self.config.blocked_paths {
            if match_path(pattern, path) {
                return Decision {
                    allowed: false,
                    reason: format!("path {} matches blocked pattern {}", path, pattern),
                    matched_rule: format!("blocked_paths: {}", pattern),
                };
            }
        }

        // 4. Check allowed paths (if non-empty, path must match at least one).
        if !self.config.allowed_paths.is_empty() {
            let matched = self
                .config
                .allowed_paths
                .iter()
                .any(|pattern| match_path(pattern, path));
            if !matched {
                return Decision {
                    allowed: false,
                    reason: format!("path {} does not match any allowed pattern", path),
                    matched_rule: "allowed_paths".to_string(),
                };
            }
        }

        // 5. Check blocked operations.
        if !operation.is_empty() {
            for op in &self.config.blocked_operations {
                if op.eq_ignore_ascii_case(operation) {
                    return Decision {
                        allowed: false,
                        reason: format!("operation {} is blocked", operation),
                        matched_rule: format!("blocked_operations: {}", op),
                    };
                }
            }
        }

        // 6. Check allowed operations (if non-empty, operation must be in list).
        if !self.config.allowed_operations.is_empty() && !operation.is_empty() {
            let found = self
                .config
                .allowed_operations
                .iter()
                .any(|op| op.eq_ignore_ascii_case(operation));
            if !found {
                return Decision {
                    allowed: false,
                    reason: format!("operation {} is not in allowed_operations", operation),
                    matched_rule: "allowed_operations".to_string(),
                };
            }
        }

        // 7. Parameter constraints.
        if !params.is_empty()
            && let Some(d) = self.check_parameter_constraints(params)
        {
            return d;
        }

        // 8. Default: allow.
        Decision {
            allowed: true,
            reason: "default allow (no matching rules)".to_string(),
            matched_rule: String::new(),
        }
    }

    fn check_parameter_constraints(
        &self,
        params: &HashMap<String, serde_json::Value>,
    ) -> Option<Decision> {
        // Check max_amount_cents.
        if let Some(max_amount) = self.config.max_amount_cents
            && let Some(amount) = get_int_param(params, "amount")
            && amount > max_amount as i128
        {
            return Some(Decision {
                allowed: false,
                reason: format!("amount {} exceeds max_amount_cents {}", amount, max_amount),
                matched_rule: "max_amount_cents".to_string(),
            });
        }

        // Check allowed_currencies.
        if !self.config.allowed_currencies.is_empty()
            && let Some(currency) = params.get("currency").and_then(|v| v.as_str())
        {
            let found = self
                .config
                .allowed_currencies
                .iter()
                .any(|c| c.eq_ignore_ascii_case(currency));
            if !found {
                return Some(Decision {
                    allowed: false,
                    reason: format!("currency {} is not in allowed_currencies", currency),
                    matched_rule: "allowed_currencies".to_string(),
                });
            }
        }

        // Check recipients (for email providers).
        if let Some(recipients) = get_string_slice_param(params, "recipients")
            && !recipients.is_empty()
        {
            // Check max_recipients_per_message.
            if let Some(max_recip) = self.config.max_recipients_per_message
                && recipients.len() > max_recip
            {
                return Some(Decision {
                    allowed: false,
                    reason: format!(
                        "recipient count {} exceeds max_recipients_per_message {}",
                        recipients.len(),
                        max_recip
                    ),
                    matched_rule: "max_recipients_per_message".to_string(),
                });
            }

            // Check blocked_recipients.
            for r in &recipients {
                for pattern in &self.config.blocked_recipients {
                    if match_glob(pattern, r) {
                        return Some(Decision {
                            allowed: false,
                            reason: format!("recipient {} matches blocked pattern {}", r, pattern),
                            matched_rule: format!("blocked_recipients: {}", pattern),
                        });
                    }
                }
            }

            // Check allowed_recipients (if non-empty, all must match at least one).
            if !self.config.allowed_recipients.is_empty() {
                for r in &recipients {
                    let matched = self
                        .config
                        .allowed_recipients
                        .iter()
                        .any(|pattern| match_glob(pattern, r));
                    if !matched {
                        return Some(Decision {
                            allowed: false,
                            reason: format!(
                                "recipient {} does not match any allowed_recipients pattern",
                                r
                            ),
                            matched_rule: "allowed_recipients".to_string(),
                        });
                    }
                }
            }
        }

        None
    }
}

/// Extracts an integer parameter from the map.
/// Handles both signed (i64) and unsigned (u64) JSON numbers by
/// promoting to i128, so values > i64::MAX are not silently skipped.
fn get_int_param(params: &HashMap<String, serde_json::Value>, key: &str) -> Option<i128> {
    let v = params.get(key)?;
    if let Some(n) = v.as_i64() {
        Some(n as i128)
    } else {
        v.as_u64().map(|n| n as i128)
    }
}

/// Extracts a string slice parameter from the map.
fn get_string_slice_param(
    params: &HashMap<String, serde_json::Value>,
    key: &str,
) -> Option<Vec<String>> {
    let v = params.get(key)?;
    let arr = v.as_array()?;
    Some(
        arr.iter()
            .filter_map(|item| item.as_str().map(|s| s.to_string()))
            .collect(),
    )
}

/// Checks if a path matches a glob pattern.
/// The * wildcard matches exactly one path segment.
fn match_path(pattern: &str, path: &str) -> bool {
    let pattern_parts: Vec<&str> = pattern.trim_matches('/').split('/').collect();
    let path_parts: Vec<&str> = path.trim_matches('/').split('/').collect();

    if pattern_parts.len() != path_parts.len() {
        return false;
    }

    for (pp, pathp) in pattern_parts.iter().zip(path_parts.iter()) {
        if *pp == "*" {
            continue;
        }
        if *pp != *pathp {
            return false;
        }
    }

    true
}

/// Performs simple glob matching on strings.
/// Supports * as a wildcard that matches any sequence of characters.
fn match_glob(pattern: &str, s: &str) -> bool {
    let pattern = pattern.to_lowercase();
    let s = s.to_lowercase();
    glob_match(pattern.as_bytes(), s.as_bytes())
}

/// Recursive glob matcher.
fn glob_match(pattern: &[u8], s: &[u8]) -> bool {
    let mut pi = 0;
    let mut si = 0;

    while pi < pattern.len() {
        if pattern[pi] == b'*' {
            // Skip consecutive stars.
            while pi < pattern.len() && pattern[pi] == b'*' {
                pi += 1;
            }
            if pi == pattern.len() {
                return true;
            }
            // Try matching the rest of the pattern at every position.
            for i in si..=s.len() {
                if glob_match(&pattern[pi..], &s[i..]) {
                    return true;
                }
            }
            return false;
        }

        if si >= s.len() {
            return false;
        }

        if pattern[pi] != s[si] {
            return false;
        }
        pi += 1;
        si += 1;
    }

    si == s.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_params(items: Vec<(&str, serde_json::Value)>) -> HashMap<String, serde_json::Value> {
        items.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
    }

    #[test]
    fn test_blocked_method() {
        let e = PolicyEvaluator::new(PolicyConfig {
            blocked_methods: vec!["POST".to_string(), "DELETE".to_string()],
            ..Default::default()
        });

        let d = e.evaluate("POST", "/anything", "", &HashMap::new());
        assert!(!d.allowed);

        let d = e.evaluate("DELETE", "/anything", "", &HashMap::new());
        assert!(!d.allowed);
    }

    #[test]
    fn test_allowed_method() {
        let e = PolicyEvaluator::new(PolicyConfig {
            allowed_methods: vec!["GET".to_string(), "HEAD".to_string()],
            ..Default::default()
        });

        let d = e.evaluate("GET", "/anything", "", &HashMap::new());
        assert!(d.allowed);

        let d = e.evaluate("HEAD", "/anything", "", &HashMap::new());
        assert!(d.allowed);
    }

    #[test]
    fn test_unlisted_method_denied() {
        let e = PolicyEvaluator::new(PolicyConfig {
            allowed_methods: vec!["GET".to_string()],
            ..Default::default()
        });

        let d = e.evaluate("POST", "/anything", "", &HashMap::new());
        assert!(!d.allowed);
    }

    #[test]
    fn test_blocked_path_exact() {
        let e = PolicyEvaluator::new(PolicyConfig {
            blocked_paths: vec!["/admin".to_string()],
            ..Default::default()
        });

        let d = e.evaluate("GET", "/admin", "", &HashMap::new());
        assert!(!d.allowed);
    }

    #[test]
    fn test_blocked_path_glob() {
        let e = PolicyEvaluator::new(PolicyConfig {
            blocked_paths: vec!["/repos/*/*/issues".to_string()],
            ..Default::default()
        });

        let d = e.evaluate(
            "GET",
            "/repos/octocat/Hello-World/issues",
            "",
            &HashMap::new(),
        );
        assert!(!d.allowed);
    }

    #[test]
    fn test_allowed_path() {
        let e = PolicyEvaluator::new(PolicyConfig {
            allowed_paths: vec!["/user".to_string(), "/repos/*/*".to_string()],
            ..Default::default()
        });

        let d = e.evaluate("GET", "/user", "", &HashMap::new());
        assert!(d.allowed);

        let d = e.evaluate("GET", "/repos/octocat/Hello-World", "", &HashMap::new());
        assert!(d.allowed);
    }

    #[test]
    fn test_path_not_in_allowed_list() {
        let e = PolicyEvaluator::new(PolicyConfig {
            allowed_paths: vec!["/user".to_string()],
            ..Default::default()
        });

        let d = e.evaluate("GET", "/admin", "", &HashMap::new());
        assert!(!d.allowed);
    }

    #[test]
    fn test_blocked_path_takes_precedence() {
        let e = PolicyEvaluator::new(PolicyConfig {
            allowed_paths: vec!["/repos/*/*/issues".to_string()],
            blocked_paths: vec!["/repos/*/*/issues".to_string()],
            ..Default::default()
        });

        let d = e.evaluate(
            "GET",
            "/repos/octocat/Hello-World/issues",
            "",
            &HashMap::new(),
        );
        assert!(!d.allowed);
    }

    #[test]
    fn test_empty_policies_allow_all() {
        let e = PolicyEvaluator::new(PolicyConfig::default());

        let d = e.evaluate("POST", "/any/path/here", "", &HashMap::new());
        assert!(d.allowed);
    }

    #[test]
    fn test_path_segment_count_mismatch() {
        let e = PolicyEvaluator::new(PolicyConfig {
            allowed_paths: vec!["/repos/*/*".to_string()],
            ..Default::default()
        });

        let d = e.evaluate(
            "GET",
            "/repos/octocat/Hello-World/issues",
            "",
            &HashMap::new(),
        );
        assert!(!d.allowed);

        let d = e.evaluate("GET", "/repos", "", &HashMap::new());
        assert!(!d.allowed);
    }

    #[test]
    fn test_full_policy_stack() {
        let e = PolicyEvaluator::new(PolicyConfig {
            allowed_methods: vec!["GET".to_string(), "HEAD".to_string()],
            blocked_methods: vec![
                "POST".to_string(),
                "PUT".to_string(),
                "DELETE".to_string(),
                "PATCH".to_string(),
            ],
            allowed_paths: vec![
                "/user".to_string(),
                "/user/repos".to_string(),
                "/repos/*".to_string(),
                "/repos/*/*".to_string(),
                "/rate_limit".to_string(),
            ],
            blocked_paths: vec!["/repos/*/*/issues".to_string()],
            ..Default::default()
        });

        let tests = vec![
            ("GET", "/user", true),
            ("GET", "/user/repos", true),
            ("GET", "/repos/octocat/Hello-World", true),
            ("GET", "/repos/octocat/Hello-World/issues", false),
            ("POST", "/repos/octocat/Hello-World/issues", false),
            ("GET", "/rate_limit", true),
            ("DELETE", "/user", false),
            ("GET", "/orgs/github", false),
        ];

        for (method, path, want) in tests {
            let d = e.evaluate(method, path, "", &HashMap::new());
            assert_eq!(
                d.allowed, want,
                "evaluate({}, {}) = allowed:{}, want:{}; reason: {}",
                method, path, d.allowed, want, d.reason
            );
        }
    }

    #[test]
    fn test_blocked_operation() {
        let e = PolicyEvaluator::new(PolicyConfig {
            blocked_operations: vec!["create_transfer".to_string(), "get_balance".to_string()],
            ..Default::default()
        });

        let d = e.evaluate("POST", "/v1/transfers", "create_transfer", &HashMap::new());
        assert!(!d.allowed);

        let d = e.evaluate("GET", "/v1/balance", "get_balance", &HashMap::new());
        assert!(!d.allowed);

        let d = e.evaluate("GET", "/v1/charges", "list_charges", &HashMap::new());
        assert!(d.allowed);
    }

    #[test]
    fn test_allowed_operation() {
        let e = PolicyEvaluator::new(PolicyConfig {
            allowed_operations: vec!["list_charges".to_string(), "get_charge".to_string()],
            ..Default::default()
        });

        let d = e.evaluate("GET", "/v1/charges", "list_charges", &HashMap::new());
        assert!(d.allowed);

        let d = e.evaluate("POST", "/v1/charges", "create_charge", &HashMap::new());
        assert!(!d.allowed);
    }

    #[test]
    fn test_max_amount_cents() {
        let e = PolicyEvaluator::new(PolicyConfig {
            max_amount_cents: Some(5000),
            ..Default::default()
        });

        let d = e.evaluate(
            "POST",
            "/v1/charges",
            "create_charge",
            &make_params(vec![("amount", serde_json::json!(3000))]),
        );
        assert!(d.allowed);

        let d = e.evaluate(
            "POST",
            "/v1/charges",
            "create_charge",
            &make_params(vec![("amount", serde_json::json!(5000))]),
        );
        assert!(d.allowed);

        let d = e.evaluate(
            "POST",
            "/v1/charges",
            "create_charge",
            &make_params(vec![("amount", serde_json::json!(8000))]),
        );
        assert!(!d.allowed);
    }

    #[test]
    fn test_allowed_currencies() {
        let e = PolicyEvaluator::new(PolicyConfig {
            allowed_currencies: vec!["usd".to_string(), "eur".to_string()],
            ..Default::default()
        });

        let d = e.evaluate(
            "POST",
            "/v1/charges",
            "create_charge",
            &make_params(vec![("currency", serde_json::json!("usd"))]),
        );
        assert!(d.allowed);

        let d = e.evaluate(
            "POST",
            "/v1/charges",
            "create_charge",
            &make_params(vec![("currency", serde_json::json!("gbp"))]),
        );
        assert!(!d.allowed);
    }

    #[test]
    fn test_allowed_recipients() {
        let e = PolicyEvaluator::new(PolicyConfig {
            allowed_recipients: vec!["*@acme.com".to_string()],
            ..Default::default()
        });

        let d = e.evaluate(
            "POST",
            "/send",
            "send_email",
            &make_params(vec![("recipients", serde_json::json!(["alice@acme.com"]))]),
        );
        assert!(d.allowed);

        let d = e.evaluate(
            "POST",
            "/send",
            "send_email",
            &make_params(vec![(
                "recipients",
                serde_json::json!(["alice@external.com"]),
            )]),
        );
        assert!(!d.allowed);

        // Mixed: one allowed, one not.
        let d = e.evaluate(
            "POST",
            "/send",
            "send_email",
            &make_params(vec![(
                "recipients",
                serde_json::json!(["alice@acme.com", "bob@external.com"]),
            )]),
        );
        assert!(!d.allowed);
    }

    #[test]
    fn test_blocked_recipients() {
        let e = PolicyEvaluator::new(PolicyConfig {
            blocked_recipients: vec!["*@competitor.com".to_string()],
            ..Default::default()
        });

        let d = e.evaluate(
            "POST",
            "/send",
            "send_email",
            &make_params(vec![(
                "recipients",
                serde_json::json!(["alice@competitor.com"]),
            )]),
        );
        assert!(!d.allowed);

        let d = e.evaluate(
            "POST",
            "/send",
            "send_email",
            &make_params(vec![("recipients", serde_json::json!(["alice@acme.com"]))]),
        );
        assert!(d.allowed);
    }

    #[test]
    fn test_max_recipients_per_message() {
        let e = PolicyEvaluator::new(PolicyConfig {
            max_recipients_per_message: Some(2),
            ..Default::default()
        });

        let d = e.evaluate(
            "POST",
            "/send",
            "send_email",
            &make_params(vec![(
                "recipients",
                serde_json::json!(["a@x.com", "b@x.com"]),
            )]),
        );
        assert!(d.allowed);

        let d = e.evaluate(
            "POST",
            "/send",
            "send_email",
            &make_params(vec![(
                "recipients",
                serde_json::json!(["a@x.com", "b@x.com", "c@x.com"]),
            )]),
        );
        assert!(!d.allowed);
    }

    #[test]
    fn test_combined_stripe_policy() {
        let e = PolicyEvaluator::new(PolicyConfig {
            allowed_methods: vec!["GET".to_string(), "POST".to_string()],
            blocked_methods: vec!["DELETE".to_string()],
            allowed_operations: vec![
                "list_charges".to_string(),
                "get_charge".to_string(),
                "create_charge".to_string(),
                "list_customers".to_string(),
                "get_customer".to_string(),
                "create_customer".to_string(),
            ],
            blocked_operations: vec!["create_transfer".to_string(), "get_balance".to_string()],
            max_amount_cents: Some(5000),
            allowed_currencies: vec!["usd".to_string()],
            ..Default::default()
        });

        // Allowed: list charges.
        let d = e.evaluate("GET", "/v1/charges", "list_charges", &HashMap::new());
        assert!(d.allowed);

        // Allowed: create charge within limits.
        let d = e.evaluate(
            "POST",
            "/v1/charges",
            "create_charge",
            &make_params(vec![
                ("amount", serde_json::json!(3000)),
                ("currency", serde_json::json!("usd")),
            ]),
        );
        assert!(d.allowed);

        // Blocked: amount too high.
        let d = e.evaluate(
            "POST",
            "/v1/charges",
            "create_charge",
            &make_params(vec![
                ("amount", serde_json::json!(8000)),
                ("currency", serde_json::json!("usd")),
            ]),
        );
        assert!(!d.allowed);

        // Blocked: wrong currency.
        let d = e.evaluate(
            "POST",
            "/v1/charges",
            "create_charge",
            &make_params(vec![
                ("amount", serde_json::json!(1000)),
                ("currency", serde_json::json!("eur")),
            ]),
        );
        assert!(!d.allowed);

        // Blocked: transfer operation.
        let d = e.evaluate("POST", "/v1/transfers", "create_transfer", &HashMap::new());
        assert!(!d.allowed);

        // Blocked: DELETE method.
        let d = e.evaluate(
            "DELETE",
            "/v1/subscriptions/sub_123",
            "cancel_subscription",
            &HashMap::new(),
        );
        assert!(!d.allowed);
    }

    #[test]
    fn test_combined_gmail_policy() {
        let e = PolicyEvaluator::new(PolicyConfig {
            allowed_methods: vec!["GET".to_string(), "POST".to_string()],
            blocked_methods: vec!["DELETE".to_string()],
            allowed_operations: vec![
                "send_email".to_string(),
                "list_messages".to_string(),
                "get_message".to_string(),
                "list_labels".to_string(),
            ],
            blocked_operations: vec!["delete_message".to_string(), "modify_message".to_string()],
            allowed_recipients: vec!["*@acme.com".to_string()],
            max_recipients_per_message: Some(5),
            ..Default::default()
        });

        // Allowed: list messages.
        let d = e.evaluate(
            "GET",
            "/gmail/v1/users/me/messages",
            "list_messages",
            &HashMap::new(),
        );
        assert!(d.allowed);

        // Allowed: send to acme.
        let d = e.evaluate(
            "POST",
            "/gmail/v1/users/me/messages/send",
            "send_email",
            &make_params(vec![("recipients", serde_json::json!(["alice@acme.com"]))]),
        );
        assert!(d.allowed);

        // Blocked: send to external.
        let d = e.evaluate(
            "POST",
            "/gmail/v1/users/me/messages/send",
            "send_email",
            &make_params(vec![(
                "recipients",
                serde_json::json!(["alice@external.com"]),
            )]),
        );
        assert!(!d.allowed);

        // Blocked: modify operation.
        let d = e.evaluate(
            "POST",
            "/gmail/v1/users/me/messages/msg123/modify",
            "modify_message",
            &HashMap::new(),
        );
        assert!(!d.allowed);
    }

    #[test]
    fn test_match_glob() {
        let tests = vec![
            ("*@acme.com", "alice@acme.com", true),
            ("*@acme.com", "alice@other.com", false),
            ("alice@*", "alice@anything.com", true),
            ("*@*.com", "alice@acme.com", true),
            ("*@*.org", "alice@acme.com", false),
            ("exact@match.com", "exact@match.com", true),
            ("exact@match.com", "other@match.com", false),
            ("*", "anything", true),
            ("", "", true),
        ];

        for (pattern, s, want) in tests {
            assert_eq!(
                match_glob(pattern, s),
                want,
                "match_glob({:?}, {:?}) = {}, want {}",
                pattern,
                s,
                !want,
                want
            );
        }
    }
}
