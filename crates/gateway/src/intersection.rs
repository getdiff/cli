use crate::config::{IntersectionPolicyConfig, PolicyConfig};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// A cross-capability policy restriction rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntersectionRule {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub when: IntersectionCondition,
    pub then: HashMap<String, PolicyConfig>,
}

/// Defines when an intersection activates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntersectionCondition {
    pub all_of: Vec<IntersectionMatcher>,
}

/// Matches a capability in the session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntersectionMatcher {
    pub provider: String,
    #[serde(default)]
    pub capability: Option<String>,
}

/// Represents an intersection rule that has been activated.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ActiveIntersection {
    pub rule: IntersectionRule,
    pub restrictions: HashMap<String, PolicyConfig>,
}

/// Returns active intersection rules given a set of provider names.
pub fn compute_intersections(
    providers: &[String],
    rules: &[IntersectionRule],
) -> Vec<ActiveIntersection> {
    let provider_set: HashSet<&str> = providers.iter().map(|s| s.as_str()).collect();

    let mut active = Vec::new();
    for rule in rules {
        if matches_condition(&provider_set, &rule.when) {
            active.push(ActiveIntersection {
                rule: rule.clone(),
                restrictions: rule.then.clone(),
            });
        }
    }
    active
}

/// Checks if all providers in the condition are present.
fn matches_condition(provider_set: &HashSet<&str>, cond: &IntersectionCondition) -> bool {
    if cond.all_of.is_empty() {
        return false;
    }
    cond.all_of
        .iter()
        .all(|matcher| provider_set.contains(matcher.provider.as_str()))
}

/// Merges intersection restrictions into base policies.
/// Intersections can only TIGHTEN, never loosen.
pub fn merge_intersections(
    base_policies: &HashMap<String, PolicyConfig>,
    intersections: &[ActiveIntersection],
) -> HashMap<String, PolicyConfig> {
    if intersections.is_empty() {
        return base_policies.clone();
    }

    // Deep copy the base policies.
    let mut result: HashMap<String, PolicyConfig> = base_policies.clone();

    for intersection in intersections {
        for (provider, restriction) in &intersection.restrictions {
            let base = result.remove(provider).unwrap_or_default();
            result.insert(provider.clone(), merge_policy_single(base, restriction));
        }
    }

    result
}

/// Merges a restriction into a base policy (tighten only).
fn merge_policy_single(mut base: PolicyConfig, restriction: &PolicyConfig) -> PolicyConfig {
    // Blocked lists: union (add more blocks).
    base.blocked_methods = union_strings(&base.blocked_methods, &restriction.blocked_methods);
    base.blocked_paths = union_strings(&base.blocked_paths, &restriction.blocked_paths);
    base.blocked_operations =
        union_strings(&base.blocked_operations, &restriction.blocked_operations);
    base.blocked_recipients =
        union_strings(&base.blocked_recipients, &restriction.blocked_recipients);

    // Allowed lists: intersection (narrow what's allowed) -- only if restriction specifies.
    if !restriction.allowed_methods.is_empty() {
        if !base.allowed_methods.is_empty() {
            base.allowed_methods =
                intersect_strings(&base.allowed_methods, &restriction.allowed_methods);
        } else {
            base.allowed_methods = restriction.allowed_methods.clone();
        }
    }
    if !restriction.allowed_paths.is_empty() {
        if !base.allowed_paths.is_empty() {
            base.allowed_paths = intersect_strings(&base.allowed_paths, &restriction.allowed_paths);
        } else {
            base.allowed_paths = restriction.allowed_paths.clone();
        }
    }
    if !restriction.allowed_operations.is_empty() {
        if !base.allowed_operations.is_empty() {
            base.allowed_operations =
                intersect_strings(&base.allowed_operations, &restriction.allowed_operations);
        } else {
            base.allowed_operations = restriction.allowed_operations.clone();
        }
    }
    if !restriction.allowed_recipients.is_empty() {
        if !base.allowed_recipients.is_empty() {
            base.allowed_recipients =
                intersect_strings(&base.allowed_recipients, &restriction.allowed_recipients);
        } else {
            base.allowed_recipients = restriction.allowed_recipients.clone();
        }
    }
    if !restriction.allowed_currencies.is_empty() {
        if !base.allowed_currencies.is_empty() {
            base.allowed_currencies =
                intersect_strings(&base.allowed_currencies, &restriction.allowed_currencies);
        } else {
            base.allowed_currencies = restriction.allowed_currencies.clone();
        }
    }

    // Numeric caps: take the minimum.
    base.max_amount_cents = min_option(base.max_amount_cents, restriction.max_amount_cents);
    base.daily_limit_cents = min_option(base.daily_limit_cents, restriction.daily_limit_cents);
    base.max_recipients_per_message = min_option_usize(
        base.max_recipients_per_message,
        restriction.max_recipients_per_message,
    );

    base
}

/// Returns the union of two string slices, maintaining order.
fn union_strings(a: &[String], b: &[String]) -> Vec<String> {
    if b.is_empty() {
        return a.to_vec();
    }
    let mut set: HashSet<String> = HashSet::new();
    let mut result = Vec::with_capacity(a.len() + b.len());

    // Add a first, then new items from b.
    for s in a {
        if set.insert(s.clone()) {
            result.push(s.clone());
        }
    }
    for s in b {
        if set.insert(s.clone()) {
            result.push(s.clone());
        }
    }
    result
}

/// Returns the intersection of two string slices.
fn intersect_strings(a: &[String], b: &[String]) -> Vec<String> {
    let b_set: HashSet<&str> = b.iter().map(|s| s.as_str()).collect();
    a.iter()
        .filter(|s| b_set.contains(s.as_str()))
        .cloned()
        .collect()
}

/// Returns the minimum of two optional i64 values.
fn min_option(a: Option<i64>, b: Option<i64>) -> Option<i64> {
    match (a, b) {
        (None, None) => None,
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (Some(a), Some(b)) => Some(a.min(b)),
    }
}

/// Returns the minimum of two optional usize values.
fn min_option_usize(a: Option<usize>, b: Option<usize>) -> Option<usize> {
    match (a, b) {
        (None, None) => None,
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (Some(a), Some(b)) => Some(a.min(b)),
    }
}

/// Converts config intersection policies to IntersectionRules.
pub fn rules_from_config(cfg_rules: &[IntersectionPolicyConfig]) -> Vec<IntersectionRule> {
    cfg_rules
        .iter()
        .map(|cr| {
            let matchers = cr
                .when
                .all_of
                .iter()
                .map(|m| IntersectionMatcher {
                    provider: m.provider.clone(),
                    capability: m.capability.clone(),
                })
                .collect();
            IntersectionRule {
                name: cr.name.clone(),
                description: cr.description.clone(),
                when: IntersectionCondition { all_of: matchers },
                then: cr.then.clone(),
            }
        })
        .collect()
}

/// Built-in intersection rules that activate when an agent has multiple
/// capabilities simultaneously.
#[allow(dead_code)]
pub fn default_intersection_rules() -> Vec<IntersectionRule> {
    vec![
        IntersectionRule {
            name: "prevent-mass-email".to_string(),
            description: "When agent has email + data source, restrict email volume".to_string(),
            when: IntersectionCondition {
                all_of: vec![
                    IntersectionMatcher {
                        provider: "gmail".to_string(),
                        capability: None,
                    },
                    IntersectionMatcher {
                        provider: "stripe".to_string(),
                        capability: None,
                    },
                ],
            },
            then: {
                let mut m = HashMap::new();
                m.insert(
                    "gmail".to_string(),
                    PolicyConfig {
                        max_recipients_per_message: Some(3),
                        ..Default::default()
                    },
                );
                m
            },
        },
        IntersectionRule {
            name: "payment-data-restriction".to_string(),
            description: "When agent has payment + customer data, lower charge caps".to_string(),
            when: IntersectionCondition {
                all_of: vec![
                    IntersectionMatcher {
                        provider: "stripe".to_string(),
                        capability: None,
                    },
                    IntersectionMatcher {
                        provider: "gmail".to_string(),
                        capability: None,
                    },
                ],
            },
            then: {
                let mut m = HashMap::new();
                m.insert(
                    "stripe".to_string(),
                    PolicyConfig {
                        max_amount_cents: Some(1000),
                        ..Default::default()
                    },
                );
                m
            },
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CapabilityMatcher, IntersectionWhen};

    #[test]
    fn test_compute_intersections_two_providers_match() {
        let rules = vec![IntersectionRule {
            name: "test-rule".to_string(),
            description: String::new(),
            when: IntersectionCondition {
                all_of: vec![
                    IntersectionMatcher {
                        provider: "gmail".to_string(),
                        capability: None,
                    },
                    IntersectionMatcher {
                        provider: "stripe".to_string(),
                        capability: None,
                    },
                ],
            },
            then: {
                let mut m = HashMap::new();
                m.insert(
                    "gmail".to_string(),
                    PolicyConfig {
                        max_recipients_per_message: Some(3),
                        ..Default::default()
                    },
                );
                m
            },
        }];

        let providers = vec!["gmail".to_string(), "stripe".to_string()];
        let active = compute_intersections(&providers, &rules);
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].rule.name, "test-rule");
    }

    #[test]
    fn test_compute_intersections_one_provider_missing() {
        let rules = vec![IntersectionRule {
            name: "test-rule".to_string(),
            description: String::new(),
            when: IntersectionCondition {
                all_of: vec![
                    IntersectionMatcher {
                        provider: "gmail".to_string(),
                        capability: None,
                    },
                    IntersectionMatcher {
                        provider: "stripe".to_string(),
                        capability: None,
                    },
                ],
            },
            then: HashMap::new(),
        }];

        let providers = vec!["gmail".to_string()];
        let active = compute_intersections(&providers, &rules);
        assert_eq!(active.len(), 0);
    }

    #[test]
    fn test_compute_intersections_three_way() {
        let rules = vec![IntersectionRule {
            name: "triple-rule".to_string(),
            description: String::new(),
            when: IntersectionCondition {
                all_of: vec![
                    IntersectionMatcher {
                        provider: "gmail".to_string(),
                        capability: None,
                    },
                    IntersectionMatcher {
                        provider: "stripe".to_string(),
                        capability: None,
                    },
                    IntersectionMatcher {
                        provider: "github".to_string(),
                        capability: None,
                    },
                ],
            },
            then: HashMap::new(),
        }];

        // All three present.
        let providers = vec![
            "gmail".to_string(),
            "stripe".to_string(),
            "github".to_string(),
        ];
        let active = compute_intersections(&providers, &rules);
        assert_eq!(active.len(), 1);

        // Only two present.
        let providers = vec!["gmail".to_string(), "stripe".to_string()];
        let active = compute_intersections(&providers, &rules);
        assert_eq!(active.len(), 0);
    }

    #[test]
    fn test_merge_blocked_lists_union() {
        let mut base = HashMap::new();
        base.insert(
            "stripe".to_string(),
            PolicyConfig {
                blocked_operations: vec!["create_transfer".to_string()],
                ..Default::default()
            },
        );

        let intersections = vec![ActiveIntersection {
            rule: IntersectionRule {
                name: "test".to_string(),
                description: String::new(),
                when: IntersectionCondition { all_of: vec![] },
                then: HashMap::new(),
            },
            restrictions: {
                let mut m = HashMap::new();
                m.insert(
                    "stripe".to_string(),
                    PolicyConfig {
                        blocked_operations: vec![
                            "get_balance".to_string(),
                            "create_transfer".to_string(),
                        ],
                        ..Default::default()
                    },
                );
                m
            },
        }];

        let result = merge_intersections(&base, &intersections);
        let blocked = &result["stripe"].blocked_operations;
        assert_eq!(blocked.len(), 2);
        let has: HashSet<&str> = blocked.iter().map(|s| s.as_str()).collect();
        assert!(has.contains("create_transfer"));
        assert!(has.contains("get_balance"));
    }

    #[test]
    fn test_merge_numeric_caps_minimum() {
        let mut base = HashMap::new();
        base.insert(
            "stripe".to_string(),
            PolicyConfig {
                max_amount_cents: Some(5000),
                ..Default::default()
            },
        );

        let intersections = vec![ActiveIntersection {
            rule: IntersectionRule {
                name: "test".to_string(),
                description: String::new(),
                when: IntersectionCondition { all_of: vec![] },
                then: HashMap::new(),
            },
            restrictions: {
                let mut m = HashMap::new();
                m.insert(
                    "stripe".to_string(),
                    PolicyConfig {
                        max_amount_cents: Some(1000),
                        ..Default::default()
                    },
                );
                m
            },
        }];

        let result = merge_intersections(&base, &intersections);
        assert_eq!(result["stripe"].max_amount_cents, Some(1000));
    }

    #[test]
    fn test_merge_does_not_loosen() {
        // Base has a tighter cap than intersection.
        let mut base = HashMap::new();
        base.insert(
            "stripe".to_string(),
            PolicyConfig {
                max_amount_cents: Some(500),
                ..Default::default()
            },
        );

        let intersections = vec![ActiveIntersection {
            rule: IntersectionRule {
                name: "test".to_string(),
                description: String::new(),
                when: IntersectionCondition { all_of: vec![] },
                then: HashMap::new(),
            },
            restrictions: {
                let mut m = HashMap::new();
                m.insert(
                    "stripe".to_string(),
                    PolicyConfig {
                        max_amount_cents: Some(1000),
                        ..Default::default()
                    },
                );
                m
            },
        }];

        let result = merge_intersections(&base, &intersections);
        assert_eq!(result["stripe"].max_amount_cents, Some(500));
    }

    #[test]
    fn test_merge_multiple_intersections() {
        let mut base = HashMap::new();
        base.insert(
            "stripe".to_string(),
            PolicyConfig {
                max_amount_cents: Some(5000),
                ..Default::default()
            },
        );
        base.insert(
            "gmail".to_string(),
            PolicyConfig {
                max_recipients_per_message: Some(10),
                ..Default::default()
            },
        );

        let dummy_rule = IntersectionRule {
            name: "test".to_string(),
            description: String::new(),
            when: IntersectionCondition { all_of: vec![] },
            then: HashMap::new(),
        };

        let intersections = vec![
            ActiveIntersection {
                rule: dummy_rule.clone(),
                restrictions: {
                    let mut m = HashMap::new();
                    m.insert(
                        "stripe".to_string(),
                        PolicyConfig {
                            max_amount_cents: Some(2000),
                            ..Default::default()
                        },
                    );
                    m.insert(
                        "gmail".to_string(),
                        PolicyConfig {
                            max_recipients_per_message: Some(5),
                            ..Default::default()
                        },
                    );
                    m
                },
            },
            ActiveIntersection {
                rule: dummy_rule,
                restrictions: {
                    let mut m = HashMap::new();
                    m.insert(
                        "stripe".to_string(),
                        PolicyConfig {
                            max_amount_cents: Some(1000),
                            ..Default::default()
                        },
                    );
                    m.insert(
                        "gmail".to_string(),
                        PolicyConfig {
                            max_recipients_per_message: Some(3),
                            ..Default::default()
                        },
                    );
                    m
                },
            },
        ];

        let result = merge_intersections(&base, &intersections);
        assert_eq!(result["stripe"].max_amount_cents, Some(1000));
        assert_eq!(result["gmail"].max_recipients_per_message, Some(3));
    }

    #[test]
    fn test_merge_no_rules() {
        let mut base = HashMap::new();
        base.insert(
            "stripe".to_string(),
            PolicyConfig {
                max_amount_cents: Some(5000),
                ..Default::default()
            },
        );

        let result = merge_intersections(&base, &[]);
        assert_eq!(result["stripe"].max_amount_cents, Some(5000));
    }

    #[test]
    fn test_merge_base_not_modified() {
        let mut base = HashMap::new();
        base.insert(
            "stripe".to_string(),
            PolicyConfig {
                max_amount_cents: Some(5000),
                blocked_operations: vec!["create_transfer".to_string()],
                ..Default::default()
            },
        );

        let intersections = vec![ActiveIntersection {
            rule: IntersectionRule {
                name: "test".to_string(),
                description: String::new(),
                when: IntersectionCondition { all_of: vec![] },
                then: HashMap::new(),
            },
            restrictions: {
                let mut m = HashMap::new();
                m.insert(
                    "stripe".to_string(),
                    PolicyConfig {
                        max_amount_cents: Some(1000),
                        blocked_operations: vec!["get_balance".to_string()],
                        ..Default::default()
                    },
                );
                m
            },
        }];

        let _ = merge_intersections(&base, &intersections);

        // Verify the original base was not modified.
        assert_eq!(base["stripe"].max_amount_cents, Some(5000));
        assert_eq!(base["stripe"].blocked_operations.len(), 1);
    }

    #[test]
    fn test_merge_recipient_cap_minimum() {
        let mut base = HashMap::new();
        base.insert(
            "gmail".to_string(),
            PolicyConfig {
                max_recipients_per_message: Some(5),
                ..Default::default()
            },
        );

        let intersections = vec![ActiveIntersection {
            rule: IntersectionRule {
                name: "test".to_string(),
                description: String::new(),
                when: IntersectionCondition { all_of: vec![] },
                then: HashMap::new(),
            },
            restrictions: {
                let mut m = HashMap::new();
                m.insert(
                    "gmail".to_string(),
                    PolicyConfig {
                        max_recipients_per_message: Some(3),
                        ..Default::default()
                    },
                );
                m
            },
        }];

        let result = merge_intersections(&base, &intersections);
        assert_eq!(result["gmail"].max_recipients_per_message, Some(3));
    }

    #[test]
    fn test_rules_from_config() {
        let cfg_rules = vec![IntersectionPolicyConfig {
            name: "test-rule".to_string(),
            description: "test desc".to_string(),
            when: IntersectionWhen {
                all_of: vec![
                    CapabilityMatcher {
                        provider: "gmail".to_string(),
                        capability: None,
                    },
                    CapabilityMatcher {
                        provider: "stripe".to_string(),
                        capability: None,
                    },
                ],
            },
            then: {
                let mut m = HashMap::new();
                m.insert(
                    "gmail".to_string(),
                    PolicyConfig {
                        max_recipients_per_message: Some(3),
                        ..Default::default()
                    },
                );
                m
            },
        }];

        let rules = rules_from_config(&cfg_rules);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "test-rule");
        assert_eq!(rules[0].when.all_of.len(), 2);
    }
}
