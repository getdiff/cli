use once_cell::sync::Lazy;
use regex::Regex;

struct SensitivePattern {
    name: &'static str,
    regex: Regex,
}

static SIMPLE_PATTERNS: Lazy<Vec<SensitivePattern>> = Lazy::new(|| {
    vec![
        SensitivePattern {
            name: "secret_aws_key",
            regex: compile_regex(r"AKIA[0-9A-Z]{16}", "secret_aws_key"),
        },
        SensitivePattern {
            name: "secret_github_token",
            regex: compile_regex(r"gh[pousr]_[A-Za-z0-9]{20,}", "secret_github_token"),
        },
        SensitivePattern {
            name: "secret_github_pat",
            regex: compile_regex(r"github_pat_[A-Za-z0-9_]{20,}", "secret_github_pat"),
        },
        SensitivePattern {
            name: "secret_anthropic_key",
            regex: compile_regex(r"sk-ant-[a-zA-Z0-9\-_]{40,}", "secret_anthropic_key"),
        },
        SensitivePattern {
            name: "secret_api_key",
            regex: compile_regex(
                r"sk-(?:[A-Za-z0-9]{20,}|(?:live|proj|test|dev)-[A-Za-z0-9_-]{10,})",
                "secret_api_key",
            ),
        },
        SensitivePattern {
            name: "secret_jwt",
            regex: compile_regex(
                r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
                "secret_jwt",
            ),
        },
        SensitivePattern {
            name: "secret_private_key",
            regex: compile_regex(
                r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
                "secret_private_key",
            ),
        },
        SensitivePattern {
            name: "secret_token_assignment",
            regex: compile_regex(
                r#"(?i)(password|secret|token|api_key|apikey|api[_-]?secret)\s*[=:]\s*['"]?[^\s'"]{8,}"#,
                "secret_token_assignment",
            ),
        },
        SensitivePattern {
            name: "secret_bearer_token",
            regex: compile_regex(
                r"(?i)Bearer\s+[A-Za-z0-9._\-/+=]{20,}",
                "secret_bearer_token",
            ),
        },
        SensitivePattern {
            name: "secret_slack_token",
            regex: compile_regex(r"xox[baprs]-[A-Za-z0-9-]{10,}", "secret_slack_token"),
        },
        SensitivePattern {
            name: "pii_email",
            regex: compile_regex(
                r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
                "pii_email",
            ),
        },
        SensitivePattern {
            name: "pii_ssn",
            regex: compile_regex(r"\b\d{3}-\d{2}-\d{4}\b", "pii_ssn"),
        },
        SensitivePattern {
            name: "pii_phone",
            regex: compile_regex(
                r"(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?){2}\d{4}",
                "pii_phone",
            ),
        },
    ]
});

static CREDIT_CARD_PATTERN: Lazy<Regex> =
    Lazy::new(|| compile_regex(r"\b(?:\d[ -]*?){13,19}\b", "CREDIT_CARD_PATTERN"));

fn compile_regex(pattern: &str, name: &str) -> Regex {
    Regex::new(pattern).unwrap_or_else(|error| {
        eprintln!("failed to compile regex '{name}': {error}. pattern: {pattern}");
        panic!("invalid regex for {name}");
    })
}

pub struct Redactor {
    extra_patterns: Vec<(String, Regex)>,
}

impl Redactor {
    pub fn new() -> Self {
        Redactor {
            extra_patterns: vec![],
        }
    }

    #[allow(dead_code)]
    pub fn add_pattern(&mut self, name: &str, pattern: &str) -> Result<(), regex::Error> {
        let re = Regex::new(pattern)?;
        self.extra_patterns.push((name.to_string(), re));
        Ok(())
    }

    pub fn redact(&self, input: &str) -> String {
        let mut result = input.to_string();

        for pattern in SIMPLE_PATTERNS.iter() {
            result = pattern
                .regex
                .replace_all(&result, format!("[REDACTED:{}]", pattern.name))
                .to_string();
        }

        result = CREDIT_CARD_PATTERN
            .replace_all(&result, |captures: &regex::Captures<'_>| {
                let matched = captures
                    .get(0)
                    .map(|capture| capture.as_str())
                    .unwrap_or_default();
                if is_likely_credit_card(matched) {
                    "[REDACTED:pii_credit_card]".to_string()
                } else {
                    matched.to_string()
                }
            })
            .to_string();

        for (name, re) in &self.extra_patterns {
            result = re
                .replace_all(&result, format!("[REDACTED:{}]", name))
                .to_string();
        }

        result
    }
}

impl Default for Redactor {
    fn default() -> Self {
        Self::new()
    }
}

fn is_likely_credit_card(value: &str) -> bool {
    let digits: String = value.chars().filter(|ch| ch.is_ascii_digit()).collect();
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }
    passes_luhn_check(&digits)
}

fn passes_luhn_check(value: &str) -> bool {
    let mut sum = 0u32;
    let mut should_double = false;

    for ch in value.chars().rev() {
        let Some(mut digit) = ch.to_digit(10) else {
            return false;
        };
        if should_double {
            digit *= 2;
            if digit > 9 {
                digit -= 9;
            }
        }
        sum += digit;
        should_double = !should_double;
    }

    sum.is_multiple_of(10)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redacts_aws_key() {
        let r = Redactor::new();
        let input = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
        let result = r.redact(input);
        assert!(result.contains("[REDACTED:secret_aws_key]"));
        assert!(!result.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn test_redacts_github_token() {
        let r = Redactor::new();
        let input = "Use ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij to authenticate";
        let result = r.redact(input);
        assert!(result.contains("[REDACTED:secret_github_token]"));
        assert!(!result.contains("ghp_ABCDEF"));
    }

    #[test]
    fn test_redacts_extended_github_token_prefixes() {
        let r = Redactor::new();
        let input = "Use ghu_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij to authenticate";
        let result = r.redact(input);
        assert!(result.contains("[REDACTED:secret_github_token]"));
    }

    #[test]
    fn test_redacts_slack_token() {
        let r = Redactor::new();
        let token = format!("xoxb-{}-{}", "123456789012", "abcdefghijklmnop");
        let input = format!("Slack token {token} should be redacted");
        let result = r.redact(&input);
        assert!(result.contains("[REDACTED:secret_slack_token]"));
    }

    #[test]
    fn test_redacts_jwt() {
        let r = Redactor::new();
        let input = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456";
        let result = r.redact(input);
        assert!(result.contains("[REDACTED:secret_jwt]"));
    }

    #[test]
    fn test_redacts_generic_secret() {
        let r = Redactor::new();
        let input = "password = supersecretvalue123";
        let result = r.redact(input);
        assert!(result.contains("[REDACTED:secret_token_assignment]"));
    }

    #[test]
    fn test_redacts_email() {
        let r = Redactor::new();
        let input = "Contact jane@example.com for access";
        let result = r.redact(input);
        assert!(result.contains("[REDACTED:pii_email]"));
        assert!(!result.contains("jane@example.com"));
    }

    #[test]
    fn test_redacts_phone() {
        let r = Redactor::new();
        let input = "Call me at 415-555-0123";
        let result = r.redact(input);
        assert!(result.contains("[REDACTED:pii_phone]"));
        assert!(!result.contains("415-555-0123"));
    }

    #[test]
    fn test_redacts_credit_card() {
        let r = Redactor::new();
        let input = "Visa 4242 4242 4242 4242 should never upload";
        let result = r.redact(input);
        assert!(result.contains("[REDACTED:pii_credit_card]"));
    }

    #[test]
    fn test_skips_invalid_credit_card() {
        let r = Redactor::new();
        let input = "Reference 1234 5678 9012 3456 in docs";
        let result = r.redact(input);
        assert_eq!(result, input);
    }

    #[test]
    fn test_preserves_normal_text() {
        let r = Redactor::new();
        let input = "This is a normal code comment about implementing authentication";
        let result = r.redact(input);
        assert_eq!(result, input);
    }

    #[test]
    fn test_custom_pattern() {
        let mut r = Redactor::new();
        r.add_pattern("internal_id", r"INTERNAL-[A-Z0-9]{10}")
            .unwrap();
        let input = "Found record INTERNAL-ABC1234567 in database";
        let result = r.redact(input);
        assert!(result.contains("[REDACTED:internal_id]"));
    }
}
