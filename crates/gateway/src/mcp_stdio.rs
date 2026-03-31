//! stdio MCP wrapper for policy-enforced MCP server communication.
//!
//! Sits between an agent and an MCP server's stdin/stdout, parsing each
//! JSON-RPC message in the stream and applying policy evaluation before
//! forwarding allowed messages.
//!
//! Usage:
//!   gateway-mcp-wrap --config gateway.yaml --provider mcp-db -- sqlite-mcp /path/to/db
//!
//! The wrapper:
//! 1. Spawns the MCP server process with the given command + args
//! 2. Reads JSON-RPC messages from its own stdin (one per line, from the agent)
//! 3. Parses using the `jsonrpc` body format adapter
//! 4. Evaluates against the provider's policy
//! 5. Forwards allowed messages to the MCP server's stdin
//! 6. Relays responses back from the MCP server's stdout to its own stdout

use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use std::process::{Child, Command, Stdio};

use crate::adapter::generic::{AdapterConfig, GenericAdapter};
use crate::adapter::ProviderAdapter;
use crate::config::PolicyConfig;
use crate::policy::PolicyEvaluator;

/// Configuration for an MCP stdio wrapper session.
pub struct McpWrapConfig {
    /// Provider name (for logging and policy lookup).
    pub provider_name: String,
    /// MCP server command to spawn.
    pub command: String,
    /// Arguments for the MCP server command.
    pub args: Vec<String>,
    /// Policy to enforce on JSON-RPC messages.
    pub policy: PolicyConfig,
    /// Optional adapter config for operation mapping.
    pub adapter_config: Option<AdapterConfig>,
    /// When true, blocked messages are forwarded with logging instead of rejected.
    pub learning_mode: bool,
}

/// Result of evaluating a single JSON-RPC message against policy.
#[derive(Debug, Clone)]
pub struct WrapDecision {
    /// Whether the message was forwarded.
    pub forwarded: bool,
    /// The operation that was extracted.
    pub operation: String,
    /// Human-readable reason for the decision.
    pub reason: String,
    /// The original JSON-RPC message (for logging).
    pub raw_line: String,
}

/// Parse a JSON-RPC line and evaluate it against the given policy.
/// Returns (operation_name, policy_decision, parsed_parameters).
pub fn evaluate_jsonrpc_line(
    line: &str,
    adapter: &GenericAdapter,
    evaluator: &PolicyEvaluator,
) -> (String, crate::policy::Decision, HashMap<String, serde_json::Value>) {
    let parsed = adapter.parse_request("POST", "/", line.as_bytes());
    let decision = evaluator.evaluate("POST", "/", &parsed.operation, &parsed.parameters);
    (parsed.operation, decision, parsed.parameters)
}

/// Build a JSON-RPC error response for a blocked request.
pub fn jsonrpc_error_response(line: &str, reason: &str) -> Option<String> {
    // Extract the "id" from the request so the agent gets a proper error.
    let obj: serde_json::Value = serde_json::from_str(line).ok()?;
    let id = obj.get("id")?;

    let error = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32600,
            "message": format!("blocked by policy: {}", reason)
        }
    });

    Some(error.to_string())
}

/// Run the MCP stdio wrapper. Blocks until the agent closes stdin or the
/// MCP server process exits.
///
/// Returns the number of messages forwarded and blocked.
pub fn run_mcp_wrap(config: McpWrapConfig) -> io::Result<(usize, usize)> {
    // Build adapter and evaluator.
    let adapter_config = config.adapter_config.unwrap_or(AdapterConfig {
        body_format: "jsonrpc".to_string(),
        ..Default::default()
    });
    let adapter = GenericAdapter::new(&config.provider_name, adapter_config);
    let evaluator = PolicyEvaluator::new(config.policy);

    // Spawn the MCP server process.
    let mut child = spawn_mcp_server(&config.command, &config.args)?;

    let child_stdin = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "failed to capture child stdin"))?;
    let child_stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "failed to capture child stdout"))?;

    // Spawn a thread to relay MCP server stdout → our stdout.
    let relay_handle = std::thread::spawn(move || {
        let reader = io::BufReader::new(child_stdout);
        let stdout = io::stdout();
        let mut stdout = stdout.lock();
        for line in reader.lines() {
            match line {
                Ok(l) => {
                    let _ = writeln!(stdout, "{}", l);
                    let _ = stdout.flush();
                }
                Err(_) => break,
            }
        }
    });

    // Process agent stdin → policy check → MCP server stdin.
    let mut child_stdin = io::BufWriter::new(child_stdin);
    let stdin = io::stdin();
    let stdin = stdin.lock();

    let mut forwarded = 0usize;
    let mut blocked = 0usize;

    for line in stdin.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };

        if line.trim().is_empty() {
            continue;
        }

        let (operation, decision, _params) = evaluate_jsonrpc_line(&line, &adapter, &evaluator);

        if decision.allowed || config.learning_mode {
            // Forward to MCP server.
            writeln!(child_stdin, "{}", line)?;
            child_stdin.flush()?;
            forwarded += 1;

            if !decision.allowed {
                eprintln!(
                    "[mcp-wrap] learning mode: forwarded blocked {} ({})",
                    operation, decision.reason
                );
            }
        } else {
            // Blocked — send error response back to agent.
            blocked += 1;
            eprintln!(
                "[mcp-wrap] blocked {} ({})",
                operation, decision.reason
            );

            if let Some(error_resp) = jsonrpc_error_response(&line, &decision.reason) {
                let stdout = io::stdout();
                let mut stdout = stdout.lock();
                let _ = writeln!(stdout, "{}", error_resp);
                let _ = stdout.flush();
            }
        }
    }

    // Agent closed stdin — close child's stdin to signal EOF.
    drop(child_stdin);

    // Wait for relay thread and child process.
    let _ = relay_handle.join();
    let _ = child.wait();

    Ok((forwarded, blocked))
}

fn spawn_mcp_server(command: &str, args: &[String]) -> io::Result<Child> {
    Command::new(command)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit()) // Pass through MCP server's stderr.
        .spawn()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_adapter() -> GenericAdapter {
        GenericAdapter::new(
            "test-mcp",
            AdapterConfig {
                body_format: "jsonrpc".to_string(),
                ..Default::default()
            },
        )
    }

    #[test]
    fn test_evaluate_tools_call_allowed() {
        let adapter = make_adapter();
        let evaluator = PolicyEvaluator::new(PolicyConfig::default()); // allow all

        let line = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 1,
            "params": {
                "name": "query_database",
                "arguments": {"sql": "SELECT 1"}
            }
        })
        .to_string();

        let (op, decision, _params) = evaluate_jsonrpc_line(&line, &adapter, &evaluator);
        assert_eq!(op, "query_database");
        assert!(decision.allowed);
    }

    #[test]
    fn test_evaluate_tools_call_blocked() {
        let adapter = make_adapter();
        let evaluator = PolicyEvaluator::new(PolicyConfig {
            blocked_operations: vec!["drop_table".to_string()],
            ..Default::default()
        });

        let line = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 2,
            "params": {
                "name": "drop_table",
                "arguments": {"table": "users"}
            }
        })
        .to_string();

        let (op, decision, _params) = evaluate_jsonrpc_line(&line, &adapter, &evaluator);
        assert_eq!(op, "drop_table");
        assert!(!decision.allowed);
    }

    #[test]
    fn test_evaluate_allowed_operations_whitelist() {
        let adapter = make_adapter();
        let evaluator = PolicyEvaluator::new(PolicyConfig {
            allowed_operations: vec!["query_database".to_string(), "list_tables".to_string()],
            ..Default::default()
        });

        // Allowed operation.
        let line = serde_json::json!({
            "jsonrpc": "2.0", "method": "tools/call", "id": 1,
            "params": { "name": "query_database", "arguments": {} }
        })
        .to_string();
        let (_, decision, _) = evaluate_jsonrpc_line(&line, &adapter, &evaluator);
        assert!(decision.allowed);

        // Not in allowed list.
        let line = serde_json::json!({
            "jsonrpc": "2.0", "method": "tools/call", "id": 2,
            "params": { "name": "delete_record", "arguments": {} }
        })
        .to_string();
        let (_, decision, _) = evaluate_jsonrpc_line(&line, &adapter, &evaluator);
        assert!(!decision.allowed);
    }

    #[test]
    fn test_jsonrpc_error_response() {
        let line = r#"{"jsonrpc":"2.0","method":"tools/call","id":42,"params":{"name":"drop_table","arguments":{}}}"#;
        let resp = jsonrpc_error_response(line, "operation is blocked").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&resp).unwrap();

        assert_eq!(parsed["jsonrpc"], "2.0");
        assert_eq!(parsed["id"], 42);
        assert_eq!(parsed["error"]["code"], -32600);
        assert!(parsed["error"]["message"]
            .as_str()
            .unwrap()
            .contains("blocked by policy"));
    }

    #[test]
    fn test_jsonrpc_error_response_no_id() {
        // Notifications have no "id" — should return None.
        let line = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        assert!(jsonrpc_error_response(line, "test").is_none());
    }

    #[test]
    fn test_jsonrpc_error_response_string_id() {
        let line = r#"{"jsonrpc":"2.0","method":"tools/call","id":"req-1","params":{"name":"test","arguments":{}}}"#;
        let resp = jsonrpc_error_response(line, "blocked").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(parsed["id"], "req-1");
    }

    #[test]
    fn test_evaluate_non_tools_call() {
        let adapter = make_adapter();
        let evaluator = PolicyEvaluator::new(PolicyConfig {
            allowed_operations: vec!["resources/read".to_string()],
            ..Default::default()
        });

        let line = serde_json::json!({
            "jsonrpc": "2.0", "method": "resources/read", "id": 1,
            "params": { "uri": "file:///tmp/data.csv" }
        })
        .to_string();

        let (op, decision, _) = evaluate_jsonrpc_line(&line, &adapter, &evaluator);
        assert_eq!(op, "resources/read");
        assert!(decision.allowed);
    }

    #[test]
    fn test_evaluate_empty_line() {
        let adapter = make_adapter();
        let evaluator = PolicyEvaluator::new(PolicyConfig::default());

        let (op, decision, _) = evaluate_jsonrpc_line("", &adapter, &evaluator);
        assert_eq!(op, "unknown");
        assert!(decision.allowed); // default allow
    }
}
