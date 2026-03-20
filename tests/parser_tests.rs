use std::path::PathBuf;

// We need to reference the library code from tests.
// Since this is a binary crate, we'll use a process-based approach
// or restructure. For now, let's test via the binary output.

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn parse_fixture(name: &str) -> serde_json::Value {
    parse_fixture_with_provider(name, None)
}

fn parse_fixture_with_provider(name: &str, provider: Option<&str>) -> serde_json::Value {
    let path = fixture_path(name);
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_getdiff"));
    command.arg("parse");
    if let Some(provider) = provider {
        command.args(["--provider", provider]);
    }
    command.args(["--file", path.to_str().unwrap()]);

    let output = command.output().unwrap_or_else(|e| {
        panic!(
            "Failed to execute getdiff parse for {}: {}",
            path.display(),
            e
        )
    });

    assert!(
        output.status.success(),
        "getdiff parse failed for {}:\nstderr: {}",
        path.display(),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout)
        .unwrap_or_else(|e| panic!("Invalid UTF-8 output from {}: {}", path.display(), e));
    serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "Failed to parse JSON output from {}:\nerror: {}\nstdout: {}",
            path.display(),
            e,
            &stdout[..stdout.len().min(500)]
        )
    })
}

#[test]
fn test_codex_session_parses() {
    let session = parse_fixture_with_provider("codex-session.jsonl", Some("codex"));

    assert_eq!(
        session["session_id"],
        "019b96cb-4157-7e43-b99e-3f021198dbb0"
    );
    assert_eq!(session["tool"], "codex");
    assert_eq!(session["tool_version"], "0.79.0");
    assert_eq!(session["git_branch"], "prototype");
    assert_eq!(session["primary_model"], "gpt-5.2-codex");
}

#[test]
fn test_codex_tool_and_token_parsing() {
    let session = parse_fixture_with_provider("codex-session.jsonl", Some("codex"));

    assert_eq!(session["total_tool_calls"].as_u64(), Some(2));
    assert_eq!(session["total_input_tokens"].as_u64(), Some(4090));
    assert_eq!(session["total_output_tokens"].as_u64(), Some(49));
    assert_eq!(session["total_cache_read_tokens"].as_u64(), Some(3200));

    let tool_names: Vec<&str> = session["tool_calls"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["tool_name"].as_str().unwrap())
        .collect();
    assert!(tool_names.contains(&"Bash"));
    assert!(tool_names.contains(&"apply_patch"));
}

#[test]
fn test_codex_reliability_and_files() {
    let session = parse_fixture_with_provider("codex-session.jsonl", Some("codex"));

    let telemetry = &session["reliability_telemetry"];
    assert_eq!(telemetry["tool_success_count"].as_u64(), Some(2));
    assert_eq!(telemetry["tool_error_count"].as_u64(), Some(0));
    assert!(telemetry["avg_tool_latency_ms"].as_u64().unwrap_or(0) > 0);

    let modified = session["files_modified"].as_array().unwrap();
    assert!(modified.iter().any(|path| path == "src/app.ts"));

    let read = session["files_read"].as_array().unwrap();
    assert!(
        read.iter()
            .any(|path| path == "src" || path == "src/app.ts")
    );
}

#[test]
fn test_codex_skips_developer_harness_messages() {
    let session = parse_fixture_with_provider("codex-developer-only.jsonl", Some("codex"));

    assert_eq!(session["message_count"].as_u64(), Some(2));
    assert_eq!(session["user_message_count"].as_u64(), Some(2));
    assert_eq!(session["assistant_message_count"].as_u64(), Some(0));
}

#[test]
fn test_opencode_session_parses() {
    let session =
        parse_fixture_with_provider("opencode/storage/session/ses_test.json", Some("opencode"));

    assert_eq!(session["session_id"], "ses_test");
    assert_eq!(session["tool"], "opencode");
    assert_eq!(session["tool_version"], "1.2.15");
    assert_eq!(session["project_path"], "/Users/testuser/project");
    assert_eq!(session["primary_model"], "gpt-5.3-codex");
}

#[test]
fn test_opencode_tokens_tools_and_files() {
    let session =
        parse_fixture_with_provider("opencode/storage/session/ses_test.json", Some("opencode"));

    assert_eq!(session["total_input_tokens"].as_u64(), Some(120));
    assert_eq!(session["total_output_tokens"].as_u64(), Some(30));
    assert_eq!(session["total_cache_read_tokens"].as_u64(), Some(50));
    assert_eq!(session["total_cache_creation_tokens"].as_u64(), Some(5));
    assert_eq!(session["total_tool_calls"].as_u64(), Some(1));

    let modified = session["files_modified"].as_array().unwrap();
    let read = session["files_read"].as_array().unwrap();
    assert!(
        modified
            .iter()
            .any(|path| path == "/Users/testuser/project/src/app.ts")
    );
    assert!(
        read.iter()
            .any(|path| path == "/Users/testuser/project/src/app.ts")
    );

    let telemetry = &session["reliability_telemetry"];
    assert_eq!(telemetry["tool_success_count"].as_u64(), Some(1));
    assert!(telemetry["avg_tool_latency_ms"].as_u64().unwrap_or(0) > 0);

    let tool_results = session["messages"][1]["tool_results"].as_array().unwrap();
    assert_eq!(tool_results.len(), 1);
    assert_eq!(tool_results[0]["is_error"], false);
}

#[test]
fn test_opencode_exported_sample_parses() {
    let session = parse_fixture_with_provider("opencode-exported.txt", Some("opencode"));

    assert_eq!(session["session_id"], "ses_exported");
    assert_eq!(session["tool"], "opencode");
    assert_eq!(session["primary_model"], "gpt-5.3-codex");
    assert_eq!(session["total_tool_calls"].as_u64(), Some(1));
    assert_eq!(session["total_input_tokens"].as_u64(), Some(220));

    let modified = session["files_modified"].as_array().unwrap();
    let read = session["files_read"].as_array().unwrap();
    assert!(
        modified
            .iter()
            .any(|path| path == "/Users/testuser/exported/src/integrations.ts")
    );
    assert!(
        read.iter()
            .any(|path| path == "/Users/testuser/exported/src/integrations.ts")
    );
}

// -----------------------------------------------------------------------
// Session-level metadata tests
// -----------------------------------------------------------------------

#[test]
fn test_session_id_extracted() {
    let session = parse_fixture("test-session.jsonl");
    assert_eq!(session["session_id"], "test-session");
}

#[test]
fn test_tool_is_claude_code() {
    let session = parse_fixture("test-session.jsonl");
    assert_eq!(session["tool"], "claude_code");
}

#[test]
fn test_tool_version_extracted() {
    let session = parse_fixture("test-session.jsonl");
    assert_eq!(session["tool_version"], "2.1.63");
}

#[test]
fn test_git_branch_extracted() {
    let session = parse_fixture("test-session.jsonl");
    // Should pick up "feature/billing", not "HEAD"
    assert_eq!(session["git_branch"], "feature/billing");
}

#[test]
fn test_primary_model_extracted() {
    let session = parse_fixture("test-session.jsonl");
    assert_eq!(session["primary_model"], "claude-opus-4-6");
}

// -----------------------------------------------------------------------
// Timeline tests
// -----------------------------------------------------------------------

#[test]
fn test_timestamps_captured() {
    let session = parse_fixture("test-session.jsonl");
    // First non-system timestamp in a user/assistant message
    assert!(session["started_at"].as_str().is_some());
    assert!(session["ended_at"].as_str().is_some());
}

#[test]
fn test_duration_computed() {
    let session = parse_fixture("test-session.jsonl");
    // Session runs from 10:00:00 to 10:00:35 = 35 seconds
    let duration = session["duration_seconds"].as_u64().unwrap();
    assert_eq!(duration, 35);
}

// -----------------------------------------------------------------------
// Message counting tests
// -----------------------------------------------------------------------

#[test]
fn test_message_counts() {
    let session = parse_fixture("test-session.jsonl");
    // 5 user messages (including tool results that start with user content),
    // plus 1 user message with just text
    // 5 assistant messages
    // queue-operation, file-history-snapshot, progress are skipped
    let user_count = session["user_message_count"].as_u64().unwrap();
    let assistant_count = session["assistant_message_count"].as_u64().unwrap();

    // Fixture has: 6 user lines + 5 assistant lines = 11 total messages
    assert_eq!(user_count, 6, "Should have 6 user messages");
    assert_eq!(assistant_count, 5, "Should have 5 assistant messages");
    assert_eq!(
        session["message_count"].as_u64().unwrap(),
        11,
        "Total message count should be 11"
    );
}

#[test]
fn test_skips_non_conversation_lines() {
    let session = parse_fixture("test-session.jsonl");
    // queue-operation, file-history-snapshot, and progress lines should not become messages
    let messages = session["messages"].as_array().unwrap();
    for msg in messages {
        let role = msg["role"].as_str().unwrap();
        assert!(
            role == "user" || role == "assistant",
            "Unexpected role: {}",
            role
        );
    }
}

// -----------------------------------------------------------------------
// Tool call extraction tests
// -----------------------------------------------------------------------

#[test]
fn test_tool_calls_extracted() {
    let session = parse_fixture("test-session.jsonl");
    let total = session["total_tool_calls"].as_u64().unwrap();
    assert_eq!(
        total, 4,
        "Should have 4 tool calls: Read, Write, Bash, Edit"
    );
}

#[test]
fn test_tool_call_summary() {
    let session = parse_fixture("test-session.jsonl");
    let summaries = session["tool_calls"].as_array().unwrap();

    let names: Vec<&str> = summaries
        .iter()
        .map(|s| s["tool_name"].as_str().unwrap())
        .collect();

    assert!(names.contains(&"Read"), "Should have Read tool call");
    assert!(names.contains(&"Write"), "Should have Write tool call");
    assert!(names.contains(&"Bash"), "Should have Bash tool call");
    assert!(names.contains(&"Edit"), "Should have Edit tool call");
}

#[test]
fn test_reliability_telemetry_extracted() {
    let session = parse_fixture("test-session.jsonl");
    let telemetry = &session["reliability_telemetry"];

    assert_eq!(telemetry["tool_error_count"].as_u64(), Some(1));
    assert_eq!(telemetry["tool_success_count"].as_u64(), Some(3));
    assert!(telemetry["avg_tool_latency_ms"].as_u64().unwrap_or(0) > 0);
    assert!(telemetry["p95_tool_latency_ms"].as_u64().unwrap_or(0) > 0);
}

#[test]
fn test_sensitive_values_are_redacted_before_upload() {
    let session = parse_fixture("sensitive-session.jsonl");
    let messages = session["messages"].as_array().unwrap();

    let first_text = messages[0]["text"].as_str().unwrap();
    assert!(first_text.contains("[REDACTED:pii_email]"));
    assert!(first_text.contains("[REDACTED:secret_api_key]"));
    assert!(first_text.contains("[REDACTED:pii_credit_card]"));
    assert!(!first_text.contains("jane@example.com"));

    let second_text = messages[1]["text"].as_str().unwrap();
    assert!(second_text.contains("[REDACTED:pii_phone]"));
    assert!(second_text.contains("[REDACTED:secret_token_assignment]"));
}

#[test]
fn test_tool_input_summarized() {
    let session = parse_fixture("test-session.jsonl");
    let messages = session["messages"].as_array().unwrap();

    // Find the assistant message with the Read tool call
    let read_msg = messages.iter().find(|m| {
        m["tool_calls"]
            .as_array()
            .map(|tc| tc.iter().any(|t| t["tool_name"] == "Read"))
            .unwrap_or(false)
    });

    assert!(
        read_msg.is_some(),
        "Should find assistant message with Read tool"
    );
    let tc = &read_msg.unwrap()["tool_calls"].as_array().unwrap()[0];
    let summary = tc["input_summary"].as_str().unwrap();
    assert!(
        summary.contains("billing/index.ts"),
        "Read summary should contain file path, got: {}",
        summary
    );
}

// -----------------------------------------------------------------------
// File tracking tests
// -----------------------------------------------------------------------

#[test]
fn test_files_modified_tracked() {
    let session = parse_fixture("test-session.jsonl");
    let modified = session["files_modified"].as_array().unwrap();

    let paths: Vec<&str> = modified.iter().map(|p| p.as_str().unwrap()).collect();
    assert!(
        paths.iter().any(|p| p.contains("subscriptions.ts")),
        "Should track subscriptions.ts as modified (Write + Edit)"
    );
}

#[test]
fn test_files_read_tracked() {
    let session = parse_fixture("test-session.jsonl");
    let read = session["files_read"].as_array().unwrap();

    let paths: Vec<&str> = read.iter().map(|p| p.as_str().unwrap()).collect();
    assert!(
        paths.iter().any(|p| p.contains("billing/index.ts")),
        "Should track billing/index.ts as read"
    );
}

// -----------------------------------------------------------------------
// Token economics tests
// -----------------------------------------------------------------------

#[test]
fn test_token_totals() {
    let session = parse_fixture("test-session.jsonl");

    // Sum of all assistant message tokens:
    // input:  1500 + 2000 + 2500 + 3000 + 3200 = 12200
    // output: 200 + 350 + 150 + 250 + 100 = 1050
    // cache_read: 5000 + 6000 + 7000 + 8000 + 9000 = 35000
    // cache_creation: 800 + 200 + 100 + 50 + 0 = 1150
    assert_eq!(session["total_input_tokens"].as_u64().unwrap(), 12200);
    assert_eq!(session["total_output_tokens"].as_u64().unwrap(), 1050);
    assert_eq!(session["total_cache_read_tokens"].as_u64().unwrap(), 35000);
    assert_eq!(
        session["total_cache_creation_tokens"].as_u64().unwrap(),
        1150
    );
}

#[test]
fn test_cost_estimation() {
    let session = parse_fixture("test-session.jsonl");
    let cost = session["estimated_cost_usd"].as_f64().unwrap();
    // opus pricing: $15/M input + $75/M output
    // 12200 input tokens * $15/M = $0.183
    // 1050 output tokens * $75/M = $0.07875
    // Total ≈ $0.26
    assert!(cost > 0.0, "Cost should be positive");
    assert!(
        cost < 1.0,
        "Cost should be less than $1 for this small session"
    );
}

// -----------------------------------------------------------------------
// Thinking block handling
// -----------------------------------------------------------------------

#[test]
fn test_thinking_detected_but_not_captured() {
    let session = parse_fixture("test-session.jsonl");
    let messages = session["messages"].as_array().unwrap();

    // First assistant message has a thinking block
    let first_assistant = messages.iter().find(|m| m["role"] == "assistant").unwrap();
    assert_eq!(first_assistant["has_thinking"], true);

    // Thinking content should NOT appear in the text
    let text = first_assistant["text"].as_str().unwrap_or("");
    assert!(
        !text.contains("Let me plan"),
        "Thinking content should not be in text"
    );
}

// -----------------------------------------------------------------------
// Redaction tests
// -----------------------------------------------------------------------

#[test]
fn test_secrets_redacted_in_user_messages() {
    let session = parse_fixture("test-session.jsonl");
    let messages = session["messages"].as_array().unwrap();

    // Message msg-008 contains a GitHub token
    let msg_with_secret = messages.iter().find(|m| {
        m["text"]
            .as_str()
            .map(|t| t.contains("billing provider"))
            .unwrap_or(false)
    });

    assert!(
        msg_with_secret.is_some(),
        "Should find message with billing provider mention"
    );
    let text = msg_with_secret.unwrap()["text"].as_str().unwrap();
    assert!(
        text.contains("[REDACTED:"),
        "GitHub token should be redacted, got: {}",
        text
    );
    assert!(
        !text.contains("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        "Raw GitHub token should not appear"
    );
}

#[test]
fn test_secrets_redacted_in_tool_results() {
    let session = parse_fixture("test-session.jsonl");
    let messages = session["messages"].as_array().unwrap();

    // The tool result from the failing test contains "password = sk-ant-secret123abc"
    let msg_with_error = messages.iter().find(|m| {
        m["tool_results"]
            .as_array()
            .map(|results| results.iter().any(|r| r["is_error"] == true))
            .unwrap_or(false)
    });

    assert!(
        msg_with_error.is_some(),
        "Should find message with error tool result"
    );
    let error_result = &msg_with_error.unwrap()["tool_results"].as_array().unwrap()[0];
    let output = error_result["output_summary"].as_str().unwrap();
    assert!(
        !output.contains("sk-ant-secret123abc"),
        "Anthropic key should be redacted in tool output, got: {}",
        output
    );
}

// -----------------------------------------------------------------------
// Tool result error tracking
// -----------------------------------------------------------------------

#[test]
fn test_tool_result_errors_captured() {
    let session = parse_fixture("test-session.jsonl");
    let messages = session["messages"].as_array().unwrap();

    let empty = vec![];
    let error_results: Vec<_> = messages
        .iter()
        .flat_map(|m| m["tool_results"].as_array().unwrap_or(&empty).iter())
        .filter(|r| r["is_error"] == true)
        .collect();

    assert_eq!(
        error_results.len(),
        1,
        "Should have exactly 1 error tool result"
    );
}

// -----------------------------------------------------------------------
// Edge case: stop_reason tracking
// -----------------------------------------------------------------------

#[test]
fn test_stop_reasons_captured() {
    let session = parse_fixture("test-session.jsonl");
    let messages = session["messages"].as_array().unwrap();

    let assistant_msgs: Vec<_> = messages
        .iter()
        .filter(|m| m["role"] == "assistant")
        .collect();

    // Last assistant message should have stop_reason "end_turn"
    let last = assistant_msgs.last().unwrap();
    assert_eq!(last["stop_reason"], "end_turn");

    // Earlier ones should have "tool_use"
    let first = assistant_msgs.first().unwrap();
    assert_eq!(first["stop_reason"], "tool_use");
}

// -----------------------------------------------------------------------
// OpenClaw tests
// -----------------------------------------------------------------------

#[test]
fn test_openclaw_session_parses() {
    let session = parse_fixture_with_provider("openclaw-session.jsonl", Some("open-claw"));

    assert_eq!(
        session["session_id"],
        "437b8b06-a88e-47d0-8c95-51ddc15a919a"
    );
    assert_eq!(session["tool"], "openclaw");
    assert_eq!(session["project_path"], "/Users/testuser/project");
    assert_eq!(session["primary_model"], "claude-opus-4-6");
}

#[test]
fn test_openclaw_message_counts() {
    let session = parse_fixture_with_provider("openclaw-session.jsonl", Some("open-claw"));

    // 2 user text messages + 3 tool results = 5 user-role messages
    // 4 assistant messages (1 text-only intro, 3 with tool calls, 1 final text)
    assert_eq!(session["user_message_count"].as_u64(), Some(5));
    assert_eq!(session["assistant_message_count"].as_u64(), Some(5));
}

#[test]
fn test_openclaw_tool_calls() {
    let session = parse_fixture_with_provider("openclaw-session.jsonl", Some("open-claw"));

    // 3 tool calls: read, exec, exec
    assert_eq!(session["total_tool_calls"].as_u64(), Some(3));

    let tool_names: Vec<&str> = session["tool_calls"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["tool_name"].as_str().unwrap())
        .collect();
    assert!(tool_names.contains(&"read"));
    assert!(tool_names.contains(&"exec"));
}

#[test]
fn test_openclaw_tokens() {
    let session = parse_fixture_with_provider("openclaw-session.jsonl", Some("open-claw"));

    // Sum of all assistant usage.input: 3 + 3 + 1 + 1 + 1 = 9
    assert_eq!(session["total_input_tokens"].as_u64(), Some(9));
    // Sum of all assistant usage.output: 517 + 93 + 89 + 65 + 84 = 848
    assert_eq!(session["total_output_tokens"].as_u64(), Some(848));
    assert!(session["total_cache_read_tokens"].as_u64().unwrap() > 0);
    assert!(session["total_cache_creation_tokens"].as_u64().unwrap() > 0);
}

#[test]
fn test_openclaw_thinking_detected() {
    let session = parse_fixture_with_provider("openclaw-session.jsonl", Some("open-claw"));
    let messages = session["messages"].as_array().unwrap();

    let first_assistant = messages.iter().find(|m| m["role"] == "assistant").unwrap();
    assert_eq!(first_assistant["has_thinking"], true);

    // Thinking content should NOT appear in text
    let text = first_assistant["text"].as_str().unwrap_or("");
    assert!(!text.contains("Let me introduce"));
}

#[test]
fn test_openclaw_stop_reasons_normalized() {
    let session = parse_fixture_with_provider("openclaw-session.jsonl", Some("open-claw"));
    let messages = session["messages"].as_array().unwrap();

    let assistant_msgs: Vec<_> = messages
        .iter()
        .filter(|m| m["role"] == "assistant")
        .collect();

    // Last assistant message should have normalized stop reason
    let last = assistant_msgs.last().unwrap();
    assert_eq!(last["stop_reason"], "end_turn");

    // Tool use messages should have normalized stop reason
    let tool_msg = assistant_msgs
        .iter()
        .find(|m| !m["tool_calls"].as_array().unwrap().is_empty())
        .unwrap();
    assert_eq!(tool_msg["stop_reason"], "tool_use");
}

#[test]
fn test_openclaw_reliability_telemetry() {
    let session = parse_fixture_with_provider("openclaw-session.jsonl", Some("open-claw"));

    let telemetry = &session["reliability_telemetry"];
    assert_eq!(telemetry["tool_success_count"].as_u64(), Some(3));
    assert_eq!(telemetry["tool_error_count"].as_u64(), Some(0));
}

#[test]
fn test_openclaw_cost_estimated() {
    let session = parse_fixture_with_provider("openclaw-session.jsonl", Some("open-claw"));

    let cost = session["estimated_cost_usd"].as_f64().unwrap();
    assert!(cost > 0.0, "Cost should be positive");
}

#[test]
fn test_openclaw_files_tracked() {
    let session = parse_fixture_with_provider("openclaw-session.jsonl", Some("open-claw"));

    let read = session["files_read"].as_array().unwrap();
    assert!(
        read.iter()
            .any(|p| p.as_str().unwrap().contains("SKILL.md")),
        "Should track the read file"
    );
}

// -----------------------------------------------------------------------
// Cursor tests
// -----------------------------------------------------------------------

#[test]
fn test_cursor_session_parses() {
    let session = parse_fixture_with_provider("cursor-session.jsonl", Some("cursor"));

    assert_eq!(session["tool"], "cursor");
    // 2 user + 4 assistant = 6 messages
    assert_eq!(session["user_message_count"].as_u64(), Some(2));
    assert_eq!(session["assistant_message_count"].as_u64(), Some(4));
    assert_eq!(session["message_count"].as_u64(), Some(6));
}

#[test]
fn test_cursor_strips_user_query_wrapper() {
    let session = parse_fixture_with_provider("cursor-session.jsonl", Some("cursor"));
    let messages = session["messages"].as_array().unwrap();

    let first_user = messages.iter().find(|m| m["role"] == "user").unwrap();
    let text = first_user["text"].as_str().unwrap();
    assert!(
        !text.contains("<user_query>"),
        "Should strip user_query tags, got: {}",
        text
    );
    assert!(
        text.contains("weather"),
        "Should preserve user text content"
    );
}

#[test]
fn test_cursor_has_timestamps_from_file_metadata() {
    let session = parse_fixture_with_provider("cursor-session.jsonl", Some("cursor"));

    // File metadata provides started_at and ended_at
    assert!(
        session["started_at"].as_str().is_some(),
        "Should have started_at from file birthtime"
    );
    assert!(
        session["ended_at"].as_str().is_some(),
        "Should have ended_at from file mtime"
    );
}

#[test]
fn test_cursor_no_tool_calls() {
    let session = parse_fixture_with_provider("cursor-session.jsonl", Some("cursor"));

    // Cursor doesn't log tool calls in transcripts
    assert_eq!(session["total_tool_calls"].as_u64(), Some(0));
}

// -----------------------------------------------------------------------
// Copilot tests
// -----------------------------------------------------------------------

#[test]
fn test_copilot_session_parses() {
    let session = parse_fixture_with_provider("copilot-session.jsonl", Some("copilot"));

    assert_eq!(
        session["session_id"],
        "5a2d4e02-22d3-4097-ac60-94abc4814998"
    );
    assert_eq!(session["tool"], "copilot");
    assert_eq!(session["tool_version"], "1.0.9");
    assert_eq!(session["project_path"], "/Users/testuser/project");
    assert_eq!(session["primary_model"], "gpt-5-mini");
}

#[test]
fn test_copilot_message_counts() {
    let session = parse_fixture_with_provider("copilot-session.jsonl", Some("copilot"));

    // 2 real user messages + tool results (counted as user role)
    assert!(session["user_message_count"].as_u64().unwrap() >= 2);
    assert!(session["assistant_message_count"].as_u64().unwrap() >= 4);
    assert!(session["message_count"].as_u64().unwrap() > 4);
}

#[test]
fn test_copilot_tool_calls() {
    let session = parse_fixture_with_provider("copilot-session.jsonl", Some("copilot"));

    // Should have web_fetch, view, bash tool calls (report_intent filtered)
    assert!(session["total_tool_calls"].as_u64().unwrap() > 0);

    let tool_names: Vec<&str> = session["tool_calls"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["tool_name"].as_str().unwrap())
        .collect();
    assert!(
        !tool_names.contains(&"report_intent"),
        "report_intent should be filtered out"
    );
    assert!(
        tool_names.contains(&"web_fetch")
            || tool_names.contains(&"view")
            || tool_names.contains(&"bash")
    );
}

#[test]
fn test_copilot_timestamps() {
    let session = parse_fixture_with_provider("copilot-session.jsonl", Some("copilot"));

    assert!(session["started_at"].as_str().is_some());
    assert!(session["ended_at"].as_str().is_some());
    assert!(session["duration_seconds"].as_u64().unwrap() > 0);
}

#[test]
fn test_copilot_thinking_detected() {
    let session = parse_fixture_with_provider("copilot-session.jsonl", Some("copilot"));
    let messages = session["messages"].as_array().unwrap();

    let assistant_with_thinking = messages
        .iter()
        .find(|m| m["role"] == "assistant" && m["has_thinking"] == true);
    assert!(
        assistant_with_thinking.is_some(),
        "Should detect reasoning/thinking in assistant messages"
    );
}

#[test]
fn test_copilot_reliability_telemetry() {
    let session = parse_fixture_with_provider("copilot-session.jsonl", Some("copilot"));

    let telemetry = &session["reliability_telemetry"];
    assert!(telemetry["tool_success_count"].as_u64().unwrap() > 0);
    assert!(telemetry["avg_tool_latency_ms"].as_u64().is_some());
}

#[test]
fn test_copilot_files_tracked() {
    let session = parse_fixture_with_provider("copilot-session.jsonl", Some("copilot"));

    let read = session["files_read"].as_array().unwrap();
    assert!(
        read.iter().any(|p| {
            let s = p.as_str().unwrap();
            s.contains("README.md") || s.contains("testuser")
        }),
        "Should track viewed files"
    );
}

#[test]
fn test_copilot_tool_errors_tracked() {
    let session = parse_fixture_with_provider("copilot-session.jsonl", Some("copilot"));

    let telemetry = &session["reliability_telemetry"];
    // The fixture has one failed view (file too large)
    assert!(telemetry["tool_error_count"].as_u64().unwrap() >= 1);
}

// -----------------------------------------------------------------------
// Gemini CLI tests
// -----------------------------------------------------------------------

#[test]
fn test_gemenicli_session_parses() {
    let session = parse_fixture_with_provider("gemenicli-session.json", Some("gemini"));
    assert_eq!(
        session["session_id"],
        "c98fc85a-d855-420a-b5a2-7d6330a7f422"
    );
    assert_eq!(session["tool"], "gemenicli");
    assert_eq!(session["primary_model"], "gemini-3-flash-preview");
}

#[test]
fn test_gemenicli_message_counts() {
    let session = parse_fixture_with_provider("gemenicli-session.json", Some("gemini"));
    assert_eq!(session["user_message_count"].as_u64(), Some(2));
    assert_eq!(session["assistant_message_count"].as_u64(), Some(6));
}

#[test]
fn test_gemenicli_tool_calls() {
    let session = parse_fixture_with_provider("gemenicli-session.json", Some("gemini"));
    assert!(session["total_tool_calls"].as_u64().unwrap() >= 5);
    let tool_names: Vec<&str> = session["tool_calls"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["tool_name"].as_str().unwrap())
        .collect();
    assert!(tool_names.contains(&"google_web_search") || tool_names.contains(&"grep_search"));
}

#[test]
fn test_gemenicli_tokens() {
    let session = parse_fixture_with_provider("gemenicli-session.json", Some("gemini"));
    assert!(session["total_input_tokens"].as_u64().unwrap() > 0);
    assert!(session["total_output_tokens"].as_u64().unwrap() > 0);
    assert!(session["total_cache_read_tokens"].as_u64().unwrap() > 0);
}

#[test]
fn test_gemenicli_thinking_detected() {
    let session = parse_fixture_with_provider("gemenicli-session.json", Some("gemini"));
    let messages = session["messages"].as_array().unwrap();
    let has_thinking = messages.iter().any(|m| m["has_thinking"] == true);
    assert!(has_thinking, "Should detect thinking in gemini messages");
}

#[test]
fn test_gemenicli_timestamps() {
    let session = parse_fixture_with_provider("gemenicli-session.json", Some("gemini"));
    assert!(session["started_at"].as_str().is_some());
    assert!(session["ended_at"].as_str().is_some());
    assert!(session["duration_seconds"].as_u64().unwrap() > 0);
}

#[test]
fn test_gemenicli_files_tracked() {
    let session = parse_fixture_with_provider("gemenicli-session.json", Some("gemini"));
    let read = session["files_read"].as_array().unwrap();
    let modified = session["files_modified"].as_array().unwrap();
    assert!(
        read.iter()
            .any(|p| p.as_str().unwrap().contains("README.md"))
    );
    assert!(
        modified
            .iter()
            .any(|p| p.as_str().unwrap().contains("README.md"))
    );
}

#[test]
fn test_gemenicli_reliability() {
    let session = parse_fixture_with_provider("gemenicli-session.json", Some("gemini"));
    let telemetry = &session["reliability_telemetry"];
    assert!(telemetry["tool_success_count"].as_u64().unwrap() >= 5);
}
