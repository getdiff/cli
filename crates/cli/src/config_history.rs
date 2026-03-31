use anyhow::Result;
use std::collections::HashMap;
use std::path::Path;

use crate::types::ConfigSnapshotPayload;

pub fn annotate_snapshot_change(
    diff_dir: &Path,
    project_path: &str,
    snapshot: &mut ConfigSnapshotPayload,
) -> Result<()> {
    let current_fingerprint = snapshot
        .snapshot()
        .get("config_fingerprint")
        .and_then(|value| value.as_str())
        .map(ToString::to_string);

    let Some(current_fingerprint) = current_fingerprint else {
        ensure_snapshot_object(snapshot)?;
        if let Some(obj) = snapshot.snapshot_object_mut() {
            obj.insert("config_changed".to_string(), serde_json::Value::Bool(false));
        }
        return Ok(());
    };

    let mut history = read_history(diff_dir)?;
    let previous = history.get(project_path).cloned();
    let changed = previous
        .as_ref()
        .map(|prior| prior != &current_fingerprint)
        .unwrap_or(false);

    ensure_snapshot_object(snapshot)?;
    if let Some(obj) = snapshot.snapshot_object_mut() {
        obj.insert(
            "config_changed".to_string(),
            serde_json::Value::Bool(changed),
        );
        if let Some(prior) = previous {
            obj.insert(
                "previous_config_fingerprint".to_string(),
                serde_json::Value::String(prior),
            );
        }
    }

    history.insert(project_path.to_string(), current_fingerprint);
    write_history(diff_dir, &history)
}

fn history_path(diff_dir: &Path) -> std::path::PathBuf {
    diff_dir.join("config-fingerprints.json")
}

fn read_history(diff_dir: &Path) -> Result<HashMap<String, String>> {
    let path = history_path(diff_dir);
    if !path.exists() {
        return Ok(HashMap::new());
    }

    let content = std::fs::read_to_string(path)?;
    match serde_json::from_str::<HashMap<String, String>>(&content) {
        Ok(parsed) => Ok(parsed),
        Err(error) => {
            eprintln!(
                "Warning: malformed config fingerprint history, starting fresh: {}",
                error
            );
            Ok(HashMap::new())
        }
    }
}

fn write_history(diff_dir: &Path, history: &HashMap<String, String>) -> Result<()> {
    std::fs::create_dir_all(diff_dir)?;
    let path = history_path(diff_dir);
    std::fs::write(path, serde_json::to_string_pretty(history)?)?;
    Ok(())
}

fn ensure_snapshot_object(snapshot: &ConfigSnapshotPayload) -> Result<()> {
    if snapshot.snapshot().as_object().is_none() {
        anyhow::bail!("config snapshot payload must be a JSON object");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::annotate_snapshot_change;
    use crate::types::ConfigSnapshotPayload;

    #[test]
    fn marks_first_snapshot_as_unchanged() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let mut snapshot = ConfigSnapshotPayload::from_redacted(
            "claude",
            serde_json::json!({
                "config_fingerprint": "sha256:first"
            }),
        )
        .expect("valid redacted snapshot");

        annotate_snapshot_change(temp.path(), "/tmp/repo", &mut snapshot)
            .expect("annotate snapshot");

        assert_eq!(snapshot.snapshot()["config_changed"], false);
    }

    #[test]
    fn marks_later_snapshot_as_changed_when_fingerprint_differs() {
        let temp = tempfile::TempDir::new().expect("temp dir");

        let mut first = ConfigSnapshotPayload::from_redacted(
            "claude",
            serde_json::json!({
                "config_fingerprint": "sha256:first"
            }),
        )
        .expect("valid redacted snapshot");
        annotate_snapshot_change(temp.path(), "/tmp/repo", &mut first).expect("annotate first");

        let mut second = ConfigSnapshotPayload::from_redacted(
            "claude",
            serde_json::json!({
                "config_fingerprint": "sha256:second"
            }),
        )
        .expect("valid redacted snapshot");
        annotate_snapshot_change(temp.path(), "/tmp/repo", &mut second).expect("annotate second");

        assert_eq!(second.snapshot()["config_changed"], true);
        assert_eq!(
            second.snapshot()["previous_config_fingerprint"],
            "sha256:first"
        );
    }

    #[test]
    fn ignores_malformed_history_file() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        std::fs::create_dir_all(temp.path()).expect("create diff dir");
        std::fs::write(temp.path().join("config-fingerprints.json"), "{not-json")
            .expect("write malformed history");

        let mut snapshot = ConfigSnapshotPayload::from_redacted(
            "claude",
            serde_json::json!({
                "config_fingerprint": "sha256:first"
            }),
        )
        .expect("valid redacted snapshot");

        annotate_snapshot_change(temp.path(), "/tmp/repo", &mut snapshot)
            .expect("annotate snapshot");

        assert_eq!(snapshot.snapshot()["config_changed"], false);
    }
}
