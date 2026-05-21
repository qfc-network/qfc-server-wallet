//! Local NDJSON audit log.
//!
//! One line per processed webhook. The log is append-only; rotation /
//! retention is the operator's problem (logrotate, journald, etc.).

use std::path::{Path, PathBuf};

use serde::Serialize;
use tokio::io::AsyncWriteExt;

/// Default audit-log path under the user's home (`~/.qfc-approver/audit.log`).
///
/// Returns `None` if the home directory can't be resolved.
#[must_use]
pub fn default_path() -> Option<PathBuf> {
    let home = dirs::home_dir()?;
    Some(home.join(".qfc-approver").join("audit.log"))
}

/// One audit record. Wider than strictly needed for forensics:
/// includes the request id, decision, the approver, signature hex (so
/// the operator can replay verification), and the server's response code.
#[derive(Clone, Debug, Serialize)]
pub struct AuditRecord {
    /// RFC 3339 timestamp at processing time.
    pub timestamp: String,
    /// `received`, `signed`, `posted`, `rejected`, `error`.
    pub event: &'static str,
    /// The signing-request ULID the webhook referenced.
    pub request_id: String,
    /// Approver acting (this client's ULID).
    pub approver_id: String,
    /// Hex-encoded SHA-256 message digest that was shown to the operator.
    pub message_hash_hex: String,
    /// `approve` / `reject` / `refused`.
    pub decision: String,
    /// Hex-encoded signature, if any.
    pub signature_hex: Option<String>,
    /// HTTP status from the server, if a POST was issued.
    pub server_status: Option<u16>,
    /// Free-form message (error reason, refusal reason).
    pub note: Option<String>,
}

impl AuditRecord {
    /// Format the current time as RFC 3339.
    #[must_use]
    pub fn now() -> String {
        let now = time::OffsetDateTime::now_utc();
        now.format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| String::from("1970-01-01T00:00:00Z"))
    }
}

/// Append one NDJSON record to `path`. Creates the parent directory if
/// it doesn't exist.
///
/// # Errors
///
/// Returns `io::Error` on filesystem failure or `serde_json::Error` on
/// encoding failure. We collapse both into an `io::Error` via
/// `into_io_error` so callers don't have to introduce a third error type
/// just for audit writes.
pub async fn append(path: &Path, record: &AuditRecord) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent).await?;
        }
    }
    let mut line = serde_json::to_vec(record).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("audit encode: {e}"),
        )
    })?;
    line.push(b'\n');
    let mut f = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await?;
    f.write_all(&line).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn writes_one_ndjson_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("audit.log");
        let rec = AuditRecord {
            timestamp: AuditRecord::now(),
            event: "signed",
            request_id: "01H".into(),
            approver_id: "01A".into(),
            message_hash_hex: "deadbeef".into(),
            decision: "approve".into(),
            signature_hex: Some("aa".into()),
            server_status: Some(200),
            note: None,
        };
        append(&path, &rec).await.unwrap();
        append(&path, &rec).await.unwrap();
        let contents = tokio::fs::read_to_string(&path).await.unwrap();
        assert_eq!(contents.lines().count(), 2);
        for line in contents.lines() {
            // each line is independently parseable JSON
            let _: serde_json::Value = serde_json::from_str(line).unwrap();
        }
    }
}
