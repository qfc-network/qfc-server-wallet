//! Interactive stdin prompt for human-in-the-loop approvals.
//!
//! Used when the binary is started with `--interactive`. Each incoming
//! webhook is summarized to stdout; the operator types `y` (approve),
//! `n` (reject), or anything else (refuse to sign — neither approve nor
//! reject, just drop).

use crate::processor::Decision;

/// One human prompt. Returns the operator's choice.
///
/// Reads exactly one line from stdin. EOF / read error is treated as
/// "refuse" — fail-closed.
pub async fn prompt_for_decision(summary: &str) -> Decision {
    use tokio::io::{AsyncBufReadExt, BufReader};

    eprintln!();
    eprintln!("=== QFC approval request ===");
    eprintln!("{summary}");
    eprintln!("Approve? [y]es / [n]o (reject) / anything else = refuse: ");

    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();
    match reader.read_line(&mut line).await {
        Ok(0) | Err(_) => Decision::Refuse,
        Ok(_) => match line.trim().to_ascii_lowercase().as_str() {
            "y" | "yes" | "approve" => Decision::Approve,
            "n" | "no" | "reject" => Decision::Reject,
            _ => Decision::Refuse,
        },
    }
}
