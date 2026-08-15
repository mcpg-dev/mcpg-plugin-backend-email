//! Operator-facing spec for the Email backend plugin.
//!
//! One binding = one operation = one MCP tool (or resource). `op: send`
//! delivers mail over SMTP (the message built from the call arguments); `op:
//! read` fetches recent messages from a mailbox over IMAP.

use serde::Deserialize;

/// The email operation a binding performs.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum EmailOp {
    /// Send a message over SMTP. `to` / `subject` / `body` come from the call
    /// arguments.
    #[default]
    Send,
    /// Read recent messages from a mailbox over IMAP.
    Read,
}

impl EmailOp {
    pub fn as_str(self) -> &'static str {
        match self {
            EmailOp::Send => "send",
            EmailOp::Read => "read",
        }
    }
}

/// Transport security.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum TlsMode {
    /// No TLS (plaintext). Trusted networks / dev only.
    None,
    /// STARTTLS upgrade on the plaintext port (SMTP only).
    Starttls,
    /// Implicit TLS for the whole connection (SMTP 465 / IMAPS 993).
    #[default]
    Implicit,
}

impl TlsMode {
    pub fn as_str(self) -> &'static str {
        match self {
            TlsMode::None => "none",
            TlsMode::Starttls => "starttls",
            TlsMode::Implicit => "implicit",
        }
    }
}

/// Operator-facing spec the gateway serializes when calling
/// `register_profile`. Mirrors `EmailBackendConfig` in the gateway crate.
// NOTE: intentionally NOT #[serde(deny_unknown_fields)] — the gateway injects
// the reserved `__mcpg_secret_refs` hint key into this spec at register_profile
// (secret-rotation scoping); denying unknown fields would reject it. The
// operator-facing schema is closed on the gateway-side *BackendConfig instead.
#[derive(Debug, Clone, Deserialize)]
pub struct EmailBackendSpec {
    /// The operation (default `send`).
    #[serde(default)]
    pub op: EmailOp,

    /// SMTP (send) or IMAP (read) host. Operator-configured.
    pub host: String,

    /// Server port (e.g. 587 STARTTLS / 465 implicit for SMTP; 993 IMAPS /
    /// 143 plaintext for IMAP).
    pub port: u16,

    /// Transport security (default `implicit`).
    #[serde(default)]
    pub tls: TlsMode,

    /// Login user. Required for `read` (IMAP login). Optional for `send`
    /// (omit for an unauthenticated relay).
    #[serde(default)]
    pub username: String,

    /// Login password — a literal, or `${env.X}` / `vault://…` resolved at
    /// config load. Per-caller `cred://` is not supported.
    #[serde(default)]
    pub password: String,

    /// `From` address for `send` (required for `send`).
    #[serde(default)]
    pub from: Option<String>,

    /// Mailbox to read (default `INBOX`). `read` only.
    #[serde(default = "default_mailbox")]
    pub mailbox: String,

    /// Max recent messages to return (default 10). `read` only.
    #[serde(default = "default_limit")]
    pub limit: usize,

    /// Per-call timeout (ms) for connect + the operation (default 15 s).
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_mailbox() -> String {
    "INBOX".into()
}
fn default_limit() -> usize {
    10
}
fn default_timeout_ms() -> u64 {
    15_000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn op_defaults_to_send() {
        assert_eq!(EmailOp::default(), EmailOp::Send);
    }

    #[test]
    fn tls_defaults_to_implicit() {
        assert_eq!(TlsMode::default(), TlsMode::Implicit);
    }

    #[test]
    fn send_spec_applies_defaults() {
        let spec: EmailBackendSpec = serde_json::from_value(serde_json::json!({
            "host": "smtp.example.com",
            "port": 587,
            "tls": "starttls",
            "username": "svc",
            "password": "${env.SMTP_PW}",
            "from": "noreply@example.com",
        }))
        .unwrap();
        assert_eq!(spec.op, EmailOp::Send);
        assert_eq!(spec.tls, TlsMode::Starttls);
        assert_eq!(spec.mailbox, "INBOX");
        assert_eq!(spec.limit, 10);
        assert_eq!(spec.timeout_ms, 15_000);
    }

    #[test]
    fn parses_read_spec() {
        let spec: EmailBackendSpec = serde_json::from_value(serde_json::json!({
            "op": "read",
            "host": "imap.example.com",
            "port": 993,
            "username": "svc",
            "password": "p",
            "mailbox": "Archive",
            "limit": 5,
        }))
        .unwrap();
        assert_eq!(spec.op, EmailOp::Read);
        assert_eq!(spec.mailbox, "Archive");
        assert_eq!(spec.limit, 5);
    }
}
