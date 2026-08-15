//! Email structured response envelope — the `BackendResponse.payload` the
//! gateway projects onto `tools/call`. A non-null `downstreamError` slot is
//! the gateway's `is_error` signal (same contract as the other backends).

use serde_json::{Value, json};

/// Build a downstream-error object for the envelope's `downstreamError` slot.
pub fn email_downstream_error(kind: &str, message: &str, retryable: bool) -> Value {
    json!({
        "kind": kind,
        "code": format!("mcpg.downstream_email.{kind}"),
        "message": message,
        "retryable": retryable,
        "retryClass": if retryable { "with_backoff" } else { "do_not_retry" },
        "suggestedAction": if retryable { "check_mail_server_connectivity_and_retry" } else { "inspect_email_error" },
    })
}

/// Classify a failure string. Connect / timeout / dropped-connection failures
/// are retryable transport errors; login / address / protocol rejections are
/// caller/config problems and are not.
pub fn classify_error(message: &str) -> Value {
    let lower = message.to_ascii_lowercase();
    let retryable = lower.contains("connect")
        || lower.contains("timed out")
        || lower.contains("timeout")
        || lower.contains("handshake")
        || lower.contains("broken pipe")
        || lower.contains("connection reset")
        // A server still coming up can accept the TCP connection but cut the
        // protocol response short — treat the read-side failures as transient.
        || lower.contains("incomplete response")
        || lower.contains("response error")
        || lower.contains("connection closed")
        || lower.contains("unexpected eof");
    let kind = if retryable {
        "transport_error"
    } else {
        "email_error"
    };
    email_downstream_error(kind, message, retryable)
}

/// Build the email structured-content envelope.
#[allow(clippy::too_many_arguments)]
pub fn build_result_envelope(
    tool_name: &str,
    profile_name: &str,
    op: &str,
    host: &str,
    mailbox: &str,
    sent: Option<bool>,
    messages: Option<&[Value]>,
    duration_ms: u128,
    downstream_error: Option<&Value>,
    error: Option<&str>,
) -> Value {
    let response = if downstream_error.is_some() {
        Value::Null
    } else {
        json!({
            "sent": sent,
            "messages": messages,
            "count": messages.map(<[Value]>::len),
            "durationMs": duration_ms,
        })
    };
    json!({
        "toolName": tool_name,
        "profile": profile_name,
        "request": {
            "op": op,
            "host": host,
            "mailbox": mailbox,
        },
        "response": response,
        "downstreamError": downstream_error,
        "downstreamErrors": downstream_error
            .map(|d| vec![d.clone()])
            .unwrap_or_default(),
        "error": error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_failure_is_retryable_transport_error() {
        let e = classify_error("IMAP connect failed: connection refused");
        assert_eq!(e["kind"], json!("transport_error"));
        assert_eq!(e["retryable"], json!(true));
    }

    #[test]
    fn login_failure_is_not_retryable() {
        let e = classify_error("IMAP login failed: authentication failed");
        assert_eq!(e["kind"], json!("email_error"));
        assert_eq!(e["retryable"], json!(false));
    }

    #[test]
    fn send_envelope_shape() {
        let env = build_result_envelope(
            "mail.send",
            "mail.send",
            "send",
            "smtp.x",
            "",
            Some(true),
            None,
            12,
            None,
            None,
        );
        assert_eq!(env["response"]["sent"], json!(true));
        assert!(env["downstreamError"].is_null());
    }

    #[test]
    fn read_envelope_has_messages_and_count() {
        let msgs = vec![json!({ "subject": "hi" })];
        let env = build_result_envelope(
            "mail.read",
            "mail.read",
            "read",
            "imap.x",
            "INBOX",
            None,
            Some(&msgs),
            30,
            None,
            None,
        );
        assert_eq!(env["response"]["count"], json!(1));
        assert_eq!(env["response"]["messages"][0]["subject"], json!("hi"));
    }
}
