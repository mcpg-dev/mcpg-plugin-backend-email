//! Email backend binding plugin for mcpg.
//!
//! Implements [`EmailBackendPlugin`] — `BackendPlugin` for `kind: "email"`.
//! `op: send` delivers a message over SMTP (built from the call arguments —
//! `to` / `subject` / `body`); `op: read` fetches recent messages from a
//! mailbox over IMAP. Structurally mirrors the soap/ldap/mssql/amqp backends;
//! protocol machinery lives in [`email`] + [`envelope`].

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use mcpg_plugin_protocol::audit::{AuditEvent, AuditOutcome};
use mcpg_plugin_protocol::types::PluginIdentity;
use mcpg_plugin_protocol::{
    BackendError, BackendHost, BackendPlugin, BackendRequest, BackendResponse, PluginManifest,
    firstparty_manifest,
};
use mcpg_plugin_sdk::HostHandle;
use serde_json::{Value, json};
use tokio::sync::RwLock;
use tracing::debug;

/// cdylib sync bridge.
pub mod cdylib;
mod email;
mod envelope;
mod types;

use envelope::{build_result_envelope, classify_error};
pub use types::{EmailBackendSpec, EmailOp, TlsMode};

/// Embedded plugin descriptor.
pub const BINDING_DESCRIPTOR_YAML: &str = include_str!("../plugin.yaml");

// --------------------------------------------------------------------- obs

fn audit_action_for_outcome(label: &str) -> Option<&'static str> {
    match label {
        "timeout" => Some("dev.mcpg.backend.email.request_timeout"),
        "transport_error" => Some("dev.mcpg.backend.email.request_failed"),
        "email_error" => Some("dev.mcpg.backend.email.operation_rejected"),
        "invalid_spec" => Some("dev.mcpg.backend.email.request_failed"),
        _ => None,
    }
}

fn rfc3339_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn synthetic_system_identity() -> PluginIdentity {
    PluginIdentity {
        kind: "system".into(),
        trust_level: "verified".into(),
        subject_id: Some("dev.mcpg.backend.email".into()),
        auth_provider: None,
        issuer: None,
        roles: vec![],
        groups: vec![],
        scopes: vec![],
        attributes: Default::default(),
    }
}

fn finalize_payload(envelope: Value) -> Result<BackendResponse, BackendError> {
    let payload = serde_json::to_vec(&envelope).map_err(|e| BackendError::Transport {
        message: format!("Email plugin envelope serialization failed: {e}"),
    })?;
    Ok(BackendResponse {
        payload,
        truncated: false,
    })
}

// ------------------------------------------------------------------ plugin

/// Per-binding email runtime. Cheap to clone; no persistent connection (SMTP /
/// IMAP connect per call).
#[derive(Clone)]
struct EmailProfile {
    op: EmailOp,
    host: String,
    port: u16,
    tls: TlsMode,
    username: String,
    password: String,
    from: String,
    mailbox: String,
    limit: usize,
    timeout: Duration,
}

/// `BackendPlugin` implementation for `kind: "email"`.
pub struct EmailBackendPlugin {
    manifest: PluginManifest,
    profiles: RwLock<BTreeMap<String, EmailProfile>>,
    host_handle: OnceLock<HostHandle>,
}

impl Default for EmailBackendPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl EmailBackendPlugin {
    #[must_use]
    pub fn new() -> Self {
        Self {
            manifest: firstparty_manifest! {
                id: "dev.mcpg.backend.email",
                name: "Email Binding",
                class: Backend,
            },
            profiles: RwLock::new(BTreeMap::new()),
            host_handle: OnceLock::new(),
        }
    }

    pub fn set_host_handle(&self, host: HostHandle) -> bool {
        self.host_handle.set(host).is_ok()
    }

    fn host_handle(&self) -> Option<&HostHandle> {
        self.host_handle.get()
    }

    async fn emit_host_observability(
        &self,
        backend_name: &str,
        outcome_label: &'static str,
        reason: Option<&str>,
        identity: Option<&PluginIdentity>,
        request_id: &str,
        duration: Duration,
    ) {
        let Some(host) = self.host_handle() else {
            return;
        };
        host.histogram(
            "mcpg_email_backend_latency_seconds",
            duration.as_secs_f64(),
            &[("outcome", outcome_label)],
        );
        host.counter(
            "mcpg_email_backend_calls_total",
            1,
            &[("outcome", outcome_label)],
        );
        if let Some(action) = audit_action_for_outcome(outcome_label) {
            let actor = identity.cloned().unwrap_or_else(synthetic_system_identity);
            let mut details = json!({
                "backend": backend_name,
                "duration_ms": duration.as_millis() as u64,
                "outcome": outcome_label,
                "alias": host.alias(),
            });
            if let Some(reason) = reason {
                details
                    .as_object_mut()
                    .expect("json object")
                    .insert("reason".into(), Value::String(reason.to_owned()));
            }
            let event = AuditEvent {
                event_id: format!("email-{}-{}", request_id, duration.as_nanos()),
                occurred_at: rfc3339_now(),
                actor,
                action: action.to_owned(),
                resource: Some(format!("email-binding://{backend_name}")),
                outcome: AuditOutcome::Failure,
                request_id: Some(request_id.to_owned()),
                node_id: None,
                details,
                prev_event_hash: None,
            };
            let host_for_audit = host.clone();
            if let Err(join_err) = tokio::task::spawn_blocking(move || {
                let _ = host_for_audit.audit_event(event);
            })
            .await
            {
                debug!(target: "mcpg::email::host_handle", error = %join_err, "audit spawn_blocking failed");
            }
        }
    }
}

impl std::fmt::Debug for EmailBackendPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailBackendPlugin")
            .field("id", &self.manifest.id)
            .finish()
    }
}

#[async_trait]
impl BackendPlugin for EmailBackendPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn kind(&self) -> &str {
        "email"
    }

    async fn register_profile(
        &self,
        backend_name: &str,
        spec: &Value,
        _host: Arc<dyn BackendHost>,
    ) -> Result<(), BackendError> {
        let parsed: EmailBackendSpec =
            serde_json::from_value(spec.clone()).map_err(|e| BackendError::InvalidSpec {
                message: format!("Email binding spec: {e}"),
            })?;

        let invalid = |m: String| BackendError::InvalidSpec { message: m };
        if parsed.host.trim().is_empty() {
            return Err(invalid("host must not be empty".into()));
        }
        if parsed.port == 0 {
            return Err(invalid("port must be greater than 0".into()));
        }
        if parsed.timeout_ms == 0 {
            return Err(invalid("timeout_ms must be greater than 0".into()));
        }
        if parsed.password.starts_with("cred://") {
            return Err(invalid(
                "password must not be a cred:// URI — per-caller credentials are unsupported; \
                 use ${env.X} / vault:// (resolved at config load)"
                    .into(),
            ));
        }
        // `host` is a transport-only connection fact (declared in the
        // manifest `backend_profile.transport_only_fields`); a per-caller
        // `cred://` ref must never land there. Rejected here so the plugin
        // is the single source of truth for the policy.
        if parsed.host.trim_start().starts_with("cred://") {
            return Err(invalid(
                "host is a transport-only field and must not be a cred:// URI".into(),
            ));
        }
        let from = match parsed.op {
            EmailOp::Send => {
                let from = parsed.from.clone().unwrap_or_default();
                if from.trim().is_empty() {
                    return Err(invalid("op 'send' requires a 'from' address".into()));
                }
                from
            }
            EmailOp::Read => {
                if parsed.username.trim().is_empty() {
                    return Err(invalid("op 'read' requires a username (IMAP login)".into()));
                }
                if parsed.tls == TlsMode::Starttls {
                    return Err(invalid(
                        "op 'read' does not support tls 'starttls' in v1 — use 'implicit' or 'none'"
                            .into(),
                    ));
                }
                String::new()
            }
        };

        if parsed.tls == TlsMode::None {
            tracing::warn!(
                backend = %backend_name,
                "email: tls=none — SMTP AUTH / IMAP LOGIN credentials and message \
                 content travel in cleartext. Use 'implicit' or 'starttls' unless \
                 on a trusted network."
            );
        }

        debug!(
            backend = %backend_name,
            op = parsed.op.as_str(),
            host = %parsed.host,
            tls = parsed.tls.as_str(),
            "registered email binding profile"
        );

        self.profiles.write().await.insert(
            backend_name.to_owned(),
            EmailProfile {
                op: parsed.op,
                host: parsed.host,
                port: parsed.port,
                tls: parsed.tls,
                username: parsed.username,
                password: parsed.password,
                from,
                mailbox: parsed.mailbox,
                limit: parsed.limit,
                timeout: Duration::from_millis(parsed.timeout_ms),
            },
        );
        Ok(())
    }

    async fn execute(
        &self,
        backend_name: &str,
        request: BackendRequest,
    ) -> Result<BackendResponse, BackendError> {
        let started = Instant::now();
        let request_id = request.request_id.clone();
        let identity = request.identity.clone();
        let host_span = self.host_handle().map(|h| {
            h.span(
                "email_backend.execute",
                json!({ "backend": backend_name, "request_id": request_id }),
            )
        });

        let profile = {
            let guard = self.profiles.read().await;
            match guard.get(backend_name).cloned() {
                Some(p) => p,
                None => {
                    let err = BackendError::ProfileNotFound {
                        backend_name: backend_name.to_owned(),
                    };
                    self.emit_host_observability(
                        backend_name,
                        "profile_not_found",
                        Some(&err.to_string()),
                        identity.as_ref(),
                        &request_id,
                        started.elapsed(),
                    )
                    .await;
                    drop(host_span);
                    return Err(err);
                }
            }
        };

        let tool_name = request
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("mcpg-tool-name"))
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| backend_name.to_owned());

        let arguments: Value = if request.payload.is_empty() {
            json!({})
        } else {
            serde_json::from_slice(&request.payload).unwrap_or(Value::Null)
        };

        // Connect + run, bounded by the per-call timeout. Returns
        // (sent, messages).
        let work = async {
            match profile.op {
                EmailOp::Send => {
                    let to = arguments
                        .get("to")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "send requires a string 'to' argument".to_owned())?;
                    let subject = arguments
                        .get("subject")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let body = arguments
                        .get("body")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned();
                    email::send(
                        &profile.host,
                        profile.port,
                        profile.tls,
                        &profile.username,
                        &profile.password,
                        &profile.from,
                        to,
                        subject,
                        body,
                    )
                    .await
                    .map(|()| (Some(true), None))
                }
                EmailOp::Read => email::read(
                    &profile.host,
                    profile.port,
                    profile.tls,
                    &profile.username,
                    &profile.password,
                    &profile.mailbox,
                    profile.limit,
                )
                .await
                .map(|msgs| (None, Some(msgs))),
            }
        };
        let result: Result<(Option<bool>, Option<Vec<Value>>), String> =
            match tokio::time::timeout(profile.timeout, work).await {
                Ok(r) => r,
                Err(_) => Err("email operation timed out".to_owned()),
            };

        let (envelope, outcome_label, audit_reason): (Value, &'static str, Option<String>) =
            match result {
                Ok((sent, messages)) => (
                    build_result_envelope(
                        &tool_name,
                        backend_name,
                        profile.op.as_str(),
                        &profile.host,
                        &profile.mailbox,
                        sent,
                        messages.as_deref(),
                        started.elapsed().as_millis(),
                        None,
                        None,
                    ),
                    "ok",
                    None,
                ),
                Err(message) => {
                    let downstream = classify_error(&message);
                    let lower = message.to_ascii_lowercase();
                    let label = if lower.contains("timed out") || lower.contains("timeout") {
                        "timeout"
                    } else if downstream["kind"] == json!("transport_error") {
                        "transport_error"
                    } else {
                        "email_error"
                    };
                    let env = build_result_envelope(
                        &tool_name,
                        backend_name,
                        profile.op.as_str(),
                        &profile.host,
                        &profile.mailbox,
                        None,
                        None,
                        started.elapsed().as_millis(),
                        Some(&downstream),
                        Some(&message),
                    );
                    (env, label, Some(message))
                }
            };

        self.emit_host_observability(
            backend_name,
            outcome_label,
            audit_reason.as_deref(),
            identity.as_ref(),
            &request_id,
            started.elapsed(),
        )
        .await;
        drop(host_span);
        finalize_payload(envelope)
    }

    fn audit_metadata(&self, _backend_name: &str) -> serde_json::Map<String, Value> {
        let mut map = serde_json::Map::new();
        map.insert("email.transport".to_owned(), json!("plugin"));
        map
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_op_host() -> Arc<dyn BackendHost> {
        Arc::new(NoOpHost)
    }

    fn send_spec() -> Value {
        json!({
            "op": "send",
            "host": "smtp.example.com",
            "port": 587,
            "tls": "starttls",
            "username": "svc",
            "password": "${env.SMTP_PW}",
            "from": "noreply@example.com",
        })
    }

    #[test]
    fn kind_is_email() {
        assert_eq!(EmailBackendPlugin::new().kind(), "email");
    }

    #[tokio::test]
    async fn register_accepts_send_spec() {
        let plugin = EmailBackendPlugin::new();
        plugin
            .register_profile("mail", &send_spec(), no_op_host())
            .await
            .expect("register");
        let profiles = plugin.profiles.read().await;
        assert_eq!(profiles.get("mail").unwrap().op, EmailOp::Send);
    }

    #[tokio::test]
    async fn register_rejects_send_without_from() {
        let plugin = EmailBackendPlugin::new();
        let mut spec = send_spec();
        spec.as_object_mut().unwrap().remove("from");
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("no from");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn register_rejects_read_without_username() {
        let plugin = EmailBackendPlugin::new();
        let spec = json!({ "op": "read", "host": "imap.x", "port": 993 });
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("no username");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn register_rejects_cred_password() {
        let plugin = EmailBackendPlugin::new();
        let mut spec = send_spec();
        spec["password"] = json!("cred://vault/smtp");
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("cred password");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    /// R2 secure-default gate. A spec that OMITS the `tls` field must
    /// resolve to the secure default the gateway's typed path materialized
    /// (`tls: implicit` — full-connection TLS), never plaintext. The plugin
    /// is now the single source of truth for this default, so an absent
    /// field MUST negotiate TLS. Downgrading this to `none`/plaintext is a
    /// silent transport-security regression (the named R2 risk).
    #[tokio::test]
    async fn register_omitting_tls_resolves_to_secure_implicit() {
        let plugin = EmailBackendPlugin::new();
        let mut spec = send_spec();
        // Remove the tls field entirely — the gateway used to inject
        // `unwrap_or_else(|| "implicit")` here; the plugin's serde default
        // must produce the identical secure value.
        spec.as_object_mut().unwrap().remove("tls");
        assert!(
            spec.get("tls").is_none(),
            "precondition: spec must omit tls"
        );
        plugin
            .register_profile("mail", &spec, no_op_host())
            .await
            .expect("register");
        let profiles = plugin.profiles.read().await;
        let resolved = &profiles.get("mail").expect("profile").tls;
        assert_eq!(
            *resolved,
            TlsMode::Implicit,
            "omitted tls must resolve to the secure implicit default, never plaintext"
        );
        assert_ne!(
            *resolved,
            TlsMode::None,
            "must never downgrade to plaintext"
        );
    }

    /// An unrecognized `tls` value is rejected at registration (InvalidSpec)
    /// — it never silently falls back to a default.
    #[tokio::test]
    async fn register_rejects_bad_tls_value() {
        let plugin = EmailBackendPlugin::new();
        let mut spec = send_spec();
        spec["tls"] = json!("bogus");
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("bad tls");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    /// A bare `cred://` in the transport-only `host` field is rejected
    /// (InvalidSpec) — host is a plaintext connection fact, never a
    /// per-caller credential reference.
    #[tokio::test]
    async fn register_rejects_cred_in_transport_only_host() {
        let plugin = EmailBackendPlugin::new();
        let mut spec = send_spec();
        spec["host"] = json!("cred://vault/smtp-host");
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("cred host");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn execute_unknown_profile_is_profile_not_found() {
        let plugin = EmailBackendPlugin::new();
        let req = BackendRequest {
            payload: vec![],
            headers: vec![],
            request_id: "rq-1".into(),
            session_id: None,
            identity: None,
            idempotency: None,
        };
        let err = plugin.execute("missing", req).await.expect_err("missing");
        assert!(matches!(err, BackendError::ProfileNotFound { .. }));
    }

    struct NoOpHost;

    #[async_trait]
    impl BackendHost for NoOpHost {
        async fn invoke_tool(
            &self,
            _ctx: &mcpg_plugin_protocol::BackendInvocationContext,
            _tool_name: &str,
            _args: &serde_json::Value,
        ) -> Result<serde_json::Value, mcpg_plugin_protocol::BackendHostError> {
            Err(mcpg_plugin_protocol::BackendHostError::NotImplemented)
        }
    }
}
