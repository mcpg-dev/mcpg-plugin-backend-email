//! cdylib sync bridge — adapts the async [`EmailBackendPlugin`] onto the sync
//! FFI trait the cdylib vtable expects ([`SyncBackendPlugin`]). A private
//! multi-thread runtime `block_on`s the async methods (lettre's tokio
//! transport + async-imap run on it); the make-time [`HostHandle`] is wrapped
//! as `Arc<dyn BackendHost>` for `register_profile` and installed on the inner
//! plugin for observability.

use std::sync::Arc;

use mcpg_plugin_protocol::{
    BackendError, BackendPlugin, BackendRequest, BackendResponse, PluginManifest,
};
use mcpg_plugin_sdk::ffi::SyncBackendPlugin;
use mcpg_plugin_sdk::{HostHandle, HostHandleBackendHost};

use crate::EmailBackendPlugin;

fn build_bridge_runtime(thread_name: &str) -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name(thread_name.to_owned())
        .enable_all()
        .build()
        .unwrap_or_else(|e| panic!("email cdylib: tokio runtime init failed: {e}"))
}

/// `SyncBackendPlugin` bridge over [`EmailBackendPlugin`].
pub struct EmailBackendCdylib {
    inner: EmailBackendPlugin,
    host: Arc<dyn mcpg_plugin_protocol::BackendHost>,
    rt: tokio::runtime::Runtime,
}

impl EmailBackendCdylib {
    /// Infallible cdylib factory. `config_json` is ignored — Email carries no
    /// plugin-level config (per-binding host / op arrive via `register_profile`).
    pub fn from_host_config(_config_json: &str, host: HostHandle) -> Self {
        let inner = EmailBackendPlugin::new();
        let _installed = inner.set_host_handle(host.clone());
        Self {
            inner,
            host: Arc::new(HostHandleBackendHost::new(host)),
            rt: build_bridge_runtime("mcpg-backend-email"),
        }
    }
}

impl SyncBackendPlugin for EmailBackendCdylib {
    fn manifest(&self) -> &PluginManifest {
        BackendPlugin::manifest(&self.inner)
    }

    fn kind(&self) -> &str {
        BackendPlugin::kind(&self.inner)
    }

    fn register_profile(
        &self,
        profile_name: &str,
        spec: &serde_json::Value,
    ) -> Result<(), BackendError> {
        self.rt.block_on(BackendPlugin::register_profile(
            &self.inner,
            profile_name,
            spec,
            Arc::clone(&self.host),
        ))
    }

    fn execute(
        &self,
        profile_name: &str,
        request: BackendRequest,
    ) -> Result<BackendResponse, BackendError> {
        self.rt
            .block_on(BackendPlugin::execute(&self.inner, profile_name, request))
    }

    fn audit_metadata(&self, profile_name: &str) -> serde_json::Map<String, serde_json::Value> {
        BackendPlugin::audit_metadata(&self.inner, profile_name)
    }
}

// cdylib export — one `backend` entity under `dev.mcpg.backend.email`.
mcpg_plugin_sdk::declare_plugin! {
    plugin_id: "dev.mcpg.backend.email",
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[::mcpg_plugin_protocol::capability::Capability::NetworkOutbound],
    // Residual per-kind facts the gateway reads back by kind. Email opens a
    // fresh SMTP/IMAP connection per call (no standing connection to probe),
    // so health is advisory (Skip — the default). It may appear as a backend
    // pipeline step. label defaults to the kind ("email"), no dynamic tool
    // list. `host` is a transport-only connection fact — the gateway's
    // generic spec-walk asserts no `cred://` lands there (the plugin's own
    // `register_profile` enforces the same). The secret is `password`, which
    // resolves config-side and rejects per-caller `cred://` directly.
    backend_profile: ::mcpg_plugin_protocol::manifest::BackendProfile {
        pipeline_capable: true,
        transport_only_fields: ::std::vec!["/host".to_owned()],
        ..::core::default::Default::default()
    },
    entities: [
        backend as binding {
            inner_name: "",
            plugin_type: EmailBackendCdylib,
            factory: |cfg, host: ::mcpg_plugin_sdk::HostHandle|
                EmailBackendCdylib::from_host_config(cfg, host),
        },
    ],
}
