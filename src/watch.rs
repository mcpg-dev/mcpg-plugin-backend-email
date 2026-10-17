//! `watch_strategy` entity (`imap_mailbox`): the messages of an IMAP
//! mailbox, each one that arrives, changes flags or leaves as the shared
//! `object.changed` event.
//!
//! The mailbox is an inventory of messages keyed by UIDVALIDITY and UID,
//! their flags the version: a new message is `created`, a flag change
//! (`\Seen`, `\Flagged`, a keyword) is `modified`, an expunged message is
//! `deleted`. The watch lists the UIDs and flags every `interval_ms` on a
//! read-only session (`EXAMINE`), and IDLE on a second session makes it list
//! at once. Only what changed is fetched in full: envelope, flags and the
//! start of the text, added to its event. Resume is exact while the listing
//! fits `snapshot_bytes`, through the SDK's inventory helper.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use async_imap::types::{Fetch, Flag};
use async_imap::{Client, Session};
use futures_util::TryStreamExt;
use mcpg_plugin_protocol::backend::WatchError;
use mcpg_plugin_protocol::{PluginManifest, firstparty_manifest};
use mcpg_plugin_sdk::HostHandle;
use mcpg_plugin_sdk::ffi::{SyncWatchStrategyPlugin, WatchHandleBox};
use mcpg_plugin_sdk::inventory::{
    self, Describe, InventoryOptions, InventoryStart, InventoryWaker, ObjectEntry,
    acknowledge_inventory_watch, cancel_inventory_watch, spawn_described_inventory_watch,
};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::email::{ImapStream, addresses_to_json, bytes_lossy, connect_imap};
use crate::types::TlsMode;

pub const PLUGIN_ID: &str = "dev.mcpg.backend.email";

/// The strategy discriminator this entity handles.
pub const WATCH_KIND: &str = "imap_mailbox";

/// The `store` of every event.
const STORE: &str = "imap";

/// Largest `preview_bytes`: the event must stay under the host's 256 KiB.
const MAX_PREVIEW_BYTES: usize = 32 * 1024;

/// Largest message whose text is fetched for its preview.
const TEXT_FETCH_LIMIT: u64 = 256 * 1024;

/// How long one IDLE lasts before it is renewed; servers drop an IDLE
/// after 30 minutes, and many NATs sooner.
const IDLE_RENEW: Duration = Duration::from_secs(300);

fn default_port() -> u16 {
    993
}

fn default_mailbox() -> String {
    "INBOX".to_owned()
}

fn default_true() -> bool {
    true
}

fn default_interval_ms() -> u64 {
    60_000
}

fn default_timeout_ms() -> u64 {
    30_000
}

fn default_preview_bytes() -> usize {
    2048
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WatchSpec {
    host: String,
    #[serde(default = "default_port")]
    port: u16,
    /// `implicit` (IMAPS, the default) or `none`.
    #[serde(default)]
    tls: TlsMode,
    username: String,
    /// Resolved before the watch starts (`${env.X}`, `${secret.X}`,
    /// `vault://…`).
    password: String,
    #[serde(default = "default_mailbox")]
    mailbox: String,
    /// IDLE for prompt changes, when the server offers it.
    #[serde(default = "default_true")]
    idle: bool,
    #[serde(default = "default_interval_ms")]
    interval_ms: u64,
    /// Budget of one listing, and of the fetch of what changed.
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
    /// The start of a message's text its event carries.
    #[serde(default = "default_preview_bytes")]
    preview_bytes: usize,
    /// Most messages listed: the newest.
    #[serde(default = "inventory::defaults::max_files")]
    max_files: usize,
    #[serde(default)]
    start_at: InventoryStart,
    #[serde(default = "inventory::defaults::snapshot_bytes")]
    snapshot_bytes: usize,
    #[serde(default = "inventory::defaults::max_in_flight")]
    max_in_flight: usize,
    #[serde(default = "inventory::defaults::ack_timeout_ms")]
    ack_timeout_ms: u64,
}

/// How to reach the mailbox.
#[derive(Clone)]
struct Mailbox {
    host: String,
    port: u16,
    tls: TlsMode,
    username: String,
    password: String,
    name: String,
}

impl Mailbox {
    async fn session(&self) -> Result<Session<ImapStream>, String> {
        let stream = connect_imap(&self.host, self.port, self.tls).await?;
        Client::new(stream)
            .login(&self.username, &self.password)
            .await
            .map_err(|(e, _)| {
                mcpg_plugin_protocol::redact::redact_in_text(&format!("IMAP login failed: {e}"))
            })
    }
}

/// The key of a message: UIDVALIDITY and a padded UID, so keys sort as
/// UIDs do.
fn message_key(uidvalidity: u32, uid: u32) -> String {
    format!("{uidvalidity}:{uid:010}")
}

fn uid_of(key: &str) -> Option<u32> {
    key.split_once(':')?.1.parse().ok()
}

/// The flags that belong to a message; `\Recent` belongs to a session.
fn flags_of(fetch: &Fetch) -> Vec<String> {
    let mut flags: Vec<String> = fetch
        .flags()
        .filter_map(|flag| match flag {
            Flag::Seen => Some("\\Seen".to_owned()),
            Flag::Answered => Some("\\Answered".to_owned()),
            Flag::Flagged => Some("\\Flagged".to_owned()),
            Flag::Deleted => Some("\\Deleted".to_owned()),
            Flag::Draft => Some("\\Draft".to_owned()),
            Flag::Custom(keyword) => Some(keyword.into_owned()),
            _ => None,
        })
        .collect();
    flags.sort();
    flags
}

/// The read-only session listings and descriptions share.
struct Reader {
    mailbox: Mailbox,
    session: Option<Session<ImapStream>>,
    uidvalidity: u32,
}

impl Reader {
    async fn examined(&mut self) -> Result<(&mut Session<ImapStream>, u32), String> {
        if self.session.is_none() {
            self.session = Some(self.mailbox.session().await?);
        }
        let session = self.session.as_mut().expect("opened above");
        let selected = session
            .examine(&self.mailbox.name)
            .await
            .map_err(|e| format!("IMAP EXAMINE '{}' failed: {e}", self.mailbox.name))?;
        self.uidvalidity = selected.uid_validity.unwrap_or(0);
        Ok((session, selected.exists))
    }

    /// The UID, flags, size and date of every message, the newest
    /// `max_files` when there are more.
    async fn list(&mut self, max_files: usize) -> Result<Vec<ObjectEntry>, String> {
        let (session, exists) = self.examined().await?;
        if exists == 0 {
            return Ok(Vec::new());
        }
        let fetches: Vec<Fetch> = session
            .uid_fetch("1:*", "(UID FLAGS RFC822.SIZE INTERNALDATE)")
            .await
            .map_err(|e| format!("IMAP UID FETCH failed: {e}"))?
            .try_collect()
            .await
            .map_err(|e| format!("IMAP UID FETCH failed: {e}"))?;
        let uidvalidity = self.uidvalidity;
        let mut entries: Vec<ObjectEntry> = fetches
            .iter()
            .filter_map(|fetch| {
                let uid = fetch.uid?;
                Some(ObjectEntry {
                    key: message_key(uidvalidity, uid),
                    size: fetch.size.map(u64::from),
                    modified_at_ms: fetch.internal_date().map(|d| d.timestamp_millis()),
                    etag: None,
                    version: Some(flags_of(fetch).join(" ")),
                })
            })
            .collect();
        if entries.len() > max_files {
            tracing::warn!(
                mailbox = %self.mailbox.name,
                messages = entries.len(),
                max_files,
                "imap_mailbox: more messages than max_files; the oldest are not watched"
            );
            entries.sort_by(|a, b| a.key.cmp(&b.key));
            entries.drain(..entries.len() - max_files);
        }
        Ok(entries)
    }

    /// The envelope, flags and start of the text of each message in
    /// `entries`. The text is fetched whole, so only for a message of at
    /// most `TEXT_FETCH_LIMIT` bytes: the IMAP parser does not read a
    /// partial section (`BODY[TEXT]<0>`).
    async fn describe(
        &mut self,
        entries: &[ObjectEntry],
        preview_bytes: usize,
    ) -> Result<HashMap<u32, Map<String, Value>>, String> {
        let (small, large): (Vec<&ObjectEntry>, Vec<&ObjectEntry>) = entries
            .iter()
            .partition(|e| e.size.is_some_and(|s| s <= TEXT_FETCH_LIMIT));
        let uids = |list: &[&ObjectEntry]| -> String {
            list.iter()
                .filter_map(|e| uid_of(&e.key))
                .map(|uid| uid.to_string())
                .collect::<Vec<_>>()
                .join(",")
        };
        let mut described = HashMap::new();
        for (set, query) in [
            (uids(&small), "(UID FLAGS ENVELOPE BODY.PEEK[TEXT])"),
            (uids(&large), "(UID FLAGS ENVELOPE)"),
        ] {
            if set.is_empty() {
                continue;
            }
            let (session, _) = self.examined().await?;
            let fetches: Vec<Fetch> = session
                .uid_fetch(set, query)
                .await
                .map_err(|e| format!("IMAP UID FETCH failed: {e}"))?
                .try_collect()
                .await
                .map_err(|e| format!("IMAP UID FETCH failed: {e}"))?;
            described.extend(
                fetches
                    .iter()
                    .filter_map(|fetch| Some((fetch.uid?, details(fetch, preview_bytes)))),
            );
        }
        Ok(described)
    }
}

/// The start of a text, at most `bytes` long, cut on a character boundary.
fn preview(text: &[u8], bytes: usize) -> String {
    let text = String::from_utf8_lossy(text);
    if text.len() <= bytes {
        return text.into_owned();
    }
    let mut end = bytes;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

/// What a subscriber reads of a message.
fn details(fetch: &Fetch, preview_bytes: usize) -> Map<String, Value> {
    let mut extra = Map::new();
    if let Some(uid) = fetch.uid {
        extra.insert("uid".into(), json!(uid));
    }
    extra.insert("flags".into(), json!(flags_of(fetch)));
    if let Some(envelope) = fetch.envelope() {
        let addresses = |list: &Option<Vec<async_imap::imap_proto::Address<'_>>>| {
            list.as_ref()
                .map(|l| addresses_to_json(l))
                .unwrap_or_default()
        };
        extra.insert("from".into(), json!(addresses(&envelope.from)));
        extra.insert("to".into(), json!(addresses(&envelope.to)));
        extra.insert("cc".into(), json!(addresses(&envelope.cc)));
        let text = |field: &Option<std::borrow::Cow<'_, [u8]>>| field.as_deref().map(bytes_lossy);
        if let Some(subject) = text(&envelope.subject) {
            extra.insert("subject".into(), json!(subject));
        }
        if let Some(date) = text(&envelope.date) {
            extra.insert("date".into(), json!(date));
        }
        if let Some(id) = text(&envelope.message_id) {
            extra.insert("messageId".into(), json!(id));
        }
        if let Some(id) = text(&envelope.in_reply_to) {
            extra.insert("inReplyTo".into(), json!(id));
        }
    }
    if let Some(text) = fetch.text() {
        extra.insert("preview".into(), json!(preview(text, preview_bytes)));
    }
    extra
}

/// Wake `waker` whenever the server reports a change on an IDLE session.
fn idle_loop(
    rt: Arc<tokio::runtime::Runtime>,
    mailbox: Mailbox,
    waker: InventoryWaker,
    stop: Arc<AtomicBool>,
    stopped: Arc<tokio::sync::Notify>,
) {
    let mut backoff = Duration::from_millis(500);
    while !stop.load(Ordering::Acquire) {
        let outcome: Result<bool, String> = rt.block_on(async {
            let mut session = mailbox.session().await?;
            let capabilities = session
                .capabilities()
                .await
                .map_err(|e| format!("IMAP CAPABILITY failed: {e}"))?;
            if !capabilities.has_str("IDLE") {
                return Ok(false);
            }
            session
                .examine(&mailbox.name)
                .await
                .map_err(|e| format!("IMAP EXAMINE '{}' failed: {e}", mailbox.name))?;
            loop {
                let mut idle = session.idle();
                idle.init()
                    .await
                    .map_err(|e| format!("IMAP IDLE failed: {e}"))?;
                let (wait, _interrupt) = idle.wait_with_timeout(IDLE_RENEW);
                let changed = tokio::select! {
                    response = wait => matches!(
                        response.map_err(|e| format!("IMAP IDLE failed: {e}"))?,
                        async_imap::extensions::idle::IdleResponse::NewData(_)
                    ),
                    () = stopped.notified() => false,
                };
                if changed {
                    waker.wake();
                }
                session = idle
                    .done()
                    .await
                    .map_err(|e| format!("IMAP IDLE DONE failed: {e}"))?;
                if stop.load(Ordering::Acquire) {
                    let _ = session.logout().await;
                    return Ok(true);
                }
            }
        });
        match outcome {
            Ok(true) => return,
            Ok(false) => {
                tracing::info!(host = %mailbox.host, "imap_mailbox: the server offers no IDLE; the mailbox is listed every interval");
                return;
            }
            Err(error) => {
                tracing::warn!(error = %error, "imap_mailbox: IDLE lost; the listing goes on at its interval");
                let until = std::time::Instant::now() + backoff;
                while std::time::Instant::now() < until && !stop.load(Ordering::Acquire) {
                    std::thread::sleep(Duration::from_millis(50));
                }
                backoff = (backoff * 2).min(Duration::from_secs(30));
            }
        }
    }
}

/// The inventory watch, with its IDLE thread when it has one.
struct MailboxWatch {
    inventory: WatchHandleBox,
    idle: Option<(Arc<AtomicBool>, Arc<tokio::sync::Notify>, JoinHandle<()>)>,
}

/// `watch_strategy` entity. Stateless beyond its manifest — each watcher's
/// server and mailbox arrive on the per-watch spec.
pub struct EmailWatchCdylib {
    manifest: PluginManifest,
}

impl EmailWatchCdylib {
    /// Infallible cdylib factory; the watch carries no plugin-level config.
    pub fn from_host_config(_config_json: &str, _host: HostHandle) -> Self {
        Self {
            manifest: firstparty_manifest! {
                id: "dev.mcpg.backend.email",
                name: "IMAP Mailbox Watch Strategy",
                class: WatchStrategy,
            },
        }
    }
}

impl SyncWatchStrategyPlugin for EmailWatchCdylib {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn kind(&self) -> &str {
        WATCH_KIND
    }

    fn watch(
        &self,
        resource_uri: &str,
        spec: &Value,
        emit_event: Box<dyn Fn(&str) + Send + Sync + 'static>,
    ) -> Result<WatchHandleBox, WatchError> {
        let (spec, resume) = mcpg_plugin_protocol::take_watch_resume(spec);
        let parsed: WatchSpec =
            serde_json::from_value(spec).map_err(|e| WatchError::InvalidSpec {
                message: format!("invalid imap_mailbox watch spec: {e}"),
            })?;
        let invalid = |m: String| WatchError::InvalidSpec { message: m };
        if parsed.host.trim().is_empty() || parsed.host.contains("cred://") {
            return Err(invalid("host must name a server".into()));
        }
        if parsed.tls == TlsMode::Starttls {
            return Err(invalid(
                "IMAP STARTTLS is not supported; use tls: implicit (IMAPS) or none".into(),
            ));
        }
        if parsed.username.trim().is_empty() || parsed.password.is_empty() {
            return Err(invalid("username and password must not be empty".into()));
        }
        if parsed.password.starts_with("cred://") {
            return Err(invalid(
                "password must not be a cred:// URI — per-caller credentials are unsupported; \
                 use ${env.X} / ${secret.X} / vault:// (resolved before the watch starts)"
                    .into(),
            ));
        }
        if parsed.mailbox.trim().is_empty() {
            return Err(invalid("mailbox must not be empty".into()));
        }
        if !(1..=MAX_PREVIEW_BYTES).contains(&parsed.preview_bytes) {
            return Err(invalid(format!(
                "preview_bytes must be 1 to {MAX_PREVIEW_BYTES}"
            )));
        }
        if !(1..=100_000).contains(&parsed.max_files) {
            return Err(invalid("max_files must be 1 to 100000".into()));
        }
        if parsed.timeout_ms == 0 {
            return Err(invalid("timeout_ms must be greater than 0".into()));
        }
        let mailbox = Mailbox {
            host: parsed.host.clone(),
            port: parsed.port,
            tls: parsed.tls,
            username: parsed.username,
            password: parsed.password,
            name: parsed.mailbox.clone(),
        };
        let location = format!("imap://{}:{}/{}", parsed.host, parsed.port, parsed.mailbox);
        let rt = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .thread_name("mcpg-imap-watch")
                .enable_all()
                .build()
                .map_err(|e| WatchError::Subscribe {
                    message: format!("imap_mailbox: tokio runtime init failed: {e}"),
                })?,
        );
        let reader = Arc::new(Mutex::new(Reader {
            mailbox: mailbox.clone(),
            session: None,
            uidvalidity: 0,
        }));
        let timeout = Duration::from_millis(parsed.timeout_ms);
        let (list_rt, list_reader, max_files) =
            (Arc::clone(&rt), Arc::clone(&reader), parsed.max_files);
        // A mailbox that cannot be listed now is listed again at the next
        // interval, on a new session: the source is not lost to an outage.
        let list = move || {
            let mut reader = list_reader.lock().unwrap_or_else(|e| e.into_inner());
            let listed = list_rt.block_on(async {
                tokio::time::timeout(timeout, reader.list(max_files))
                    .await
                    .map_err(|_| "IMAP listing timed out".to_owned())?
            });
            if listed.is_err() {
                reader.session = None;
            }
            listed
        };
        let (describe_rt, describe_reader, preview_bytes) =
            (Arc::clone(&rt), Arc::clone(&reader), parsed.preview_bytes);
        let describe: Describe = Box::new(move |entries: &[ObjectEntry]| {
            let mut reader = describe_reader.lock().unwrap_or_else(|e| e.into_inner());
            let described = describe_rt.block_on(async {
                tokio::time::timeout(timeout, reader.describe(entries, preview_bytes))
                    .await
                    .map_err(|_| "IMAP fetch timed out".to_owned())?
            });
            let mut details = described.unwrap_or_else(|error| {
                // The events still go out, with what the listing knows.
                tracing::warn!(error = %error, "imap_mailbox: cannot fetch what changed; its events carry no envelope");
                reader.session = None;
                HashMap::new()
            });
            entries
                .iter()
                .map(|e| uid_of(&e.key).and_then(|uid| details.remove(&uid)))
                .collect()
        });
        let (inventory, waker) = spawn_described_inventory_watch(
            resource_uri,
            InventoryOptions {
                store: STORE.into(),
                location,
                interval: Duration::from_millis(parsed.interval_ms),
                start: parsed.start_at,
                snapshot_bytes: parsed.snapshot_bytes,
                max_in_flight: parsed.max_in_flight,
                ack_timeout: Duration::from_millis(parsed.ack_timeout_ms),
            },
            resume,
            emit_event,
            list,
            Some(describe),
        )?;
        let idle = if parsed.idle {
            let stop = Arc::new(AtomicBool::new(false));
            let stopped = Arc::new(tokio::sync::Notify::new());
            let (idle_stop, idle_stopped) = (Arc::clone(&stop), Arc::clone(&stopped));
            let spawned = std::thread::Builder::new()
                .name("mcpg-imap-idle".to_owned())
                .spawn(move || idle_loop(rt, mailbox, waker, idle_stop, idle_stopped));
            match spawned {
                Ok(join) => Some((stop, stopped, join)),
                Err(e) => {
                    cancel_inventory_watch(inventory);
                    return Err(WatchError::Subscribe {
                        message: format!("imap_mailbox: cannot start the IDLE thread: {e}"),
                    });
                }
            }
        } else {
            None
        };
        let state = Box::new(MailboxWatch { inventory, idle });
        Ok(WatchHandleBox(Box::into_raw(state) as *mut ()))
    }

    fn acknowledge(&self, watch_handle: &WatchHandleBox, position: &Value) {
        if watch_handle.0.is_null() {
            return;
        }
        // SAFETY: the pointer `watch` returned, still owned by the host,
        // which never acknowledges after cancel.
        #[allow(unsafe_code)]
        let state = unsafe { &*(watch_handle.0 as *const MailboxWatch) };
        acknowledge_inventory_watch(&state.inventory, position);
    }

    fn cancel(&self, watch_handle: WatchHandleBox) {
        if watch_handle.0.is_null() {
            return;
        }
        // SAFETY: produced by `Box::into_raw` in `watch` and round-tripped by
        // the host exactly once.
        #[allow(unsafe_code)]
        let state = unsafe { Box::from_raw(watch_handle.0 as *mut MailboxWatch) };
        let MailboxWatch { inventory, idle } = *state;
        if let Some((stop, stopped, join)) = idle {
            stop.store(true, Ordering::Release);
            stopped.notify_waiters();
            let _ = join.join();
        }
        cancel_inventory_watch(inventory);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stub_host() -> HostHandle {
        // SAFETY: `stub_host_ref` returns a process-static no-op host ref; the
        // factory ignores the host entirely.
        #[allow(unsafe_code)]
        unsafe {
            HostHandle::from_ffi(mcpg_plugin_sdk::testing::stub_host_ref())
        }
    }

    fn plugin() -> EmailWatchCdylib {
        EmailWatchCdylib::from_host_config("", stub_host())
    }

    fn refused(spec: Value) -> String {
        match plugin().watch("mcpg-event://inbox", &spec, Box::new(|_| {})) {
            Err(WatchError::InvalidSpec { message }) => message,
            Err(other) => panic!("not a spec error: {other:?}"),
            Ok(handle) => {
                plugin().cancel(handle);
                panic!("accepted {spec}");
            }
        }
    }

    #[test]
    fn manifest_and_kind_are_correct() {
        use mcpg_plugin_protocol::PluginClass;
        let p = plugin();
        assert_eq!(SyncWatchStrategyPlugin::manifest(&p).id, PLUGIN_ID);
        assert_eq!(
            SyncWatchStrategyPlugin::manifest(&p).plugin_class,
            PluginClass::WatchStrategy
        );
        assert_eq!(p.kind(), WATCH_KIND);
    }

    #[test]
    fn spec_parses_with_defaults() {
        let parsed: WatchSpec = serde_json::from_value(json!({
            "host": "imap.example.com", "username": "u", "password": "p",
        }))
        .unwrap();
        assert_eq!(parsed.port, 993);
        assert_eq!(parsed.tls, TlsMode::Implicit);
        assert_eq!(parsed.mailbox, "INBOX");
        assert!(parsed.idle);
        assert_eq!(parsed.preview_bytes, 2048);
    }

    #[test]
    fn a_bad_spec_is_refused_before_anything_connects() {
        let with = |extra: Value| {
            let mut spec = json!({ "host": "imap.example.com", "username": "u", "password": "p" });
            for (k, v) in extra.as_object().unwrap() {
                spec[k] = v.clone();
            }
            spec
        };
        assert!(refused(with(json!({ "bogus": 1 }))).contains("unknown field"));
        assert!(refused(with(json!({ "host": " " }))).contains("host"));
        assert!(refused(with(json!({ "tls": "starttls" }))).contains("STARTTLS"));
        assert!(refused(with(json!({ "password": "" }))).contains("password"));
        assert!(refused(with(json!({ "password": "cred://vault/imap" }))).contains("cred://"));
        assert!(refused(with(json!({ "mailbox": "" }))).contains("mailbox"));
        assert!(refused(with(json!({ "preview_bytes": 0 }))).contains("preview_bytes"));
        assert!(refused(with(json!({ "max_files": 0 }))).contains("max_files"));
        assert!(refused(with(json!({ "interval_ms": 10 }))).contains("interval_ms"));
    }

    #[test]
    fn a_preview_is_cut_on_a_character_boundary() {
        assert_eq!(preview(b"hello", 10), "hello");
        assert_eq!(preview(b"hello", 3), "hel");
        assert_eq!(preview("héllo".as_bytes(), 2), "h", "é is two bytes");
    }

    #[test]
    fn a_message_key_sorts_as_its_uid() {
        assert_eq!(message_key(7, 42), "7:0000000042");
        assert!(message_key(7, 9) < message_key(7, 10));
        assert_eq!(uid_of(&message_key(7, 42)), Some(42));
        assert_eq!(uid_of("nope"), None);
    }
}
