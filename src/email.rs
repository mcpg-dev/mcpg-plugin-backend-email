//! Email machinery: SMTP send (lettre) and IMAP read (async-imap), plus
//! message → JSON projection.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_imap::Client;
use async_imap::imap_proto::Address;
use futures_util::TryStreamExt;
use lettre::message::Message;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::types::TlsMode;

// ----------------------------------------------------------------- SMTP send

/// Build + send one message. `username` empty ⇒ no SMTP AUTH (open relay).
#[allow(clippy::too_many_arguments)]
pub async fn send(
    host: &str,
    port: u16,
    tls: TlsMode,
    username: &str,
    password: &str,
    from: &str,
    to: &str,
    subject: &str,
    body: String,
) -> Result<(), String> {
    let from_mb = from
        .parse()
        .map_err(|e| format!("invalid from address '{from}': {e}"))?;
    let to_mb = to
        .parse()
        .map_err(|e| format!("invalid to address '{to}': {e}"))?;
    let email = Message::builder()
        .from(from_mb)
        .to(to_mb)
        .subject(subject)
        .body(body)
        .map_err(|e| format!("building message: {e}"))?;

    let builder = match tls {
        TlsMode::None => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host),
        TlsMode::Starttls => {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host).map_err(|e| {
                mcpg_plugin_protocol::redact::redact_in_text(&format!("smtp starttls relay: {e}"))
            })?
        }
        TlsMode::Implicit => AsyncSmtpTransport::<Tokio1Executor>::relay(host).map_err(|e| {
            mcpg_plugin_protocol::redact::redact_in_text(&format!("smtp relay: {e}"))
        })?,
    };
    let builder = builder.port(port);
    let builder = if username.is_empty() {
        builder
    } else {
        builder.credentials(Credentials::new(username.to_owned(), password.to_owned()))
    };
    let mailer = builder.build();
    mailer.send(email).await.map_err(|e| {
        mcpg_plugin_protocol::redact::redact_in_text(&format!("SMTP send failed: {e}"))
    })?;
    Ok(())
}

// ----------------------------------------------------------------- IMAP read

/// Either a plaintext or a TLS-wrapped IMAP stream — async-imap's `Client<T>`
/// (with `runtime-tokio`) requires `T: tokio AsyncRead + AsyncWrite + Unpin +
/// Debug + Send`, which rules out boxing, so the two transports are unified
/// through this enum (delegating the tokio io traits).
#[derive(Debug)]
enum ImapStream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for ImapStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            ImapStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            ImapStream::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ImapStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            ImapStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            ImapStream::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            ImapStream::Plain(s) => Pin::new(s).poll_flush(cx),
            ImapStream::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            ImapStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            ImapStream::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

fn tls_connector() -> Result<tokio_rustls::TlsConnector, String> {
    use tokio_rustls::rustls::{ClientConfig, RootCertStore};
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    // Pin the ring provider explicitly so this works regardless of whether a
    // process-default crypto provider has been installed.
    let config = ClientConfig::builder_with_provider(Arc::new(
        tokio_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| format!("rustls config: {e}"))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(tokio_rustls::TlsConnector::from(Arc::new(config)))
}

async fn connect_imap(host: &str, port: u16, tls: TlsMode) -> Result<ImapStream, String> {
    let tcp = TcpStream::connect((host, port)).await.map_err(|e| {
        mcpg_plugin_protocol::redact::redact_in_text(&format!("IMAP connect failed: {e}"))
    })?;
    match tls {
        TlsMode::None => Ok(ImapStream::Plain(tcp)),
        TlsMode::Implicit => {
            let connector = tls_connector()?;
            let server_name =
                tokio_rustls::rustls::pki_types::ServerName::try_from(host.to_owned())
                    .map_err(|e| format!("invalid IMAP server name '{host}': {e}"))?;
            let tls_stream = connector
                .connect(server_name, tcp)
                .await
                .map_err(|e| format!("IMAP TLS handshake failed: {e}"))?;
            Ok(ImapStream::Tls(Box::new(tls_stream)))
        }
        TlsMode::Starttls => {
            Err("IMAP STARTTLS is not supported in v1; use implicit TLS (imaps) or none".to_owned())
        }
    }
}

/// Connect, log in, select `mailbox`, and return the most recent `limit`
/// messages (newest last), read non-destructively (`BODY.PEEK`).
pub async fn read(
    host: &str,
    port: u16,
    tls: TlsMode,
    username: &str,
    password: &str,
    mailbox: &str,
    limit: usize,
) -> Result<Vec<Value>, String> {
    let stream = connect_imap(host, port, tls).await?;
    let client = Client::new(stream);
    let mut session = client
        .login(username, password)
        .await
        .map_err(|(e, _client)| {
            mcpg_plugin_protocol::redact::redact_in_text(&format!("IMAP login failed: {e}"))
        })?;

    let mailbox_info = session
        .select(mailbox)
        .await
        .map_err(|e| format!("IMAP select '{mailbox}' failed: {e}"))?;
    let exists = mailbox_info.exists;

    let mut out = Vec::new();
    if exists > 0 {
        let start = exists.saturating_sub(limit as u32).saturating_add(1).max(1);
        let seq = format!("{start}:{exists}");
        let mut fetch_stream = session
            .fetch(seq, "(ENVELOPE INTERNALDATE BODY.PEEK[TEXT])")
            .await
            .map_err(|e| format!("IMAP fetch failed: {e}"))?;
        while let Some(fetch) = fetch_stream
            .try_next()
            .await
            .map_err(|e| format!("IMAP fetch read failed: {e}"))?
        {
            out.push(fetch_to_json(&fetch));
        }
    }
    let _ = session.logout().await;
    Ok(out)
}

fn fetch_to_json(fetch: &async_imap::types::Fetch) -> Value {
    let env = fetch.envelope();
    json!({
        "seq": fetch.message,
        "from": env.and_then(|e| e.from.as_ref()).map(|v| addresses_to_json(v)),
        "to": env.and_then(|e| e.to.as_ref()).map(|v| addresses_to_json(v)),
        "subject": env.and_then(|e| e.subject.as_deref()).map(bytes_lossy),
        "date": env.and_then(|e| e.date.as_deref()).map(bytes_lossy),
        "internalDate": fetch.internal_date().map(|d| d.to_rfc3339()),
        "body": fetch.text().map(|b| String::from_utf8_lossy(b).into_owned()),
    })
}

fn addresses_to_json(addrs: &[Address<'_>]) -> Vec<String> {
    addrs.iter().map(address_to_string).collect()
}

fn address_to_string(a: &Address<'_>) -> String {
    let mailbox = a.mailbox.as_deref().map(bytes_lossy).unwrap_or_default();
    let host = a.host.as_deref().map(bytes_lossy).unwrap_or_default();
    let email = if host.is_empty() {
        mailbox
    } else {
        format!("{mailbox}@{host}")
    };
    match a.name.as_deref().map(bytes_lossy) {
        Some(name) if !name.is_empty() => format!("{name} <{email}>"),
        _ => email,
    }
}

fn bytes_lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;

    #[test]
    fn address_with_name() {
        let a = Address {
            name: Some(Cow::Borrowed(b"Alice".as_slice())),
            adl: None,
            mailbox: Some(Cow::Borrowed(b"alice".as_slice())),
            host: Some(Cow::Borrowed(b"example.org".as_slice())),
        };
        assert_eq!(address_to_string(&a), "Alice <alice@example.org>");
    }

    #[test]
    fn address_without_name() {
        let a = Address {
            name: None,
            adl: None,
            mailbox: Some(Cow::Borrowed(b"bob".as_slice())),
            host: Some(Cow::Borrowed(b"example.org".as_slice())),
        };
        assert_eq!(address_to_string(&a), "bob@example.org");
    }
}
