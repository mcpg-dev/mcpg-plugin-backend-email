# `mcpg-plugin-backend-email`

Email backend binding plugin for mcpg (`kind: email`). Sends mail over SMTP
(lettre) and reads a mailbox over IMAP (async-imap) as MCP **tools** and
**resources** — over rustls TLS (STARTTLS / implicit) or plaintext.

Part of the legacy → MCP bridge suite. Lets an
agent send notifications/alerts and triage an inbox.

## How it works

One binding = one operation = one MCP tool (or resource):

| `op` | Behaviour | Returns |
|---|---|---|
| `send` (default) | Build a message from the call arguments (`to` / `subject` / `body`) and deliver it over SMTP. | `{ sent: true }` |
| `read` | Fetch the most recent `limit` messages from `mailbox` over IMAP (envelope + text body, read non-destructively via `BODY.PEEK`). | `{ messages, count }` |

## Configuration

| Field | Type | Default | Notes |
|---|---|---|---|
| `op` | `send`\|`read` | `send` | The operation. |
| `host` | string (required) | — | SMTP (send) or IMAP (read) host. |
| `port` | int (required) | — | e.g. 587 (SMTP STARTTLS) / 465 (SMTP implicit) / 993 (IMAPS) / 143 (IMAP plaintext). |
| `tls` | `none`\|`starttls`\|`implicit` | `implicit` | `starttls` is SMTP-only. |
| `username` | string | `""` | Login user. Required for `read`; optional for an unauthenticated `send`. |
| `password` | string | `""` | Resolved via the gateway secret-resolver (`${env.X}` / `vault://…`). Per-caller `cred://` is **not** supported. |
| `from` | string | — | `From` address. Required for `send`. |
| `mailbox` | string | `INBOX` | Mailbox to read. `read` only. |
| `limit` | int | `10` | Max recent messages to return. `read` only. |
| `timeout_ms` | int | `15000` | connect + operation timeout. |

### As a send tool

```yaml
mcp:
  capabilities:
    tools:
      - name: alerts.notify
        description: Send an alert email.
        input_schema:
          type: object
          properties:
            to: { type: string }
            subject: { type: string }
            body: { type: string }
          required: [to, subject, body]
        backend:
          kind: email
          op: send
          host: "smtp.corp.example.com"
          port: 587
          tls: starttls
          username: "svc-mcpg"
          password: "${env.SMTP_PASSWORD}"
          from: "alerts@corp.example.com"
```

### As a read tool

```yaml
      backend:
        kind: email
        op: read
        host: "imap.corp.example.com"
        port: 993
        tls: implicit
        username: "shared-inbox@corp.example.com"
        password: "${env.IMAP_PASSWORD}"
        mailbox: INBOX
        limit: 20
```

## Response envelope

```jsonc
{
  "toolName": "alerts.notify",
  "profile":  "alerts.notify",
  "request":  { "op": "send", "host": "smtp.corp.example.com", "mailbox": "" },
  "response": { "sent": true, "messages": null, "count": null, "durationMs": 120 },
  "downstreamError": null,        // non-null ⇒ isError:true (email_error / transport_error)
  "downstreamErrors": [],
  "error": null
}
```

`op: read` instead returns `messages` (and `count`); each message:

```jsonc
{
  "seq": 12,
  "from": ["Alice <alice@x>"], "to": ["shared@corp"],
  "subject": "Re: ticket", "date": "Tue, 10 Jun 2026 …",
  "internalDate": "2026-06-10T09:00:00+00:00",
  "body": "the plain-text body …"
}
```

## Security

- **No plaintext secrets.** The login `password` resolves through the gateway
  secret-resolver (`${env.X}` / `vault://…`); it is never committed.
- **`cred://` not supported.** Per-caller `cred://` is rejected at config
  validation — use a service mailbox + the config secret-resolver.
- **Non-destructive read.** `read` fetches with `BODY.PEEK`, so it does not
  set the `\Seen` flag.
- **TLS.** rustls (lettre's `tokio1-rustls-tls`; IMAP wrapped with
  `tokio-rustls` + `webpki-roots`). native-tls is banned. IMAP certificates
  are validated against the system roots.

## Build / test

```bash
nx build mcpg-plugin-backend-email
nx test  mcpg-plugin-backend-email                                   # unit tests
cargo test -p mcpg-plugin-backend-email --features integration-tests  # GreenMail (docker)
nx lint  mcpg-plugin-backend-email
```

## Scope / deferred

- **IMAP STARTTLS** — `read` supports `implicit` (IMAPS) or `none`; STARTTLS
  upgrade on 143 is a follow-on.
- **MIME / attachments** — `read` returns the envelope + the text body;
  attachment extraction + MIME-word-decoded headers are a follow-on.
- **Search criteria** — `read` fetches the most recent N; IMAP `SEARCH`
  (unseen, from, since) is a follow-on.
- **Per-caller credentials** (`cred://`) — v1 is one service mailbox per
  binding.
