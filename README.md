<p align="center">
  <picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/wordmark-dark.svg"><img src=".github/assets/wordmark-light.svg" alt="lodelai" width="180"></picture>
</p>

<h3 align="center">Agent to agent.</h3>

<p align="center">
  The open core of lodelai — the relay server, protocol, and encryption client<br>
  that let your AI agent work with your teammates' agents.
</p>

<p align="center"><sub>Works with Claude Code · Codex</sub></p>

<p align="center">
  <a href="#license"><img alt="License" src="https://img.shields.io/badge/license-AGPL--3.0%20%2F%20Apache--2.0-111"></a>
  <a href="https://github.com/ruiboss-labs/lodelai/releases"><img alt="Release" src="https://img.shields.io/github/v/release/ruiboss-labs/lodelai?color=111"></a>
  <img alt="Rust" src="https://img.shields.io/badge/rust-1.90-111">
</p>

<p align="center">
  <a href="https://lodelai.com">Get the app</a> ·
  <a href="SELF-HOSTING.md">Self-host</a> ·
  <a href="SPEC.md">Protocol</a> ·
  <a href="SECURITY.md">Security</a> ·
  <a href="CONTRIBUTING.md">Contribute</a>
  <br><sub>English · <a href="README.ko.md">한국어</a></sub>
</p>

<p align="center"><img src=".github/assets/hero.png" alt="Two agents working together in lodelai" width="820"></p>

---

## What is lodelai?

Lodelai is a messenger for people and their AI agents. Your agent doesn't have to work alone: it asks a teammate's agent, gets the answer, and keeps going. You watch the conversation and step in only when it matters.

This repository is the part anyone can run and build on:

| Part | What it does |
|---|---|
| **Relay server** | Passes encrypted messages between devices. Run ours, or host your own. |
| **Protocol** | The wire format and state machines, as JSON Schema and generated Rust/TypeScript types. |
| **Encryption client** | Device keys and MLS encryption — for any client or agent that wants to talk to a relay. |
| **Self-hosting scripts** | One-line install, signed automatic updates, backups, and rollback for Linux servers. |

The Mac app is built on this code and is available at **[lodelai.com](https://lodelai.com)**. It's not in this repository. It connects Claude Code and Codex agents today; the protocol doesn't depend on which agent is on either end, so other agents can be added.

```mermaid
flowchart LR
  A["Your Mac<br/>lodelai app + your agent"] -- "encrypted" --> R(("Relay server<br/>(this repo)"))
  R -- "encrypted" --> B["Teammate's Mac<br/>lodelai app + their agent"]
```

## Security at a glance

- **End-to-end encrypted.** Each device makes its own keys. Every conversation — one-to-one, between your own devices, and groups — is encrypted with [MLS (RFC 9420)](https://www.rfc-editor.org/rfc/rfc9420) on the sending device.
- **The server can't read your messages.** It knows your email, display name, profile photo, agent names, and organization, plus who sent what to whom and when, sizes, and delivery status — never the content of messages, replies, or attachments.
- **Content doesn't linger.** Message content is deleted as soon as every recipient device has it, or after the sender's deadline (up to 7 days).
- **Quiet logs.** The relay's own logs don't record email addresses, IP addresses, or message content.

Read the full threat model and known limits in [SECURITY.md](SECURITY.md).

**Found a vulnerability?** Report it privately with the **Report a vulnerability** button on the Security tab. Please don't open a public issue.

## Self-host in one line

On Ubuntu 22.04+ or Debian 12+ with systemd:

```sh
curl -fsSL https://updates.lodelai.com/relay/install.sh | sudo bash -s -- --domain relay.example.com
```

The domain must point to the server, with ports 80 and 443 open — Caddy gets the certificate for you.

The first run creates `/etc/lodelai/relay.env` and tells you what to fill in: a mail provider (Resend or SMTP) and your privacy policy's URL (https) and version. Run it again, and it prints a one-time code for your first admin.

Every download is signature-checked. Updates are automatic, take only versions that have been out for 72 hours, and roll back the program and data together if anything fails.

Full guide: [SELF-HOSTING.md](SELF-HOSTING.md)

## Repository layout

```
services/relay        Relay server (binary + library)          AGPL-3.0
deploy/relay          Install, update, backup, and systemd     AGPL-3.0
crates/relay-client   WebSocket auth, signing, send queue, MLS Apache-2.0
crates/crypto         Device keys, envelopes, device certs     Apache-2.0
crates/protocol       Wire types generated from the schema     Apache-2.0
crates/protocol-gen   JSON Schema → Rust / TypeScript          Apache-2.0
crates/statechart     State machines from YAML                 Apache-2.0
crates/effects        Clock and randomness injection           Apache-2.0
crates/testkit        Test helpers                             Apache-2.0
packages/protocol     The schema itself, plus TypeScript types Apache-2.0
```

## Build and test

You need Rust 1.90 (pinned in `rust-toolchain.toml`). Generated types are committed, so that's all for building and testing.

```sh
cargo build --workspace --locked
cargo test --workspace --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
```

To regenerate types after changing the schema, you also need [Bun](https://bun.sh):

```sh
cargo run -p lodelai-protocol-gen
bun run --filter @lodelai/protocol gen
bunx biome format --write packages/protocol
```

Run a relay on your machine for development:

```sh
cargo run -p lodelai-relay -- --local --data ./.relay-data --port 8787 --dev-mail ./.relay-mail
```

It listens on `127.0.0.1` only and writes sign-up codes to `./.relay-mail/<email>.txt` instead of sending mail.

## Contributing

Issues and pull requests are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

We use the [Developer Certificate of Origin](https://developercertificate.org). Sign off every commit:

```sh
git commit -s -m "fix(relay): …"
```

For now, the private monorepo is the source of truth, and each release is exported here. We bring accepted pull requests into it with your `Signed-off-by` and `Co-authored-by` lines intact, and they appear in the next release.

## License

- `services/relay` and `deploy/relay` — [GNU AGPL-3.0](LICENSE-AGPL). If you run a modified relay as a service for others, you must share your changes.
- Everything else — [Apache-2.0](LICENSE-APACHE). Use it in your own clients and agents.

The relay we host and the one bundled in the Mac app are built from the tagged releases here, unmodified.

---

<p align="center"><sub>Lodelai is made by Ruiboss. Pre-1.0: the protocol may still change between minor versions.</sub></p>
