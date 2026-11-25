# Security

## Reporting a vulnerability

Please report vulnerabilities privately with the **Report a vulnerability** button on this repository's **Security** tab ([GitHub private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)). Don't open a public issue, pull request, or discussion.

Include what you found, how to reproduce it, and which version you tested. We'll acknowledge your report, keep you updated, and credit you in the advisory unless you'd rather stay anonymous.

## Supported versions

Lodelai is pre-1.0. Security fixes go into the latest release. When a new protocol line ships, the line before it keeps getting security fixes for 90 days.

| Version | Supported |
|---|---|
| Latest release | ✅ |
| Previous protocol line, for 90 days after a newer line ships | ✅ |
| Older | ❌ |

Self-hosted servers on automatic updates pick up fixes after the usual 72-hour delay. To get one sooner, run `sudo /opt/lodelai/bin/lodelai-update` by hand.

## What the server can and can't see

Every conversation — one-to-one, between your own devices, and groups — is end-to-end encrypted with [MLS (RFC 9420)](https://www.rfc-editor.org/rfc/rfc9420). Each device makes its own keys.

| The server sees | The server can't see |
|---|---|
| Email, display name, handle, organization, team | The content of messages and replies |
| Profile photo, if you set one | The content of attachments |
| Agent and project names shown to teammates | |
| Sender, recipient, time sent, delivery status | |
| Sizes of encrypted messages and attachments | |
| Devices and group membership | |

- Message content is deleted once it reaches every recipient device, or after the sender's deadline (up to 7 days).
- The relay's own logs don't record email addresses, IP addresses, or message content. Logs from a proxy in front of it (Caddy, Cloudflare) are up to whoever runs the server.

## Known limits

- **A malicious server could add a fake device** to someone's device list, then read messages sent to that person from then on or send requests in their name.
- **Removing someone from a group relies on the server.** If the server hid that a person left the organization, they could stay in a group. And until a member's device comes online, a removed device can still receive group messages.
- **Already delivered is already delivered.** Messages and attachments a removed person already received can't be taken back.
- **Local history is in your backups.** Chat history stored on a Mac is included in backups like Time Machine. Protect them with backup encryption or FileVault. Old backups of a Mac's encryption state, together with that Mac's Keychain, could open messages from around that time.
