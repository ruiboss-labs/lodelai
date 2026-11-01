# Changelog

This file is for people who run their own lodelai relay. It lists what changes for you as an operator: protocol versions, relay settings, database changes, and which app versions can connect. App features aren't listed here.

The newest version is at the top. The version number is what `lodelai-relay --version` prints, which is also the `version` in the signed manifest and the value `install.sh --version` takes.

Relay updates only move forward. The relay doesn't check the database's schema version, so to go back to an older relay, restore the program and the database copy saved before that update together ([Rolling back](SELF-HOSTING.md#rolling-back)).

Each version has these parts, in this order. A part with nothing in it is left out.

- **Before you update**: something you have to do by hand before or right after updating
- **Protocol**: the version range the relay accepts, and what was added
- **Settings**: values in `/etc/lodelai/relay.env`
- **Database**: schema changes. Going back needs the database copy saved before the update
- **Install and update**: changes to `install.sh`, `lodelai-update`, and the service files

## 0.1.1

First public release. Protocol **12**. The relay accepts `hello.v` from **9 to 12** and sends `Lodelai-Protocol: 9-12`.

### Protocol

- Devices on versions 9 to 12 work together. Version 9 is the minimum because it renamed the signing domain tags to `lodelai-*-v1`. Versions 10 to 12 only add things: 10 adds `request.no_reply`, the `done` state, `recipient_outdated`, and `v` on directory devices; 11 adds typing frames; 12 adds reactions. See [SPEC.md §3](SPEC.md#3-versioning-and-negotiation).
- Apps older than version 9, or apps that still use the product's earlier name, can't connect.
- When an app needs a newer protocol than your relay has, the app says the server is out of date and holds back its own update until you update the relay. Leaving automatic updates on avoids this.

### Settings

| Setting | |
|---|---|
| `LODELAI_MAIL`, `LODELAI_MAIL_FROM`, and `RESEND_API_KEY` or `SMTP_URL` | Required. Sign-up email ([Mail](SELF-HOSTING.md#mail)). |
| `LODELAI_PRIVACY_VERSION`, `LODELAI_PRIVACY_URL` | Required. The URL must start with `https://`. |
| `LODELAI_RELAY_DATA`, `LODELAI_PUBLIC_HOST`, `LODELAI_BEHIND_CLOUDFLARE` | Written by the installer from `--data-dir`, `--domain`, and `--tls`. |
| `LODELAI_EMAIL_HMAC_KEY` | Generated once by the installer. It isn't in backups, so move it with `relay.env` when you change servers. |
| `LODELAI_MAIL_PER_DAY` | Optional. Daily sending limit, default 80. |
| `LODELAI_GROUPS` | Optional. Empty or `true` means on, `false` means off. Any other value stops the relay from starting. |

### Database

- The relay creates `<root>/data/relay.sqlite3` on first start and upgrades the schema itself when a new version starts.
- Every update saves a copy first as `<root>/data/pre-update-<version>.sqlite3` and keeps the 3 most recent. To roll back, restore the program and that copy together ([Rolling back](SELF-HOSTING.md#rolling-back)).

### Install and update

- One-line install with `install.sh --domain <name>`. Options are listed in [SELF-HOSTING.md](SELF-HOSTING.md#install-in-one-line).
- Downloads are checked with a minisign signature and sha256 before anything is changed.
- Automatic updates are on by default. They check once a day and only take versions that have been out for 72 hours. `sudo /opt/lodelai/bin/lodelai-update` updates right away.
- `--binary <path>` installs your own build. In that case, automatic updates aren't set up.
