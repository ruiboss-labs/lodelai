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
- **Fixes**: bugs fixed that you may have noticed

## 0.2.2

Protocol stays **13**. The relay accepts `hello.v` from **9 to 13**, as in 0.2.0. There was no 0.2.1 relay.

### Fixes

- Emails for device recovery by email are sent again: requested, blocked, canceled, revoked by an admin, and done. Since 0.1.1 the relay logged a warning with `no reactor running` instead of sending them. Other emails weren't affected.

## 0.2.0

Protocol **13**. The relay accepts `hello.v` from **9 to 13** and sends `Lodelai-Protocol: 9-13`. Apps that speak 9 to 12 keep working. Apps that speak 13 can't connect to a 0.1.x relay, so update the relay before your users update the app.

### Protocol

- `session.publish` takes two optional fields: `agent` (which agent program runs the session, for example `codex`) and `no` (a number that tells apart sessions with the same name, 1 to 999). The relay stores them and puts them on directory sessions. See SPEC §3 and §6.
- A directory session carries `offline: true` when the relay marked it `dead` because the device that published it went offline, not because the owner ended it.
- Connections below 13 don't get `agent`, `no`, `offline` or `recovery.postponed` in `directory` (on connect and in answer to `directory.list`). They get `by: admin` instead of `admin_device`, and `error{protocol}` instead of `device_unconfirmed`.
- `member.revoke_device{user, device_id}`: an organization admin can revoke a target device of another member's scheduled email recovery at once (`by: admin_device`). The member gets an email. See SPEC §9.
- If an older device was connected when a recovery started, or connected after it, the relay moves `at` 24 hours later once instead of revoking. The directory shows `recovery.postponed: true`. See SPEC §9.
- If an admin revokes every target of a recovery, the recovery ends as done right away, and the requesting device gets `device.recovered` with empty `targets`.
- An admin device that isn't leaf-eligible yet gets `error{device_unconfirmed}` for organization management frames.
- `POST /v1/signup/verify` may return `approved: true` and `waitlist_url`. On a relay that needs an organization code, an email with a live code bound to it (`bootstrap --email`) can create its organization without typing the code.

### Settings

- `LODELAI_WAITLIST_URL` (optional, `https://` only): the page the app shows to a new email that has no organization code. Empty means the app shows the code field as before.

### Database

- Five new columns, all empty or `0` on old rows:
  - `sessions_public`: `agent`, `no`, `offline`
  - `recoveries`: `seen_after`, `deferred`
- An older relay still opens the database, so you can roll back the program alone. While rolled back, a scheduled recovery runs at its time without being postponed. Apps that already speak 13 stop connecting until you update again.
- Leaving or being removed from an organization now also deletes that user's recovery and block records. Revoking a device clears its last sign-in time.
- Organization codes are deleted 30 days after they expire. Until then the relay keeps them to tell the app that a code has expired.

### Install and update

- Running `install.sh` again on the same version now restarts the relay, so changed `relay.env` values take effect. Before, if the relay was stopped, it stayed stopped. `lodelai-update` on the same local build starts the relay if it's stopped.

## 0.1.2

Protocol stays **12**. Organization codes from `bootstrap` can now be bound to an email, and several can be live at once.

### Before you update

- If you installed with `--operator`, run `install.sh` once more with the same options after updating. Updates don't rewrite `/etc/sudoers.d/lodelai-update`, and the new `bootstrap` options need the new lines.

### Database

- The single-row `setup_code` table becomes `setup_codes` (one row per code). An unused code is moved over with the time it has left, and the old table is dropped.

### Install and update

- `lodelai-relay bootstrap --data <dir> --email <address> [--ttl 7d]` issues a code that only works for a sign-up confirmed with that email. It lasts 7 days by default, 14 days at most. A new code for the same email replaces the old one.
- `bootstrap` without `--email` works as before: 1 hour, and it replaces only the previous code that has no email.
- `bootstrap --list` shows each live code's id, a partly hidden email, and when it expires. It never shows codes. `bootstrap --revoke <id>` deletes one.
- Wrong codes no longer delete the code after 5 tries. Instead code checks pause for an hour (`429` with `Retry-After`): after 5 wrong codes for one sign-up email (that email only), 20 code tries of any kind from one IP address (that address only), or 200 code tries in total (everyone), each counted within an hour.
- A correct code that has expired, or that belongs to another email, is refused with a reason (`setup_code_expired`, `setup_code_other_email`) and a message the app can show. These don't count as wrong tries.

## 0.1.1

First public release. Protocol **12**. The relay accepts `hello.v` from **9 to 12** and sends `Lodelai-Protocol: 9-12`.

### Protocol

- Devices on versions 9 to 13 work together. Version 9 is the minimum because it renamed the signing domain tags to `lodelai-*-v1`. Versions 10 to 13 only add things: 10 adds `request.no_reply`, the `done` state, `recipient_outdated`, and `v` on directory devices; 11 adds typing frames; 12 adds reactions; 13 adds `agent` to published sessions so people can see which agent program runs each one, and `no`, the number the owner sees next to sessions that share a name. A relay on 13 leaves both fields out of the full directory it sends to apps on 12 or older. See [SPEC.md §3](SPEC.md#3-versioning-and-negotiation).
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
