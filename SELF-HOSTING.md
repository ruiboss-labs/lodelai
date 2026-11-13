# Self-hosting the lodelai relay

This guide is for running the lodelai relay server on your own machine, so your organization's messages go through a server you control.

The relay only passes messages along. Message content is encrypted between devices, so no readable text is ever stored on the server. The only secrets on the server are your own settings: your mail key and your backup public key.

## Requirements

- **OS:** Ubuntu 22.04+ or Debian 12+, with systemd, on x86_64 or arm64. On anything else, the installer stops at the start.
- **Root access (sudo):** the installer uses `apt-get` to install `curl`, `jq`, `minisign`, `age`, and `sqlite3`, plus `caddy` with `--tls caddy`. On Ubuntu, the universe repository must be enabled.
- **A public domain** (for example, `relay.example.com`) that can be reached from outside. With the default (Caddy), ports 80 and 443 must be open to get a certificate.
- **A way to send sign-up email:** a Resend API key or an SMTP server. Sign-up uses email codes, so this is required.
- **Your privacy policy's URL (https).** Handling personal data is the operator's responsibility.

## Install in one line

```sh
curl -fsSL https://updates.lodelai.com/relay/install.sh | sudo bash -s -- --domain relay.example.com
```

| Option | What it does |
|---|---|
| `--domain <name>` | Required. The relay's public address, which is also its server name (see [Choosing a domain](#choosing-a-domain)). |
| `--tls caddy\|cloudflare\|none` | How outside connections reach the relay. `caddy` (default) installs Caddy with `reverse_proxy 127.0.0.1:8787` and gets certificates automatically. With `cloudflare`, you create a Cloudflare Tunnel yourself (`domain → http://127.0.0.1:8787`). With `none`, you run your own proxy. **The relay itself doesn't do TLS and listens only on `127.0.0.1:8787`.** |
| `--data-dir <root>` | Default `/var/lib/lodelai`. An absolute path with only letters, digits, and `/ . _ -`. Creates `data/` (the database, owned by `lodelai`, mode 0700) and `backup/` under it. |
| `--require-mount` | Installs or resets only if the root is on a separate file system (its own disk), not on `/`. |
| `--operator <user>` | Lets that user run `sudo /opt/lodelai/bin/lodelai-update`, `sudo /opt/lodelai/bin/lodelai-reset` (no arguments, full path — they aren't on sudo's PATH), and the commands for creating an organization and suspending an account, without a password. Without this option, no sudoers rule is added and root runs them. |
| `--version <x.y.z>` | Installs that version (default: latest). |
| `--no-auto-update` | Doesn't set up the automatic update timer (see [Automatic updates](#automatic-updates)). |
| `--binary <path>` | Installs a `lodelai-relay` you built yourself instead of a signed release (see [Using your own build](#using-your-own-build)). Can't be used with `--version`. |

The first run creates `/etc/lodelai/relay.env`. If any required value is empty, it stops **before changing the relay** and tells you in one line what to fill in. Fill it in and run the same command again. Running it again any number of times gives the same result.

The installer checks every download. If anything doesn't match, it stops without changing anything.

1. It checks the signature on `relay/latest.json` (or `relay/<version>/manifest.json`). It's signed with a minisign key used only for the relay, and the public key is built into the install script.
2. It trusts the version, publish time, and sha256 only from inside the signed manifest.
3. It checks the downloaded tar's hash before unpacking it. The tar contains `lodelai-relay` together with the service files and scripts (`deploy/`).

## Mail

In `/etc/lodelai/relay.env`:

| Setting | Also needs |
|---|---|
| `LODELAI_MAIL=resend` | `RESEND_API_KEY` and `LODELAI_MAIL_FROM` |
| `LODELAI_MAIL=smtp` | `SMTP_URL` (`smtps://user:password@host:465`, or `smtp://…:587` with STARTTLS required) and `LODELAI_MAIL_FROM` |
| `LODELAI_MAIL_PER_DAY` | Daily sending limit (default 80) |
| `LODELAI_REPORT_EMAIL` | Where reports from the app go (for example, `report@example.com`). Needs mail sending above. If it's empty, the app doesn't show Report for this server. If it isn't an email address, or mail sending isn't set up, the relay names it in one line and doesn't start. Each report is mailed to this address right away; the relay keeps only who reported whom, the reason and the time (30 days), and the reported messages exist only in the mail |
| `LODELAI_INVITE_MAIL=on` | Send invite mail to people who haven't signed up (off by default). This sends mail to other people from your sending address. Invites made while it's off wait up to 30 days and go out if you turn it on within that time. |

`LODELAI_MAIL_FROM` is required either way (for example, `"lodelai <noreply@mail.example.com>"`). If a value is missing, the relay names it in one line and doesn't start.

After changing a value, run `sudo systemctl restart lodelai-relay`. Don't paste keys into chats or issues.

## Phones

Mobile notifications work only with the lodelai hosted server. On your own server, the mobile apps get messages while they're open, without notifications.

## Privacy policy

Set `LODELAI_PRIVACY_VERSION` (the version, which is its effective date) and `LODELAI_PRIVACY_URL`, which must start with `https://`. The app opens **the URL of the server it's connected to** on the sign-up screen and in Settings › About. If either is empty, the installer stops.

## Group chats

`LODELAI_GROUPS` turns group chats on or off. Empty means on, and `false` means off. Any value other than `true` or `false` stops the relay from starting. After changing it, run `sudo systemctl restart lodelai-relay`.

## First admin

On a new database, the installer shows a one-time code for creating an organization at the end (valid for 1 hour, single use). In the app, sign up, confirm the email code, choose **Create a new organization**, and enter that code. That person becomes the first admin. To get another code (the previous code without an email stops working):

```sh
sudo -u lodelai /opt/lodelai/bin/lodelai-relay bootstrap --data /var/lib/lodelai/data
```

To give codes to the first admins of several organizations, bind each code to an email. Only a sign-up confirmed with that email can use it, once. It lasts 7 days by default, up to 14 days with `--ttl` (`14d`, `36h`). A new code for the same email replaces the old one. If someone uses it with another email, or after it expires, the app shows why.

```sh
sudo -u lodelai /opt/lodelai/bin/lodelai-relay bootstrap --data /var/lib/lodelai/data --email boss@example.com [--ttl 7d]
sudo -u lodelai /opt/lodelai/bin/lodelai-relay bootstrap --data /var/lib/lodelai/data --list          # id, partly hidden email, expiry (never the code)
sudo -u lodelai /opt/lodelai/bin/lodelai-relay bootstrap --data /var/lib/lodelai/data --revoke <id>   # delete one code
```

`--email` prints four lines: `code:`, `id:`, `expires:`, and `email:`.

## Who can sign up

By default, anyone who confirms an email code can sign up with a personal space and connect with others as contacts. To let in only people invited to an organization, set `LODELAI_PERSONAL_SIGNUP=off` in `/etc/lodelai/relay.env` and run `sudo systemctl restart lodelai-relay`. The default is `on`. Any other value stops the relay from starting.

With it off:

- Signing up needs an organization invite or a code for creating an organization. The app shows the invite code field.
- Contact and group invites to email addresses that haven't signed up don't send mail. Organization invites still do.
- Members can't leave their organization for a personal space. They can still delete their account.
- Existing personal spaces stay as they are.

If organization creation is open (`--org-create open`), anyone can still sign up by creating an organization, and the relay logs a warning at start. For invited people only, keep it at `code`, the default.

Wrong codes don't delete a code. Instead code checks pause for an hour (`429` with `Retry-After`) after 5 wrong codes for one sign-up email (that email only), 20 code tries of any kind from one IP address (that address only), or 200 code tries in total (everyone), each counted within an hour.

If you installed with `--operator` before relay 0.1.2, run `install.sh` once more with the same options after updating. Updates don't rewrite `/etc/sudoers.d/lodelai-update`, and the operator needs the new lines to run `--email`, `--list`, and `--revoke` without a password. The same goes for `suspend` and `unsuspend`, added in relay 0.3.1.

## Choosing a domain

Pick a `--domain` that's **fine to make public**. The server name is part of every address (`user@<server>/<session>`), so it ends up in teammates' and agents' conversation history. Don't use internal network names or people's names.

## Backups

- Every day at around 04:30 (server time, up to 10 minutes later), a copy of the database is saved to `<root>/backup/relay-<time>.sqlite3.gz`. The 7 most recent copies are kept.
- An off-site copy is optional. Put S3-compatible storage settings (`R2_ACCOUNT_ID`, `R2_BUCKET`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`) and an age public key (`AGE_RECIPIENT=age1…`) in `/etc/lodelai/backup.env`, and **only copies encrypted with age** are uploaded. Without a public key, nothing unencrypted leaves the server. The private key is never kept on the server.
- `LODELAI_EMAIL_HMAC_KEY` lives outside the database (in `relay.env`), so it isn't in backups. When you move servers, move `relay.env` too. If this key changes, someone who left and comes back with the same email won't get the same ID.
- Monitoring: put healthchecks-style ping URLs in `HC_RELAY_URL` and `HC_BACKUP_URL` in `backup.env`. The relay's outside health check is reported every 5 minutes, and each backup's result after it runs. Leave them empty to turn this off.

## Automatic updates

- On by default. `lodelai-autoupdate.timer` checks for the latest version once a day (04:00 plus a random 0–60 minutes). It **only takes versions that have been out for 72 hours** (already running on our hosted relay). If a version's publish time is later than the server's clock, it suspects the clock, skips the update, and logs one line.
- Each update goes: check the signature → back up the database (`<root>/data/pre-update-<version>.sqlite3`, 3 most recent kept) → replace the program → restart → check health. If anything fails, it rolls back **the program and the database together**.
- To turn it off: install with `--no-auto-update`, or run `sudo systemctl disable --now lodelai-autoupdate.timer`.
- To update by hand: `sudo /opt/lodelai/bin/lodelai-update` (latest version, no 72-hour wait), or `sudo /opt/lodelai/bin/lodelai-update --version <x.y.z>` (that version, root only).
- Running `install.sh` again with the same options keeps your settings. From relay 0.2.0 it restarts the relay even on the same version, so changed `relay.env` values take effect and a stopped relay starts again.
- Results: `journalctl -u lodelai-autoupdate`. If the relay falls behind and the app needs a newer protocol version, the app shows that the server is out of date and holds its own update until the relay is updated.
- When we change the signing key, we first publish the new public key signed with the old one (`relay/next-key.pub` and `.minisig`). The server checks it, switches to `/etc/lodelai/relay-signing.pub`, and from then on trusts only the new key. There's nothing for you to do.

## Commands

Run all of these as root (sudo). A user set with `--operator` can run the ones marked ○ without a password.

| Command | What it does | Operator |
|---|---|---|
| `/opt/lodelai/bin/lodelai-update` | Updates from the source in `/etc/lodelai/update.env` (the latest signed release, or your own build). No 72-hour wait | ○ |
| `/opt/lodelai/bin/lodelai-update --version <x.y.z>` | Updates to that version (lower versions too) | root only |
| `/opt/lodelai/bin/lodelai-update --binary <path>` | Updates to your own build | root only |
| `/opt/lodelai/bin/lodelai-reset` | **Deletes every account, organization, and message.** First saves the whole data folder to `<root>/backup/reset-<time>.tar.gz` (3 most recent kept). Does nothing while a backup is running | ○ |
| `sudo -u lodelai /opt/lodelai/bin/lodelai-relay bootstrap --data <root>/data` | Issues another code for creating an organization (1 hour, single use) | ○ |
| The command above + `--email <address> [--ttl 7d]`, `--list`, `--revoke <id>` | Issues a code bound to an email (7 days, up to 14), lists live codes, deletes one | ○ |
| `sudo -u lodelai /opt/lodelai/bin/lodelai-relay suspend --data <root>/data --user <id> [--for 7d]` | Suspends an account (without `--for`, until you lift it). The running relay closes that person's connections within a minute | ○ |
| `sudo -u lodelai /opt/lodelai/bin/lodelai-relay unsuspend --data <root>/data --user <id>` | Lifts a suspension | ○ |
| `systemctl restart lodelai-relay` | After changing `relay.env` | root |
| `journalctl -u lodelai-relay`, `-u lodelai-autoupdate`, `-u lodelai-backup` | Logs | root |

Every update takes the same path: check signature and hash → back up the database → replace → restart → check health. If it fails, the program and database are rolled back together.

## Using your own build

To run a `lodelai-relay` you built from this repository (not signed with our key):

```sh
sudo deploy/relay/install.sh --domain relay.example.com --binary /home/me/src/relay/target/release/lodelai-relay
```

- Run `deploy/relay/install.sh` from your checkout of this repository. It takes the service files and scripts from there.
- The path is saved in `/etc/lodelai/update.env` as `LODELAI_UPDATE_SOURCE=binary:<path>`, and `lodelai-update` (with no arguments) reads it from then on. After rebuilding, run `sudo /opt/lodelai/bin/lodelai-update`.
- **Automatic updates are not set up** (the log says `unsigned local binary — no automatic update timer`). To go back to signed releases, run `install.sh --domain …` again without `--binary`.
- Every part of the path, from `/` down to the file, must be closed to writes by other users. If any part isn't, it stops — so a file someone else swapped in is never started as root.

## If it stops

When the installer or an update finds a problem, it changes **nothing** and stops with one line, `lodelai: <reason>`. Common ones:

| Message | What to do |
|---|---|
| `fill in … in /etc/lodelai/relay.env, then run again` | Fill in those values and run the same command again ([Mail](#mail), [Privacy policy](#privacy-policy)). |
| `LODELAI_PRIVACY_URL in … must start with https://` | Use an https URL for your privacy policy. |
| `apt-get install … failed` | On Ubuntu, run `sudo add-apt-repository universe`, then try again. |
| `unsupported distribution`, `systemd isn't running`, `unsupported CPU` | Outside the [requirements](#requirements). If you're in a container, use a VM that runs systemd. |
| `… isn't on a separate disk — stopping (--require-mount)` | Attach a disk and put the `--data-dir` root on it. |
| `manifest signature doesn't match`, `tar hash doesn't match the manifest` | The download was changed on the way. Check your proxy or mirror. If it keeps happening, [open an issue](https://github.com/ruiboss-labs/lodelai/issues). |
| `relay signing public key is empty` | The install script isn't an official release. Download it again from the one-line install URL above. |
| `relay didn't start on the new version` | Already rolled back. Check the log above and `journalctl -u lodelai-relay`. |
| `the new version didn't start — recent log:` followed by `rolled back the program and database to: <version>` | The update failed, and the program and database were rolled back together. The relay is running the previous version. Please [report the log](https://github.com/ruiboss-labs/lodelai/issues). |
| `the new version didn't start` followed by `the previous version (<version>) won't start either` | Roll back by hand ([Rolling back](#rolling-back)). |
| `apt-get update failed` | Check your network and apt repository settings, then run again. |
| `couldn't enable systemd units`, `couldn't start the backup and health timers` | Find out why with `systemctl status lodelai-backup.timer` and similar. |
| `writable by other users: <path>` | Close write access on the `--binary` path with `chmod go-w`. |

## Rolling back

If automatic rollback failed, or you find a problem after an update (as root):

```sh
ls -1t /opt/lodelai/bin | grep '^lodelai-relay-'           # versions kept (5 most recent)
ls -1t /var/lib/lodelai/data | grep '^pre-update-'         # databases saved before each update (3 most recent; the version in the name is the new version being installed)
sudo systemctl stop lodelai-relay
sudo rm -f /var/lib/lodelai/data/relay.sqlite3-wal /var/lib/lodelai/data/relay.sqlite3-shm
sudo install -o lodelai -g lodelai -m 0600 /var/lib/lodelai/data/pre-update-<version>.sqlite3 /var/lib/lodelai/data/relay.sqlite3
sudo ln -sfn lodelai-relay-<previous version> /opt/lodelai/bin/lodelai-relay
sudo systemctl start lodelai-relay && curl -sS http://127.0.0.1:8787/v1/healthz
```

The version in `pre-update-<version>.sqlite3` is **the new version that was being installed** — it's the database from just before switching to that version. If that version caused the problem, restore that file. Restoring the database loses any sign-ups and queued messages since the backup. If you only need to roll back the program (the schema only ever adds), you can skip the database lines.

## File locations

| Path | |
|---|---|
| `/opt/lodelai/bin/lodelai-relay` | Link to the current version → `lodelai-relay-<version>` |
| `/opt/lodelai/bin/lodelai-update`, `lodelai-reset`, `lodelai-backup`, `lodelai-health` | Scripts (updated along with signed releases) |
| `/opt/lodelai/lib/install.sh` | The update engine (updated along with them) |
| `/etc/lodelai/relay.env`, `backup.env` (root:lodelai 0640) | Settings and secrets |
| `/etc/lodelai/update.env` | Update source (`release`) |
| `/etc/lodelai/relay-signing.pub` | The signing public key after a key change (if absent, the key built into the install script) |
