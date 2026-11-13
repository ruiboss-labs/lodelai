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

## 0.3.1

Protocol stays at **16**. The relay accepts `hello.v` from **9 to 16**. Apps from 0.2.0 on keep working.

### Protocol

- `Lodelai-Features` now also lists `link_block` (always) and `report` (only when `LODELAI_REPORT_EMAIL` is set, see Settings). `no_duty` is now listed always, not only when phone push is set up. `org_leave` isn't listed when `LODELAI_PERSONAL_SIGNUP` is `off`.
- `report{req, peer, reason, group?, note?, messages}` sends a report about a person, with the messages the reporter picked. The relay mails it right away to `LODELAI_REPORT_EMAIL` and doesn't store the messages or the note anywhere. The answer is `report.sent{req}`, also when the account doesn't exist or is the reporter, so the answer doesn't show whether an account exists (no mail goes out then). Over the limit it's `error{rate_limited, until, ref}`, and if the mail can't be sent it's `error{internal, ref}`. More than 20 messages, a message over 4000 characters, or a note over 1000 characters is `error{protocol, ref}`. The reported person gets nothing.
- `link.block{req, peer}` blocks someone you already know: a member of your organization, or someone you have a contact or a contact request with. The answer is always `link.sent{req}`. For anyone else, or yourself, nothing changes. The other person gets nothing. `link.unblock` lifts it.
- The directory has a new top-level `blocked`: everyone you blocked, contacts included. Only connections whose `hello` has `blocks: true` get it, and only from an approved device.
- A device that isn't approved yet gets `error{device_unconfirmed, ref}` for `report`, `link.block` and `link.unblock`.
- A device that isn't approved yet gets `error{device_unconfirmed}` without `ref` for `server.status` (added to `UNCONFIRMED_REF_LESS_FRAMES`). Before, it could read the server status.
- When personal sign-up is off, the sign-up confirmation answer for a new address carries `personal: "closed"`, and a personal-space sign-up gets 403 `org_create_closed`.

### Settings

- `LODELAI_PERSONAL_SIGNUP=off` (or `--personal-signup off`): only people invited to an organization can sign up. Default `on`. Remote relays only.
  - A new personal-space sign-up gets 403 `org_create_closed`. Apps from 0.3.0 show the invitation code field for it. Existing personal-space accounts stay.
  - Contact and group invitation mail to people who haven't signed up isn't sent, because they couldn't sign up. Organization invitation mail still goes. The sender's app shows the invitation the same way either way.
  - Leaving an organization for a personal space isn't possible (`org_leave` isn't listed and `org.leave` is refused). Deleting the account is the way out.
  - If `--org-create` is `open`, anyone can still create an organization and sign up that way, and the relay logs a warning when it starts. For invited people only, use `--org-create code` too.
- `LODELAI_REPORT_EMAIL`: where reports from the app go. Unset by default, and then the apps don't show Report. Needs mail sending set up. If the value isn't an email address, or the relay is local, it doesn't start. The relay keeps only who reported whom, the reason, and when, for 30 days. Limits per 24 hours: 3 for one reporter about one person, 10 per reporter, 500 for the relay.

### Database

- New table `reports` (`reporter`, `reported`, `reason`, `at_ms`). Rows older than 30 days are deleted. Deleting an account deletes the reports that person made.
- New column `links.rerequested_ms`.
- The relay adds both the first time 0.3.1 starts. Nothing to do for operators.
- Deleting an account now also clears its profile look (`users.look_json`).

### Install and update

- The `--operator` sudoers entry now also covers `lodelai-relay suspend` and `unsuspend` (as `lodelai`, on your data folder only). Updates don't rewrite `/etc/sudoers.d/lodelai-update`, so run `install.sh` once more with the same options to get the new lines. Until then, run them as root.
- `install.sh` now stops if `--data-dir` has characters other than letters, digits, and `/ . _ -`, because the path goes into the sudoers rule.

### Fixes

- Invitation mail from a self-hosted relay now carries your relay's address: the link is the lodelai website's `/i/#s=<your host>` and the mail says the server address. Apps that know it fill it in at sign-up. The hosted server's mail is unchanged.
- On a relay without phone push, a phone no longer gets group tasks such as adding a new device or removing a revoked one. Before, `no_duty` wasn't listed there, so the task waited while the phone app was in the background.
- When an organization blocks outside contact, someone outside who taps "Request again" now sees the request as sent, the same as a declined request. Before, nothing happened. The organization's member still sees nothing.
- A device revoked while a group change that adds it was still being confirmed is now removed from that group afterwards. Before, its slot could stay.
- When someone in a personal space joins an organization, pending contact requests between them and its members are removed.
- The server status no longer warns about disk space on large disks with plenty of room left. `disk_low` is now a warning when free space is under the smaller of 15% of the disk and 20 GB, and a problem under the smaller of 5% and 5 GB. Before, it warned under 15% or under 2 GB, so a 1 TB disk with 50 GB free showed a warning.

## 0.3.0

Protocol is now **16**. The relay accepts `hello.v` from **9 to 16** and sends `Lodelai-Protocol: 9-16`. Apps from 0.2.0 on keep working: the relay leaves out of their frames what they don't know.

### Before you update

- Update the relay before your users update the app. A 0.3.0 app still connects to a 0.2.x relay: it reads the range the relay announces and speaks 14 to it, so the newer features stay hidden until the relay is updated.
- Invitation mail from a self-hosted relay still links to the lodelai website, and the link doesn't carry your relay's address. Tell invited people your server address. A later 0.3.x version adds it to the link.
- A device that isn't approved yet is now limited on every app version (see Protocol). On an older app, a new device waiting for approval gets its messages refused until it is approved, and at that moment its connection is closed once and it connects again.
- People can now sign up to your relay without an organization code. A new account can choose a personal space (`org: "personal"`), which needs only a confirmed email. This doesn't depend on `--org-create`, and there is no setting to turn it off. What limits it is the daily sign-up mail limit (`LODELAI_MAIL_PER_DAY`) and the daily new-account limit per IP address, which is shared with organization creation (`--org-create-per-ip-day`, default 5). Someone in a personal space can reach only people who accept their contact request. Creating an organization from a personal space still needs an organization code when `--org-create` is `code`.

### Protocol

- `Lodelai-Features` now also lists these. Always: `device_os`, `own_control`, `own_alert_kinds`, `history_transfer`, `org_leave`, `link_unblock`, `org_color`, `lists`, `org_external`, `org_external_preview`, `look`, `org_move`, `mutes`, `pins`, `away`. When the relay has `LODELAI_EMAIL_HMAC_KEY` (always on a public relay): `contacts`. Only when phone push is set up (see Settings): `push`, `push_prefs`, `push_multi`, `no_duty`, `own_live`.
- 15 adds `online` and `os` to the devices in your own directory entry, and `os` to `device.name`. Connections below 15 don't get them.
- 16 adds messages between your own devices (`own_control`, `own_control_result`, `own_delete`, sent only in your own MLS group), `own_stream` (relayed live between your own devices, not stored), `own_alert` (a fixed-text push to your devices that aren't connected), and `reply_to` on `request`. A message that carries `reply_to` has `v` 16. Other messages keep their `v`.
- New frames for contacts (`link.*`, including `link.unblock` to lift a block you set), invitations to organizations and groups (`org.invite`, `group.invite`), joining or creating an organization from a personal space (`org.code.check`, `org.join`, `org.create`), leaving an organization for a personal space (`org.leave`), friend lists (`list.put`, `list.delete`), mute and pin (`mute.set`, `pin.set`), a profile look (`profile.update.look`), and an organization color and outside-contact setting (`org.update`). The directory gets matching fields. A connection gets each of them only if its `hello` says it knows them (`contacts`, `look`, `mutes`, `pins`, `away`) or if it speaks 16.
- `link.unblock{req, peer}` removes only your block on that person. It doesn't make them a contact or send a request. The answer is `link.sent` with the same `req`, also when there was no block, the ID doesn't exist, or it's you, so the answer doesn't show whether an account exists. The other person gets nothing. Apps send it only when the relay lists `link_unblock`.
- When you take back a contact request (`link.withdraw`), the other person also gets a directory update, so the request leaves their list right away. It is sent whether they were still deciding or had declined, so it doesn't show which.
- `error{daily_quota, until}` is new for `blob.reserve`. Connections below 16 get `quota` instead.
- On connect, `key_packages.low` can carry `last_resort: false`. Connections below 16 don't get it.
- A device that isn't approved yet can keep its connection, read its own data, set up its own keys and name, register for push, recover or sign out this device, and acknowledge messages. Typing, presence, profile, and session publishing from it are dropped. Anything else is refused with `error{device_unconfirmed}` (`protocol` below 13) when the frame has a `req` or `msg_id`. Organization management frames get it without `ref`. Its directory shows only its own entry, without friend lists. This applies whatever `hello.v` it speaks. When the device is approved, the relay sends `error{approved}` and closes the connection, and the app connects again. Apps below 16 don't know `approved`, but the connection is closed either way.
- An account you suspend (see Install and update) gets `account_suspended` with when it ends. Apps that don't know it get `error{protocol}`.

### Settings

- `LODELAI_BLOB_DAILY_MAX_BYTES` (or `--blob-daily-max-bytes`): how many bytes of attachments one account can reserve in a UTC day. Default 2147483648 (2 GiB). `0` turns it off. Profile and organization pictures aren't counted. Moving chat history to a new device has its own limits of the same size, and `0` turns those off too. If the value isn't a number, the relay doesn't start.
- `LODELAI_INVITE_MAIL=on`: email invitations to people who haven't signed up. Off by default. Invitations made while it's off are kept for 30 days and go out if you turn it on within that time. Limits are fixed: 5 a day per sender, 3 per address in 30 days, 50 a day per organization, and 2000 a day for the relay. The mail links to the lodelai website to get the app, and to `https://<your domain>/v1/mail/stop` for opting out. The link doesn't carry your relay's address yet, so the app signs up to the default server unless the person enters yours. Tell invited people your server address until a later version adds it to the link.
- `LODELAI_CONTACT_EMAIL` (optional): a contact address shown in invitation mail.
- Phone push. The relay sends a push to a phone that isn't connected only when these are set. Without them it doesn't advertise `push`, and phones still get messages when they connect.
  - APNs: `LODELAI_APNS_KEY_FILE`, `LODELAI_APNS_KEY_ID`, `LODELAI_APNS_TEAM_ID`, `LODELAI_APNS_TOPIC`. Set all four or none.
  - FCM: `LODELAI_FCM_SERVICE_ACCOUNT_FILE` and `LODELAI_FCM_APP_ID`.
  - The credentials must belong to the app build your users run. The relay accepts a phone's registration only if its app ID matches `LODELAI_APNS_TOPIC` or `LODELAI_FCM_APP_ID`.
  - The published lodelai phone apps use their publisher's push credentials, so on a self-hosted relay push stays off for them. Phones get their messages when the app connects.
  - Key files must be regular files (not links) that only the service user can read (`0600`), outside `/home`, for example in `/etc/lodelai/`. If a value is missing or a file is wrong, the relay names it in one line and doesn't start.
  - Pushes carry only ciphertext or a fixed notification type, never names or message text.

### Database

- New tables: `links`, `link_invites`, `link_counts`, `contact_links`, `org_invites`, `group_invites`, `invites_sent`, `signup_pending`, `mail_jobs`, `mail_log`, `mail_blocks`, `lists`, `mutes`, `pins`, `blob_daily`, `blob_history_daily`, `push_tokens`, `mls_duty_sent`.
- New columns, empty or default on old rows:
  - `devices`: `own`, `os`, `away`
  - `users`: `look_json`, `suspended_ms`, `suspended_until`, `throttled_until`
  - `orgs`: `kind` (`org` on old rows), `color`, `external`
  - `blobs`: `for_device`
  - `blocks`: `at_ms`
  - `group_members`: `left_org`
- The relay adds them the first time 0.3.0 starts. Nothing to do for operators. Existing rows aren't rewritten.

### Install and update

- `install.sh`, `lodelai-update`, and the service files didn't change.
- `sudo -u lodelai /opt/lodelai/bin/lodelai-relay suspend --data /var/lib/lodelai/data --user <id> [--for 7d]` suspends an account. Without `--for` it stays suspended until `lodelai-relay unsuspend --data <dir> --user <id>`. The running relay closes that person's connections within a minute, and they can't sign in or add a device until it ends. Leaving an organization doesn't end it. The `--operator` sudoers entry covers only `bootstrap`, so run `suspend` and `unsuspend` as root.

### Fixes

- A group change is confirmed right away when no member who could answer is connected and nobody answered `commit_fail`. Before, it waited the full 60 seconds, so adding a new device to a group whose members were all offline took over a minute.
- A new device that uploads its first KeyPackages some time after it was approved now joins its conversations. Before, a member device that had already been asked to add it didn't get asked again while it stayed connected.
- When a device is removed after an email recovery, members get the directory update before the group task. Before, the new device could keep backing off for up to a minute.
- A device that comes back after more than 90 days uploads a new last-resort KeyPackage when it runs a 0.3.0 app. Before, the relay counted the expired one as still there. Older apps behave as before.
- A `delivered_ack{unreadable: true}` over the limit of 100 an hour is now dropped instead of being counted as an ordinary ack. Before, the sender saw those messages as received and they were never sent again. The device reports them again on its next connection.
- Two devices of one person registered in the same millisecond, or after the relay's clock went back, can no longer swap which one counts as the first device.
- The relay logs one `info` line when it refuses a device registration, with the reason but no email or user name.

## 0.2.7

Protocol stays at **14**. `group_alert` takes a new `reason`. Apps that don't know it drop that one frame and stay connected.

### Protocol

- `group_alert` has a new `reason: duty_stuck`. When the relay hands a group task to a device (removing a revoked device, removing someone who left the organization, adding a member's new device), and that device's Commit is voided 3 times, the relay sends this to the group's admin devices once. Its optional fields say what is stuck: `task`, `subject` (the person), `subject_device`, `failed` (who couldn't process it), and `stale_clients` (those of them whose device runs an older app). When the task is finally done, the relay sends the same frame again with `done: true`. Admin devices that were offline get the open alerts when they connect.
- In a `duty_stuck` alert, `by` is who sent the last voided Commit and `count` is how many times that task's Commit was voided. `commit_unprocessed` alerts are unchanged.

### Database

- `mls_duties` gets three columns: `voids`, `next_ms`, `voided_by`. There is a new table `mls_duty_stuck`. The relay adds both the first time 0.2.7 starts. Nothing to do for operators.

### Fixes

- A group task no longer repeats every hour without end when one connected member keeps failing its Commit. The next try goes to a different device first. After 3 voided tries the relay waits a day between tries and tells the admins. The task is never dropped, so a revoked device's slot in the group is still removed once a try succeeds. A revoked device can't connect in the meantime, so it doesn't receive group messages.
- When someone recovers their account on a new device and some group members are offline, the new device joins the group right after the old device is removed. Before, it could wait up to another minute because nothing told it that the removal was done. The relay now sends `rejoin_needed` again to that new device at that moment.

## 0.2.6

Protocol is now **14**. The relay accepts `hello.v` from **9 to 14**. The additions below are optional, so apps from 0.2.0 on keep working. A 0.2.6 app sends the new field only to a relay that lists `unreadable_ack` in `Lodelai-Features`.

### Protocol

- `Lodelai-Features` now also lists `unreadable_ack`. For example it reads `groups,device_name,kp_reset,unreadable_ack`.
- `delivered_ack` takes an optional `unreadable: true`. It means the receiving device got the message but couldn't open it. The relay counts that device as having received it, but doesn't send `received` to the sender. About 30 seconds later, once that device is back in step with the conversation, the relay sends the sender `status{state: failed, fail_reason: recipient_unreadable, by}`. The sending app then sends the same message again once, and the relay delivers that copy only to the device that reported. If that copy can't be opened either, the sender gets `recipient_unreadable_final`. The relay sends neither to connections below `hello.v` 14. Each device can report at most 100 messages an hour. Reports beyond that count as ordinary acks.

### Database

- New table `unreadable_reports`. Rows are deleted when the message's retention ends.
- `setup_codes` gets a column `email_keyed`. An email bound to an organization setup code is now stored keyed with `LODELAI_EMAIL_HMAC_KEY`, like the other email values. `lodelai-relay bootstrap` doesn't read that key, so it still writes the plain hash. The running relay rewrites such rows within 30 seconds and when it starts, and keeps only the newest code for each email. Existing rows are rewritten the first time 0.2.6 starts. Nothing to do for operators. A relay started without that key, as in local development, leaves them as they are.

### Fixes

- A group change no longer waits up to an hour for a device that stays connected but never answers `commit_ack` or `commit_fail`. Five minutes after delivery, the relay treats it as not connected and confirms the change. If any member answered `commit_fail`, it still waits.
- A group whose creation failed, and that its creator didn't create again, is now deleted 30 days after it was started. Before, it stayed in the database.
- `groups` (and the reply to `groups.list`) no longer lists a group whose creation hasn't finished (`seq` 1). Before, the creator's other devices could join such a group on their own, and the creator then couldn't start it again.
- A device of someone who left a group no longer gets `rejoin_needed` for that group.
- Without `RUST_LOG` the relay now logs at `info` to stderr. Before, it logged only errors, so a relay started without `relay.env` left an empty log. Color codes are written only when stderr is a terminal, so journald and log files stay plain text. Logs never carry message bodies, emails, codes, or keys.

## 0.2.5

Protocol stays **13**. The relay accepts `hello.v` from **9 to 13**, as in 0.2.2. There were no 0.2.3 or 0.2.4 relay releases. The additions below are optional fields that older apps don't send, so apps from 0.2.0 on keep working. A 0.2.5 app sends the new field only to a relay that lists `kp_reset` in `Lodelai-Features`.

### Protocol

- `Lodelai-Features` (on the WebSocket upgrade and on `GET /v1/healthz`) now always lists `kp_reset`. For example it reads `groups,device_name,kp_reset`, or `device_name,kp_reset` with groups off.
- `key_packages.publish` takes an optional `reset: true`. The relay deletes that device's remaining KeyPackages (regular and last-resort) and stores the new ones in the same transaction. An app sends it on its first upload after its local data was lost, for example after reinstalling on the same Mac.
- `error{rate_limited}` for `key_packages.claim` now carries `until`, the earliest time the same claim works again. The daily claim limit for one user claiming one device's KeyPackages is now 25 (was 10). The limit of 50 claims a day per target device is unchanged.

### Fixes

- A group member change (add, remove, rename, admin change, key update) no longer waits for members who are offline. Once every member with a connected device has answered `commit_ack`, the relay confirms the change right away. Before, one offline member made everyone wait the full 60 seconds, so a person added to a group saw the group only after up to a minute.
- If no member who can answer is connected when the 60-second window ends, and nobody answered `commit_fail`, the relay now confirms the change instead of holding it for up to an hour. Members who come back later receive the confirmed change and catch up.
- Group changes no longer wait for a device that is in the middle of rejoining that group. It can't answer until it has rejoined.
- Members who were offline during a key update or a rejoin in a group can read that group's later messages again. The confirmed change now carries the group's current sequence number.
- If creating a group failed partway, the same person can now try again from the same device. Before, the leftover empty group made every retry fail.
- When the app is reinstalled on the same device and its local data is lost, the relay now drops that device's old KeyPackages and tells it to rejoin every conversation it was in. Before, new 1:1 chats and group invitations to it failed with "No matching key package", and its old conversations stayed unreadable.
- When someone confirms a new device and turns the old one off right away, the new device now joins existing 1:1 chats and groups within about a minute. The relay tells the new device to rejoin when no other device of that person is connected to add it. Before, it took up to 30 minutes, and messages kept going only to the old device.
- Messages sent during that gap that none of the recipient's devices had received are sent again to the new device once it joins (the sender is told `recipient_device_changed`). Messages already received aren't sent twice.
- Group messages now go only to devices of current members. Before, a member who left still received messages until the change removing their devices was confirmed. The relay also stops asking a member who left to rejoin, and stops adding their new devices to that group.

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
