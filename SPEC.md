# Lodelai Protocol

This is a summary of the wire protocol spoken between lodelai clients and a lodelai relay server. It is written for people who want to build a compatible client, run their own relay, or audit the one we host.

The normative definitions are machine-readable and live in this repository:

| File | What it defines |
|---|---|
| `packages/protocol/schema/message.schema.json` | Messages, addresses, identifiers, message bodies |
| `packages/protocol/schema/ws.schema.json` | Every WebSocket frame |
| `packages/protocol/schema/states.schema.json` | State enums (generated from the YAML below) |
| `packages/protocol/schema/constants.json` | Protocol version, size limits, quotas |
| `crates/statechart/machines/wire.yaml` | Message state machines (`request_recipient`, `request_sender_view`, `envelope_server`) |

Rust and TypeScript types are generated from these files (`crates/protocol`, `packages/protocol`). If this document and those files disagree, the files win.

Pre-1.0: the protocol may still change between minor versions.

---

## 1. Scope

**In scope**

- Addresses and identifiers
- The WebSocket connection: authentication, frames, delivery, status
- Message kinds and their fields
- End-to-end encryption (MLS profile), device keys, and device certification
- Message state machines as seen by the relay, the sender, and the recipient
- Attachments and avatars (blobs)
- HTTP endpoints, limits, and error codes

**Out of scope**

How a client presents messages, how it hands requests to a local AI agent, how it asks the user for approval, and any local IPC between parts of an app. These are implementation details of a client. A compatible client only needs to speak the wire protocol below.

## 2. Conventions

- **Encoding.** All frames are UTF-8 JSON text frames. Binary WebSocket frames are rejected.
- **Bytes.** Keys, nonces, signatures, and ciphertext are base64url **without padding** (RFC 4648 §5).
- **Timestamps.** RFC 3339 UTC with exactly three fractional digits, for example `2026-01-01T00:00:00.000Z`. Signatures cover the string bytes, so senders must emit this exact form.
- **Canonical JSON.** Anything that is signed is serialized with the JSON Canonicalization Scheme (RFC 8785). Header fields never carry integers above 2^53; large numbers go in strings.
- **Domain separation.** Every signature input is `tag ‖ 0x00 ‖ payload`, where `tag` is an ASCII string. A new use always gets a new tag.
- **Unknown fields.** Frames and messages are closed (`additionalProperties: false`). A relay rejects fields it does not know.

## 3. Versioning and negotiation

- The protocol version is `PROTOCOL_VERSION` in `constants.json`, currently **12**. The client sends its version in `hello.v`.
- A relay accepts versions in the range `[PROTOCOL_MIN, PROTOCOL_VERSION]`, today `[9, 12]`.
- Version 9 renamed the signing domain tags to `lodelai-*-v1`. It can't work with version 8, so the minimum is 9.
- Versions 10 to 12 only add things, so devices on 9 to 12 work together:
  - **10:** `request.no_reply`, the `done` state, `fail_reason: recipient_outdated`, and `v` on directory devices (§6.3).
  - **11:** typing frames (§6.1, §6.2).
  - **12:** reactions (§7.2).
- A message's `v` is the version of the fields it uses, not the sender's version. `chat`, `request`, `reply` and the other kinds use 9, or 10 when they carry a field added in 10. `reaction` always uses 12, and MLS Handshake messages use 9. `MESSAGE_V_MAX` is 12.
- If `hello.v` is outside the range, the relay answers `error{code: "version_unsupported", min, max}` and closes the connection. It does this before sending a challenge, so a version mismatch is never confused with an authentication failure.
- A receiving client drops any message whose `v` is below `PROTOCOL_MIN` or outside its kind's range: 9 to 10 for `chat`, `request`, `reply`, `rejected`, and the other ordinary kinds; exactly 12 for `reaction`; 9 for MLS Handshake messages. A `reaction` with a lower `v` is a format error. This prevents downgrades. The overall ceiling is `MESSAGE_V_MAX` (12), which is separate from `PROTOCOL_VERSION`: a new version may change only the connection and leave message `v` as it was, as 11 did.
- A client sends a version-10 field only when every receiving device is on 10 or later. If the relay finds a recipient device that is older than a message's `v`, it does not deliver the message to that device. For `v` 10, it tells the sender with `status{state: failed, fail_reason: recipient_outdated}`, and the sending client sends the message once more with the same `msg_id`, without the new fields, as `v` 9. For a reaction (`v` 12), it says nothing.

**Discovery headers.** The relay adds these response headers to both the WebSocket upgrade response (`101`) and `GET /v1/healthz`. Header names are case-insensitive.

| Header | Value | Use |
|---|---|---|
| `Lodelai-Protocol` | `<PROTOCOL_MIN>-<PROTOCOL_VERSION>`, for example `9-12` | Accepted version range. If the header is missing, the relay is older than version 9 or still uses the product's earlier name, and the client won't connect. |
| `Lodelai-Server` | The relay's server name | The name the relay uses to check challenge signatures. Clients compare it with the host they connected to and stop sign-up if they differ. Clients never sign with this value (see §5). |
| `Lodelai-Features` | Comma-separated list, or `none` | Optional features that are turned on. Today the only feature is `groups`. The header is always sent; `none` means nothing is on. |

A proxy may strip headers from the `101` response, so a client that does not find them there can read them from `/v1/healthz` once.

## 4. Addresses and identifiers

### 4.1 Addresses

```
<user>@<server>             a person
<user>@<server>/<session>   one of that person's published agent sessions
+<gid>@<server>             a group (only ever in `to`)
```

| Part | Pattern | Notes |
|---|---|---|
| `user` | `[a-z0-9][a-z0-9._-]{0,31}` | Unique on the server. Chosen by the person. |
| `server` | `[a-z0-9][a-z0-9.-]{0,62}` | The relay's host name, such as `relay.example.com`. Organizations are not part of the address. |
| `session` | `[a-z0-9][a-z0-9-]{0,31}` | A public slug for an agent session. Unique within one person. |
| `gid` | 26 lowercase ULID characters | A user name cannot start with `+`, so group addresses never collide with person addresses. |

`from.address` is always a person or a session, never a group.

### 4.2 Identifiers

| Identifier | Format |
|---|---|
| `msg_id`, `thread_id` | ULID, 26 characters of Crockford base32 (`^[0-9A-HJKMNP-TV-Z]{26}$`). Generated by the sending client. |
| `device_id` | `k1_` + base64url(SHA-256(Ed25519 public key)[0..16]), 25 characters. `k1_` is the key-algorithm version. |
| `blob_id` | 128 random bits, base64url (22 characters). Generated by the relay. |
| MLS group id | pair and self groups: base64url SHA-256 (43 characters). Groups: the lowercase ULID `gid` (26 characters). See §8.2. |
| `session_id` | An opaque string from the agent runtime, 1 to 256 characters. |

**Idempotent send.** If a relay already holds a `msg_id` from the **same** sending user, it acknowledges again without storing or delivering it twice. If the `msg_id` belongs to a different sender, it answers `nack unroutable`. A client that gets no `ack`, `nack`, or matching `error` within 30 seconds reconnects and resends the same `msg_id`.

## 5. Transport and authentication

- One WebSocket per device: `wss://<server>/v1/ws`. Plain `ws://` is only for local development on `127.0.0.1`.
- Clients do not send an `Origin` header. The relay rejects requests that have one, and accepts a `Host` only if it is the public host (optionally with `:443`) or `127.0.0.1:<port>` / `localhost:<port>`.
- Before authentication, frames are limited to 4096 bytes and the handshake must finish within 10 seconds. Upgrade attempts are rate-limited per IP address (§12).

### 5.1 Handshake

```
C→S  {"t":"hello", "v":9, "device_id":"k1_…", "user":"alice"}
S→C  {"t":"challenge", "nonce":"<base64url 32 bytes>"}
C→S  {"t":"auth", "sig":"<base64url 64 bytes>"}
S→C  {"t":"ready", "server":"relay.example.com", "now":"…", "pending":12, "admin":false}
```

The `auth` signature is Ed25519, made with the device signing key over:

```
"lodelai-auth-v1" ‖ 0x00 ‖ server (UTF-8) ‖ 0x00 ‖ device_id (ASCII) ‖ 0x00 ‖ nonce (32 raw bytes)
```

- `server` is the host the client connected to over TLS: lowercase ASCII, no port. The client never uses a name the relay supplies. Otherwise a malicious relay could get a signature that is valid for a different relay.
- `server` and `device_id` must not contain `0x00`.
- The relay recomputes `device_id` from the registered public key and checks the signature. Every failure gets the same response, with one exception: a revoked device that signs correctly gets `error{code: "device_revoked", by, at}`, where `by` is `device`, `admin`, `left`, or `recovery` and `at` is when it was revoked.
- `ready.pending` is the number of stored messages waiting for this device. `ready.admin` (remote relays only) tells whether this user administers their organization.

### 5.2 Keepalive

The relay sends `ping` every 30 seconds (`WS_PING_INTERVAL_S`) and closes connections that have been silent for 90 seconds. Either side may send `ping`; the other side answers `pong`.

## 6. Frames

`ws.schema.json` (`$defs/Frame`, discriminated by `t`) is the normative list. Frames that answer a request carry the request's `req`, or `msg_id` for `send`. The relay echoes it as `error.ref`. An `error` without `ref` is not tied to any queued request.

### 6.1 Client to server

| `t` | Purpose |
|---|---|
| `hello`, `auth` | Handshake (§5.1). |
| `send` | Submit one message (§7). Answered by `ack{msg_id, group_seq?}` or `nack{msg_id, reason}`. |
| `delivered_ack` | This device has received a delivered message. Clears only this device's copy. |
| `status` | Report a state transition for a message (§10). Allowed values depend on the message's kind. |
| `session.publish` / `session.unpublish` | Publish, update, or withdraw a session: `slug`, `grade`, `liveness` (`live:channel`, `live:pty`, `dead`), optional `display`, `folder`, `project`, `capabilities`, `busy`, and `audience` (`org`, or `people` with 1 to 256 users). |
| `directory.list` | Ask for the directory. |
| `profile.update` | Change your own display name and teams, or remove your avatar. |
| `presence.set` | Turn sharing your online and typing status on or off. This is reciprocal: if you turn it off, you also stop seeing others' status. |
| `typing` | `{to, on}`: you are typing to a person or group, or stopped (version 11). Not stored, queued, or answered. The relay drops it silently when the recipient is out of scope, when you send more than one per second, or when you have turned sharing off. |
| `device.revoke` | Revoke this device, or another device of the same user, with an optional signed `proof` (§9.3). |
| `device.certify` | Certify another device of the same user (§9.2). |
| `device.recover`, `device.recover_cancel`, `device.recover_block` | Start, cancel, or block a recovery by email confirmation (§9.5). |
| `org.update`, `team.create`, `team.update`, `team.delete`, `org.admin`, `member.remove`, `invite.create` | Organization administration (admins only). |
| `member.leave` | Leave the organization. This revokes all your devices. |
| `server.status` | Ask for aggregate relay health (admins of a remote relay only). |
| `groups.list`, `groups.replay` | List your groups and their last `group_seq`; replay group messages from a sequence number. |
| `blob.reserve`, `blob.get`, `blob.fetched` | Attachment upload reservation, download ticket, and confirmation that this device has fetched a blob (§11). |
| `key_packages.publish`, `key_packages.claim` | Upload MLS KeyPackages; claim one KeyPackage per target device (§8.3). |
| `group_info.get` | Fetch the latest GroupInfo for an external commit. |
| `commit_ack`, `commit_fail` | Vote on a pending group Commit (§8.4). |
| `ping`, `pong` | Keepalive. |

`device.register` is still in the schema, but relays reject it with `error{protocol}`.

### 6.2 Server to client

| `t` | Purpose |
|---|---|
| `challenge`, `ready` | Handshake (§5.1). |
| `ack`, `nack` | Result of `send`. |
| `deliver` | An incoming message, with `group_seq` for group-scoped messages. When the relay delivers your own message to your other devices, it adds the current `sender_view`. |
| `status` | The other party's state transition. `by` is filled in only for group messages, with the member the relay authenticated. |
| `typing` | `{from, group?, on}`: someone is typing to you or to a group you are in (version 11). The relay fills in `from` and sends it only on connections of version 11 or later. Clients turn it off if no update arrives for 6 seconds. |
| `directory`, `directory.update` | The whole directory. Updates are always the full list, never a diff. |
| `device.revoked` | Answer to `device.revoke`, or sent to a device that another of the user's devices, an admin, or a recovery revoked. Carries `by` and `at`; `by: recovery` means a recovery revoked it (§9.5). |
| `device.recover_scheduled`, `device.recover_canceled`, `device.recovered` | To the device that started a recovery: when the older devices will be revoked, that the recovery ended early, or that they were revoked (§9.5). |
| `device.recover_against`, `device.recover_against_ended` | To each older device a recovery would revoke: the details for a block prompt, and that the prompt can be withdrawn (§9.5). |
| `invite.created` | Answer to `invite.create`: a one-time token and its expiry. |
| `server.status` | Answer to `server.status`: aggregate counts only. |
| `groups` | Your groups and their last `group_seq`. Also sent on connect, before stored messages are delivered. |
| `blob.reserved`, `blob.ticket` | One-time HTTP tokens for upload and download (§11). |
| `key_packages.low` | Fewer than 20 regular KeyPackages are left for this device. |
| `key_packages` | Answer to `key_packages.claim`. |
| `group_info` | Answer to `group_info.get`. |
| `commit_final`, `commit_void` | A pending group Commit was finalized or voided (§8.4). |
| `group_alert` | Sent to group admins when two or more members could not process a finalized Commit. This is an unsigned claim by the server. |
| `duty` | Asks this device to add a device, remove a device, or remove a user in a group, in a ranked order (§8.5). |
| `rejoin_needed` | This device's stored Handshake messages for these groups were dropped. Rejoin with an external commit. |
| `error` | `code`, a diagnostic `message`, and optionally `ref`, `by`, `at`, `reason`, `until`, `min`, `max` (§15). |
| `ping`, `pong` | Keepalive. |

### 6.3 Directory

The directory is scoped to the receiver's organization. Each `people[]` entry has `address` and `devices[]`. It may also have `display`, `email`, `teams`, `avatar` (a `blob_id`), `online`, `revocations[]`, and `recovery` (§9.5). Each device has:

- `device_id`
- `device_pubkeys`: `ed25519`, `x25519`, and `x25519_sig`
- optional `added_at` and `last_seen_at`
- optional `v`: the `hello.v` of the device's last connection, or 9 if missing. The relay includes it only for connections of version 10 or later.
- up to 16 `certs[]`, each with `{signer, sig}`

`sessions[]` lists only the published sessions the receiver is allowed to see under each session's `audience`.

## 7. Messages

### 7.1 Common fields

| Field | Notes |
|---|---|
| `v` | The version of the fields this message uses (§3) |
| `msg_id`, `thread_id` | ULIDs. A first message uses its own `msg_id` as `thread_id`. |
| `kind` | `chat`, `request`, `reply`, `rejected`, `system`, `group`, `mls`, `reaction` |
| `from` | `address`, `author` (`human` or `agent`), `device_id`. Also `session_id` (agent authors), `assisted_by` (a session address: a person sent a draft written by that session), and `verbatim: true` (the draft was sent unchanged; requires `assisted_by`). |
| `to` | `{address}` |
| `body` | §7.3 |
| `created_at`, `expires_at` | Timestamps |
| `mls_group`, `epoch` | Required when `body.enc` is `mls` |
| `group` | The group address, when the message belongs to a group conversation |
| `state` | The sender's view of the state. Not signed. |
| `sig` | Ed25519 by `from.device_id` (§7.4) |

A session address with `author: human` is not allowed. People always send from their person address, even when they reject a request or reply to one that was addressed to their session.

### 7.2 Kinds

| Kind | Purpose | Extra fields |
|---|---|---|
| `chat` | Person-to-person message. No acceptance step. | `reply_to?` (quote), `edits?` (the original chat this replaces), `blobs?` |
| `request` | A question or task for an agent session. It must be accepted before the session sees it. | `grade` (`question` or `task`), `blobs?`, `no_reply?: true` (no answer needed; version 10, signed and outside the envelope) |
| `reply` | Answer to a request | `reply_to`, `need?: "task"` (the receiving session only had `question` rights), `blobs?` |
| `rejected` | The recipient declined | `reply_to`. The body is the reason. |
| `system` | Notice that a request expired, failed, was aborted, or was withdrawn | `reply_to`, `reason` (`expired`, `failed`, `aborted`, `withdrawn`), `abort_reason?`, `fail_reason?`. The body is always `{enc: "plain", text: ""}`. |
| `group` | Group membership change, carried as an MLS Commit or Start | `group_op`, `subject?`, `subjects?` (initial members on create), `base_seq` |
| `mls` | MLS Handshake (Start or Commit) for pair and self groups | Requires `mls_group`, `epoch`, `sig` |
| `reaction` | An emoji reaction to a message (version 12). The encrypted plaintext is `{target, emoji, on}`; the header does not name the target, so the relay only sees that one person reacted to another person or a group. Clients never pass reactions to an agent session. For the same (target, person, emoji), the latest wins. | No `grade`, `reply_to`, `edits`, or `blobs`. `to` is a person or group address, never a session. |

States, reasons, and errors travel as codes, never as text. The receiving client shows them in its own language. `error.message` is for diagnostics only.

Accepted `group_op` values: `create`, `add`, `remove`, `leave`, `org_left`, `admin`, `update`.

### 7.3 Bodies

| `enc` | Used for |
|---|---|
| `mls` | Required for every kind except `system`. Shape: `{enc: "mls", wire, payload?, group_info?, welcome?}`. `wire` is one of: `app` (application message, an MLS PrivateMessage, carries `payload`), `start` (epoch 0, carries `group_info`), or `commit` (carries `payload` and `group_info`, plus `welcome` if the Commit adds members). `kind: mls` uses only `start` and `commit`, `kind: group` may use all three, and every other kind uses `app`. Each payload is either `{data}` (inline base64url) or `{blob: {blob_id, size, sha256}}` (§11.3). |
| `plain` | `system` only, and `text` must be empty. |

A relay rejects any other combination as a format error. A receiving client treats it as `failed(bad_envelope)`. Protocol versions 7 and earlier also had an `enc: box` body. It is no longer part of the protocol: a relay of version 8 or later rejects it like any unknown `enc`, as a malformed frame (`error{protocol}`).

**Inner plaintext of an MLS application message:**

```
{"v":1[,"files":[…]][,"origin":…,"origin_msg":…]}\n<body text as raw UTF-8>
```

- The first line is a one-line JSON header, followed by `\n` and the body bytes, which are not escaped.
- A header with `v != 1` is `bad_envelope`.
- `files[].blob_id` must match the message header's `blobs` in both membership and order.
- Receivers ignore `origin` and `origin_msg` unless the sender is one of the receiver's own devices.
- A group `chat` may add `mentions` (1 to 20 person or session addresses) to this header. A group `request` created by mentioning an agent session may add `of`: the `msg_id` of the group chat it belongs to. Both are optional and do not change the version; older clients skip them. Receivers use a mention only if a person sent it and the address is a current member, or a member's session.

### 7.4 Signature

```
sig = Ed25519( "lodelai-msg-v1" ‖ 0x00 ‖ JCS(message without "state" and "sig") )
```

The signature covers `kind`, `grade`, `to`, `from`, and the whole `body`, ciphertext included, so none of them can be changed in transit. The order is **encrypt, then sign**. On receipt the order is **verify the signature, then check the body format, then decrypt**. A message with a bad signature is never opened.

Both the relay and the receiving client verify the signature. A client that does not know `from.device_id` refreshes the directory once. If the device is still unknown, the message fails with `bad_signature`.

### 7.5 Relay routing rules

The relay checks a `send` in this order and stops at the first failure:

1. **Rate limit.** If the user is over the limit, the relay sends `error{rate_limited}` and closes the connection.
2. **Sender identity.** `from.device_id` must be the authenticated device, `from.address` must belong to the authenticated user, and `sig` must verify. Otherwise `nack auth`. Oversized bodies get `nack too_large`.
3. **Recipient.** The recipient must be in the sender's organization, must not have blocked the sender, and must have at least one non-revoked device. A `request` must go to a published session address whose grade allows it, from a sender inside the session's `audience`. Every failure here gets the same `nack unroutable`. The response bytes are identical and the relay performs the same lookups, so a sender cannot use it to probe for users or sessions.
4. **`reply`, `rejected`, `system`.** `reply_to` must name a stored header where the original `to` user is the current `from` user and the original `from` is the current `to`. A `reply` is accepted only while the sender view of the original is `pending`, `accepted`, `consumed`, `replied`, or `done`, or is `aborted` with `abort_reason` `turn_ended` or `needs_task`. A `system` message with `reason: withdrawn` may only go from the original sender to the original recipient.
5. **`chat`** goes only to person addresses in the same organization. For `edits`, the original must be a chat from the same user to the same recipient.
6. **MLS.** `mls_group` must equal the id the relay computes from `from` and `to` (§8.2). Otherwise `unroutable`.

The relay never writes messages of its own. It reports only through `ack`, `nack`, `status`, and `error`.

## 8. End-to-end encryption

Every conversation is an MLS group (RFC 9420): one-to-one conversations, your own devices, and groups. Encryption and decryption happen in the client library (`crates/relay-client`), at the same point where messages are signed.

### 8.1 Profile

| Item | Value |
|---|---|
| Ciphersuite | `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519` (`0x0003`) only. KeyPackages and groups with any other ciphersuite are rejected. |
| Leaf signature key | The device's Ed25519 key. A KeyPackage whose signature key differs from the directory's `ed25519` for that device is invalid. |
| Credential | `BasicCredential(identity = device_id as UTF-8)` |
| Wire format policy | Pure plaintext: Handshake (Commit, Proposal) as **PublicMessage**, application messages as **PrivateMessage** |
| Proposals | By value, inside the Commit (add, remove, self-update) |
| Past epochs kept | 3 |
| Out-of-order tolerance / max forward distance | 50 / 1000 |
| Ratchet tree extension | On |
| GroupContext extension | `0xF0A1` = `{kind: pair, group, or self, admins?}`, required for all leaves. Group names are never placed in it. |

Handshakes are PublicMessages so that the relay can check Adds and Removes (§8.4). They reveal the member device list and leaf public keys, which the relay already knows from routing.

### 8.2 Group kinds and ids

| Kind | Group id | Members |
|---|---|---|
| pair | `SHA-256("lodelai-pair-v1" ‖ 0x00 ‖ min(a,b) ‖ 0x00 ‖ max(a,b))` over the two user names (UTF-8) | The two users, derived from the id |
| self | `SHA-256("lodelai-self-v1" ‖ 0x00 ‖ user)` | One user's devices |
| group | The group's lowercase ULID (the `gid` in `+<gid>@server`), as UTF-8 | The relay's membership table, up to `GROUP_MAX_MEMBERS` (50, including the creator; a group is created with at most 49 others). One user can be in up to `GROUPS_PER_USER` (100) groups. |

For pair and self groups, the relay accepts epoch 0 (`start`) only once. A second `start` gets `nack epoch_taken`, and the losing device waits for the winner's Welcome.

### 8.3 KeyPackages

- Each device uploads up to 100 regular KeyPackages and one last-resort KeyPackage. When fewer than 20 regular ones are left, the relay sends `key_packages.low`.
- `key_packages.claim` returns one KeyPackage per device, regular first, and deletes regular ones once they are claimed. Devices outside the organization, unknown devices, and revoked devices are simply missing from the answer, with no reason given. One claim lists at most 200 devices.
- KeyPackage lifetime is at most 90 days. Both the relay and receivers reject anything longer or expired.
- Claim limits (`error{rate_limited}`):
  - 300 per hour per claiming user
  - 10 per day per (claiming user, target device)
  - 50 per day per target device, not counting claims by the device's owner
  - When an owner claims for their own devices, the per-pair limit is replaced by `GROUPS_PER_USER` plus the number of peers.

### 8.4 Commit checks

The relay keeps the public MLS state of each group (no secrets), verifies each Commit against it, and only then assigns it an order. A device that commits must upload the new epoch's GroupInfo with the Commit. A Commit that fails any check gets `nack invalid_commit` and never gets an epoch:

1. `epoch` must equal the group's current epoch. Otherwise `nack stale_epoch`.
2. The sender's leaf signature must verify, and the leaf key must match the sender's directory `ed25519`.
3. Every Add needs a valid KeyPackage (ciphersuite `0x0003`, valid signature, an eligible device per §9.4). In groups, it must also follow the membership rules.
4. Every Remove must match the header's `group_op` and `subject`. User-level operations (`remove`, `leave`, `org_left`) must leave that user with no leaves.
5. An external commit is allowed only from an eligible device whose user had a leaf in the previous epoch. For pair and self groups, the user only has to be derivable from the id. The commit must also remove the device's old leaf, if there is one.
6. Rate limits: 30 Commits per hour per device per group, and 1000 Commits per day per group. External-commit recovery has its own limit of 60 per hour per device per group. Over the limit: `nack rate_limited`.

**Two-phase finalization (groups only).** The relay cannot see inside UpdatePath encryption, so a group Commit is first delivered as *pending*. Each receiving device stages it without merging and answers `commit_ack` or `commit_fail`. When the 60-second voting window closes, the relay finalizes the Commit if any eligible user (not the sender, not a removed user) has acked it. If there are no acks and at least two distinct eligible users have sent fails, the relay voids it. Any Commit that is still pending after one hour is voided.

- `commit_final{group, epoch, commit_hash}`: devices merge.
- `commit_void`: devices discard the staged Commit. Application messages that the sender sealed for the next epoch are returned to it as `nack commit_void`.

`commit_hash` is the SHA-256 of the Commit bytes (base64url, 43 characters). Pair and self groups do not use two-phase finalization.

Receivers repeat checks 1 to 5 themselves; they do not trust the relay.

### 8.5 Delivery

- The relay decides who receives an MLS message from the group's leaf list. Messages carry no recipient list.
- A Commit with Adds is delivered unchanged to existing leaves and new leaves. New leaves read `body.welcome`. In groups, new leaves receive it only after `commit_final`.
- Each group-scoped message gets a `group_seq` from the relay. Clients catch up with `groups.list` and `groups.replay`.
- Adding new devices, removing revoked devices, and removing users who left the organization are handed out with `duty{group, task, subject, rank}` to devices that are currently connected. Rank 0 acts at once. Rank *k* acts if the job is still not done after *k* × 2 minutes, capped at 30 minutes. The relay shuffles the ranks.

## 9. Devices

### 9.1 Device keys

Each device generates its own Ed25519 signing key and X25519 key. It binds the X25519 key to the signing key:

```
x25519_sig = Ed25519( "lodelai-xkey-v1" ‖ 0x00 ‖ device_id (ASCII) ‖ 0x00 ‖ x25519 public key (32 bytes) )
```

When a client learns a device from the directory, it recomputes `device_id` from `ed25519` and verifies `x25519_sig`. It discards entries that fail or have no signature. A user can have at most 4 devices by default (relay option `--max-devices-per-user`), and can add at most 5 devices per 24 hours.

The server name is part of every device-level signature (`lodelai-auth-v1`, `lodelai-devcert-v1`, `lodelai-devrevoke-v1`), so a signature made for one relay cannot be reused on another. Clients should also use a separate device key for each relay they connect to; then two relay operators cannot link the same device by its `device_id`.

### 9.2 Device certification

An existing device certifies a new device of the **same user**:

```
sig = Ed25519_signer( "lodelai-devcert-v1" ‖ 0x00 ‖ server ‖ 0x00 ‖ user ‖ 0x00 ‖
                      target device_id ‖ 0x00 ‖ target x25519 (32 bytes) ‖ 0x00 ‖ signer device_id )
```

`server` is the same string as `ready.server`. The client sends `device.certify{device_id, sig}`. The relay checks that the signer is the authenticated device, that the target belongs to the same user, that neither device is revoked and they are different devices, and that the signature verifies. It then stores one certificate per (signer, target) pair and publishes it in the directory as `certs[]`. If either device is later revoked, the relay deletes the certificate.

Peers verify certificates themselves. The relay cannot create one, because it does not hold the signer's key.

### 9.3 Revocation

`device.revoke` without `device_id`, or with this device's id, revokes this device. With another device of the same user:

- If the target was registered after the requesting device, it is revoked at once.
- If the target was registered earlier, the requester must have been registered for at least 24 hours. Otherwise the relay answers `error{too_early}`.

A revocation may carry a proof:

```
proof.sig = Ed25519_signer( "lodelai-devrevoke-v1" ‖ 0x00 ‖ server ‖ 0x00 ‖ revoked device_id ‖ 0x00 ‖ at )
```

`at` is the RFC 3339 string exactly as sent. The relay checks it against its own clock, allowing five minutes of skew. Revocations with a proof appear in the directory as `revocations[]`, with the revoked device's `added_at`.

### 9.4 Leaf eligibility

A device D of user U may be an MLS leaf only if all of the following hold:

1. D is in U's directory, is not revoked, and its leaf key equals the directory `ed25519`.
2. U is a member of the group (derived from the id for pair and self groups; from the relay table and the Commit for groups).
3. D is reachable along certification edges from U's **root**:
   - The graph's nodes are U's non-revoked devices plus devices revoked with a proof. Its edges are stored certificates, from signer to target.
   - A root candidate is a node from which some non-revoked device is reachable.
   - The root is the candidate with the earliest registration time, with ties broken by `device_id` bytes.

The relay and every receiving client run the same calculation over the same directory. A device added by someone who only took over the user's email has no certificate from the existing devices. Unless the user has no other live devices, it cannot become a leaf. Recovery (§9.5) reaches that case: after 24 hours that nobody blocked, the relay revokes the older devices without a proof, so they leave the graph and the new device becomes the root.

### 9.5 Recovery by email confirmation

A user who has lost every certified device can sign in again with their email and register a new device. That device is pending: it is not leaf-eligible (§9.4). It can ask the relay to revoke the user's older devices:

1. The pending device sends `device.recover`. The relay accepts it only if the device is not leaf-eligible and the user has at least one older, non-revoked device. It sets `at` to 24 hours from now and answers `device.recover_scheduled{at, targets}`. Sending it again returns the same answer. While another device's recovery is scheduled, the relay answers `error{protocol}`.
2. The relay sends `device.recover_against{at, requester}` to each older device, and again after each of its authentications while the recovery is scheduled. It also sends `directory.update` to the organization and an email to the user. A device connecting or coming online does not stop a recovery; only blocking does.
3. A recovery ends early in one of three ways:
   - The pending device sends `device.recover_cancel`.
   - Any older device sends `device.recover_block`. Clients send it only on a person's action, never from an agent.
   - The pending device becomes leaf-eligible, for example because an older device certified it. This is the normal path, so there is no wait and no email.

   The pending device gets `device.recover_canceled{reason: requester | blocked | certified}`. On a block it also gets `by` and `at`. After a cancel or a block, `retry_at` says when it may try again. The older devices get `device.recover_against_ended{reason: canceled | blocked | certified}`. Both are sent only if the device is connected; an older device that was offline learns it because `device.recover_against` no longer arrives after it authenticates.
4. At `at`, the relay revokes every older device, with no proof, and sends `device.recovered{targets, at}` to the pending device if it is connected, followed by `directory.update`. The revoked devices get `by: recovery`. Clients do not erase their local data automatically; they keep the history and show why the device was revoked.

After a cancel or a block, a new recovery must wait 24 hours. Three blocks within 30 days stop recoveries until that window passes. Refusals are `error{recover_refused, reason, until?}` (§15), and the connection stays open.

Each `people[]` entry in the directory carries the user's current `recovery`, or none. `state` is `scheduled`, `blocked`, `canceled`, `exhausted`, or `done` (for 24 hours after the revocation), and `at` is the matching time. Other members see only `state`, `at`, and `requester`. The user also sees `targets` and `blocked_by`, and `exhausted` appears only in their own entry.

## 10. Message state machines

`crates/statechart/machines/wire.yaml` is normative. The tables below summarize it.

### 10.1 Request, recipient side (`request_recipient`)

| State | Terminal | Sender sees | Meaning |
|---|---|---|---|
| `held` | | (nothing) | The signature is valid, but the sending device is not yet trusted. Moves to `pending` once it is trusted. |
| `pending` | | `pending` | Waiting for the recipient's decision |
| `accepted` | | `accepted` | Accepted. Delivery to the session is queued. |
| `queued` | | `accepted` | Waiting at a delivery gate. Gates are implementation-defined. |
| `injected` | | `accepted` | Handed to the session |
| `consumed` | | `consumed` | The session started working on it |
| `drafted` | | `consumed` | The session's reply is held as a draft for a person to review |
| `failed` | no (resting) | `failed` | Could not be delivered. Leaves this state only through retry, a direct reply, or a rejection. The reason is never sent to the sender. |
| `replied` | yes | `replied` | A reply was sent |
| `rejected` | yes | `rejected` | The recipient declined |
| `aborted` | yes | `aborted` | The turn ended without a reply. `abort_reason` is one of `turn_ended`, `owner_aborted`, `session_exited`, `mode_escalated`, `draft_discarded`, `needs_task`. |
| `discarded` | yes | `aborted` | A person discarded the draft |
| `expired` | yes | `expired` | `expires_at` passed |
| `withdrawn` | yes | `withdrawn` | The sender withdrew it (allowed only from `held` or `pending`) |
| `done` | yes | `done` | The request had `no_reply`, and the turn ended without a reply. No one is notified. A late reply is still sent, like after `aborted(turn_ended)`. |
| `unreadable` | yes | (nothing) | This device cannot open the message |

The only ways from `pending` to `accepted` are `human_accept`, `human_accept_draft`, and `policy_accept`. Terminal states never transition again. The exceptions are the YAML's same-state rows: a supplemental reply from `replied`, and a late reply from `aborted` when the reason is `turn_ended` or `needs_task`, and a late reply from `done`. A message is never `injected` twice.

### 10.2 Request, sender view (`request_sender_view`)

| State | `sent` | `stored` | `received` | `pending` | `accepted` | `failed` | `consumed` | `replied` / `rejected` / `aborted` / `expired` / `withdrawn` / `done` |
|---|---|---|---|---|---|---|---|---|
| Rank | 0 | 10 | 20 | 30 | 40 | 50 | 60 | 90 (terminal) |

- `server_ack` leads to `stored`, `server_device_received` (a recipient device sent `delivered_ack`) leads to `received`, and `status` frames lead to their named states.
- **Rank rule:** a status with a higher rank is applied directly, filling in any skipped states. A status with an equal or lower rank is ignored. Among terminal states, the first to arrive wins.
- `withdrawn` is an explicit transition, allowed only from `sent`, `stored`, `received`, or `pending`.
- `queued`, `injected`, and `drafted` are never visible to the sender.
- `aborted` and `done` are not final for the sender even though they rank 90. A late reply (`status replied`) moves `done` to `replied`, and moves `aborted` to `replied` only when `abort_reason` is `turn_ended` or `needs_task`. `abort_reason` is kept.

### 10.3 Relay copy (`envelope_server`)

| State | Meaning |
|---|---|
| `stored` | Held for the target devices |
| `device_received` | At least one target device has acknowledged it. The body is deleted once every target device has acked or been revoked. |
| `expired` | Past `expires_at`. The header is deleted and the sender is told `expired`. |

The relay keeps the header and the sender-view state until `expires_at`, so it can check `reply_to` (§7.5, rule 4). `status` frames update the tracked view by the rank rule. A withdrawal drops the copies for devices that have not acked yet.

**What a `status` frame may carry** depends on the stored header's kind:

- `request`: any `SenderViewState` value
- `chat`: only the recipient's `read` and `acknowledged`, relayed to the sender without changing the relay's view
- `reply`, `rejected`, `system`: none

A status the relay does not allow gets `error{protocol}`.

## 11. Attachments and avatars

### 11.1 Flow

1. `blob.reserve{req, ct_len, purpose: message|avatar}` returns `blob.reserved{req, blob_id, put_token}`.
2. `PUT /v1/blobs/{blob_id}` with `Authorization: Bearer <put_token>` and exactly `ct_len` bytes. The response is `204`.
3. Reference the blob in a message's `blobs` (1 to 10 ids, no duplicates; `chat`, `request`, and `reply` only). The relay binds each blob only if this user uploaded it and it is not yet attached. Otherwise `nack blob_unavailable`.
4. A recipient sends `blob.get{req, blob_id}` and receives `blob.ticket{req, blob_id, get_token}`, then calls `GET /v1/blobs/{blob_id}` with `Authorization: Bearer <get_token>`.
5. `blob.fetched{blob_id}` confirms this device has the blob. When every non-revoked target device has fetched it, the relay deletes the file.

Tokens are 32 random bytes, used once (each request consumes its token, whether it succeeds or fails), and stored only as SHA-256. Message blobs are available only to the message's target devices. Avatars are available within the organization. An unauthorized request, an unknown blob, and a deleted blob all get the same `error{protocol, ref}`.

### 11.2 File encryption

Each file is encrypted with its own random file key, using STREAM over XChaCha20-Poly1305:

```
chunks     = 65 536 plaintext bytes each (the last one may be short or empty)
nonce      = prefix (19 bytes) ‖ BE32 chunk index ‖ last flag (0x00 | 0x01)
AAD        = "lodelai-blob-v1" ‖ 0x00 ‖ blob_id
ct length  = n + 16 × ceil(max(n, 1) / 65 536)
```

The file key and the file's metadata are delivered inside the MLS-encrypted message, as one `files[]` entry per file: `blob_id`, `name`, `mime`, `size`, `ct_sha256`, `fk` (the file key), `prefix`, and an optional `role`. Avatars are not end-to-end encrypted. They must be PNG, at most 512 pixels on each side and 131 072 bytes.

### 11.3 Large MLS messages

If a serialized MLS message is larger than `MLS_INLINE_MAX_BYTES` (49 152), the sender moves its largest payloads, one at a time, into blobs (`{blob_id, size, sha256}`) until it fits. Receivers check `sha256` before processing. These blobs are already MLS data and are not encrypted again. They live as long as the Handshake they belong to (§13). The relay accepts MLS blobs of up to 1 MiB.

## 12. Limits

Values from `constants.json` unless noted.

| Limit | Value |
|---|---|
| WebSocket frame (`WS_MAX_FRAME_BYTES`) | 73 728 bytes. The relay closes the connection if a frame is larger. |
| Pre-authentication frame | 4096 bytes (relay) |
| Body: `request`, `reply`, `chat` | 32 768 bytes of UTF-8 text |
| Body: `rejected`, `system` | 500 characters (`REASON_MAX_CHARS`) |
| Body: `group` | 8192 bytes |
| Body: `reaction` | 256 bytes of plaintext (`BODY_MAX_BYTES_REACTION`) |
| MLS application message | ciphertext length − 512 ≤ kind limit + 64 + 1024 × number of `blobs` |
| Attachments | 25 MiB per file (`FILE_MAX_BYTES`), 10 per message, 1024 bytes per file entry. Group messages: 25 MiB in total (`GROUP_FILES_MAX_BYTES`). |
| Pending (unfetched) blob bytes per user | 1 GiB |
| Blob reservations | 200 per hour per user. Avatars: 10 per hour, counted separately. |
| Blob tokens | upload 600 s, download 300 s. Unattached blobs are deleted after 3600 s. |
| Frames per user | Token bucket, 20 per second with a burst of 60 (relay default). Exceeding it gets `error{rate_limited}` and closes the connection. |
| Upgrade / pre-auth attempts per IP | Bucket of 30, refilling at 0.5 per second (relay) |
| Invites | 20 per hour per admin. Tokens are valid for 7 days. |
| Session `audience` | 1 to 256 users |
| Group size | 50 members including the creator. 100 groups per user. |

## 13. Retention

- A `request` expires 24 hours after sending by default (`REQUEST_EXPIRES_H`), and a `chat` after 7 days (`CHAT_EXPIRES_D`). The relay stores nothing beyond `min(expires_at, received + 7 days)`.
- Message content is deleted as soon as every target device has acknowledged it, or when it expires, whichever comes first.
- MLS Handshake messages and their blobs are kept until the target leaf fetches them, up to 2000 messages, 64 MiB, or 30 days per device. If that limit is exceeded, the relay drops the device's Handshakes for the affected groups and sends `rejoin_needed` on the next connect.
- The relay keeps only the latest GroupInfo for each group.

## 14. HTTP endpoints

Every endpoint rejects requests that carry an `Origin` header and enforces the `Host` rule from §5.

| Endpoint | Purpose |
|---|---|
| `GET /v1/healthz` | `200 ok` if the database is readable, otherwise `503`. Carries the discovery headers (§3). |
| `GET /v1/privacy` | `{version, url?}` for the relay's current privacy policy. |
| `POST /v1/signup` | `{email, locale?, privacy: {version}}` returns `202` whether or not the email exists, and mails a code. Returns `422` if the privacy version is missing or out of date, `400` for an invalid email, `429` when over a limit, and `503` if mail fails. |
| `POST /v1/signup/verify` | `{email, code}` returns `200 {signup_token, kind: existing or new, account?, org_create?}`. Every failure is the same `400`. |
| `POST /v1/invites/check` | `{signup_token, invite}` returns `200 {org_name, inviter, teams}`, or the same `404` for any failure. Does not consume the invite. |
| `POST /v1/devices` | Register a device: `device_pubkeys{ed25519, x25519, x25519_sig}`, `signup_token`, and for new accounts `user`, `display_name`, `org: {invite}` or `org: {create: {name, setup_code?}}`, `teams`. Returns `{user, device_id, server}`. |
| `PUT /v1/blobs/{blob_id}` / `GET /v1/blobs/{blob_id}` | Blob transfer with one-time bearer tokens (§11). |
| `GET /v1/connected`, `POST /v1/wipe` | Local single-machine relay only, protected by the registration token. |

Sign-up limits (relay defaults):

| Limit | Value |
|---|---|
| Codes per email | 5 per hour and 10 per day |
| Attempts per IP | 20 per hour |
| Mail per relay | 80 per UTC day (configurable) |
| Code lifetime | 10 minutes, 5 wrong attempts allowed |
| Sign-up token lifetime | 30 minutes |
| Organization setup code (`lodelai-relay bootstrap`) | 1 hour, single use, 5 wrong attempts allowed |
| Wrong invite checks per token | 10 |

## 15. Error codes

**`nack.reason`** (answer to `send`):

| Code | Meaning |
|---|---|
| `auth` | The sender's identity or signature does not match the connection |
| `unroutable` | No such recipient, not allowed, or wrong group id. The response bytes are identical in every case. |
| `too_large` | The body or attachments exceed the limit |
| `stale_devices` | A group message found no device to deliver to: every member device is revoked |
| `epoch_taken` | A pair or self group was already started |
| `stale_epoch` | The Commit's epoch is not the current one |
| `invalid_commit` | The Commit failed a relay check (§8.4) |
| `commit_void` | The message was sealed for an epoch that was voided |
| `rate_limited` | Too many MLS Handshake messages (Commit rate limit) |
| `blob_unavailable` | A referenced blob is not yours, is already attached, or does not exist |

**`error.code`**:

| Code | Meaning |
|---|---|
| `protocol` | Malformed or disallowed frame. Carries `ref` when the request can be identified. |
| `rate_limited` | Over a limit. For per-user frame limits the connection is closed; for request-scoped limits (invites, blobs, KeyPackage claims) only that request fails. |
| `internal` | Relay error. Carries `ref` when the request can be identified. |
| `version_unsupported` | `hello.v` is out of range. Carries `min` and `max`. |
| `device_revoked` | This device is revoked. Carries `by` (`device`, `admin`, `left`, or `recovery`) and `at`, when it was revoked. |
| `too_early` | Revoking an older device before the 24-hour wait is over |
| `name_taken` | A team name is already in use |
| `handle_taken` | A user name is already in use |
| `last_admin` | The change would leave the organization without an admin |
| `quota` | The pending blob bytes for this user are over the limit |
| `storage_full` | The relay is below its free-disk floor |
| `recover_refused` | A recovery request was refused (§9.5). Carries `reason`: for `device.recover`, `trusted` (already leaf-eligible), `no_older` (no older device to revoke), `cooldown` (within 24 hours of a cancel or block), or `exhausted` (three blocks in 30 days), with `until` for the last two; for `device.recover_cancel`, `not_scheduled`; for `device.recover_block`, `not_target` or `ended`. The connection stays open. |

**`fail_reason`**: `bad_signature`, `unknown_delivery`, `bad_envelope`, `not_sent`, `recipient_device_changed`, `recipient_outdated`. Clients show unknown values as a generic failure.

`recipient_outdated`: a recipient device is on an older version than the message (§3). The sending client resends it once without the newer fields.

`recipient_device_changed`: the recipient's device was revoked while a message was queued only for that device. The relay sends the sender `status{state: failed, fail_reason: recipient_device_changed}`. When the recipient has a new leaf, the sending client sends the message once more with the same `msg_id`, and retries with backoff if it fails the same way again, until the message expires.

## 16. Security considerations

The relay is treated as **semi-trusted**: it is trusted for routing and availability, but not for confidentiality. The operator, a self-host admin, or anyone who copies the database can learn the following.

| The relay can see | The relay cannot see |
|---|---|
| Sender and recipient addresses, `kind`, `grade`, `need`, `from.assisted_by` | Message text: requests, replies, chats, rejection reasons |
| `msg_id`, `thread_id`, `reply_to`, timestamps, delivery and status states | Attachment contents and file names |
| Ciphertext and blob sizes, number of attachments | Group names, which travel inside application messages |
| Device ids, public keys, leaf lists, and group membership (handshakes are PublicMessages) | |
| Directory data: email, display name, avatar, teams, organization, published sessions, online status (if shared) | |

Known limits:

- **Root changes are trusted.** If every device of a user is replaced, for example after recovery by email, clients accept the new root and log one line in the conversation. A malicious relay that invents a root can read that user's future conversations and send requests in that user's name. The only trace is that log line.
- **Recovery is decided by the relay.** A recovery revokes the older devices without their signature. The older devices are told and can block it for 24 hours, but a malicious relay could skip that notice.
- **Organization membership comes from the server.** Removals of users who left the organization are triggered by the relay's directory, so a malicious relay could hide them. Removals and leaves that members sign themselves are not affected.
- **Removal needs a connected member.** A revoked device stays a leaf until some member's device commits its removal. Until then, the relay withholding delivery is the only protection.
- **Unlocked devices.** Anyone holding an unlocked device can certify new devices. Revoking that device removes the certificates it made.
- **Backups can keep deleted data.** The relay stores data in SQLite, overwrites deleted rows with zeros (`secure_delete`), and truncates its write-ahead log after checkpoints. A backup taken before a deletion (`lodelai-relay backup`) still holds whatever ciphertext and metadata existed when the backup was made.

Receiving clients verify everything that matters for confidentiality themselves: signatures, `device_id` fingerprints, `x25519_sig`, certificates, leaf eligibility, and Commit rules. A relay that lies can delay or drop messages, but it cannot read them or alter them undetected.

## 17. Conformance and test vectors

`packages/protocol/fixtures/` holds golden messages with sorted keys. Their signatures come from deterministic test keys:

```
DeviceKeys::generate(SHA-512("lodelai-fixture-v1:" + user))
```

`keys.json` lists the public keys and device ids; they are not secrets. A conforming implementation must:

- parse each fixture with the generated types and re-serialize it to the **same JCS bytes**;
- verify each `sig` with `keys.json`.

The Rust (`crates/protocol/tests`) and TypeScript (`packages/protocol/src`) test suites both run these checks, so the two JCS implementations must agree byte for byte.

`fixtures/e2e/blob-vectors.json` holds attachment-encryption vectors.

`crates/protocol-gen` generates the types, and re-signs the fixtures whenever their content changes. Build and regeneration commands are in the README.
