#!/usr/bin/env bash
# lodelai 서버(relay) 설치·갱신 — 자체 호스팅과 hosted 가 같은 스크립트를 쓴다(묶음 29 §1·§2, SELF-HOSTING.md).
#
# 설치(root, 여러 번 실행해도 같다):
#   curl -fsSL https://updates.lodelai.com/relay/install.sh | sudo bash -s -- --domain relay.example.com \
#     [--tls caddy|cloudflare|none] [--data-dir /var/lib/lodelai] [--require-mount] [--operator <user>] \
#     [--version <x.y.z>] [--no-auto-update]
#   sudo bash deploy/relay/install.sh --domain … --binary <빌드한 lodelai-relay>   # 레포 체크아웃에서, 로컬 빌드 판
#
# 갱신은 설치가 둔 /opt/lodelai/bin/lodelai-update 가 이 스크립트의 설치된 사본(/opt/lodelai/lib/install.sh)을 --update 로 부른다.
#
# 받는 판은 공개 R2 의 relay/ 아래다. 확인 순서(§1-2): manifest 서명(relay 전용 minisign 키) → 서명된 manifest 안의
# sha256·published_at 만 믿는다 → tar 해시 → 풀기. 어긋나면 아무것도 바꾸지 않고 멈춘다. tar 안에 lodelai-relay 와 이
# 디렉터리(deploy/)가 같이 들어 있어서 서비스 파일·갱신 스크립트도 같은 서명으로 확인된다.
# 판 바꾸기(§2): DB 백업(옛 바이너리로) → 링크 교체 → 재시작 → healthz → 실패면 바이너리와 DB 를 함께 되돌린다.
# relay 설정은 /etc/lodelai/relay.env 의 env 로만 넘긴다(LODELAI_RELAY_DATA·LODELAI_PUBLIC_HOST·LODELAI_BEHIND_CLOUDFLARE 등).
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
umask 022

# relay 전용 minisign 공개키(base64 한 줄, `minisign -G` 가 만든 .pub 의 둘째 줄). 앱 업데이트 키와 따로다(§1-2).
# 비밀키는 릴리스 서명자의 맥에만 있다. 키를 만든 뒤 여기에 채운다 — 비어 있으면 설치·갱신 모두 멈춘다(fail-closed).
RELAY_PUBKEY_BUILTIN="RWTd4+DsW302VNw9QDa0XCemaQxsX+9gk0tk1FbGKdaFAgswpOC3pYJ6"
# 리허설용으로만 바꾼다. 다른 주소에서 받아도 서명은 위 키(또는 next-key 로 넘어간 키)로 확인한다.
BASE_URL="${LODELAI_RELAY_BASE_URL:-https://updates.lodelai.com/relay}"
ETC=/etc/lodelai
PUBKEY_FILE=$ETC/relay-signing.pub
OPT=/opt/lodelai
BIN=$OPT/bin
LIB=$OPT/lib
KEEP_BIN=5
KEEP_DB=3
AUTO_MIN_AGE=$((72 * 3600))
HEALTH_URL=http://127.0.0.1:8787/v1/healthz
# 판 헤더는 PROTOCOL 8(22 §12-28)부터 있고 9(#571 단계 B)부터 이름이 Lodelai-Protocol 이다 — 8 판은 200 만 본다.
HEADER_SINCE=9

die() { printf 'lodelai: %s\n' "$*" >&2; exit 1; }
log() { printf 'lodelai: %s\n' "$*"; }

# ---------------------------------------------------------------- 받기·확인(설치·갱신 공통)

arch_name() {
  case "$(uname -m)" in
    x86_64 | amd64) echo x86_64 ;;
    aarch64 | arm64) echo aarch64 ;;
    *) die "unsupported CPU: $(uname -m) (x86_64 and arm64 only)" ;;
  esac
}

sha256_of() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

# minisign .pub 파일(또는 그 꼴의 글)에서 키 한 줄.
key_line() { grep -v '^untrusted comment:' "$1" | sed '/^[[:space:]]*$/d' | tail -1 | tr -d '[:space:]'; }

# 지금 믿는 공개키. next-key 로 넘어간 뒤면 파일이 이기고, 박아 둔 키로 돌아가지 않는다. 둘 다 비면 멈춘다.
current_pubkey() {
  local k=""
  if [ -s "$PUBKEY_FILE" ]; then k=$(key_line "$PUBKEY_FILE"); else k=$RELAY_PUBKEY_BUILTIN; fi
  [ -n "$k" ] || die "relay signing public key is empty — can't verify the download, stopping (RELAY_PUBKEY_BUILTIN in install.sh)"
  printf '%s' "$k"
}

# 받는다. 출력은 HTTP 코드(file:// 는 000). https 만 — 리허설 주소를 줬을 때만 file:// 도.
fetch() { # fetch <url> <out>
  local proto='=https'
  [ -z "${LODELAI_RELAY_BASE_URL:-}" ] || proto='=https,file'
  rm -f -- "$2"
  curl -sSL --proto "$proto" --proto-redir '=https' --max-time 300 -o "$2" -w '%{http_code}' "$1" 2>/dev/null || true
}
fetched() { case "$1" in 200 | 000) [ -s "$2" ] ;; *) return 1 ;; esac; } # fetched <코드> <파일>
fetch_ok() { # fetch_ok <url> <out> — 못 받으면 멈춘다
  local code
  code=$(fetch "$1" "$2")
  fetched "$code" "$2" || die "couldn't download: $1 (HTTP ${code:-?})"
}

verify_sig() { minisign -Vq -P "$3" -m "$1" -x "$2" >/dev/null 2>&1; } # verify_sig <파일> <서명> <공개키>

# 키 바꾸기(§1-2): relay/next-key.pub 와 그것을 지금 키로 서명한 next-key.pub.minisig 가 있으면 받아들이고 그 키로 넘어간다.
# 없으면(404) 아무것도 안 한다. 받기 실패·서명 실패는 로그만 남기고 지금 키를 그대로 쓴다.
check_next_key() { # check_next_key <임시 폴더>
  local t=$1 key code new
  key=$(current_pubkey)
  code=$(fetch "$BASE_URL/next-key.pub" "$t/next-key.pub")
  [ "$code" != 404 ] || return 0
  if ! fetched "$code" "$t/next-key.pub"; then
    [ "$code" = 000 ] || log "couldn't download next-key (HTTP $code) — continuing with the current key"
    return 0
  fi
  code=$(fetch "$BASE_URL/next-key.pub.minisig" "$t/next-key.pub.minisig")
  fetched "$code" "$t/next-key.pub.minisig" || { log "next-key has no signature — ignored"; return 0; }
  verify_sig "$t/next-key.pub" "$t/next-key.pub.minisig" "$key" || { log "next-key signature doesn't match the current key — ignored"; return 0; }
  new=$(key_line "$t/next-key.pub")
  printf '%s' "$new" | grep -Eq '^[A-Za-z0-9+/]{40,}={0,2}$' || { log "next-key isn't valid — ignored"; return 0; }
  [ "$new" != "$key" ] || return 0
  install -d -m 0755 "$(dirname "$PUBKEY_FILE")"
  install -m 0644 "$t/next-key.pub" "$PUBKEY_FILE.tmp"
  mv -f "$PUBKEY_FILE.tmp" "$PUBKEY_FILE"
  log "switched the relay signing key to the new key ($PUBKEY_FILE)"
}

valid_version() { printf '%s' "$1" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$'; }

utc_epoch() { date -u -d "$1" +%s 2>/dev/null || date -u -j -f '%Y-%m-%dT%H:%M:%SZ' "$1" +%s 2>/dev/null; }

# 판을 고르고 서명된 manifest 를 읽는다. 결과는 전역 R_*.
#   resolve_release <임시 폴더> <판|""(latest)> <auto 0|1>  → 0: 받을 판 있음, 2: auto 인데 아직 받지 않음
resolve_release() {
  local t=$1 want=$2 auto=$3 url key arch pub now age
  if [ -n "$want" ]; then
    valid_version "$want" || die "not a valid version: $want"
    url="$BASE_URL/$want/manifest.json"
  else
    url="$BASE_URL/latest.json"
  fi
  fetch_ok "$url" "$t/manifest.json"
  fetch_ok "$url.minisig" "$t/manifest.json.minisig"
  key=$(current_pubkey)
  verify_sig "$t/manifest.json" "$t/manifest.json.minisig" "$key" || die "manifest signature doesn't match — nothing changed ($url)"
  arch=$(arch_name)
  R_VERSION=$(jq -er '.version' "$t/manifest.json") || die "manifest has no version"
  valid_version "$R_VERSION" || die "manifest version isn't valid: $R_VERSION"
  [ -z "$want" ] || [ "$R_VERSION" = "$want" ] || die "manifest version ($R_VERSION) doesn't match the requested version ($want)"
  R_PUBLISHED=$(jq -er '.published_at' "$t/manifest.json") || die "manifest has no published_at"
  R_URL=$(jq -er --arg a "$arch" '.assets[$a].url' "$t/manifest.json") || die "manifest has no asset for $arch"
  R_SHA=$(jq -er --arg a "$arch" '.assets[$a].sha256' "$t/manifest.json") || die "manifest has no sha256 for $arch"
  R_PMIN=$(jq -r '.protocol.min // empty' "$t/manifest.json")
  R_PMAX=$(jq -r '.protocol.max // empty' "$t/manifest.json")
  printf '%s' "$R_SHA" | grep -Eq '^[0-9a-f]{64}$' || die "manifest sha256 isn't valid"
  case "$R_URL" in
    https://*) ;;
    file://*) [ -n "${LODELAI_RELAY_BASE_URL:-}" ] || die "asset URL isn't https: $R_URL" ;;
    *) die "asset URL isn't https: $R_URL" ;;
  esac
  [ "$auto" = 1 ] || return 0
  # 72시간 문턱(§2) — 스스로 받기에만. 서명된 published_at 과 이 서버 시계로 센다.
  pub=$(utc_epoch "$R_PUBLISHED") || die "couldn't read published_at: $R_PUBLISHED"
  now=$(date -u +%s)
  age=$((now - pub))
  if [ "$age" -lt 0 ]; then
    log "version $R_VERSION was published later than this server's clock — check the server clock (skipped this time)"
    return 2
  fi
  if [ "$age" -lt "$AUTO_MIN_AGE" ]; then
    log "version $R_VERSION was published $((age / 3600)) hours ago — automatic updates wait 72 hours (skipped this time)"
    return 2
  fi
  return 0
}

is_elf() { [ "$(head -c 4 "$1" | od -An -tx1 | tr -d ' \n')" = "7f454c46" ]; }

# tar 를 받아 해시를 보고 푼다. 결과: <임시 폴더>/x/lodelai-relay, <임시 폴더>/x/deploy/
download_release() { # download_release <임시 폴더>
  local t=$1
  fetch_ok "$R_URL" "$t/relay.tar.gz"
  [ "$(sha256_of "$t/relay.tar.gz")" = "$R_SHA" ] || die "tar hash doesn't match the manifest — nothing changed"
  rm -rf "$t/x"
  mkdir -p "$t/x"
  tar -xzf "$t/relay.tar.gz" -C "$t/x" --no-same-owner
  [ -f "$t/x/lodelai-relay" ] && [ -f "$t/x/deploy/install.sh" ] || die "tar is missing lodelai-relay or deploy/"
  is_elf "$t/x/lodelai-relay" || die "lodelai-relay in the tar isn't an ELF executable"
}

perm_of() { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"; }
owner_of() { stat -c '%U' "$1" 2>/dev/null || stat -f '%Su' "$1"; }

# 로컬 빌드 판(--binary·update.env 의 binary:) 경로가 남에게 쓰기 열려 있지 않은지 — 심볼릭 링크를 다 푼 실제 경로의
# / 부터 파일까지 모든 구성 요소. 그룹·다른 사람 쓰기가 하나라도 있으면 쓰지 않는다(그 사람이 root 가 깔 바이너리를 바꿀 수 있다).
binary_path_ok() { # binary_path_ok <절대 경로> — 안 되면 까닭을 찍고 1
  local p=$1 cur="" part
  case "$p" in /*) ;; *) echo "not an absolute path: $p"; return 1 ;; esac
  [ -f "$p" ] || { echo "file not found: $p"; return 1; }
  p=$(readlink -f -- "$p") || { echo "couldn't resolve the path: $1"; return 1; }
  if [ $((0$(perm_of /) & 022)) -ne 0 ]; then echo "/ is writable by other users"; return 1; fi
  local IFS=/
  for part in $p; do
    [ -n "$part" ] || continue
    cur="$cur/$part"
    if [ $((0$(perm_of "$cur") & 022)) -ne 0 ]; then
      echo "writable by other users: $cur ($(perm_of "$cur"))"
      return 1
    fi
  done
  return 0
}

# ---------------------------------------------------------------- 판 바꾸기(설치·갱신 공통)

env_value() { [ -f "$2" ] && sed -n "s/^$1=//p" "$2" | tail -1 | sed 's/^"\(.*\)"$/\1/' || true; }

# healthz 확인. 서명된 manifest 의 protocol.max 가 9 이상이면 Lodelai-Protocol 헤더가 있고 그 [min,max] 가 manifest 와
# 같아야 한다(없거나 다르면 실패 → 되돌림). 9 미만·로컬 빌드 판은 200 만 본다.
healthy() { # healthy <protocol min> <protocol max>
  local i hdr got gmin gmax
  for i in 1 2 3 4 5 6 7 8; do
    sleep 2
    systemctl is-active --quiet lodelai-relay.service || continue
    hdr=$(curl -sS -m 3 -o /dev/null -D - -w '%{http_code}' "$HEALTH_URL" 2>/dev/null) || continue
    [ "${hdr: -3}" = 200 ] || continue
    if [ -z "$2" ] || [ "$2" -lt "$HEADER_SINCE" ]; then return 0; fi
    got=$(printf '%s' "$hdr" | tr -d '\r' | sed -n 's/^[Ll]odelai-[Pp]rotocol:[[:space:]]*//p' | head -1)
    gmin=${got%%-*}
    gmax=${got##*-}
    [ "$gmin" = "$1" ] && [ "$gmax" = "$2" ] && return 0
    log "healthz reports Lodelai-Protocol '${got:-none}' — the manifest expects $1-$2"
  done
  return 1
}

prune_bins() { # prune_bins <지금> <이전>
  local n=0 f
  for f in $(ls -1t "$BIN" | grep '^lodelai-relay-'); do
    n=$((n + 1))
    if [ "$n" -gt "$KEEP_BIN" ] && [ "$f" != "$1" ] && [ "$f" != "$2" ]; then rm -f -- "${BIN:?}/$f"; fi
  done
}

prune_db_backups() { # prune_db_backups <데이터 폴더> — pre-update-* 는 최근 KEEP_DB 개만
  local f
  ls -1t "$1" | grep '^pre-update-.*\.sqlite3$' | tail -n +$((KEEP_DB + 1)) | while IFS= read -r f; do
    rm -f -- "${1:?}/$f"
  done
}

# 새 바이너리로 바꾼다. 실패하면 바이너리와 DB 를 함께 되돌리고 1.
# 같은 판이면 바이너리는 두되, 설치(restart=1)는 relay.env·데이터 폴더가 바뀌었을 수 있어 다시 띄우고, 갱신은 멈춰 있을 때만
# 켠다(멈춘 채 같은 판으로 install.sh 를 돌리면 relay 가 꺼진 채 끝나 바깥 502 였다).
switch_to() { # switch_to <새 바이너리> <판 이름> <protocol min> <protocol max> [restart=1]
  local src=$1 label=$2 pmin=$3 pmax=$4 restart=${5:-0} data prev new db backup=""
  data=$(env_value LODELAI_RELAY_DATA "$ETC/relay.env")
  [ -n "$data" ] || die "LODELAI_RELAY_DATA is missing from $ETC/relay.env — run install.sh again"
  db="$data/relay.sqlite3"
  new="lodelai-relay-$label"
  prev=$(readlink "$BIN/lodelai-relay" || true)
  if [ "$prev" = "$new" ]; then
    log "already on this version: $new"
    if [ "$restart" = 1 ]; then
      systemctl restart lodelai-relay.service
    elif ! systemctl is-active --quiet lodelai-relay.service; then
      log "the relay isn't running — starting it"
      systemctl start lodelai-relay.service
    else
      return 0
    fi
    healthy "$pmin" "$pmax" && return 0
    log "the relay didn't come up — recent log:"
    journalctl -u lodelai-relay.service -n 30 --no-pager >&2 || true
    return 1
  fi
  install -d -o root -g root -m 0755 "$BIN"
  install -o root -g root -m 0755 "$src" "$BIN/.$new.tmp"
  mv -f "$BIN/.$new.tmp" "$BIN/$new"

  # DB 백업은 지금(옛) 바이너리로 — 새 판이 스키마를 더하기 전의 모습.
  if [ -n "$prev" ] && [ -f "$db" ]; then
    backup="$data/pre-update-$label.sqlite3"
    rm -f -- "$backup"
    if ! runuser -u lodelai -- "$BIN/lodelai-relay" backup --data "$data" --out "$backup" >/dev/null; then
      rm -f -- "$BIN/$new"
      die "couldn't back up the database before updating — nothing changed"
    fi
    prune_db_backups "$data"
  fi

  ln -sfn "$new" "$BIN/lodelai-relay"
  systemctl restart lodelai-relay.service
  if healthy "$pmin" "$pmax"; then
    log "version: ${prev:-none} → $new"
    prune_bins "$new" "$prev"
    return 0
  fi
  log "the new version didn't start — recent log:"
  journalctl -u lodelai-relay.service -n 30 --no-pager >&2 || true
  [ -n "$prev" ] || return 1
  systemctl stop lodelai-relay.service
  if [ -n "$backup" ] && [ -f "$backup" ]; then
    # 되돌린 DB 위에 새 판의 WAL 이 재생되지 않게 -wal·-shm 을 먼저 지운다.
    rm -f -- "$db-wal" "$db-shm"
    install -o lodelai -g lodelai -m 0600 "$backup" "$db"
  fi
  ln -sfn "$prev" "$BIN/lodelai-relay"
  systemctl start lodelai-relay.service
  if healthy "" ""; then
    log "rolled back the program and database to: $prev"
  else
    log "the previous version ($prev) won't start either — check journalctl -u lodelai-relay"
  fi
  return 1
}

# 로컬 빌드 판 읽기: 주인 권한으로 읽는다(주인이 못 읽는 파일을 심볼릭 링크로 끌어오지 못하게).
read_local_binary() { # read_local_binary <경로> <출력>
  local why owner
  why=$(binary_path_ok "$1") ||
    die "not using the local build — $why. Close that one folder as its owner: chmod go-w <that folder> (deploy/relay/build-local.sh builds with umask 022 and closes the clone)"
  owner=$(owner_of "$1")
  if [ "$owner" = root ]; then cat -- "$1" >"$2"; else runuser -u "$owner" -- cat -- "$1" >"$2"; fi
  is_elf "$2" || die "not an ELF executable: $1"
}

local_label() { echo "$(date +%Y%m%d)-$(sha256_of "$1" | cut -c1-12)"; }

UNITS="lodelai-relay.service lodelai-backup.service lodelai-backup.timer lodelai-health.service lodelai-health.timer
  lodelai-autoupdate.service lodelai-autoupdate.timer"

# 서명된 tar 의 deploy/(또는 레포)로 스크립트·유닛 원본을 깐다 — 갱신 때마다 그 판의 것으로.
install_scripts() { # install_scripts <deploy 폴더>
  local d=$1 u
  install -d -o root -g root -m 0755 "$BIN" "$LIB"
  install -o root -g root -m 0755 "$d/install.sh" "$LIB/install.sh"
  install -o root -g root -m 0755 "$d/lodelai-update.sh" "$BIN/lodelai-update"
  install -o root -g root -m 0755 "$d/lodelai-reset.sh" "$BIN/lodelai-reset"
  install -o root -g root -m 0755 "$d/lodelai-backup.sh" "$BIN/lodelai-backup"
  install -o root -g root -m 0755 "$d/lodelai-health.sh" "$BIN/lodelai-health"
  for u in $UNITS; do install -o root -g root -m 0644 "$d/$u" "$LIB/$u"; done
}

# 깔린 유닛을 lib 의 원본으로 맞춘다(갱신에서 유닛이 바뀌었을 수 있다). 스스로 받기 유닛은 이미 깔려 있을 때만.
refresh_units() {
  local u changed=0
  for u in $UNITS; do
    [ -e "/etc/systemd/system/$u" ] || continue
    cmp -s "$LIB/$u" "/etc/systemd/system/$u" && continue
    install -o root -g root -m 0644 "$LIB/$u" "/etc/systemd/system/$u"
    changed=1
  done
  [ "$changed" = 0 ] || systemctl daemon-reload
}

# ---------------------------------------------------------------- 갱신(lodelai-update 가 부른다)

update_main() { # --update [--auto] [--version x.y.z | --binary <path>]
  local auto=0 version="" binary="" source rc=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --auto) auto=1; shift ;;
      --version) version=${2:?--version needs a value}; shift 2 ;;
      --binary) binary=${2:?--binary needs a value}; shift 2 ;;
      *) die "unknown option: $1" ;;
    esac
  done
  [ "$(id -u)" -eq 0 ] || die "run as root"
  [ -z "$version" ] || [ -z "$binary" ] || die "--version and --binary can't be used together"
  if [ -z "$version" ] && [ -z "$binary" ]; then
    source=$(env_value LODELAI_UPDATE_SOURCE "$ETC/update.env")
    case "$source" in
      binary:/*) binary=${source#binary:} ;;
      "" | release) ;;
      *) die "LODELAI_UPDATE_SOURCE in $ETC/update.env isn't valid: $source" ;;
    esac
  fi
  # 필수 운영자 값(메일 보내는 주소 등)이 비면 판을 바꾸기 전에 멈춘다 — 새 relay 가 뜨지 못해 되돌림으로 가지 않게.
  check_operator_env "$ETC/relay.env"
  TMPD=$(mktemp -d)
  trap 'rm -rf "$TMPD"' EXIT
  [ -n "$binary" ] || need_minisign
  if [ -n "$binary" ]; then
    if [ "$auto" = 1 ]; then
      log "unsigned local binary — not updating automatically"
      return 0
    fi
    read_local_binary "$binary" "$TMPD/lodelai-relay"
    switch_to "$TMPD/lodelai-relay" "$(local_label "$TMPD/lodelai-relay")" "" ""
    return
  fi
  check_next_key "$TMPD"
  resolve_release "$TMPD" "$version" "$auto" || rc=$?
  [ "$rc" != 2 ] || return 0
  [ "$rc" = 0 ] || return "$rc"
  if [ "$(readlink "$BIN/lodelai-relay" || true)" = "lodelai-relay-$R_VERSION" ]; then
    log "already on this version: $R_VERSION"
    return 0
  fi
  download_release "$TMPD"
  install_scripts "$TMPD/x/deploy"
  refresh_units
  switch_to "$TMPD/x/lodelai-relay" "$R_VERSION" "$R_PMIN" "$R_PMAX"
}

# ---------------------------------------------------------------- 설치

set_kv() { # set_kv <키> <값> <파일> — 설치가 정하는 값(도메인 등)은 늘 덮어쓴다
  local tmp
  if grep -q "^$1=" "$3"; then
    tmp=$(mktemp)
    awk -v k="$1" -v v="$2" 'index($0, k "=") == 1 { print k "=" v; next } { print }' "$3" >"$tmp"
    cat "$tmp" >"$3"
    rm -f "$tmp"
  else
    printf '%s=%s\n' "$1" "$2" >>"$3"
  fi
}
fill_if_empty() { # fill_if_empty <키> <값> <파일> — 값이 비었을 때만
  [ -n "$(env_value "$1" "$3")" ] || { set_kv "$1" "$2" "$3"; log "$3: filled in $1"; }
}
ensure_key() { grep -q "^$1=" "$2" || printf '%s=\n' "$1" >>"$2"; }

check_platform() {
  [ -r /etc/os-release ] || die "/etc/os-release not found — Ubuntu 22.04+ and Debian 12+ only"
  local id ver
  id=$(. /etc/os-release && echo "${ID:-}")
  ver=$(. /etc/os-release && echo "${VERSION_ID:-0}")
  case "$id" in
    ubuntu) [ "${ver%%.*}" -ge 22 ] || die "Ubuntu $ver — 22.04 or later required" ;;
    debian) [ "${ver%%.*}" -ge 12 ] || die "Debian $ver — 12 or later required" ;;
    *) die "unsupported distribution: $id (Ubuntu 22.04+ and Debian 12+ only)" ;;
  esac
  command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ] || die "systemd isn't running"
  arch_name >/dev/null
}

# install_main 이 apt 로 까는 패키지(한 곳 — 서버 이전 스크립트 0단계도 `--list-packages` 로 이것을 본다).
# minisign 은 판을 받을 때(서명 확인)만 — 로컬 빌드(--binary)는 받지 않는다. Ubuntu 22.04 엔 minisign 패키지가 없다(#571 ③).
# x86_64 의 rclone 은 해시 고정 zip 이라 unzip, 그 밖은 배포판 rclone.
install_packages() { # install_packages <binary|release> <tls>
  local p=(ca-certificates curl jq age sqlite3 tzdata)
  [ "$1" = binary ] || p+=(minisign)
  [ "$2" != caddy ] || p+=(caddy)
  if [ "$(arch_name)" = x86_64 ]; then p+=(unzip); else p+=(rclone); fi
  printf '%s\n' "${p[@]}"
}

# 판을 받는 길(설치·갱신)은 minisign 이 있어야 서명을 확인한다 — 없으면 '서명이 안 맞는다'로 엉뚱하게 멈추지 않게 먼저.
need_minisign() {
  command -v minisign >/dev/null 2>&1 ||
    die "minisign isn't installed — it's needed to verify downloaded releases. Install it (Debian 12+/Ubuntu 23.04+ package, or a release from github.com/jedisct1/minisign), or install a local build with --binary"
}

apt_install() { # 없는 것만
  local missing=() p
  for p in "$@"; do dpkg -s "$p" >/dev/null 2>&1 || missing+=("$p"); done
  [ ${#missing[@]} -eq 0 ] && return 0
  # 갓 만든 서버·컨테이너는 패키지 목록이 비어 있다 — 한 번 받고 깐다(QA 29 리허설 F1).
  if [ -z "${APT_UPDATED:-}" ]; then
    DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null ||
      die "apt-get update failed — check your network and apt repository settings"
    APT_UPDATED=1
  fi
  DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}" >/dev/null ||
    die "apt-get install ${missing[*]} failed — on Ubuntu, enable the universe repository (for minisign and caddy)"
}

# 필수 운영자 값(§1-6·§1-7). 비면 relay 를 바꾸기 전에 멈추고 무엇을 채울지 한 줄 안내한다.
check_operator_env() { # check_operator_env <relay.env>
  local f=$1 missing=() mail k
  mail=$(env_value LODELAI_MAIL "$f")
  case "${mail:-resend}" in
    resend) for k in RESEND_API_KEY LODELAI_MAIL_FROM; do [ -n "$(env_value "$k" "$f")" ] || missing+=("$k"); done ;;
    smtp) for k in SMTP_URL LODELAI_MAIL_FROM; do [ -n "$(env_value "$k" "$f")" ] || missing+=("$k"); done ;;
    *) die "LODELAI_MAIL in $f must be resend or smtp: $mail" ;;
  esac
  for k in LODELAI_PRIVACY_VERSION LODELAI_PRIVACY_URL; do [ -n "$(env_value "$k" "$f")" ] || missing+=("$k"); done
  case "$(env_value LODELAI_PRIVACY_URL "$f")" in "" | https://*) ;; *) die "LODELAI_PRIVACY_URL in $f must start with https://" ;; esac
  [ ${#missing[@]} -eq 0 ] ||
    die "fill in ${missing[*]} in $f, then run again (see 'Mail' and 'Privacy policy' in SELF-HOSTING.md). The relay wasn't changed"
}

install_main() {
  local domain="" tls=caddy root=/var/lib/lodelai require_mount=0 operator="" version="" auto=1 binary=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --domain) domain=${2:?--domain needs a value}; shift 2 ;;
      --tls) tls=${2:?--tls needs a value}; shift 2 ;;
      --data-dir) root=${2:?--data-dir needs a value}; shift 2 ;;
      --require-mount) require_mount=1; shift ;;
      --operator) operator=${2:?--operator needs a value}; shift 2 ;;
      --version) version=${2:?--version needs a value}; shift 2 ;;
      --no-auto-update) auto=0; shift ;;
      --binary) binary=${2:?--binary needs a value}; shift 2 ;;
      --admin) die "--admin was removed — the installer shows a code for creating an organization at the end" ;;
      *) die "unknown option: $1" ;;
    esac
  done
  [ "$(id -u)" -eq 0 ] || die "run as root (sudo)"
  [ -n "$domain" ] || die "--domain <relay address> is required (for example, relay.example.com)"
  domain=$(printf '%s' "$domain" | tr 'A-Z' 'a-z')
  printf '%s' "$domain" | grep -Eq '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$' ||
    die "not a valid domain: $domain"
  case "$tls" in caddy | cloudflare | none) ;; *) die "--tls must be caddy, cloudflare, or none" ;; esac
  check_data_dir "$root"
  root=${root%/}
  [ -z "$version" ] || [ -z "$binary" ] || die "--version and --binary can't be used together"
  if [ -n "$operator" ]; then
    printf '%s' "$operator" | grep -Eq '^[a-z_][a-z0-9_-]{0,31}$' || die "--operator isn't a valid user name"
    getent passwd "$operator" >/dev/null || die "user $operator doesn't exist"
  fi
  check_platform
  if [ "$require_mount" = 1 ]; then
    [ -d "$root" ] || die "$root doesn't exist (--require-mount)"
    [ "$(findmnt -n -o TARGET -T "$root")" != / ] || die "$root isn't on a separate disk — stopping (--require-mount)"
  fi

  local pkgs=() p
  while IFS= read -r p; do pkgs+=("$p"); done < <(install_packages "$([ -n "$binary" ] && echo binary || echo release)" "$tls")
  apt_install "${pkgs[@]}"
  [ -n "$binary" ] || need_minisign

  # 받을 판(서명 확인까지) — 무엇이든 바꾸기 전에.
  local deploy src label pmin="" pmax="" here
  TMPD=$(mktemp -d)
  trap 'rm -rf "$TMPD"' EXIT
  if [ -n "$binary" ]; then
    here="${BASH_SOURCE[0]:-}"
    [ -n "$here" ] && [ -f "$here" ] || die "with --binary, run deploy/relay/install.sh from your checkout of the repository"
    deploy=$(cd "$(dirname "$here")" && pwd)
    case "$binary" in /*) ;; *) binary="$(pwd)/$binary" ;; esac
    read_local_binary "$binary" "$TMPD/lodelai-relay"
    src="$TMPD/lodelai-relay"
    label=$(local_label "$src")
  else
    check_next_key "$TMPD"
    resolve_release "$TMPD" "$version" 0
    download_release "$TMPD"
    deploy="$TMPD/x/deploy"
    src="$TMPD/x/lodelai-relay"
    label=$R_VERSION
    pmin=$R_PMIN
    pmax=$R_PMAX
  fi

  # 1) 사용자·폴더
  id lodelai >/dev/null 2>&1 || useradd --system --home-dir "$root" --no-create-home --shell /usr/sbin/nologin lodelai
  install -d -o root -g root -m 0755 "$root"
  install -d -o lodelai -g lodelai -m 0700 "$root/data" "$root/backup"
  local fresh=0
  [ -f "$root/data/relay.sqlite3" ] || fresh=1

  # 2) 환경 파일 — 운영자 값은 그대로, 설치가 정하는 값만 덮는다. 바이너리를 바꾸기 전에 본다(빈 키로 멈춰도 지금 relay 가 남게).
  install -d -o root -g lodelai -m 0750 "$ETC"
  local renv=$ETC/relay.env benv=$ETC/backup.env uenv=$ETC/update.env k
  if [ ! -e "$renv" ]; then
    install -o root -g lodelai -m 0640 /dev/null "$renv"
    printf '%s\n' '# lodelai relay settings (see SELF-HOSTING.md). After changing a value, run: sudo systemctl restart lodelai-relay' 'RUST_LOG=info' >"$renv"
  fi
  set_kv LODELAI_RELAY_DATA "$root/data" "$renv"
  set_kv LODELAI_RELAY_BACKUP "$root/backup" "$renv"
  set_kv LODELAI_PUBLIC_HOST "$domain" "$renv"
  set_kv LODELAI_REQUIRE_MOUNT "$require_mount" "$renv"
  if [ "$tls" = cloudflare ]; then set_kv LODELAI_BEHIND_CLOUDFLARE true "$renv"; else set_kv LODELAI_BEHIND_CLOUDFLARE false "$renv"; fi
  ensure_key LODELAI_MAIL "$renv"
  fill_if_empty LODELAI_MAIL resend "$renv"
  for k in RESEND_API_KEY SMTP_URL LODELAI_MAIL_FROM LODELAI_PRIVACY_VERSION LODELAI_PRIVACY_URL; do ensure_key "$k" "$renv"; done
  # 그룹 대화: 비우면 켬, false 면 끔(docs/ops/self-host.md "그룹"). 운영자 값은 그대로.
  ensure_key LODELAI_GROUPS "$renv"
  # 이메일 HMAC 키(정보 파기 A): 한 번 만들고 바꾸지 않는다. DB 밖이라 백업에 없다 — 옮길 때 relay.env 도 같이.
  fill_if_empty LODELAI_EMAIL_HMAC_KEY "$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')" "$renv"
  check_operator_env "$renv"

  if [ ! -e "$benv" ]; then
    install -o root -g lodelai -m 0640 /dev/null "$benv"
    printf '%s\n' '# Off-site backup (S3-compatible, rclone) and health-check pings. Leave empty to keep local copies only (see "Backups" in SELF-HOSTING.md).' >"$benv"
  fi
  for k in R2_ACCOUNT_ID R2_BUCKET R2_ACCESS_KEY_ID R2_SECRET_ACCESS_KEY AGE_RECIPIENT HC_RELAY_URL HC_BACKUP_URL; do ensure_key "$k" "$benv"; done
  if [ -n "$operator" ] && [ -z "$(env_value AGE_RECIPIENT "$benv")" ]; then
    local ohome rf rec
    ohome=$(getent passwd "$operator" | cut -d: -f6)
    rf="$ohome/.config/lodelai/age-recipient"
    if [ -e "$rf" ]; then
      # 운영자 권한으로 읽는다(심볼릭 링크로 root 만 읽는 파일을 끌어오지 못하게).
      rec=$(runuser -u "$operator" -- cat -- "$rf" | tr -d '\r' | sed '/^[[:space:]]*$/d')
      if [ "$(printf '%s\n' "$rec" | grep -c .)" != 1 ] || ! printf '%s' "$rec" | grep -Eq '^age1[02-9ac-hj-np-z]{58}$'; then
        die "$rf isn't a single age public key line (age1…) — fix it and run again. The relay wasn't changed"
      fi
      fill_if_empty AGE_RECIPIENT "$rec" "$benv"
    fi
  fi

  [ -e "$uenv" ] || install -o root -g root -m 0644 /dev/null "$uenv"
  if [ -n "$binary" ]; then set_kv LODELAI_UPDATE_SOURCE "binary:$binary" "$uenv"; else set_kv LODELAI_UPDATE_SOURCE release "$uenv"; fi

  # 3) 스크립트·rclone
  install_scripts "$deploy"
  install_rclone

  # 4) systemd — 경로가 설치마다 달라 ReadWritePaths 는 drop-in 에 쓴다(유닛 파일은 env 치환을 못 한다).
  local u self_update=1
  for u in lodelai-relay.service lodelai-backup.service lodelai-backup.timer lodelai-health.service lodelai-health.timer; do
    install -o root -g root -m 0644 "$LIB/$u" "/etc/systemd/system/$u"
  done
  install -d -o root -g root -m 0755 /etc/systemd/system/lodelai-relay.service.d /etc/systemd/system/lodelai-backup.service.d
  printf '[Service]\nReadWritePaths=%s\n' "$root/data" >/etc/systemd/system/lodelai-relay.service.d/paths.conf
  printf '[Service]\nReadWritePaths=%s %s\n' "$root/data" "$root/backup" >/etc/systemd/system/lodelai-backup.service.d/paths.conf
  { [ "$auto" = 1 ] && [ -z "$binary" ]; } || self_update=0
  if [ "$self_update" = 1 ]; then
    install -o root -g root -m 0644 "$LIB/lodelai-autoupdate.service" /etc/systemd/system/lodelai-autoupdate.service
    install -o root -g root -m 0644 "$LIB/lodelai-autoupdate.timer" /etc/systemd/system/lodelai-autoupdate.timer
  else
    systemctl disable --now lodelai-autoupdate.timer >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/lodelai-autoupdate.service /etc/systemd/system/lodelai-autoupdate.timer
    [ -z "$binary" ] || log "unsigned local binary — no automatic update timer"
  fi
  systemctl daemon-reload
  systemctl enable lodelai-relay.service lodelai-backup.timer lodelai-health.timer >/dev/null ||
    die "couldn't enable systemd units (lodelai-relay, lodelai-backup.timer, lodelai-health.timer) — check with systemctl status"

  # 5) 판 바꾸기(DB 백업 → 링크 → 재시작 → healthz → 실패면 되돌림)
  switch_to "$src" "$label" "$pmin" "$pmax" 1 || die "relay didn't start (see the log above)"
  systemctl start lodelai-backup.timer lodelai-health.timer ||
    die "couldn't start the backup and health timers — check with systemctl status lodelai-backup.timer (the relay is running the new version)"
  [ "$self_update" = 0 ] || systemctl enable --now lodelai-autoupdate.timer >/dev/null

  # 6) 바깥 연결 — relay 는 TLS 를 하지 않는다.
  case "$tls" in
    caddy) setup_caddy "$domain" ;;
    cloudflare) log "create a Cloudflare Tunnel yourself: $domain → http://127.0.0.1:8787 (see SELF-HOSTING.md)" ;;
    none) log "set up your own proxy: https://$domain → http://127.0.0.1:8787" ;;
  esac

  # 7) 운영자 sudoers([`operator_sudoers`]) — 스크립트는 인자 없이만, bootstrap·suspend·unsuspend 는 이 데이터 폴더로만 lodelai 로.
  #    운영자가 없으면 두지 않는다.
  #    relay 0.1.2: 이메일 코드·목록·지우기(`--email`·`--list`·`--revoke`)도. `*` 뒤에 인자를 더 붙여도 bootstrap 은 같은 인자를
  #    두 번 받지 않으므로(`--data` 를 바꿀 수 없다) 이 폴더 밖을 건드리지 못한다. 갱신(--update)은 이 파일을 다시 쓰지 않는다 —
  #    0.1.1 에서 올린 서버는 install.sh 를 같은 인자로 한 번 더 돌리면 새 줄이 들어간다.
  if [ -n "$operator" ]; then
    local s
    s=$(mktemp)
    operator_sudoers "$operator" "$root" >"$s"
    visudo -cf "$s" >/dev/null || { rm -f "$s"; die "sudoers snippet failed validation — not installed"; }
    install -o root -g root -m 0440 "$s" /etc/sudoers.d/lodelai-update
    rm -f "$s"
    visudo -c >/dev/null
  else
    rm -f /etc/sudoers.d/lodelai-update
  fi

  # 8) 첫 관리자(§1-9) — 새 DB 일 때만 조직 만들기 코드 하나(1시간).
  if [ "$fresh" = 1 ]; then
    log "code for creating an organization (valid for 1 hour):"
    runuser -u lodelai -- "$BIN/lodelai-relay" bootstrap --data "$root/data" ||
      log "couldn't issue a code — later, run: sudo -u lodelai $BIN/lodelai-relay bootstrap --data $root/data"
  fi
  log "done. Logs: journalctl -u lodelai-relay -f · Update: sudo $BIN/lodelai-update · Automatic updates: $([ "$self_update" = 1 ] && echo on || echo off)"
}

# 데이터 폴더 경로(#955): 절대 경로이고 글자는 영문·숫자·`/._-` 만 — sudoers 줄(operator_sudoers)에 그대로 들어가므로
# `*?[`·빈칸·쉼표·`\` 가 들면 와일드카드·구분자로 읽혀 줄의 뜻이 바뀐다.
check_data_dir() {
  local LC_ALL=C # A-Z 범위가 로캘 따라 넓어지지 않게
  case "$1" in /*) ;; *) die "--data-dir must be an absolute path" ;; esac
  case "$1" in *[!A-Za-z0-9/._-]*) die "--data-dir can use only letters, digits, and / . _ - (it goes into the sudoers rule)" ;; esac
}

# 운영자 sudoers 줄(7단계·test-sudoers.sh 가 같이 쓴다). 스크립트는 인자 없이만, lodelai-relay 의 bootstrap·suspend·unsuspend(#906)는
# lodelai 로 이 데이터 폴더로만 — 같은 인자를 두 번 받지 않으므로(`--data` 를 바꿀 수 없다) `*` 뒤에 무엇을 붙여도 이 폴더 밖을 못 건드린다.
operator_sudoers() {
  local op=$1 root=$2 r="$BIN/lodelai-relay"
  local b="$r bootstrap --data $root/data" su="$r suspend --data $root/data --user" un="$r unsuspend --data $root/data --user"
  printf '%s\n' '# lodelai relay update and reset (set by install.sh). Scripts run without arguments only; bootstrap, suspend and unsuspend run as lodelai on this data folder only.' \
    "$op ALL=(root) NOPASSWD: $BIN/lodelai-update \"\", $BIN/lodelai-reset \"\"" \
    "$op ALL=(lodelai) NOPASSWD: $b, $b --email *, $b --list, $b --revoke *, $su *, $un *"
}

# rclone(바깥 백업) — x86_64 는 판·해시 고정, arm64 는 배포판 패키지(서명된 저장소).
install_rclone() {
  local ver=v1.68.2 sha=0e6fa18051e67fc600d803a2dcb10ddedb092247fc6eee61be97f64ec080a13c r
  if [ "$(arch_name)" != x86_64 ]; then
    apt_install rclone
    ln -sfn "$(command -v rclone)" "$BIN/rclone"
    return
  fi
  if grep -q "^rclone $ver\$" <<<"$("$BIN/rclone" version 2>/dev/null)"; then return; fi
  apt_install unzip
  r=$(mktemp -d)
  curl -fsSL --proto '=https' --max-time 300 -o "$r/rclone.zip" "https://downloads.rclone.org/$ver/rclone-$ver-linux-amd64.zip"
  [ "$(sha256_of "$r/rclone.zip")" = "$sha" ] || { rm -rf "$r"; die "rclone hash doesn't match — not installed"; }
  unzip -q -j "$r/rclone.zip" "rclone-$ver-linux-amd64/rclone" -d "$r"
  install -o root -g root -m 0755 "$r/rclone" "$BIN/rclone"
  rm -rf "$r"
}

# Caddy(기본): 배포판 패키지. Caddyfile 은 이 스크립트가 만든 것(첫 줄 표시)일 때만 다시 쓴다.
setup_caddy() { # setup_caddy <domain>
  local f=/etc/caddy/Caddyfile mark='# lodelai install.sh'
  if [ -s "$f" ] && ! head -1 "$f" | grep -qF "$mark"; then
    log "$f already exists (yours) — leaving it alone. It needs this: $1 { reverse_proxy 127.0.0.1:8787 }"
    return
  fi
  printf '%s\n%s {\n\treverse_proxy 127.0.0.1:8787\n}\n' "$mark" "$1" >"$f"
  systemctl enable caddy >/dev/null 2>&1 || true
  systemctl reload-or-restart caddy
  log "Caddy: https://$1 → 127.0.0.1:8787 (Caddy gets the certificate — ports 80 and 443 must be open)"
}

main() {
  if [ "${1:-}" = --list-packages ]; then
    install_packages "${2:?--list-packages binary|release <tls>}" "${3:?--list-packages binary|release <tls>}"
    return
  fi
  if [ "${1:-}" = --update ]; then
    shift
    update_main "$@"
  else
    install_main "$@"
  fi
}

# source 해서 함수만 쓰는 시험(deploy/relay/test-install.sh)에서는 돌리지 않는다. curl | bash 면 BASH_SOURCE 가 비어 돈다.
if [ -z "${BASH_SOURCE[0]:-}" ] || [ "${BASH_SOURCE[0]}" = "$0" ]; then
  main "$@"
fi
