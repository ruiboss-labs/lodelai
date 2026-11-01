#!/usr/bin/env bash
# deploy/relay/install.sh 의 받기·확인 함수 시험(묶음 29 §1-2·§2). 맥·리눅스에서 root 없이 돈다 — systemd·apt 는 건드리지 않는다.
#   bash deploy/relay/test-install.sh
# 일회용 minisign 키(시험 폴더 안, 끝나면 지움)로 manifest 를 서명하고 file:// 주소로 받는다. relay 서명 키와 무관하다.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
command -v minisign >/dev/null || { echo "minisign 이 없다(brew install minisign / apt install minisign)" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq 가 없다" >&2; exit 2; }

T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
export LODELAI_RELAY_BASE_URL="file://$T/r2/relay"
# shellcheck source=install.sh
saved_path=$PATH
. "$here/install.sh"
PATH=$saved_path # install.sh 는 서버용으로 PATH 를 고정한다 — 시험에선 minisign·jq 가 있는 원래 PATH
set +e # 시험은 실패를 받아 본다
ETC="$T/etc"
PUBKEY_FILE="$ETC/relay-signing.pub"
mkdir -p "$ETC" "$T/r2/relay" "$T/keys"

pass=0 fail=0
ok() { pass=$((pass + 1)); printf '  ok  %s\n' "$1"; }
no() { fail=$((fail + 1)); printf '  FAIL %s\n' "$1"; }
expect() { # expect <설명> <기대 종료 코드> <명령…> — die 는 exit 라서 하위 셸에서 돌린다
  local what=$1 want=$2 got
  shift 2
  ("$@") >"$T/out" 2>&1
  got=$?
  if [ "$got" = "$want" ]; then ok "$what"; else no "$what (종료 $got, 기대 $want): $(tail -2 "$T/out" | tr '\n' ' ')"; fi
}

minisign -G -W -p "$T/keys/a.pub" -s "$T/keys/a.key" >/dev/null 2>&1
minisign -G -W -p "$T/keys/b.pub" -s "$T/keys/b.key" >/dev/null 2>&1
KEY_A=$(key_line "$T/keys/a.pub")
sign() { minisign -S -s "$T/keys/$1.key" -m "$2" -x "$2.minisig" >/dev/null 2>&1 </dev/null; }

arch=$(arch_name)
# 가짜 판: ELF 머리 4바이트 + deploy/install.sh
make_release() { # make_release <판> <published_at> [protocol max]
  local v=$1 d="$T/build/$1"
  mkdir -p "$d/deploy" "$T/r2/relay/$v"
  printf '\177ELF가짜 relay %s\n' "$v" >"$d/lodelai-relay"
  cp "$here"/install.sh "$here"/lodelai-update.sh "$d/deploy/"
  COPYFILE_DISABLE=1 tar -czf "$T/r2/relay/$v/lodelai-relay-$v-linux-$arch.tar.gz" -C "$d" lodelai-relay deploy
  local sha
  sha=$(sha256_of "$T/r2/relay/$v/lodelai-relay-$v-linux-$arch.tar.gz")
  jq -n --arg v "$v" --arg p "$2" --arg u "$LODELAI_RELAY_BASE_URL/$v/lodelai-relay-$v-linux-$arch.tar.gz" --arg s "$sha" \
    --arg a "$arch" --argjson max "${3:-8}" \
    '{version:$v, published_at:$p, protocol:{min:8, max:$max}, assets:{($a):{url:$u, sha256:$s}}}' >"$T/r2/relay/$v/manifest.json"
  sign a "$T/r2/relay/$v/manifest.json"
}
latest() { cp "$T/r2/relay/$1/manifest.json" "$T/r2/relay/latest.json"; cp "$T/r2/relay/$1/manifest.json.minisig" "$T/r2/relay/latest.json.minisig"; }

old=$(date -u -r $(($(date +%s) - 4 * 86400)) +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '-4 days' +%Y-%m-%dT%H:%M:%SZ)
fresh=$(date -u +%Y-%m-%dT%H:%M:%SZ)
future=$(date -u -r $(($(date +%s) + 86400)) +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '+1 day' +%Y-%m-%dT%H:%M:%SZ)
make_release 0.3.0 "$old"
make_release 0.3.1 "$fresh"
make_release 0.3.2 "$future"
latest 0.3.0

echo "키"
RELAY_PUBKEY_BUILTIN=""
expect "공개키가 비면 멈춤(fail-closed)" 1 resolve_release "$T/w" "" 0
RELAY_PUBKEY_BUILTIN=$KEY_A

echo "manifest·tar 확인"
mkdir -p "$T/w"
expect "서명된 latest → 받음" 0 resolve_release "$T/w" "" 0
expect "고른 판(--version) → 받음" 0 resolve_release "$T/w" 0.3.1 0
expect "판 꼴이 아님 → 멈춤" 1 resolve_release "$T/w" "0.3" 0
( resolve_release "$T/w" 0.3.0 0 && download_release "$T/w" && [ -f "$T/w/x/deploy/install.sh" ] ) >/dev/null 2>&1 &&
  ok "tar 해시 맞음 → 풀림(lodelai-relay·deploy/)" || no "tar 해시 맞음 → 풀림"
cp "$T/r2/relay/0.3.0/manifest.json" "$T/m.bak"
jq '.version="0.3.9"' "$T/m.bak" >"$T/r2/relay/0.3.0/manifest.json"
expect "서명 뒤 manifest 를 바꿈 → 멈춤" 1 resolve_release "$T/w" 0.3.0 0
cp "$T/m.bak" "$T/r2/relay/0.3.0/manifest.json"
sign b "$T/r2/relay/0.3.0/manifest.json"
expect "다른 키로 서명한 manifest → 멈춤" 1 resolve_release "$T/w" 0.3.0 0
sign a "$T/r2/relay/0.3.0/manifest.json"
tarf="$T/r2/relay/0.3.0/lodelai-relay-0.3.0-linux-$arch.tar.gz"
cp "$tarf" "$T/t.bak"
printf 'x' >>"$tarf"
tar_bad() { resolve_release "$T/w" 0.3.0 0 && download_release "$T/w"; }
expect "tar 해시 틀림 → 멈춤" 1 tar_bad
cp "$T/t.bak" "$tarf"
jq --arg a "$arch" '.assets[$a].url="http://example.com/x.tar.gz"' "$T/m.bak" >"$T/r2/relay/0.3.0/manifest.json"
sign a "$T/r2/relay/0.3.0/manifest.json"
expect "자산 주소가 https 가 아님 → 멈춤" 1 resolve_release "$T/w" 0.3.0 0
cp "$T/m.bak" "$T/r2/relay/0.3.0/manifest.json"
sign a "$T/r2/relay/0.3.0/manifest.json"

echo "72시간(스스로 받기만)"
expect "4일 지난 판 → auto 받음" 0 resolve_release "$T/w" 0.3.0 1
expect "막 낸 판 → auto 건너뜀(2)" 2 resolve_release "$T/w" 0.3.1 1
expect "막 낸 판 → 수동은 받음" 0 resolve_release "$T/w" 0.3.1 0
expect "게시 시각이 서버보다 뒤 → auto 건너뜀(2)" 2 resolve_release "$T/w" 0.3.2 1

echo "next-key"
expect "next-key 없음(파일 없음) → 그대로" 0 check_next_key "$T/w"
[ ! -e "$PUBKEY_FILE" ] && ok "  키 파일 안 생김" || no "  키 파일 안 생김"
cp "$T/keys/b.pub" "$T/r2/relay/next-key.pub"
minisign -S -s "$T/keys/b.key" -m "$T/r2/relay/next-key.pub" -x "$T/r2/relay/next-key.pub.minisig" >/dev/null 2>&1 </dev/null
( check_next_key "$T/w" ) >/dev/null 2>&1
[ ! -e "$PUBKEY_FILE" ] && ok "새 키가 스스로 서명한 next-key → 무시" || no "새 키가 스스로 서명한 next-key → 무시"
minisign -S -s "$T/keys/a.key" -m "$T/r2/relay/next-key.pub" -x "$T/r2/relay/next-key.pub.minisig" >/dev/null 2>&1 </dev/null
( check_next_key "$T/w" ) >/dev/null 2>&1
[ "$(key_line "$PUBKEY_FILE" 2>/dev/null)" = "$(key_line "$T/keys/b.pub")" ] && ok "옛 키로 서명한 next-key → 새 키로 넘어감" || no "옛 키로 서명한 next-key → 새 키로 넘어감"
expect "넘어간 뒤 옛 키 서명 manifest → 멈춤" 1 resolve_release "$T/w" 0.3.0 0
sign b "$T/r2/relay/0.3.0/manifest.json"
expect "넘어간 뒤 새 키 서명 manifest → 받음" 0 resolve_release "$T/w" 0.3.0 0
RELAY_PUBKEY_BUILTIN=""
expect "박은 키가 비어도 넘어간 키 파일이 이김" 0 resolve_release "$T/w" 0.3.0 0
RELAY_PUBKEY_BUILTIN=$KEY_A
rm -f "$PUBKEY_FILE" "$T/r2/relay/next-key.pub" "$T/r2/relay/next-key.pub.minisig"

echo "로컬 빌드 판 경로"
mkdir -p "$T/bin-ok"
chmod 0755 "$T" "$T/bin-ok"
printf '\177ELF' >"$T/bin-ok/lodelai-relay"
chmod 0755 "$T/bin-ok/lodelai-relay"
# mktemp 폴더의 윗 폴더(/var/folders/…·/tmp)는 남에게 열려 있을 수 있어 경로 검사를 시험 폴더 아래로만 본다.
under() { local p=$1 cur=$T part IFS=/; for part in ${p#"$T"}; do [ -n "$part" ] || continue; cur="$cur/$part"; [ $((0$(perm_of "$cur") & 022)) -eq 0 ] || return 1; done; }
under "$T/bin-ok/lodelai-relay" && ok "남에게 닫힌 경로 → 씀" || no "남에게 닫힌 경로 → 씀"
chmod 0775 "$T/bin-ok"
under "$T/bin-ok/lodelai-relay" && no "그룹 쓰기 열린 폴더 → 안 씀" || ok "그룹 쓰기 열린 폴더 → 안 씀"
chmod 0755 "$T/bin-ok"
chmod 0757 "$T/bin-ok/lodelai-relay"
under "$T/bin-ok/lodelai-relay" && no "다른 사람 쓰기 열린 파일 → 안 씀" || ok "다른 사람 쓰기 열린 파일 → 안 씀"
expect "binary_path_ok: /tmp 아래(다른 사람 쓰기 열림) → 안 씀" 1 binary_path_ok "$(mktemp /tmp/lodelai-test-bin.XXXXXX)"
rm -f /tmp/lodelai-test-bin.*
expect "binary_path_ok: 상대 경로 → 안 씀" 1 binary_path_ok lodelai-relay
# 로컬 빌드 거절은 열린 폴더와 고치는 한 줄을 말한다(#571 단계 B — umask 002 서버).
mkdir -p "$T/bin-open" && chmod 0775 "$T/bin-open" && printf '\177ELF' >"$T/bin-open/lodelai-relay"
expect "read_local_binary: 그룹 쓰기 열린 폴더 → 멈춤" 1 read_local_binary "$T/bin-open/lodelai-relay" "$T/out.bin"
grep -q "writable by other users: .*bin-open (775)" "$T/out" && grep -q "chmod go-w <that folder>" "$T/out" &&
  ok "거절 문구에 열린 폴더·chmod 한 줄" || no "거절 문구에 열린 폴더·chmod 한 줄: $(tail -1 "$T/out")"

echo "env 파일"
f="$T/relay.env"
printf 'RUST_LOG=info\nLODELAI_PUBLIC_HOST=old.example\nLODELAI_PUBLIC_HOST_X=keep\n' >"$f"
set_kv LODELAI_PUBLIC_HOST new.example "$f"
[ "$(env_value LODELAI_PUBLIC_HOST "$f")" = new.example ] && [ "$(env_value LODELAI_PUBLIC_HOST_X "$f")" = keep ] &&
  ok "set_kv 는 그 키만 바꿈(앞이 같은 키는 그대로)" || no "set_kv 는 그 키만 바꿈"
set_kv LODELAI_PRIVACY_URL 'https://a.example/p?x=1&y=2' "$f"
[ "$(env_value LODELAI_PRIVACY_URL "$f")" = 'https://a.example/p?x=1&y=2' ] && ok "set_kv 값에 &·? 그대로" || no "set_kv 값에 &·? 그대로"
( fill_if_empty LODELAI_EMAIL_HMAC_KEY aaaa "$f"; fill_if_empty LODELAI_EMAIL_HMAC_KEY bbbb "$f" ) >/dev/null
[ "$(env_value LODELAI_EMAIL_HMAC_KEY "$f")" = aaaa ] && ok "fill_if_empty 는 처음 한 번만" || no "fill_if_empty 는 처음 한 번만"
expect "메일 키·처리방침 비면 멈춤" 1 check_operator_env "$f"
printf 'LODELAI_MAIL=resend\nRESEND_API_KEY=k\nLODELAI_MAIL_FROM="lodelai <noreply@b.c>"\nLODELAI_PRIVACY_VERSION=2026-10-25\nLODELAI_PRIVACY_URL=https://x/p\n' >>"$f"
expect "resend 값 다 있음 → 통과" 0 check_operator_env "$f"
[ "$(env_value LODELAI_MAIL_FROM "$f")" = "lodelai <noreply@b.c>" ] && ok "따옴표 값은 따옴표를 벗겨 읽음" || no "따옴표 값은 따옴표를 벗겨 읽음"
printf 'LODELAI_MAIL=smtp\n' >>"$f"
expect "smtp 인데 SMTP_URL 없음 → 멈춤" 1 check_operator_env "$f"
printf 'SMTP_URL=smtps://u:p@mail.example:465\n' >>"$f"
expect "smtp 값 다 있음 → 통과" 0 check_operator_env "$f"
printf 'LODELAI_PRIVACY_URL=http://x/p\n' >>"$f"
expect "처리방침 주소가 https 아님 → 멈춤" 1 check_operator_env "$f"

echo
echo "통과 $pass · 실패 $fail"
[ "$fail" = 0 ]
