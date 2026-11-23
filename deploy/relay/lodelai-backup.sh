#!/usr/bin/env bash
# lodelai 서버 DB 사본(#364). lodelai-backup.service 가 사용자 lodelai 로 부른다(/opt/lodelai/bin/lodelai-backup).
#  1) lodelai-relay backup = VACUUM INTO — 서비스가 도는 중에도 일관된 단일 파일
#  2) gzip → <백업 폴더>/relay-<UTC 시각>.sqlite3.gz, 최근 7개만 남긴다
#  3) /etc/lodelai/backup.env 에 R2 값이 있으면 **age 로 암호화한 사본만** R2 로 올린다(rclone, 키는 env 로만). 없으면 로컬 사본만.
#     암호화 공개키는 AGE_RECIPIENT(운영자가 만든 키의 공개 쪽) — 비밀키는 서버·R2 어디에도 없다. 공개키가 비어 있으면
#     평문을 내보내지 않고 바깥 사본 실패로 기록한다(관리자 화면 offsite_failed). 로컬 사본(같은 기계, 7개)은 평문 gzip.
#  4) 결과를 relay DB 에 기록(lodelai-relay backup 이 시도 시각, 여기서 gzip 뒤 --local-ok·R2 뒤 --offsite·중간 실패 --failed — m1-spec §17.3)
#  5) HC_BACKUP_URL 이 있으면 결과 코드를 감시 서비스에 알린다(성공·실패 모두)
# 본문은 E2E 봉투라 사본에도 평문 메시지는 없다. 키는 인자로 넘기지 않는다(ps 로 보임) — rclone 은 env, curl 은 설정을 stdin 으로.
set -euo pipefail

# 데이터·백업 경로는 install.sh 가 /etc/lodelai/relay.env 에 적은 값(그 파일의 비밀 값은 env 로 받지 않고 이 두 줄만 읽는다).
conf() { sed -n "s/^$1=//p" /etc/lodelai/relay.env | tail -1; }
DATA=$(conf LODELAI_RELAY_DATA)
DIR=$(conf LODELAI_RELAY_BACKUP)
[ -n "$DATA" ] && [ -n "$DIR" ] || { echo "LODELAI_RELAY_DATA or LODELAI_RELAY_BACKUP is missing from /etc/lodelai/relay.env" >&2; exit 1; }
KEEP=7
umask 077

# 감시(SELF-HOSTING.md): 끝날 때 결과 코드를 healthchecks 에 알린다(0 = 성공, 그 밖 = 실패 알림).
# 24시간 동안 ping 이 없어도 알림이 간다. URL 은 backup.env 의 HC_BACKUP_URL — 인자로 넘기지 않는다(ps 로 보임).
ping_hc() {
  [ -n "${HC_BACKUP_URL:-}" ] || return 0
  printf 'url = "%s/%s"\n' "$HC_BACKUP_URL" "$1" |
    curl --config - --fail --silent --show-error --max-time 10 --retry 3 -o /dev/null ||
    echo "health-check ping failed" >&2
}
trap 'ping_hc $?' EXIT
# 결과 기록(m1-spec §17.3 — 관리자 화면 server.status 가 읽는다). 시도 시각은 lodelai-relay backup 이 직접 쓴다.
# 로컬 성공은 gzip 사본이 생긴 뒤 --local-ok, 중간에 실패하면 --failed, 바깥 사본 결과는 아래에서 --offsite.
mark() { /opt/lodelai/bin/lodelai-relay backup-mark --data "$DATA" "$@" || echo "couldn't record the backup: $*" >&2; }
trap 'mark --failed' ERR

stamp=$(date -u +%Y%m%dT%H%M%SZ)
name="relay-$stamp.sqlite3"
/opt/lodelai/bin/lodelai-relay backup --data "$DATA" --out "$DIR/$name"
gzip -9 "$DIR/$name"
file="$DIR/$name.gz"
echo "local copy: $file ($(stat -c %s "$file") bytes)"
mark --local-ok

# 오래된 로컬 사본 정리(최근 $KEEP 개).
mapfile -t old < <(ls -1t "$DIR"/relay-*.sqlite3.gz | tail -n +$((KEEP + 1)))
if [ "${#old[@]}" -gt 0 ]; then
  rm -f -- "${old[@]}"
fi

if [ -z "${R2_ACCOUNT_ID:-}" ] || [ -z "${R2_BUCKET:-}" ] || [ -z "${R2_ACCESS_KEY_ID:-}" ] || [ -z "${R2_SECRET_ACCESS_KEY:-}" ]; then
  echo "no off-site storage settings (/etc/lodelai/backup.env) — local copy only"
  mark --offsite skipped
  exit 0
fi

# 바깥 사본은 업로드 전에 암호화한다(처리방침 2026-10-25 — R2 사본은 별도 암호화). 공개키가 없으면 올리지 않는다.
if [ -z "${AGE_RECIPIENT:-}" ] || [ "${AGE_RECIPIENT#age1}" = "$AGE_RECIPIENT" ]; then
  echo "AGE_RECIPIENT (age public key, age1…) is missing — unencrypted copies are never uploaded (/etc/lodelai/backup.env)" >&2
  mark --offsite failed
  trap - ERR
  exit 1
fi
enc="$file.age"
trap 'rc=$?; rm -f -- "$enc"; ping_hc $rc' EXIT
if ! age -r "$AGE_RECIPIENT" -o "$enc" "$file"; then
  mark --offsite failed
  trap - ERR
  echo "age encryption failed" >&2
  exit 1
fi

# rclone(install.sh 가 판·해시를 고정해 둔다). 설정 파일 없이 env 로만 — 키가 인자(ps)·파일에 남지 않는다.
# curl 7.81 의 --aws-sigv4 는 R2 에서 403 이었다(10-25 첫 실행).
export RCLONE_CONFIG_R2_TYPE=s3 RCLONE_CONFIG_R2_PROVIDER=Cloudflare
export RCLONE_CONFIG_R2_ENDPOINT="https://$R2_ACCOUNT_ID.r2.cloudflarestorage.com"
export RCLONE_CONFIG_R2_ACCESS_KEY_ID="$R2_ACCESS_KEY_ID" RCLONE_CONFIG_R2_SECRET_ACCESS_KEY="$R2_SECRET_ACCESS_KEY"
# 토큰은 그 버킷의 객체 읽기·쓰기만 — 버킷 확인·만들기는 하지 않는다.
export RCLONE_CONFIG_R2_NO_CHECK_BUCKET=true
trap - ERR
if /opt/lodelai/bin/rclone --config "" --retries 3 --low-level-retries 3 --contimeout 30s --timeout 300s \
  copyto "$enc" "r2:$R2_BUCKET/relay/$name.gz.age"; then
  mark --offsite ok
  echo "uploaded (encrypted): $R2_BUCKET/relay/$name.gz.age"
else
  mark --offsite failed
  echo "upload failed" >&2
  exit 1
fi
