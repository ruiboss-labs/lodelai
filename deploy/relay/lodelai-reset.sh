#!/usr/bin/env bash
# lodelai 서버 데이터 초기화(개발 단계, 묶음 5). install.sh 가 /opt/lodelai/bin/lodelai-reset(root 0755)로 두고,
# /etc/sudoers.d/lodelai-update 가 운영자(install.sh --operator)에게 이 파일만 인자 없이 NOPASSWD 로 허용한다.
#
#   sudo /opt/lodelai/bin/lodelai-reset
#
# 인자를 받지 않는다. 모든 계정·조직·메시지가 사라진다 — 되돌릴 사본을 먼저 뜬다.
#  1) lodelai-relay 를 멈춘다(백업이 도는 중이면 아무것도 하지 않고 끝난다)
#  2) 데이터 폴더 전체를 <백업 폴더>/reset-<UTC 시각>.tar.gz(lodelai 0600)로 뜬다 — 실패하면 지우지 않고 다시 띄운다
#  3) 데이터 폴더 안을 비운다(폴더는 남긴다) → 다시 시작 → 127.0.0.1:8787/v1/healthz 확인
#  4) reset-* 사본은 최근 3개만 남긴다(빈 DB 를 연달아 초기화해도 앞의 진짜 사본이 바로 밀려나지 않게)
# 그 뒤 첫 관리자 코드: sudo -u lodelai /opt/lodelai/bin/lodelai-relay bootstrap --data <데이터 폴더> (운영자, 비밀번호 없이)
# 경로는 /etc/lodelai/relay.env 의 LODELAI_RELAY_DATA·LODELAI_RELAY_BACKUP(install.sh 가 적는다).
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 077

# 데이터·백업 경로는 install.sh 가 /etc/lodelai/relay.env 에 적은 값(그 파일의 비밀 값은 env 로 받지 않고 이 두 줄만 읽는다).
conf() { sed -n "s/^$1=//p" /etc/lodelai/relay.env | tail -1; }
DATA=$(conf LODELAI_RELAY_DATA)
DIR=$(conf LODELAI_RELAY_BACKUP)
KEEP=3

if [ $# -ne 0 ]; then
  echo "run without arguments: sudo $0" >&2
  exit 2
fi
if [ "$(id -u)" -ne 0 ]; then
  echo "run with sudo: sudo $0" >&2
  exit 1
fi
[ -n "$DATA" ] && [ -n "$DIR" ] || { echo "LODELAI_RELAY_DATA or LODELAI_RELAY_BACKUP is missing from /etc/lodelai/relay.env" >&2; exit 1; }
# --require-mount 로 깐 서버(데이터를 별도 디스크에 둔 서버)는 데이터가 별도 디스크에 있을 때만 지운다.
if [ "$(conf LODELAI_REQUIRE_MOUNT)" = 1 ] && [ "$(findmnt -n -o TARGET -T "$DATA")" = / ]; then
  echo "$DATA isn't on a separate disk — stopping" >&2
  exit 1
fi
if systemctl is-active --quiet lodelai-backup.service; then
  echo "a backup is running — run again when it's done" >&2
  exit 1
fi

healthy() {
  local i
  for i in 1 2 3 4 5; do
    sleep 2
    if systemctl is-active --quiet lodelai-relay.service &&
      curl -fsS -m 3 -o /dev/null http://127.0.0.1:8787/v1/healthz; then
      return 0
    fi
  done
  return 1
}

systemctl stop lodelai-relay.service

stamp=$(date -u +%Y%m%dT%H%M%SZ)
out="$DIR/reset-$stamp.tar.gz"
if ! tar -C "$DATA" -czf "$out" .; then
  rm -f -- "$out"
  echo "couldn't save a copy — data left as is, restarting the relay" >&2
  systemctl start lodelai-relay.service
  exit 1
fi
chown lodelai:lodelai "$out"
chmod 0600 "$out"
echo "copy saved: $out ($(du -h "$out" | cut -f1))"

find "$DATA" -mindepth 1 -delete
systemctl start lodelai-relay.service
if ! healthy; then
  echo "the relay didn't start with empty data — recent log (copy: $out):" >&2
  journalctl -u lodelai-relay.service -n 30 --no-pager >&2
  exit 1
fi
echo "reset: $DATA emptied, lodelai-relay active"

# 오래된 초기화 사본 정리(일일 백업 relay-*.sqlite3.gz 는 lodelai-backup 몫이라 건드리지 않는다)
mapfile -t old < <(ls -1t "$DIR"/reset-*.tar.gz | tail -n +$((KEEP + 1)))
for f in "${old[@]}"; do
  rm -f -- "$f"
done
echo "next: sudo -u lodelai /opt/lodelai/bin/lodelai-relay bootstrap --data $DATA"
