#!/usr/bin/env bash
# install.sh --operator 가 두는 sudoers 규칙을 실제 Ubuntu sudo 로 본다(묶음 29). 운영자는 전체 경로
# `sudo /opt/lodelai/bin/lodelai-update` 로 비밀번호 없이 부르고, 인자를 붙인 부름(sudoers 의 "" = 인자 없이만)은 막힌다.
# /usr/local/bin 링크로는 규칙이 걸리지 않는다(sudo 1.9.15p5 실측 10-28) — 그래서 링크를 두지 않고 문서는 전체 경로.
#   bash deploy/relay/test-sudoers.sh        # docker 가 있어야 한다(ubuntu:24.04)
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
command -v docker >/dev/null || { echo "docker 가 없다" >&2; exit 2; }

docker run --rm -i -v "$here/install.sh:/src/install.sh:ro" ubuntu:24.04 bash -s <<'EOS'
set -u
apt-get update -qq >/dev/null && apt-get install -y -qq sudo >/dev/null 2>&1 || { echo "sudo 설치 실패"; exit 2; }
useradd -m op
# install.sh 의 함수·변수만 쓴다(source 하면 본체는 돌지 않는다).
. /src/install.sh
set +e
install -d -m 0755 "$BIN"
for c in lodelai-update lodelai-reset; do printf '#!/bin/sh\necho "ran %s as $(id -un)"\n' "$c" >"$BIN/$c"; chmod 0755 "$BIN/$c"; done
printf '%s\n' "op ALL=(root) NOPASSWD: $BIN/lodelai-update \"\", $BIN/lodelai-reset \"\"" >/etc/sudoers.d/lodelai-update
chmod 0440 /etc/sudoers.d/lodelai-update
visudo -c >/dev/null || { echo "sudoers 검사 실패"; exit 2; }

pass=0 fail=0
chk() { if [ "$2" = "$3" ]; then pass=$((pass + 1)); echo "  ok  $1"; else fail=$((fail + 1)); echo "  FAIL $1 ($2)"; fi; }
out=$(su op -c "sudo -n $BIN/lodelai-update" 2>&1); chk "운영자 sudo $BIN/lodelai-update 비밀번호 없이" "$out" "ran lodelai-update as root"
out=$(su op -c "sudo -n $BIN/lodelai-reset" 2>&1); chk "운영자 sudo $BIN/lodelai-reset 비밀번호 없이" "$out" "ran lodelai-reset as root"
su op -c "sudo -n $BIN/lodelai-update --version 9.9.9" >/dev/null 2>&1; chk "인자 붙인 부름은 막힘" "$?" 1
echo
echo "통과 $pass · 실패 $fail"
[ "$fail" = 0 ]
EOS
