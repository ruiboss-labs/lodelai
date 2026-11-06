#!/usr/bin/env bash
# lodelai 서버 갱신(묶음 29 §2). install.sh 가 /opt/lodelai/bin/lodelai-update(root 0755)로 둔다.
#
#   sudo /opt/lodelai/bin/lodelai-update                   # 인자 없이 — /etc/lodelai/update.env 의 소스(서명된 최신 판, 또는 로컬 빌드 판)
#   sudo /opt/lodelai/bin/lodelai-update --version 0.3.1   # 그 판(root 만 — 운영자 sudoers 는 인자 없는 꼴만 허용한다)
#   sudo /opt/lodelai/bin/lodelai-update --binary <경로>   # 로컬 빌드 판(root 만)
#   lodelai-autoupdate.service 가 --auto 로 부른다(게시 뒤 72시간이 지난 판만, 로컬 빌드 판이면 하지 않음)
#
# 본체는 설치된 install.sh(/opt/lodelai/lib/install.sh — 서명된 판과 함께 갱신된다)의 --update 다. 확인·백업·되돌리기가 거기 한 곳에 있다.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

if [ "$(id -u)" -ne 0 ]; then
  echo "run with sudo: sudo $0" >&2
  exit 1
fi
exec /opt/lodelai/lib/install.sh --update "$@"
