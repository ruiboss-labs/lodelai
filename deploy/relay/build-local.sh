#!/usr/bin/env bash
# relay 로컬 빌드 판(운영자, sudo 없이) — 서버에서 직접 빌드해 `lodelai-update`(`binary:` 소스)로 올릴 때.
#
#   bash ~/lodelai-build/deploy/relay/build-local.sh [<브랜치·태그>]    # 받고(없으면 develop) → 빌드 → 경로를 남이 못 쓰게
#   sudo /opt/lodelai/bin/lodelai-update                                 # 그 판으로
#
# install.sh·lodelai-update 는 root 가 깔 바이너리의 경로(/ 부터 파일까지)에 그룹·다른 사람 쓰기가 있으면 쓰지 않는다
# (binary_path_ok). Ubuntu 의 기본 umask 002 로 clone·checkout·cargo 를 돌리면 폴더·파일이 775 가 되어 그 검사에 걸린다
# (#571 단계 B — umask 002 서버). 그래서 umask 022 로 받고 빌드한 뒤, 클론 전체에 go-w 를 한 번 더 건다.
set -euo pipefail
umask 022

repo=$(cd "$(dirname "$0")/../.." && pwd)
cd "$repo"
# 늘 원격의 그 판을 받아 detach 한다 — 태그로 한 번 detach 된 뒤에도 인자 없이 다시 돌릴 수 있게(pull 은 detached 에서 멈춘다).
ref=${1:-develop}
git fetch -q origin "$ref"
git checkout -q --detach FETCH_HEAD
nice -n 10 "${CARGO:-$HOME/.cargo/bin/cargo}" build --release --locked -j "${JOBS:-2}" -p lodelai-relay
chmod -R go-w "$repo"
bin="$repo/target/release/lodelai-relay"
printf '빌드: %s · %s\n바이너리: %s\n' "$(git log -1 --format='%h %s')" "$(sha256sum "$bin" 2>/dev/null | cut -c1-16 || shasum -a 256 "$bin" | cut -c1-16)" "$bin"
echo "다음: sudo /opt/lodelai/bin/lodelai-update"
