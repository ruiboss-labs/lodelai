#!/usr/bin/env bash
# lodelai 서버 감시(#364). lodelai-health.timer 가 5분마다 사용자 lodelai 로 부른다(/opt/lodelai/bin/lodelai-health).
# 바깥 주소(/etc/lodelai/relay.env 의 LODELAI_PUBLIC_HOST)의 /v1/healthz 가 200 이면 healthchecks 에 성공을, 아니면 실패를 알린다.
# 서버·프록시·relay·DB 중 어디가 죽어도 ping 이 끊기거나 실패가 가서 메일이 온다(docs/ops/self-host.md "감시").
# URL 은 /etc/lodelai/backup.env 의 HC_RELAY_URL — 인자로 넘기지 않는다(ps 로 보임).
set -euo pipefail

host=$(sed -n "s/^LODELAI_PUBLIC_HOST=//p" /etc/lodelai/relay.env | tail -1)
[ -n "$host" ] || { echo "LODELAI_PUBLIC_HOST is missing from /etc/lodelai/relay.env" >&2; exit 1; }
PUBLIC="https://$host/v1/healthz"

if [ -z "${HC_RELAY_URL:-}" ]; then
  echo "no HC_RELAY_URL (/etc/lodelai/backup.env) — health checks off"
  exit 0
fi
ping_hc() {
  printf 'url = "%s%s"\n' "$HC_RELAY_URL" "$1" |
    curl --config - --fail --silent --show-error --max-time 10 --retry 3 -o /dev/null
}
if curl --fail --silent --show-error --max-time 10 -o /dev/null "$PUBLIC"; then
  ping_hc ""
else
  echo "health check failed: $PUBLIC" >&2
  ping_hc "/fail" || true
  exit 1
fi
