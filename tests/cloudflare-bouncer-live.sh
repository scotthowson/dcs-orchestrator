#!/bin/bash
# =============================================================================
# Push bans to Cloudflare against a real CrowdSec
#
# tests/smoke.sh drives "Push bans to Cloudflare" against stand-ins for cscli and CrowdSec's API. This runs it against the real thing: a
# throwaway CrowdSec container (its own Docker name, its API published on loopback), a DCS install in a temporary folder, and the Cloudflare
# stand-in tests/mock-cloudflare-waf.py (the real Cloudflare is never asked). It checks that the bouncer DCS registers is accepted by CrowdSec,
# that CrowdSec answers DCS's query (type, scopes, origins) with the bans it holds and records the bouncer's pull, that the bans CrowdSec adds
# and lifts reach the list, and that the off switch takes the bouncer and the list away.
#
# Not part of tests/smoke.sh or CI: it needs Docker and the CrowdSec image (used as it is, never pulled). It refuses to run where a CrowdSec
# container exists already (DCS would find that one): run it in a sandbox (Docker in Docker). It takes about a minute.
#
# Usage: tests/cloudflare-bouncer-live.sh [IMAGE]     IMAGE defaults to crowdsecurity/crowdsec:v1.8.1; exit status 0 = every check passed
# =============================================================================

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${1:-crowdsecurity/crowdsec:v1.8.1}"
NAME="CrowdSec"
PORT="${CFB_LIVE_PORT:-18070}"
TOK="cfbLIVE_token_0123456789abcdefghijklmn"     # a placeholder: the stand-in's token

command -v docker >/dev/null 2>&1 || { echo "skipped: no docker"; exit 0; }
command -v python3 >/dev/null 2>&1 || { echo "skipped: no python3 (the Cloudflare stand-in)"; exit 0; }
docker image inspect "$IMAGE" >/dev/null 2>&1 || { echo "skipped: $IMAGE is not here (this test never pulls it)"; exit 0; }
if [[ -n "$(docker ps -aq --filter label=com.docker.compose.service=crowdsec)" || -n "$(docker ps -a --format '{{.Names}}' | grep -ix crowdsec)" ]]; then
    echo "skipped: a CrowdSec container exists on this Docker already, and DCS would work on that one. Run this in a sandbox (Docker in Docker)."; exit 0
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/dcs-cfb-live-XXXXXX")"
RIP=""
cleanup() { [[ -n "$RIP" ]] && kill "$RIP" 2>/dev/null; docker rm -f "$NAME" >/dev/null 2>&1; rm -rf "$WORK"; }
trap cleanup EXIT

PASS=0; FAIL=0
check() {
    if [[ "$3" == "$2" ]]; then PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; else FAIL=$((FAIL + 1)); printf '  FAIL %s (expected %s, got %s)\n' "$1" "$2" "$3"; fi
}

echo "A real CrowdSec ($IMAGE)"
docker run -d --name "$NAME" --label com.docker.compose.service=crowdsec -e DISABLE_ONLINE_API=true -e CROWDSEC_BYPASS_DB_VOLUME_CHECK=true \
    -p "127.0.0.1:$PORT:8080" "$IMAGE" >/dev/null || { echo "could not start CrowdSec"; exit 1; }
for _ in $(seq 1 90); do docker exec "$NAME" cscli lapi status >/dev/null 2>&1 && break; sleep 1; done
check "CrowdSec's API answers" 0 "$(docker exec "$NAME" cscli lapi status >/dev/null 2>&1; echo $?)"
cs() { docker exec "$NAME" cscli "$@"; }

# the bans CrowdSec holds: an address, a network, an IPv6 address, a CAPTCHA (not a ban), a country (not an address), an import
cs decisions add --ip 198.51.100.7 --duration 4h --reason live-test >/dev/null 2>&1
cs decisions add --range 192.0.2.0/24 --duration 4h --reason live-test >/dev/null 2>&1
cs decisions add --ip 2a01:4f8:1:2::3 --duration 4h --reason live-test >/dev/null 2>&1
cs decisions add --ip 198.51.100.9 --duration 4h --type captcha --reason live-test >/dev/null 2>&1
cs decisions add --scope Country --value DE --duration 4h --reason live-test >/dev/null 2>&1
printf '203.0.113.77\n' | docker exec -i "$NAME" cscli decisions import -i - --format values --duration 4h --reason live-import >/dev/null 2>&1
check "CrowdSec holds the test decisions" 6 "$(cs decisions list -o json 2>/dev/null | jq '[.[].decisions[]] | length')"

# -- a DCS install of its own, and the Cloudflare stand-in
echo "DCS against it"
mkdir -p "$WORK/dcs"/{.scripts,.lib,.config,.data,logs,.api-auth,Stacks}
cp "$ROOT/.scripts/api-server.sh" "$WORK/dcs/.scripts/"; cp -r "$ROOT/.lib/." "$WORK/dcs/.lib/"; cp -r "$ROOT/.config/." "$WORK/dcs/.config/"; cp "$ROOT/VERSION" "$WORK/dcs/"
grep -vE '^(API_BIND|API_AUTH_ENABLED|API_INSECURE_NO_AUTH|API_TRUSTED_PROXIES|API_IP_WHITELIST|API_PORT|PROXY_DOMAIN)=' "$ROOT/.env.example" > "$WORK/dcs/.env"
# (no minute between two changes of the list here: the checks below change the bans and sync at once; tests/smoke.sh checks the minute)
printf 'API_PORT=9876\nMETRICS_ENABLED=false\nPROXY_DOMAIN=lab.example.test\nCLOUDFLARE_BOUNCER_PUSH_GAP=0\n' >> "$WORK/dcs/.env"
API="$WORK/dcs/.scripts/api-server.sh"
python3 "$ROOT/tests/mock-cloudflare-waf.py" "$WORK/cf.port" "$WORK/cf.json" >/dev/null 2>&1 &
RIP=$!
for _ in $(seq 1 100); do [[ -s "$WORK/cf.port" ]] && break; sleep 0.05; done
CFP=$(cat "$WORK/cf.port")
curl -s "http://127.0.0.1:$CFP/_mock/config" -X POST -H 'Content-Type: application/json' -d "$(jq -nc --arg t "$TOK" \
    '{tokens: {($t): {kind: "user", rights: ["zones", "lists", "waf"]}}, zones: [{id: "zone-example-test", name: "example.test", account: {id: "acc-lab", name: "Lab"}, plan: "free"}]}')" >/dev/null
fake() { curl -s "http://127.0.0.1:$CFP/_mock/state" | jq -r "$1"; }
items() { fake '[.lists[][] | select(.name == "dcs_crowdsec_bans") | .items[].ip] | sort | join(" ")'; }

ENVS=(DOCKER_COMPOSE_CMD="docker compose" API_RATE_LIMIT=0 DCS_API_EFFECTIVE_AUTH=true DCS_API_EFFECTIVE_BIND=127.0.0.1 CF_API_BASE="http://127.0.0.1:$CFP/client/v4")
TOKEN=""; ST=""; BODY=""
req() {
    local m="$1" p="$2" b="${3:-}" hdr="" raw
    [[ -n "$TOKEN" ]] && hdr="Authorization: Bearer $TOKEN"$'\r\n'
    raw=$(printf '%s %s HTTP/1.1\r\nHost: test\r\n%sContent-Length: %d\r\n\r\n%s' "$m" "$p" "$hdr" "$(printf '%s' "$b" | wc -c)" "$b" \
        | env -u SOCAT_PEERADDR "${ENVS[@]}" "$API" --handle-request 2>>"$WORK/api-stderr.log")
    ST="${raw:9:3}"; BODY="${raw#*$'\r\n\r\n'}"
}
req POST /auth/setup '{"username":"admin","password":"correct horse battery"}'
TOKEN=$(jq -r '.token // empty' <<< "$BODY")
check "an admin" yes "$([[ -n "$TOKEN" ]] && echo yes || echo no)"

req POST /crowdsec/cloudflare/enable "{\"token\":\"$TOK\"}"
check "turned on" 200 "$ST"
[[ "$ST" == 200 ]] || echo "       (the answer said: $(jq -r '.message // empty' <<< "$BODY"))"
check "the answer does not wait for the first push" running "$(jq -r '.first_sync' <<< "$BODY")"
for _ in $(seq 1 120); do
    req GET /crowdsec/cloudflare
    [[ "$(jq -r '.health' <<< "$BODY")" == ok && "$(jq -r '.sync.running' <<< "$BODY")" == null ]] && break; sleep 0.25
done
check "the first push" ok "$(jq -r '.health' <<< "$BODY")"
check "the list holds CrowdSec's bans (the address, the network, the IPv6 address, the import; no CAPTCHA, no country)" \
    "192.0.2.0/24 198.51.100.7 203.0.113.77 2a01:4f8:1:2::3" "$(items)"
check "the rule blocks the list" "block ip.src in \$dcs_crowdsec_bans" "$(fake '[.rulesets[].rules[] | select(.ref == "dcs_crowdsec_bans") | .action + " " + .expression] | join(",")')"
req GET /crowdsec/cloudflare
check "DCS found CrowdSec's API where Docker publishes it" ok "$(jq -r '.health' <<< "$BODY")"
bj=$(cs bouncers list -o json 2>/dev/null)
check "CrowdSec knows the bouncer" 1 "$(jq '[.[] | select(.name == "dcs-cloudflare-bouncer")] | length' <<< "$bj")"
check "CrowdSec recorded its pull" true "$(jq '[.[] | select(.name == "dcs-cloudflare-bouncer")][0].last_pull != null' <<< "$bj")"
check "CrowdSec names it by its user agent" dcs-cloudflare-bouncer "$(jq -r '[.[] | select(.name == "dcs-cloudflare-bouncer")][0].type // ""' <<< "$bj")"
check "the status shows the registration" true "$(jq -r '.bouncer.registered' <<< "$BODY")"

# a ban lifted and one added in CrowdSec reach the list with the next sync
cs decisions delete --ip 198.51.100.7 >/dev/null 2>&1
cs decisions add --ip 198.51.100.44 --duration 1h --reason live-test >/dev/null 2>&1
req POST /crowdsec/cloudflare/sync ''
check "sync now" 200 "$ST"
check "the list follows CrowdSec" "192.0.2.0/24 198.51.100.44 203.0.113.77 2a01:4f8:1:2::3" "$(items)"
# the Bouncers tab keeps the bouncer while the switch is on
req DELETE /crowdsec/bouncers/dcs-cloudflare-bouncer
check "the Bouncers tab does not delete it while the switch is on" 409 "$ST"
# the bouncer deleted behind DCS's back (a CrowdSec reset): CrowdSec refuses the old key, DCS registers it again and the list follows
cs bouncers delete dcs-cloudflare-bouncer >/dev/null 2>&1
cs decisions add --ip 198.51.100.45 --duration 1h --reason live-test >/dev/null 2>&1
req POST /crowdsec/cloudflare/sync ''
check "a deleted bouncer is registered again" "ok null" "$(jq -r '.health' <<< "$BODY") $(jq -c '.error' <<< "$BODY")"
check "…CrowdSec knows it again" 1 "$(cs bouncers list -o json 2>/dev/null | jq '[.[] | select(.name == "dcs-cloudflare-bouncer")] | length')"
check "…and the list follows" "192.0.2.0/24 198.51.100.44 198.51.100.45 203.0.113.77 2a01:4f8:1:2::3" "$(items)"
# on again (a fresh key), then off with the clean-up
req POST /crowdsec/cloudflare/enable '{}'
check "on again with the stored token" 200 "$ST"
for _ in $(seq 1 120); do [[ -d "$WORK/dcs/.data/crowdsec/.cloudflare.lock.d" ]] || break; sleep 0.25; done
req POST /crowdsec/cloudflare/disable '{"cleanup": true}'
check "off with the clean-up" "200 true" "$ST $(jq -r '.cleanup.ok' <<< "$BODY")"
check "the bouncer is gone from CrowdSec" 0 "$(cs bouncers list -o json 2>/dev/null | jq '[.[] | select(.name == "dcs-cloudflare-bouncer")] | length')"
check "the list and the rule are gone from Cloudflare" "0 0" "$(fake '[.lists[][]] | length') $(fake '[.rulesets[].rules[]] | length')"
check "the token is in no file but the secret" 0 "$(grep -rlF -- "$TOK" "$WORK/dcs/.data" "$WORK/dcs/logs" "$WORK/dcs/.api-auth" "$WORK/dcs/.env" "$WORK/api-stderr.log" 2>/dev/null | wc -l | tr -d ' ')"

echo
echo "$PASS passed, $FAIL failed"
(( FAIL == 0 ))
