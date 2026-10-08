#!/bin/bash
# =============================================================================
# upgrade-path.sh — "easy to update", proven: the previous release, used, then updated to the commit under test
#
# A throwaway install of the PREVIOUS release (the newest vX.Y.Z tag that is an ancestor of HEAD and not HEAD itself, or
# --from TAG) is cloned the way the README installs DCS, started as a real listener on a loopback port, and used through
# its own API: an admin and a viewer, a session, an API key, a .env with a server name and settings of its own (one
# saved through POST /config), an automation rule, alert thresholds, a backup destination and a backup schedule, a
# secret, a stored theme that every dashboard follows, a CrowdSec trusted address and the CrowdSec page's settings, a
# fleet join code, an edit to a stack and to a template file the update changes too. Then the OLD code's updater
# (POST /system/update/apply {confirm, restart}) brings it to the commit under test and restarts the listener in place.
#
# Asserted afterwards: VERSION and HEAD are the new ones and the restarted listener reports the new version; the old
# session token, the viewer's token and the API key still authenticate (each with its own role); .env is byte for byte
# what it was, and the settings the new .env.example brings are the ones the answer lists; every state file is
# unchanged in content and mode (.env 600, .api-auth, .secrets, themes, CrowdSec, schedules, fleet); the edited user
# files are kept and counted; the audit log keeps every earlier line and gains the SYSTEM_UPDATE line with the kept
# count; nothing touched a container. Last, a second update is a no-op ("Already up to date").
#
# Where the update comes from: the install's `origin` is a bare repository in the temp directory that holds the
# previous release and the commit under test, tagged as the next release. That is the remote the updater already reads
# (git ls-remote + git fetch of the newest vX.Y.Z tag on the stable channel), so the OLD updater runs unmodified and
# nothing reaches GitHub. No Docker daemon is used: a stand-in `docker` on PATH answers and records every call.
#
# Usage: tests/upgrade-path.sh [--from vX.Y.Z] [--keep]   (exit status 0 = all passed; needs git, jq, curl, socat)
#        --keep leaves the temp directory for a look afterwards (its path is printed)
# =============================================================================
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FROM="" KEEP=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --from) FROM="${2:-}"; shift 2 ;;
        --from=*) FROM="${1#--from=}"; shift ;;
        --keep) KEEP=true; shift ;;
        -h|--help) sed -n '2,/^# ====/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $1 (see --help)" >&2; exit 2 ;;
    esac
done
for t in git jq curl socat; do command -v "$t" >/dev/null 2>&1 || { echo "skip: $t is not installed"; exit 0; }; done

PASS=0; FAIL=0
ok()    { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
bad()   { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$1"; [[ -n "${2:-}" ]] && printf '%s\n' "$2" | head -40 | sed 's/^/         /'; return 0; }
check() { if [[ "$3" == "$2" ]]; then ok "$1"; else bad "$1 (expected [$2], got [$3])"; fi; }
same()  { local d; if d=$(diff -u "$2" "$3"); then ok "$1"; else bad "$1" "$(printf '%s\n' "$d" | sed -n '3,$p' | grep '^[-+]')"; fi; }
die()   { echo "FAIL $1"; exit 1; }

# ---- what is updated to what
TARGET=$(git -C "$ROOT" rev-parse --verify -q 'HEAD^{commit}') || die "$ROOT is not a git checkout"
if [[ -z "$FROM" ]]; then
    while IFS= read -r t; do
        [[ "$t" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
        [[ "$(git -C "$ROOT" rev-parse "refs/tags/$t^{commit}")" == "$TARGET" ]] && continue
        FROM="$t"; break
    done < <(git -C "$ROOT" tag --merged "$TARGET" --sort=-v:refname -l 'v[0-9]*' 2>/dev/null)
    [[ -n "$FROM" ]] || die "no earlier release tag in $ROOT (a shallow clone? CI needs fetch-depth: 0), or pass --from vX.Y.Z"
fi
FROM_SHA=$(git -C "$ROOT" rev-parse --verify -q "refs/tags/$FROM^{commit}") || die "no tag $FROM in $ROOT"
[[ "$FROM_SHA" != "$TARGET" ]] || die "$FROM is the commit under test itself: nothing to update"
git -C "$ROOT" merge-base --is-ancestor "$FROM_SHA" "$TARGET" || die "$FROM is not an ancestor of the commit under test: the updater only moves forward"
FROM_VER=$(git -C "$ROOT" show "$FROM_SHA:VERSION" | tr -d '[:space:]')
NEW_VER=$(git -C "$ROOT" show "$TARGET:VERSION" | tr -d '[:space:]')
# the release tag the commit under test gets in the stand-in origin: its own version, or the one after FROM's when the
# commit under test has not bumped VERSION yet (the stable channel takes the highest vX.Y.Z tag)
REL="v$NEW_VER"
if [[ ! "$REL" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ || "$REL" == "$FROM" || "$(printf '%s\n%s\n' "$FROM" "$REL" | sort -V | tail -1)" != "$REL" ]]; then
    IFS=. read -r _ma _mi _pa <<< "${FROM#v}"; REL="v$_ma.$_mi.$((_pa + 1))"
fi
echo "Upgrade path: $FROM ($FROM_VER, ${FROM_SHA:0:7}) -> ${TARGET:0:7} (VERSION $NEW_VER), released as $REL in a local origin"
[[ -n "$(git -C "$ROOT" status --porcelain --untracked-files=no 2>/dev/null)" ]] && echo "  note: uncommitted changes in $ROOT are not part of the update under test (HEAD is)"

W="$(mktemp -d "${TMPDIR:-/tmp}/dcs-upgrade-XXXXXX")"
ORIGIN="$W/origin.git"; INST="$W/install"; FAKE="$W/fakebin"; BK="$W/backups"; FP="$W/fp"
LPID=""
cleanup() {
    if [[ -x "$INST/.scripts/api-server.sh" ]]; then (cd "$INST" && PATH="$FAKE:$PATH" .scripts/api-server.sh --stop >/dev/null 2>&1) || true; fi
    [[ -n "$LPID" ]] && kill "$LPID" 2>/dev/null
    if [[ "$KEEP" == true ]]; then echo "kept: $W"; else rm -rf "${W:?}"; fi
}
trap cleanup EXIT
mkdir -p "$FAKE/state" "$BK" "$FP"

# ---- the stand-in docker: every call written down; containers, images and volumes are refused, never touched
cat > "$FAKE/docker" <<'FAKEDOCKER'
#!/bin/bash
printf '%s\n' "$*" >> "$(dirname "$0")/state/calls.log"
case "${1:-}" in
    --version|version) echo "Docker version 27.0.0, build upgrade-path" ;;
    compose) [[ " $* " == *" version "* ]] && echo "Docker Compose version v2.99.0 (upgrade-path stand-in)" ;;
    inspect) echo "Error: No such object: ${2:-}" >&2; exit 1 ;;
    image|pull|run|volume|exec|create|rm|rmi|tag|network|start|stop|restart|kill) exit 1 ;;
esac
exit 0
FAKEDOCKER
chmod +x "$FAKE/docker"

# ---- the stand-in origin: the previous release on main, as GitHub had it the day the install was made
git init -q --bare "$ORIGIN" && git -C "$ORIGIN" symbolic-ref HEAD refs/heads/main
git -C "$ORIGIN" fetch -q --no-tags "$ROOT" "$FROM_SHA:refs/heads/main" "$TARGET:refs/heads/under-test" "+refs/tags/$FROM:refs/tags/$FROM" \
    || die "could not copy $FROM and the commit under test into the stand-in origin"
git -C "$ORIGIN" update-ref -d refs/heads/under-test

# ---- the install: git clone and first start, as the README does it (setup.sh's .env, minus Docker)
git clone -q "$ORIGIN" "$INST" || die "clone of the stand-in origin failed"
check "the install is the previous release" "$FROM_VER" "$(tr -d '[:space:]' < "$INST/VERSION")"
mkdir -p "$INST/.data" "$INST/logs"
PORT=""
for _i in $(seq 1 100); do
    _p=$(( 20000 + RANDOM % 12768 )); ( exec 3<>"/dev/tcp/127.0.0.1/$_p" ) 2>/dev/null || { PORT="$_p"; break; }
done
[[ -n "$PORT" ]] || die "no free loopback port"
# setup.sh: cp .env.example .env; chmod 600 .env. Then what this server's owner chose, and what a test box needs
# (loopback, no background engines, a backup destination of its own)
cp "$INST/.env.example" "$INST/.env" && chmod 600 "$INST/.env"
sed -i -E '/^(SERVER_NAME|API_PORT|API_BIND|API_AUTH_ENABLED|API_INSECURE_NO_AUTH|METRICS_ENABLED|AUTOMATIONS_ENABLED|DDNS_ENABLED|UPS_ENABLED|BACKUP_DEST_DIR|BACKUP_RETENTION_COUNT|CROWDSEC_HOME_IPV6_PREFIX|UPDATE_CHANNEL|UPDATE_ON_BOOT)=/d' "$INST/.env"
cat >> "$INST/.env" <<EOF
SERVER_NAME="Upgrade Path Box"
CROWDSEC_HOME_IPV6_PREFIX=56
MY_OWN_NOTE="a line DCS does not know: it stays"
API_PORT=$PORT
API_BIND=127.0.0.1
API_AUTH_ENABLED=true
METRICS_ENABLED=false
AUTOMATIONS_ENABLED=false
DDNS_ENABLED=false
UPS_ENABLED=false
UPDATE_CHANNEL=stable
UPDATE_ON_BOOT=false
BACKUP_DEST_DIR=$BK
BACKUP_RETENTION_COUNT=9
EOF

# ---- the listener, as start.sh runs it (socat, the worker pool, the restart-in-place signal)
start_listener() {
    (cd "$INST" && PATH="$FAKE:$PATH" setsid nohup .scripts/api-server.sh --bind 127.0.0.1 --port "$PORT" >> "$INST/logs/upgrade-listener.log" 2>&1 < /dev/null &)
}
ping_ok() { [[ "$(curl -s -m 2 "http://127.0.0.1:$PORT/ping" 2>/dev/null)" == *ok* ]]; }
wait_up() { local i; for ((i = 0; i < ${1:-120}; i++)); do ping_ok && return 0; sleep 0.25; done; return 1; }
# api METHOD PATH [BODY] [TOKEN] — "STATUS BODY" from the listener
api() {
    local m="$1" p="$2" b="${3:-}" t="${4-$TOKEN}" out code
    local -a h=(-H 'Content-Type: application/json')
    [[ -n "$t" ]] && h+=(-H "Authorization: Bearer $t")
    if [[ -n "$b" ]]; then out=$(curl -s -m 120 -X "$m" "${h[@]}" --data-binary "$b" -w '\n%{http_code}' "http://127.0.0.1:$PORT$p" 2>/dev/null)
    else out=$(curl -s -m 120 -X "$m" "${h[@]}" -w '\n%{http_code}' "http://127.0.0.1:$PORT$p" 2>/dev/null); fi
    code="${out##*$'\n'}"; printf '%s %s' "${code:-000}" "${out%$'\n'*}"
}
st() { printf '%s' "${1%% *}"; }
bd() { printf '%s' "${1#* }"; }
TOKEN=""

echo "The previous release, first start"
start_listener
wait_up 160 || die "the $FROM listener did not answer on 127.0.0.1:$PORT (see logs/upgrade-listener.log)$(tail -20 "$INST/logs/upgrade-listener.log" 2>/dev/null | sed 's/^/\n    /')"
LPID=$(cat "$INST/.data/api-server.pid" 2>/dev/null)
R=$(api GET /version "" "")
check "it answers as $FROM_VER" "$FROM_VER" "$(bd "$R" | jq -r '.framework_version' 2>/dev/null)"

echo "State, made through its own API"
R=$(api POST /auth/setup '{"username":"owner","password":"Upgrade-Path-Pass-1"}' "")
check "admin account made" 200 "$(st "$R")"
: > "$INST/.api-auth/.setup-complete"
R=$(api POST /auth/login '{"username":"owner","password":"Upgrade-Path-Pass-1"}' "")
TOKEN=$(bd "$R" | jq -r '.token // empty' 2>/dev/null)
check "session token issued" yes "$([[ ${#TOKEN} -ge 32 ]] && echo yes || echo no)"
R=$(api POST /auth/keys '{"name":"Homarr","role":"read"}')
KEY=$(bd "$R" | jq -r '.key // empty' 2>/dev/null)
check "API key made" yes "$([[ "$KEY" == dcs_* ]] && echo yes || echo no)"
INVITE=$(bd "$(api POST /auth/invite '{"role":"user"}')" | jq -r '.code // empty' 2>/dev/null)
R=$(api POST /auth/register "{\"username\":\"viewer\",\"password\":\"Viewer-Pass-123\",\"invite_code\":\"$INVITE\"}" "")
VTOKEN=$(bd "$R" | jq -r '.token // empty' 2>/dev/null)
check "viewer registered" yes "$([[ ${#VTOKEN} -ge 32 ]] && echo yes || echo no)"
check "a setting saved through POST /config" 200 "$(st "$(api POST /config '{"NOTIFY_COOLDOWN_MINUTES":"45"}')")"
check "automation rule made" 200 "$(st "$(api POST /automations '{"name":"cpu watch","trigger_type":"condition","trigger_value":"high_cpu","action_type":"notification_send","action_target":"upgrade","threshold":85,"cooldown":120}')")"
check "alert thresholds saved" 200 "$(st "$(api POST /alerts/config '{"thresholds":{"cpu_warning":71,"disk_critical":97}}')")"
check "backup schedule made" 200 "$(st "$(api POST /schedules '{"name":"nightly backup","schedule":"0 3 * * *","action":"backup","target":""}')")"
check "secret stored" 200 "$(st "$(api POST /secrets '{"key":"UPGRADE_PATH_SECRET","value":"kept-across-updates"}')")"
check "theme stored" 200 "$(st "$(api POST /themes '{"schema":1,"name":"upgrade-dusk","title":"Upgrade Dusk","mode":"dark","palette":{"accent":"#f97316","accentSecondary":"#22d3ee","bg":"#0b1020","surface":"#111827","text":"#f8fafc"},"css":""}')")"
check "every dashboard follows it" 200 "$(st "$(api PUT /themes/active '{"name":"upgrade-dusk"}')")"
check "CrowdSec: an address trusted" 200 "$(st "$(api POST /crowdsec/trust '{"ip":"203.0.113.7"}')")"
check "fleet: a join code minted" 200 "$(st "$(api POST /fleet/join-tokens '{"ttl_hours":24}')")"
# the CrowdSec page's own settings (.data/crowdsec/): written the way the page leaves them, the live apply needs a CrowdSec
mkdir -p "$INST/.data/crowdsec"
printf '{"ban_duration":"8h","escalate":true,"updated":"2026-10-01T00:00:00Z"}\n' > "$INST/.data/crowdsec/settings.json"
printf '{"enabled":false,"min_severity":"high"}\n' > "$INST/.data/crowdsec/notify.json"; chmod 600 "$INST/.data/crowdsec/notify.json"
# the owner's edits to tracked files that are theirs: a stack's .env (the update leaves it alone) and a file the
# update DOES change (it must be put back byte for byte and counted as kept)
printf '# my own line\nPUID=1234\n' >> "$INST/Stacks/core-infrastructure/.env"
KEPT_FILE=""
while IFS= read -r f; do
    [[ -f "$INST/$f" ]] && git -C "$ROOT" cat-file -e "$TARGET:$f" 2>/dev/null && { KEPT_FILE="$f"; break; }
done < <(git -C "$ROOT" diff --name-only "$FROM_SHA" "$TARGET" -- Stacks .templates .api-auth .plugins 2>/dev/null)
[[ -n "$KEPT_FILE" ]] && printf '\n# edited on this server, kept by every update\n' >> "$INST/$KEPT_FILE"

# ---- what must come through the update unchanged: content and mode of every state file, and the modes of their folders
STATE_DIRS=(.api-auth .secrets .config/themes .data/crowdsec .data/schedules)
STATE_FILES=(.env .data/crowdsec-trusted.json .data/fleet.json Stacks/core-infrastructure/.env ${KEPT_FILE:+"$KEPT_FILE"})
# files a request rewrites by itself (sessions' last use, rate counters, caches, the auth log): modes only
VOLATILE='^\./\.api-auth/(tokens\.json|terminal-sessions\.json|rate_limits\.json|rates|\.totp-attempts|auth-audit\.log|.*\.lock|cache)'
fingerprint() {
    local p f
    (cd "$INST" && for p in "${STATE_DIRS[@]}" "${STATE_FILES[@]}"; do [[ -e "$p" ]] && find "./$p" -print0; done | LC_ALL=C sort -zu | while IFS= read -r -d '' f; do
        if [[ -d "$f" ]]; then printf 'd %s %s\n' "$(stat -c %a -- "$f")" "$f"
        elif [[ "$f" =~ $VOLATILE ]]; then printf 'f %s (rewritten by requests) %s\n' "$(stat -c %a -- "$f")" "$f"
        else printf 'f %s %s %s\n' "$(stat -c %a -- "$f")" "$(sha256sum -- "$f" | cut -c1-64)" "$f"; fi
    done)
}
check "the .env is private" 600 "$(stat -c %a "$INST/.env")"
check "the state is all there" yes "$(for f in .api-auth/users.json .api-auth/api-keys.json .api-auth/tokens.json .data/crowdsec-trusted.json .data/schedules/schedules.json .config/themes/upgrade-dusk.json .config/themes/active; do [[ -s "$INST/$f" ]] || { echo "missing $f"; exit; }; done; ls "$INST/.secrets/"* >/dev/null 2>&1 && echo yes || echo "no secret")"
fingerprint > "$FP/before"
command cp -f "$INST/.env" "$FP/env.before"
git -C "$INST" -c core.fileMode=false status --porcelain --untracked-files=no | cut -c4- | sort > "$FP/dirty.before"
command cp -f "$INST/.data/audit.jsonl" "$FP/audit.before" 2>/dev/null || : > "$FP/audit.before"
: > "$FAKE/state/calls.log"

echo "The update, by the previous release's own updater"
R=$(api GET /system/update/check)
check "check: nothing newer yet" "false current $FROM" "$(bd "$R" | jq -r '"\(.available) \(.state) \(.latest_name)"' 2>/dev/null)"
# the next release appears upstream only now: main moves on and the commit under test is tagged
git -C "$ORIGIN" update-ref refs/heads/main "$TARGET" && git -C "$ORIGIN" tag "$REL" "$TARGET"
R=$(api GET /system/update/check)
check "check: the new release is offered" "true behind $REL $NEW_VER" "$(bd "$R" | jq -r '"\(.available) \(.state) \(.latest_name) \(.latest_version)"' 2>/dev/null)"
check "check: the edited template is listed as kept" "${KEPT_FILE:-}" "$(bd "$R" | jq -r '.local_changes.kept | join(" ")' 2>/dev/null)"
check "check: no framework conflicts" "" "$(bd "$R" | jq -r '.local_changes.conflicts | join(" ")' 2>/dev/null)"
check "check: the listener can restart itself" reexec "$(bd "$R" | jq -r '.restart_method' 2>/dev/null)"
OLD_PID="$LPID"
APPLY=$(api POST /system/update/apply '{"confirm":true,"restart":true}')
AB=$(bd "$APPLY")
check "apply: answered" 200 "$(st "$APPLY")"
check "apply: updated from $FROM_VER to $NEW_VER" "true $FROM_VER $NEW_VER" "$(jq -r '"\(.updated) \(.previous_version) \(.new_version)"' <<< "$AB" 2>/dev/null)"
check "apply: the restart is scheduled in place" "true reexec" "$(jq -r '"\(.restart_scheduled) \(.restart.method)"' <<< "$AB" 2>/dev/null)"
check "apply: the edited template kept" "${KEPT_FILE:-}" "$(jq -r '.kept_local | join(" ")' <<< "$AB" 2>/dev/null)"
check "apply: nothing replaced" "" "$(jq -r '.replaced_local | join(" ")' <<< "$AB" 2>/dev/null)"
BACKUP_TAG=$(jq -r '.backup_tag // empty' <<< "$AB" 2>/dev/null)
check "apply: a backup tag to roll back to" yes "$([[ -n "$BACKUP_TAG" ]] && git -C "$INST" rev-parse -q --verify "refs/tags/$BACKUP_TAG^{commit}" 2>/dev/null | grep -qx "$FROM_SHA" && echo yes || echo no)"
NEW_KEYS=$(comm -23 <(grep -oE '^[A-Z_][A-Z0-9_]*=' "$INST/.env.example" | tr -d '=' | sort -u) <(grep -oE '^[A-Z_][A-Z0-9_]*=' "$FP/env.before" | tr -d '=' | sort -u) | paste -sd' ')
check "apply: lists the settings the new .env.example brings" "$NEW_KEYS" "$(jq -r '.new_settings | join(" ")' <<< "$AB" 2>/dev/null)"

# the restart: a second after the answer the old listener re-executes itself with the new code (same process) and
# writes its pid file again; until then the old code still answers, so the wait is for that, then for the port
_restarted=no
for _i in $(seq 1 240); do
    [[ "$(grep -c 'Starting API server on' "$INST/logs/upgrade-listener.log" 2>/dev/null)" -ge 2 && -s "$INST/.data/api-server.pid" ]] && { _restarted=yes; break; }
    sleep 0.25
done
wait_up 160
NEW_API_VER=$(git -C "$ROOT" show "$TARGET:.scripts/api-server.sh" | sed -n 's/^API_VERSION="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' | head -1)
echo "After the update"
fingerprint > "$FP/after"
check "the listener restarted itself" yes "$_restarted"
check "the API is back, on the new code" "$NEW_VER $NEW_API_VER" "$(curl -s -m 5 "http://127.0.0.1:$PORT/ping" 2>/dev/null | jq -r '"\(.version) \(.api_version)"' 2>/dev/null)"
LPID=$(cat "$INST/.data/api-server.pid" 2>/dev/null)
check "restarted in place (the same process)" "$OLD_PID" "$LPID"
check "VERSION is the new one" "$NEW_VER" "$(tr -d '[:space:]' < "$INST/VERSION")"
check "HEAD is the commit under test" "$TARGET" "$(git -C "$INST" rev-parse HEAD)"
check "the owner's tracked files are the only modified ones, as before" "$(paste -sd' ' "$FP/dirty.before")" \
    "$(git -C "$INST" -c core.fileMode=false status --porcelain --untracked-files=no | cut -c4- | sort | paste -sd' ')"
same "every state file: same content and mode (.env, .api-auth, .secrets, themes, CrowdSec, schedules, fleet, user edits)" "$FP/before" "$FP/after"
check ".env is still 600" 600 "$(stat -c %a "$INST/.env")"
same ".env is byte for byte what it was" "$FP/env.before" "$INST/.env"
check ".api-auth is still private" "$(stat -c %a "$INST/.api-auth" 2>/dev/null)" "$(sed -n 's/^d \([0-7]*\) \.\/\.api-auth$/\1/p' "$FP/before")"
check "users.json is still 600" 600 "$(stat -c %a "$INST/.api-auth/users.json")"
check "the session token still authenticates" 200 "$(st "$(api GET /auth/verify)")"
check "…as the admin it was" "owner admin" "$(bd "$(api GET /auth/verify)" | jq -r '"\(.username // .user.username) \(.role // .user.role)"' 2>/dev/null)"
check "the API key still works" 200 "$(st "$(api GET /stacks "" "$KEY")")"
check "…as a key that reads only" 403 "$(st "$(api POST /maintenance/prune "" "$KEY")")"
check "the viewer's session still works" 200 "$(st "$(api GET /stacks "" "$VTOKEN")")"
check "…and is still a viewer" 403 "$(st "$(api GET /env "" "$VTOKEN")")"
check "a bad token is still refused" 401 "$(st "$(api GET /stacks "" "not-a-token")")"
check "the admin signs in with the old password" 200 "$(st "$(api POST /auth/login '{"username":"owner","password":"Upgrade-Path-Pass-1"}' "")")"
TOKEN=$(bd "$(api POST /auth/login '{"username":"owner","password":"Upgrade-Path-Pass-1"}' "")" | jq -r '.token // empty' 2>/dev/null)
check "SERVER_NAME read back" "Upgrade Path Box" "$(bd "$(api GET /status)" | jq -r '.server_name' 2>/dev/null)"
check "settings read back (one saved through POST /config, one of the owner's own)" "45 56 a line DCS does not know: it stays" \
    "$(bd "$(api GET /env)" | jq -r '.variables | map(select(.key != "")) | from_entries | "\(.NOTIFY_COOLDOWN_MINUTES) \(.CROWDSEC_HOME_IPV6_PREFIX) \(.MY_OWN_NOTE)"' 2>/dev/null)"
check "the automation rule read back" "85 120" "$(bd "$(api GET /automations)" | jq -r '.automations[] | select(.name == "cpu watch") | "\(.threshold) \(.cooldown)"' 2>/dev/null)"
check "the backup destination and retention read back" "true $BK 9" "$(bd "$(api GET /backups/config)" | jq -r '"\(.configured) \(.destination) \(.retention_count)"' 2>/dev/null)"
check "the backup schedule read back" 1 "$(bd "$(api GET /schedules)" | jq -r '[(.schedules // .)[] | select(.name == "nightly backup")] | length' 2>/dev/null)"
check "the secret is still there" true "$(bd "$(api GET /secrets/UPGRADE_PATH_SECRET/exists)" | jq -r '.exists' 2>/dev/null)"
check "the theme every dashboard follows" upgrade-dusk "$(bd "$(api GET /themes)" | jq -r '.active' 2>/dev/null)"
check "the trusted CrowdSec address" yes "$(jq -e '.ips | index("203.0.113.7")' "$INST/.data/crowdsec-trusted.json" >/dev/null 2>&1 && echo yes || echo no)"
check "the fleet join code is still valid" 1 "$(bd "$(api GET /fleet/join-tokens)" | jq -r '.tokens | length' 2>/dev/null)"
check "the API key is still listed" Homarr "$(bd "$(api GET /auth/keys)" | jq -r '[.keys[].name] | join(" ")' 2>/dev/null)"
# the audit trail: every earlier line kept, one SYSTEM_UPDATE line with the counts
check "the audit log kept every earlier line" yes "$(head -c "$(stat -c %s "$FP/audit.before")" "$INST/.data/audit.jsonl" | cmp -s - "$FP/audit.before" && echo yes || echo no)"
UPD_LINE=$(grep '"action":"SYSTEM_UPDATE"' "$INST/.data/audit.jsonl" 2>/dev/null)
check "one SYSTEM_UPDATE line" 1 "$(printf '%s' "$UPD_LINE" | grep -c . )"
_kn=0; [[ -n "$KEPT_FILE" ]] && _kn=1
check "…with the versions and the kept count" yes "$(jq -r '.detail' <<< "$UPD_LINE" 2>/dev/null | grep -qF "$FROM_VER→$NEW_VER" && jq -r '.detail' <<< "$UPD_LINE" | grep -qE "kept $_kn user files, replaced 0\)" && echo yes || echo no)"
check "no container, image or volume was touched" "" "$(grep -E '(^| )(up|down|pull|push|rm|rmi|tag|stop|start|kill|restart|run|create|exec|prune|load|import|commit)( |$)' "$FAKE/state/calls.log" | sort -u | head -5)"

echo "A second update is a no-op"
fingerprint > "$FP/before2"
R=$(api GET /system/update/check)
check "check: up to date" "false current" "$(bd "$R" | jq -r '"\(.available) \(.state)"' 2>/dev/null)"
R=$(api POST /system/update/apply '{"confirm":true}')
check "apply: answered" 200 "$(st "$R")"
check "apply: nothing to do" "false current" "$(bd "$R" | jq -r '"\(.updated) \(.state)"' 2>/dev/null)"
check "apply: says it is already up to date" yes "$(bd "$R" | jq -r '.message' 2>/dev/null | grep -q 'Already up to date' && echo yes || echo no)"
check "HEAD has not moved" "$TARGET" "$(git -C "$INST" rev-parse HEAD)"
check "no second SYSTEM_UPDATE line" 1 "$(grep -c '"action":"SYSTEM_UPDATE"' "$INST/.data/audit.jsonl" 2>/dev/null)"
check "no second backup tag" 1 "$(git -C "$INST" tag -l 'dcs-backup-*' | grep -c .)"
fingerprint > "$FP/again"
same "the state is still the same" "$FP/before2" "$FP/again"

echo
echo "Upgrade path $FROM -> ${TARGET:0:7}: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
