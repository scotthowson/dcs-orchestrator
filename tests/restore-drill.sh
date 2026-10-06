#!/bin/bash
# =============================================================================
# restore-drill.sh — a restore from scratch, proven file by file
#
# A throwaway install with three stacks and their App-Data (one stack's on a "drive" of its own, one with Traefik's
# files), files of several modes (and of other owners when it runs as root, as CI's Debian job does) is backed up and
# put in a recovery bundle; both are downloaded the way the dashboard downloads them. Then the install is wiped (the
# drive's App-Data too) and brought back twice on a "new machine": the backup uploaded and restored, then the bundle
# through the setup wizard's POST /setup/restore. Every file is compared with what was there: content (sha256), mode,
# link target, and owner when root. Anything missing, extra or different fails the drill and is named.
# Then a bundle is restored over a running install: the stacks whose App-Data it brings back are stopped and started
# again (only those that ran), the App-Data that was there is set aside whole (old and new files never mix), and the
# copies kept from before a restore are pruned to BACKUP_PRE_RESTORE_KEEP. Last, a stack whose containers will not stop
# is skipped by both restores: its data stays as it is, nothing of it is started, and the answer names it.
#
# No Docker daemon is needed or touched: a stand-in `docker` on PATH answers for the stacks' containers (which ones run,
# what was stopped and started) and refuses images, volumes and helper containers. The request handler is driven over
# stdin, the way socat drives it.
#
# Usage: tests/restore-drill.sh   (exit status 0 = all passed; needs jq, openssl, tar, gzip, sha256sum, base64)
# =============================================================================
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
for t in jq openssl tar gzip sha256sum base64; do command -v "$t" >/dev/null 2>&1 || { echo "skip: $t is not installed"; exit 0; }; done
W="$(mktemp -d "${TMPDIR:-/tmp}/dcs-drill-XXXXXX")"
trap 'rm -rf "${W:?}"' EXIT
INST="$W/install"                  # the install: the same path every time (a restore puts things back where they were)
DRV="$W/disk2/appdata/drive-app"   # the App-Data of the stack "drive", on a drive of its own
BK="$W/backups"                    # BACKUP_DEST_DIR (a NAS: it goes with the machine in this drill, the copies off the box stay)
OFF="$W/offbox"                    # what was downloaded and kept elsewhere: the archive, its .sha256, the bundle
FAKE="$W/fakebin"                  # the stand-in docker
PASS=0; FAIL=0
ROOTED=false; [[ "$(id -u)" == 0 ]] && ROOTED=true
ADMIN_USER=drill; ADMIN_PASS='Drill-Pass-12345'; BUNDLE_PASS='Bundle-Pass-6789'
mkdir -p "$OFF" "$FAKE/state/run" "$FAKE/state/off" "$FAKE/state/stuck"

ok()   { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
bad()  { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$1"; [[ -n "${2:-}" ]] && printf '%s\n' "$2" | head -40 | sed 's/^/         /'; return 0; }
check() { if [[ "$3" == "$2" ]]; then ok "$1"; else bad "$1 (expected [$2], got [$3])"; fi; }
# same NAME FILE_A FILE_B — two fingerprints agree, line for line; the lines that differ are shown
same() { local d; if d=$(diff -u "$2" "$3"); then ok "$1"; else bad "$1" "$(printf '%s\n' "$d" | sed -n '3,$p' | grep '^[-+]')"; fi; }

# ---- the stand-in docker: containers per compose project, stop/start/pause written down; no images, volumes or helpers
cat > "$FAKE/docker" <<'FAKEDOCKER'
#!/bin/bash
st="$(dirname "$0")/state"; mkdir -p "$st/run" "$st/off"
printf '%s\n' "$*" >> "$st/calls.log"
proj_of() { local f=""; while [[ $# -gt 0 ]]; do [[ "$1" == -f ]] && { f="$2"; shift; }; shift; done; [[ -n "$f" ]] && basename "$(dirname "$f")" | tr '[:upper:]' '[:lower:]'; }
ids_of() { local p="$1" f; for f in "$st"/run/*; do [[ -f "$f" && "$(cat "$f")" == "$p" ]] && basename "$f"; done; return 0; }
case "${1:-}" in
    compose)
        shift
        case " $* " in
            *" version "*) echo "Docker Compose version v2.99.0 (drill stand-in)" ;;
            *" ps "*) p=$(proj_of "$@"); [[ -n "$p" ]] && ids_of "$p" ;;
        esac
        exit 0 ;;
    ps)
        for a in "$@"; do [[ "$a" == label=com.docker.compose.project=* ]] && ids_of "${a#label=com.docker.compose.project=}"; done
        exit 0 ;;
    stop)
        # a container named in state/stuck will not stop (Docker says so and the stop fails, as a hung one does)
        shift; [[ "${1:-}" == -t ]] && shift 2; rc=0
        for id in "$@"; do
            echo "stop $id" >> "$st/actions.log"
            if [[ -f "$st/stuck/$id" ]]; then echo "Error response from daemon: cannot stop container: $id: tried to kill container, but did not receive an exit event" >&2; rc=1; continue; fi
            [[ -f "$st/run/$id" ]] && mv "$st/run/$id" "$st/off/$id"
        done
        exit "$rc" ;;
    start)
        shift
        for id in "$@"; do [[ -f "$st/off/$id" ]] && mv "$st/off/$id" "$st/run/$id"; echo "start $id" >> "$st/actions.log"; done
        exit 0 ;;
    pause|unpause) act="$1"; shift; for id in "$@"; do echo "$act $id" >> "$st/actions.log"; done; exit 0 ;;
    image|pull|run|volume|exec|create|rm|tag|network) exit 1 ;;
    *) exit 0 ;;
esac
FAKEDOCKER
chmod +x "$FAKE/docker"
# container ID of project P, running (run) or stopped (off)
container() { rm -f "$FAKE/state/run/$1" "$FAKE/state/off/$1"; printf '%s' "$2" > "$FAKE/state/$3/$1"; }
running() { local f out=""; for f in "$FAKE"/state/run/*; do [[ -f "$f" ]] && out+="$(basename "$f") "; done; printf '%s' "${out% }"; }

# ---- talking to the install's request handler, the way socat does
TOKEN=""
API_ENV=(PATH="$FAKE:$PATH" DOCKER_COMPOSE_CMD="docker compose" DCS_API_EFFECTIVE_AUTH=true DCS_API_EFFECTIVE_BIND=127.0.0.1)
# req METHOD PATH [BODY] — the full response; the session token when there is one
req() {
    local m="$1" p="$2" b="${3:-}" auth=""
    [[ -n "$TOKEN" ]] && auth="Authorization: Bearer $TOKEN"$'\r\n'
    printf '%s %s HTTP/1.1\r\nHost: drill\r\n%sContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s' "$m" "$p" "$auth" "${#b}" "$b" \
        | env "${API_ENV[@]}" "$INST/.scripts/api-server.sh" --handle-request 2>/dev/null
}
# req_file METHOD PATH FILE [CONTENT_TYPE] — FILE as the body, byte for byte
req_file() {
    local auth=""
    [[ -n "$TOKEN" ]] && auth="Authorization: Bearer $TOKEN"$'\r\n'
    { printf '%s %s HTTP/1.1\r\nHost: drill\r\n%sContent-Type: %s\r\nContent-Length: %d\r\n\r\n' "$1" "$2" "$auth" "${4:-application/octet-stream}" "$(stat -c %s "$3")"; cat "$3"; } \
        | env "${API_ENV[@]}" "$INST/.scripts/api-server.sh" --handle-request 2>/dev/null
}
# get_raw PATH OUT — a GET without the session (a browser download); the body into OUT, the headers on stdout
get_raw() {
    local tmp="$OUT_TMP" line
    printf 'GET %s HTTP/1.1\r\nHost: drill\r\n\r\n' "$1" | env "${API_ENV[@]}" "$INST/.scripts/api-server.sh" --handle-request > "$tmp" 2>/dev/null
    # the headers up to the blank line, the rest byte for byte (bash's read leaves a regular file right after the line);
    # the headers are printed last, once the body is written (a reader that stops after the status line cannot cut it short)
    { while IFS= read -r line; do line="${line%$'\r'}"; [[ -z "$line" ]] && break; printf '%s\n' "$line"; done > "$tmp.hdr"; cat > "$2"; } < "$tmp"
    cat "$tmp.hdr"
}
OUT_TMP="$W/raw.out"
code() { head -1 | awk '{print $2}'; }
body() { sed -n '/^\r*$/,$p' | sed '1d'; }
login() { TOKEN=$(req POST /auth/login "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" | body | jq -r '.token // empty'); }
# wait_idle — the background backup or restore has finished: its last status on stdout
wait_idle() {
    local s="" i
    for (( i = 0; i < 300; i++ )); do
        s=$(req GET /backups/status | body)
        [[ "$(jq -r '.status' <<< "$s" 2>/dev/null)" =~ ^(running|restoring)$ ]] || { printf '%s' "$s"; return 0; }
        sleep 0.5
    done
    printf '{"status":"timeout"}'
}

# ---- an install: the code, an .env, nothing else
mk_install() {
    rm -rf "$INST"
    mkdir -p "$INST/.scripts" "$INST/.lib" "$INST/.config" "$INST/Stacks" "$INST/.data" "$INST/logs" "$INST/.api-auth"
    cp "$ROOT/.scripts/api-server.sh" "$ROOT/.scripts/api-dispatch.sh" "$INST/.scripts/"
    cp -r "$ROOT/.lib/." "$INST/.lib/"; cp -r "$ROOT/.config/." "$INST/.config/"; cp "$ROOT/VERSION" "$ROOT/compose.sh" "$INST/"
    grep -vE '^(API_BIND|API_AUTH_ENABLED|API_INSECURE_NO_AUTH|API_TRUSTED_PROXIES|API_IP_WHITELIST|API_PORT|BACKUP_[A-Z_]+|RECOVERY_[A-Z_]+|METRICS_ENABLED|API_RESPONSE_CACHE)=' "$ROOT/.env.example" > "$INST/.env"
    printf 'API_PORT=9876\nMETRICS_ENABLED=false\nAPI_RESPONSE_CACHE=false\nBACKUP_DEST_DIR=%s\nBACKUP_RETENTION_COUNT=6\n' "$BK" >> "$INST/.env"
}

# ---- fingerprints: one line per path — type, mode, owner (root only), sha256 or link target
fp() {
    local d="$1"
    [[ -d "$d" ]] || { echo "(missing: $d)"; return 0; }
    (cd "$d" && find . -mindepth 1 -print0 | LC_ALL=C sort -z | while IFS= read -r -d '' p; do
        local own=""; [[ "$ROOTED" == true ]] && own=" $(stat -c %u:%g -- "$p")"
        if [[ -L "$p" ]]; then printf 'l %s%s -> %s %s\n' "$(stat -c %a -- "$p")" "$own" "$(readlink -- "$p")" "$p"
        elif [[ -d "$p" ]]; then printf 'd %s%s %s\n' "$(stat -c %a -- "$p")" "$own" "$p"
        else printf 'f %s%s %s %s\n' "$(stat -c %a -- "$p")" "$own" "$(sha256sum -- "$p" | cut -c1-64)" "$p"; fi
    done)
}
fp_state() { local f; for f in .env .api-auth/users.json .data/schedules/schedules.json .secrets/A.enc; do printf '%s %s\n' "$( [[ -f "$INST/$f" ]] && sha256sum < "$INST/$f" | cut -c1-64 || echo MISSING)" "$f"; done; }
# fingerprint of the whole install's data: the stacks (their App-Data inside), the drive, the state
fp_all() { { echo "== Stacks"; fp "$INST/Stacks"; echo "== drive"; fp "$DRV"; echo "== state"; fp_state; } > "$1"; }

echo "Restore drill ($([[ "$ROOTED" == true ]] && echo "as root: owners checked too" || echo "not root: contents, modes and links checked; owners need root"))"

# =============================================================================
echo "The install, its stacks and their App-Data"
mk_install
TOKEN=$(req POST /auth/setup "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" | body | jq -r '.token // empty')
check "an admin is made" yes "$([[ ${#TOKEN} -ge 32 ]] && echo yes || echo no)"
: > "$INST/.api-auth/.setup-complete"
S="$INST/Stacks"
# web: App-Data in its own folder, a database, a link, a name with spaces, an empty folder, a private folder
mkdir -p "$S/web/App-Data/html" "$S/web/App-Data/db" "$S/web/App-Data/empty" "$S/web/config"
printf 'services:\n  web:\n    image: nginx:alpine\n    volumes:\n      - ./App-Data/html:/usr/share/nginx/html\n' > "$S/web/docker-compose.yml"
printf 'TZ=Etc/UTC\n' > "$S/web/.env"; printf 'listen: 80\n' > "$S/web/config/app.yml"; chmod 640 "$S/web/config/app.yml"
printf '<h1>hello</h1>\n' > "$S/web/App-Data/html/index.html"
head -c 300000 /dev/urandom > "$S/web/App-Data/html/blob.bin"
head -c 200000 /dev/urandom > "$S/web/App-Data/db/data.db"; chmod 600 "$S/web/App-Data/db/data.db"; chmod 700 "$S/web/App-Data/db"
ln -s db/data.db "$S/web/App-Data/current"
printf 'notes\n' > "$S/web/App-Data/my notes.txt"; chmod 444 "$S/web/App-Data/my notes.txt"
chmod 750 "$S/web/App-Data/html"
# drive: App-Data on a drive of its own (an absolute APP_DATA_DIR and DCS's marker)
mkdir -p "$S/drive" "$DRV/conf"
printf 'services:\n  app:\n    image: alpine:3\n    volumes:\n      - ${APP_DATA_DIR:-./App-Data}/conf:/conf\n' > "$S/drive/docker-compose.yml"
printf 'APP_DATA_DIR=%s\n' "$DRV" > "$S/drive/.env"
printf '{"stack": "drive", "created": "2026-01-01T00:00:00Z"}\n' > "$DRV/.dcs-appdata"
printf 'drive-conf\n' > "$DRV/conf/settings.conf"; head -c 250000 /dev/urandom > "$DRV/conf/state.bin"; chmod 600 "$DRV/conf/state.bin"
# proxy: Traefik's files (a bundle always carries those), and other data a bundle carries only when asked
mkdir -p "$S/proxy/App-Data/Traefik" "$S/proxy/App-Data/other"
printf 'services:\n  traefik:\n    image: traefik:v3\n' > "$S/proxy/docker-compose.yml"
printf '{"le": 1}\n' > "$S/proxy/App-Data/Traefik/acme.json"; chmod 600 "$S/proxy/App-Data/Traefik/acme.json"
printf 'entryPoints: {}\n' > "$S/proxy/App-Data/Traefik/traefik.yml"; printf 'other\n' > "$S/proxy/App-Data/other/x.txt"
# files of other owners, and one nobody but root may read (root only: a user cannot make them)
if [[ "$ROOTED" == true ]]; then
    chown 999:999 "$S/web/App-Data/db/data.db" "$S/web/App-Data/db"
    chown -h 33:33 "$S/web/App-Data/current"
    printf 'locked\n' > "$S/web/App-Data/html/locked.txt"; chmod 000 "$S/web/App-Data/html/locked.txt"
    chown 1234:1234 "$DRV/conf/state.bin" "$DRV/conf"
    chown 65534:65534 "$S/proxy/App-Data/Traefik/traefik.yml"
fi
# the install's own state
mkdir -p "$INST/.data/schedules" "$INST/.secrets"
printf '[{"id":"s1","name":"nightly","schedule":"0 3 * * *","action":"backup","target":""}]\n' > "$INST/.data/schedules/schedules.json"
printf 'encrypted-secret\n' > "$INST/.secrets/A.enc"; printf 'the-master-key\n' > "$INST/.secrets/.master-key"; chmod 600 "$INST/.secrets/"*
# web and drive run, proxy is stopped
container web-1 web run; container drive-1 drive run; container proxy-1 proxy off
fp_all "$W/fp-source.txt"
check "the fingerprint holds every kind of file" yes "$(grep -q '^l .*current$' "$W/fp-source.txt" && grep -q "my notes.txt" "$W/fp-source.txt" && grep -q 'state.bin$' "$W/fp-source.txt" && echo yes || echo no)"

# =============================================================================
echo "A backup and a recovery bundle, downloaded and kept off the box"
check "backup: started" 200 "$(req POST /backups/trigger '{}' | code)"
ST=$(wait_idle)
check "backup: complete and checked, three stacks" "true true 3" "$(jq -r '.last_backup | "\(.complete) \(.verified) \(.stacks)"' <<< "$ST")"
ARCH=$(jq -r '.last_backup.filename // empty' <<< "$ST")
check "backup: the drive's App-Data is a part of its own" drive "$(tar -xzOf "$BK/$ARCH" ./.dcs-backup/manifest.json 2>/dev/null | jq -r '[.parts[] | select(.kind == "appdata") | .name] | join(",")')"
check "backup: the running stacks were paused and resumed" "pause drive-1 pause web-1 unpause drive-1 unpause web-1" "$(grep -E '^(pause|unpause) ' "$FAKE/state/actions.log" | sort | tr '\n' ' ' | sed 's/ $//')"
LINK=$(req POST /backups/download-link "{\"filename\":\"$ARCH\"}" | body)
check "download link: one-time, with size and checksum" "yes $(stat -c %s "$BK/$ARCH") $(cut -c1-64 "$BK/$ARCH.sha256")" \
    "$(jq -r '"\(.url | test("^/backups/.*/download\\?ticket=[0-9a-f]{48}$") | if . then "yes" else "no" end) \(.size) \(.sha256)"' <<< "$LINK")"
URL=$(jq -r '.url' <<< "$LINK")
HDR=$(TOKEN="" get_raw "$URL" "$OFF/$ARCH")
check "download: the link works without the session" "200" "$(head -1 <<< "$HDR" | awk '{print $2}')"
check "download: byte for byte the archive" "$(sha256sum < "$BK/$ARCH")" "$(sha256sum < "$OFF/$ARCH")"
check "download: the checksum header is its .sha256" "$(cut -c1-64 "$BK/$ARCH.sha256")" "$(sed -n 's/^X-Checksum-SHA256: //p' <<< "$HDR")"
check "download: the link is used up" 401 "$(TOKEN="" get_raw "$URL" "$W/again.bin" | head -1 | awk '{print $2}')"
check "download: …and says so" yes "$(grep -q 'expired or was used' "$W/again.bin" && echo yes || echo no)"
check "download: a link is good for its own path only" 401 "$(L2=$(req POST /backups/download-link "{\"filename\":\"$ARCH\"}" | body | jq -r '.url'); TOKEN="" get_raw "/backups/$ARCH/checksum?${L2#*\?}" "$W/x.bin" | head -1 | awk '{print $2}')"
check "download: with the session too (streamed)" "$(sha256sum < "$BK/$ARCH")" "$(req GET "/backups/$ARCH/download" | body | sha256sum)"
req GET "/backups/$ARCH/checksum" | body | jq -j '.checksum_file' > "$OFF/$ARCH.sha256"
check "download: its .sha256 checks the download" yes "$( (cd "$OFF" && sha256sum -c --status "$ARCH.sha256") && echo yes || echo no)"
check "download: a name that is not an archive's is refused" "400 400" "$(req GET '/backups/..%2f.env/download' | code) $(req POST /backups/download-link '{"filename":"../../.env"}' | code)"
check "download: an archive that is not there is a 404" 404 "$(req GET '/backups/Docker-Compose-Backup-2020-01-01_000000.tar.gz/download' | code)"
R=$(req POST /recovery/bundle "{\"passphrase\":\"$BUNDLE_PASS\",\"include_app_data\":[\"web\",\"drive\"]}")
check "bundle: made, App-Data of web and drive, nothing missing" "200 drive,web []" "$(code <<< "$R") $(body <<< "$R" | jq -r '"\(.app_data | sort | join(",")) \(.warnings | tojson)"')"
BUN=$(body <<< "$R" | jq -r '.file')
check "bundle: it and its .sha256 are private (600)" "600 600" "$(stat -c %a "$BK/recovery/$BUN" "$BK/recovery/$BUN.sha256" | tr '\n' ' ' | sed 's/ $//')"
req GET "/recovery/$BUN/download" | body > "$OFF/$BUN"
check "bundle: downloaded byte for byte" "$(sha256sum < "$BK/recovery/$BUN")" "$(sha256sum < "$OFF/$BUN")"

# =============================================================================
echo "The machine is lost: the install, the drive's App-Data and the backups are gone"
rm -rf "$INST" "$W/disk2" "$BK"
: > "$FAKE/state/actions.log"; rm -f "$FAKE"/state/run/* "$FAKE"/state/off/*
check "nothing is left" "no no no" "$([[ -e "$INST" ]] && echo yes || echo no) $([[ -e "$DRV" ]] && echo yes || echo no) $([[ -e "$BK" ]] && echo yes || echo no)"

# =============================================================================
echo "A new machine, restored from the backup"
mk_install
mkdir -p "$DRV"   # the new drive, with the empty folder the stack's App-Data goes back to (docs/OPERATIONS.md says so)
TOKEN=$(req POST /auth/setup "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" | body | jq -r '.token // empty'); : > "$INST/.api-auth/.setup-complete"
# junk is refused, and nothing of it stays
printf 'not an archive at all\n' > "$W/junk.tar.gz"
R=$(req_file POST "/backups/upload?filename=Docker-Compose-Backup-2026-01-01_000000.tar.gz" "$W/junk.tar.gz")
check "upload: junk is refused, said why" "400 yes" "$(code <<< "$R") $(body <<< "$R" | jq -r '.message' | grep -q 'not gzip' && echo yes || echo no)"
head -c 200000 "$OFF/$ARCH" > "$W/cut.tar.gz"
check "upload: an archive cut short is refused" 400 "$(req_file POST "/backups/upload?filename=x.tar.gz" "$W/cut.tar.gz" | code)"
tar -czf "$W/plain.tar.gz" -C "$ROOT" VERSION
R=$(req_file POST "/backups/upload" "$W/plain.tar.gz")
check "upload: a tar.gz that is not a DCS backup is refused" "400 yes" "$(code <<< "$R") $(body <<< "$R" | jq -r '.message' | grep -q 'no manifest' && echo yes || echo no)"
check "upload: a wrong checksum is refused" 400 "$(req_file POST "/backups/upload?filename=$ARCH&sha256=$(printf '0%.0s' {1..64})" "$OFF/$ARCH" | code)"
check "upload: no session, no upload" 401 "$(TOKEN=nope req_file POST "/backups/upload?filename=$ARCH" "$OFF/$ARCH" | code)"
# a disk without room for it: refused before a byte is stored (a stand-in df says how much is free)
mkdir -p "$W/tinydisk"; printf '#!/bin/sh\necho "Filesystem 1B-blocks Used Available Use%% Mounted on"\necho "/dev/tiny 100000000 99000000 1000000 99%% /"\n' > "$W/tinydisk/df"; chmod +x "$W/tinydisk/df"
R=$(API_ENV=(PATH="$W/tinydisk:$FAKE:$PATH" DOCKER_COMPOSE_CMD="docker compose" DCS_API_EFFECTIVE_AUTH=true DCS_API_EFFECTIVE_BIND=127.0.0.1); req_file POST "/backups/upload?filename=$ARCH" "$OFF/$ARCH")
check "upload: no room for it is a 507, said why" "507 yes" "$(code <<< "$R") $(body <<< "$R" | jq -r '.message' | grep -q '^Not enough room for this archive: .* free' && echo yes || echo no)"
check "upload: the room and the limit are in GET /backups/config" "yes 21474836480" "$(req GET /backups/config | body | jq -r '"\(.upload.free_bytes > 0 | if . then "yes" else "no" end) \(.upload.max_bytes)"')"
printf 'API_MAX_BACKUP_UPLOAD_SIZE=100000\n' >> "$INST/.env"
R=$(req_file POST "/backups/upload?filename=$ARCH" "$OFF/$ARCH")
check "upload: over API_MAX_BACKUP_UPLOAD_SIZE is a 413 that names it" "413 yes" "$(code <<< "$R") $(body <<< "$R" | jq -r '.message' | grep -q 'takes uploads up to 98 KB (API_MAX_BACKUP_UPLOAD_SIZE' && echo yes || echo no)"
sed -i '/^API_MAX_BACKUP_UPLOAD_SIZE=/d' "$INST/.env"
check "upload: nothing of the refused ones is left" "" "$(find "$BK" -mindepth 1 -maxdepth 1 2>/dev/null | grep -v '/recovery$')"
R=$(req_file POST "/backups/upload?filename=$ARCH&sha256=$(cut -c1-64 "$OFF/$ARCH.sha256")" "$OFF/$ARCH")
check "upload: stored under its own name, checked" "200 $ARCH true false" "$(code <<< "$R") $(body <<< "$R" | jq -r '"\(.filename) \(.verified) \(.renamed)"')"
check "upload: private, with its .sha256" "600 600 yes" "$(stat -c %a "$BK/$ARCH" "$BK/$ARCH.sha256" | tr '\n' ' ')$( (cd "$BK" && sha256sum -c --status "$ARCH.sha256") && echo yes || echo no)"
check "upload: listed, as made when it was made" "$ARCH full" "$(req GET /backups | body | jq -r '.backups[0] | "\(.filename) \(.kind)"')"
cp "$OFF/$ARCH" "$W/copy (1).tar.gz"
R=$(req_file POST "/backups/upload?filename=copy%20(1).tar.gz" "$W/copy (1).tar.gz")
check "upload: the same archive again is not stored twice" "200 true $ARCH" "$(code <<< "$R") $(body <<< "$R" | jq -r '"\(.duplicate) \(.filename)"')"
R=$(req POST /backups/restore "{\"filename\":\"$ARCH\",\"confirm\":\"RESTORE\"}")
check "restore: started" 200 "$(code <<< "$R")"
ST=$(wait_idle)
check "restore: everything, no warnings" "true web,drive,proxy drive []" "$(jq -r '.last_restore | "\(.install) \(.stacks | join(",")) \(.appdata | join(",")) \(.warnings | tojson)"' <<< "$ST" | sed 's/web,drive,proxy\|drive,proxy,web\|drive,web,proxy\|proxy,drive,web\|proxy,web,drive\|web,proxy,drive/web,drive,proxy/')"
fp_all "$W/fp-backup.txt"
same "backup restore: every file as it was (content, mode, links$([[ "$ROOTED" == true ]] && echo ', owners'))" "$W/fp-source.txt" "$W/fp-backup.txt"
check "backup restore: no container was started on the new machine" "" "$(running)"

# =============================================================================
echo "Again from nothing: the bundle, through the setup wizard"
rm -rf "$INST" "$W/disk2" "$BK"
mk_install
mkdir -p "$DRV"
TOKEN=""
jq -nc --rawfile b <(base64 -w0 "$OFF/$BUN") --arg p "$BUNDLE_PASS" '{passphrase: $p, content_b64: $b}' > "$W/setup.json"
check "wizard: a wrong passphrase is refused" 400 "$(req POST /setup/restore "$(jq -c '.passphrase = "not-the-passphrase"' "$W/setup.json")" | code)"
R=$(req POST /setup/restore "$(cat "$W/setup.json")")
check "wizard: restored, the account is back, nothing missing" "200 3 1 true []" "$(code <<< "$R") $(body <<< "$R" | jq -r '"\(.stacks) \(.users) \(.initialized) \(.warnings | tojson)"')"
check "wizard: App-Data of web, drive and Traefik" "drive,proxy/Traefik,web" "$(body <<< "$R" | jq -r '.app_data | sort | join(",")')"
check "wizard: nothing ran, nothing stopped or started, nothing set aside" "[] [] [] null" "$(body <<< "$R" | jq -c '.stopped, .started, .set_aside, .kept_before' | tr '\n' ' ' | sed 's/ $//')"
fp_all "$W/fp-bundle.txt"
# a bundle carries Traefik's folder of a stack, not the rest of its App-Data unless asked: proxy's "other" is not in it (by design)
grep -v -e ' ./proxy/App-Data/other' -e '^d [0-9]*\( [0-9:]*\)\? ./proxy/App-Data$' "$W/fp-source.txt" > "$W/fp-source-bundle.txt"
grep -v -e '^d [0-9]*\( [0-9:]*\)\? ./proxy/App-Data$' "$W/fp-bundle.txt" > "$W/fp-bundle-cmp.txt"
same "bundle restore: every file as it was (content, mode, links$([[ "$ROOTED" == true ]] && echo ', owners'))" "$W/fp-source-bundle.txt" "$W/fp-bundle-cmp.txt"
check "bundle restore: the secret store's key came back too" "$(printf 'the-master-key\n' | sha256sum)" "$(sha256sum < "$INST/.secrets/.master-key")"
login
check "bundle restore: the old account signs in" yes "$([[ ${#TOKEN} -ge 32 ]] && echo yes || echo no)"

# =============================================================================
echo "A bundle restored over a running install: stop, set aside, restore, start"
container web-1 web run; container drive-1 drive run; container proxy-1 proxy off; : > "$FAKE/state/actions.log"
printf 'stray\n' > "$S/web/App-Data/html/stray.txt"; printf 'CHANGED\n' > "$S/web/App-Data/html/index.html"
printf 'new\n' > "$DRV/conf/new.txt"; printf 'CHANGED\n' > "$DRV/conf/settings.conf"
printf 'CHANGED\n' > "$S/proxy/App-Data/Traefik/traefik.yml"
mkdir -p "$S/proxy/App-Data/other"; printf 'other\n' > "$S/proxy/App-Data/other/x.txt"
jq -nc --rawfile b <(base64 -w0 "$OFF/$BUN") --arg f "$BUN" '{filename: $f, content_b64: $b}' > "$W/up.json"
check "bundle upload" 200 "$(req POST /recovery/upload "$(cat "$W/up.json")" | code)"
R=$(req_file POST "/recovery/upload?filename=$BUN&sha256=$(sha256sum < "$OFF/$BUN" | cut -c1-64)" "$OFF/$BUN")
check "bundle upload (the file itself, streamed): kept byte for byte, under a name of its own (that one is taken)" "200 yes yes" "$(code <<< "$R") $(F=$(body <<< "$R" | jq -r '.file'); [[ "$F" != "$BUN" && "$F" == dcs-recovery-uploaded-* ]] && echo yes || echo no) $(F=$(body <<< "$R" | jq -r '.file'); cmp -s "$OFF/$BUN" "$BK/recovery/$F" && echo yes || echo no)"
rm -f "$BK/recovery/$(body <<< "$R" | jq -r '.file')" "$BK/recovery/$(body <<< "$R" | jq -r '.file').sha256"
R=$(req_file POST "/recovery/upload?filename=dcs-recovery-junk.tar.gz.enc" "$W/junk.tar.gz")
check "bundle upload: a file that is not a bundle is refused, nothing kept" "400 yes 0" "$(code <<< "$R") $(body <<< "$R" | jq -r '.message' | grep -q 'Not a DCS recovery bundle' && echo yes || echo no) $(find "$BK/recovery" -maxdepth 1 \( -name '*junk*' -o -name '.upload-*' \) | wc -l)"
R=$(req POST /recovery/restore "{\"file\":\"$BUN\",\"passphrase\":\"$BUNDLE_PASS\",\"confirm\":true,\"restart\":false}")
check "restore: done, nothing left undone" "200 []" "$(code <<< "$R") $(body <<< "$R" | jq -c '.warnings')"
check "restore: the stacks that ran were stopped and started again, the stopped one left alone" '["drive","web"] ["drive","web"]' "$(body <<< "$R" | jq -c '.stopped, .started' | tr '\n' ' ' | sed 's/ $//')"
check "restore: …stopped before, started after (docker saw it)" "stop drive-1 stop web-1 start drive-1 start web-1" "$(grep -E '^(stop|start) ' "$FAKE/state/actions.log" | tr '\n' ' ' | sed 's/ $//')"
check "restore: …and they run now" "drive-1 web-1" "$(running)"
KB=$(body <<< "$R" | jq -r '.kept_before // ""')
check "restore: the App-Data that was there is set aside in .data/pre-restore" yes "$([[ "$KB" == "$INST/.data/pre-restore/"* && -d "$KB" ]] && echo yes || echo no)"
check "restore: …web's whole folder and Traefik's, the drive's beside it" "drive:$DRV.before-restore-* proxy/Traefik:$KB/appdata/proxy/Traefik web:$KB/appdata/web" \
    "$(body <<< "$R" | jq -r '[.set_aside[] | "\(.stack)\(if .part != "" then "/" + .part else "" end):\(.kept_in | sub("before-restore-[0-9-]+$"; "before-restore-*"))"] | sort | join(" ")')"
check "restore: the message says what was stopped and where the old data is" yes "$(body <<< "$R" | jq -r '.message' | grep -q 'Stopped for it: drive, web; started again: drive, web.' && body <<< "$R" | jq -r '.message' | grep -q 'kept in' && echo yes || echo no)"
fp_all "$W/fp-over.txt"
grep -v -e '^d [0-9]*\( [0-9:]*\)\? ./proxy/App-Data$' "$W/fp-over.txt" | grep -v ' ./proxy/App-Data/other' > "$W/fp-over-cmp.txt"
grep -v ' ./proxy/App-Data/other' "$W/fp-source-bundle.txt" > "$W/fp-source-over.txt"
same "restore over a running install: the App-Data is the bundle's, file for file (no stray file stays)" "$W/fp-source-over.txt" "$W/fp-over-cmp.txt"
check "restore: what was there is kept whole (the stray file, the changed files)" "stray CHANGED new CHANGED CHANGED" \
    "$(cat "$KB/appdata/web/html/stray.txt" "$KB/appdata/web/html/index.html" "$DRV".before-restore-*/conf/new.txt "$DRV".before-restore-*/conf/settings.conf "$KB/appdata/proxy/Traefik/traefik.yml" 2>/dev/null | tr '\n' ' ' | sed 's/ $//')"
check "restore: the other App-Data of proxy (not in the bundle) is untouched" other "$(cat "$S/proxy/App-Data/other/x.txt" 2>/dev/null)"
check "restore: GET /recovery remembers it" '["drive","web"]' "$(req GET /recovery | body | jq -c '.last_restore.stopped')"
check "restore: the audit log says what was stopped and kept" yes "$(grep RECOVERY_RESTORE "$INST/.data/audit.jsonl" | tail -1 | grep -q 'stopped and started again: drive web' && echo yes || echo no)"
container web-1 web run; container drive-1 drive run
check "restore: refused while another restore runs" 409 "$(echo $$ > "$INST/.api-auth/restore.pid"; req POST /recovery/restore "{\"file\":\"$BUN\",\"passphrase\":\"$BUNDLE_PASS\",\"confirm\":true,\"restart\":false}" | code; rm -f "$INST/.api-auth/restore.pid")"

# =============================================================================
echo "The copies kept from before a restore are pruned (BACKUP_PRE_RESTORE_KEEP, 2)"
LAST=""; PRUNED='[]'
for _i in 1 2 3; do
    R=$(req POST /recovery/restore "{\"file\":\"$BUN\",\"passphrase\":\"$BUNDLE_PASS\",\"confirm\":true,\"restart\":false}")
    LAST=$(body <<< "$R" | jq -r '.kept_before // ""'); PRUNED=$(body <<< "$R" | jq -c --argjson p "$PRUNED" '$p + .pruned')
done
check "prune: two sets in .data/pre-restore, the newest is the last restore's" "2 yes" "$(find "$INST/.data/pre-restore" -mindepth 1 -maxdepth 1 -type d | wc -l) $([[ -n "$LAST" && -d "$LAST" ]] && echo yes || echo no)"
check "prune: two copies beside the drive's App-Data" 2 "$(find "$W/disk2/appdata" -mindepth 1 -maxdepth 1 -name 'drive-app.before-restore-*' | wc -l)"
check "prune: the answers named what went (2 sets and 2 drive copies)" "2 2" "$(jq -r '[.[] | select(contains("/.data/pre-restore/"))] | length' <<< "$PRUNED") $(jq -r '[.[] | select(contains("drive-app.before-restore-"))] | length' <<< "$PRUNED")"
check "prune: written in the audit log" yes "$(grep -q '"action":"restore_pruned"' "$INST/.data/audit.jsonl" && echo yes || echo no)"
check "prune: the App-Data is still the bundle's" "<h1>hello</h1>" "$(cat "$S/web/App-Data/html/index.html")"
# a backup restore prunes the same way, with BACKUP_PRE_RESTORE_KEEP from .env
printf 'BACKUP_PRE_RESTORE_KEEP=1\n' >> "$INST/.env"
mkdir -p "$BK"; cp "$OFF/$ARCH" "$OFF/$ARCH.sha256" "$BK/"
req POST /backups/restore "{\"filename\":\"$ARCH\",\"confirm\":\"RESTORE\",\"stack\":\"drive\"}" >/dev/null
ST=$(wait_idle)
check "prune: a backup restore with BACKUP_PRE_RESTORE_KEEP=1 keeps its own set alone" "1 $(jq -r '.last_restore.kept_before' <<< "$ST")" "$(find "$INST/.data/pre-restore" -mindepth 1 -maxdepth 1 -type d | wc -l) $(find "$INST/.data/pre-restore" -mindepth 1 -maxdepth 1 -type d)"
check "prune: …and one copy beside the drive" 1 "$(find "$W/disk2/appdata" -mindepth 1 -maxdepth 1 -name 'drive-app.before-restore-*' | wc -l)"
check "prune: …named in its result" true "$(jq -r '.last_restore.pruned | length > 0' <<< "$ST")"

# =============================================================================
echo "A stack whose containers will not stop is skipped, by a backup restore and by a bundle restore"
rm -f "$FAKE"/state/run/* "$FAKE"/state/off/*
container web-1 web run; container drive-1 drive run; : > "$FAKE/state/stuck/drive-1"; : > "$FAKE/state/actions.log"
printf 'CHANGED\n' > "$S/web/App-Data/html/index.html"; printf 'CHANGED\n' > "$DRV/conf/settings.conf"; printf 'mine\n' > "$S/drive/local-note.txt"
R=$(req POST /backups/restore "{\"filename\":\"$ARCH\",\"confirm\":\"RESTORE\"}")
check "skip (backup): the restore runs" 200 "$(code <<< "$R")"
ST=$(wait_idle)
check "skip (backup): drive is named, with Docker's reason" "drive yes" "$(jq -r '.last_restore.skipped | (map(.stack) | join(",")), (.[0].reason | test("did not stop .*did not receive an exit event") | if . then "yes" else "no" end)' <<< "$ST" | tr '\n' ' ' | sed 's/ $//')"
check "skip (backup): …in the warnings and the message, as the owner reads it" "yes yes" \
    "$(jq -r '.last_restore | (.warnings | any(startswith("drive was not restored: its containers did not stop (") and endswith("). Stop it and restore that stack alone."))), (.message | test("^drive was not restored: .*Stop it and restore that stack alone\\.$"))' <<< "$ST" | sed 's/true/yes/; s/false/no/' | tr '\n' ' ' | sed 's/ $//')"
check "skip (backup): the other stacks were restored" "proxy,web" "$(jq -r '.last_restore.stacks | sort | join(",")' <<< "$ST")"
check "skip (backup): drive's App-Data and folder are untouched" "CHANGED mine" "$(cat "$DRV/conf/settings.conf" "$S/drive/local-note.txt" 2>/dev/null | tr '\n' ' ' | sed 's/ $//')"
check "skip (backup): web's App-Data is the archive's" "<h1>hello</h1>" "$(cat "$S/web/App-Data/html/index.html")"
check "skip (backup): web stopped and started, drive asked to stop and never started" "stop drive-1 stop web-1 start web-1" "$( { grep '^stop ' "$FAKE/state/actions.log" | sort; grep '^start ' "$FAKE/state/actions.log"; } | tr '\n' ' ' | sed 's/ $//')"
check "skip (backup): both run now (drive never stopped)" "drive-1 web-1" "$(running)"
check "skip (backup): written in the audit log" yes "$(grep '"action":"backup_restore"' "$INST/.data/audit.jsonl" | tail -1 | grep -q 'not restored (containers did not stop): drive' && echo yes || echo no)"
# the bundle: drive's App-Data stays, web's comes back
: > "$FAKE/state/actions.log"
printf 'CHANGED\n' > "$S/web/App-Data/html/index.html"
R=$(req POST /recovery/restore "{\"file\":\"$BUN\",\"passphrase\":\"$BUNDLE_PASS\",\"confirm\":true,\"restart\":false}")
check "skip (bundle): done, drive skipped with its reason" "200 drive yes" "$(code <<< "$R") $(body <<< "$R" | jq -r '(.skipped | map(.stack) | join(",")) + " " + (.skipped[0].reason | test("^its containers did not stop \\(Error response from daemon") | if . then "yes" else "no" end)')"
check "skip (bundle): the message leads with it" yes "$(body <<< "$R" | jq -r '.message' | grep -q 'drive was not restored: its containers did not stop (.*). Stop it and restore the bundle again.' && echo yes || echo no)"
check "skip (bundle): web stopped and started again, drive neither" '["web"] ["web"]' "$(body <<< "$R" | jq -c '.stopped, .started' | tr '\n' ' ' | sed 's/ $//')"
check "skip (bundle): web's App-Data restored, drive's not" "web <h1>hello</h1> CHANGED" "$(body <<< "$R" | jq -r '[.app_data[] | select(startswith("drive") | not)] | map(select(. == "web")) | join(",")') $(cat "$S/web/App-Data/html/index.html") $(cat "$DRV/conf/settings.conf")"
check "skip (bundle): docker never started drive-1" "stop drive-1 stop web-1 start web-1" "$(grep -E '^(stop|start) ' "$FAKE/state/actions.log" | tr '\n' ' ' | sed 's/ $//')"
check "skip (bundle): GET /recovery remembers it" drive "$(req GET /recovery | body | jq -r '.last_restore.skipped | map(.stack) | join(",")')"
rm -f "$FAKE/state/stuck/drive-1"

echo
echo "passed $PASS, failed $FAIL"
[[ "$FAIL" -eq 0 ]]
