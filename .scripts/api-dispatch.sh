#!/bin/bash
# =============================================================================
# api-dispatch.sh — the front of the API when it runs with worker processes.
#
# socat starts this for every connection, with the client on stdin / stdout.
# It reads the request (the line, the headers, the body the Content-Length
# announces: what the API reads itself, with the same 10 s patience), then
# hands it to one of the worker processes the server keeps — each one is
# api-server.sh, read once, listening on its own unix socket — with the
# client's address in front. A busy worker refuses the connection at once, so
# the next one is tried with the same request.
#
# The pool is a fast path, never a queue: a request that stays open (an event
# stream is open for as long as a dashboard is) and a request that finds every
# worker busy for a second (a slow call each, say to a VM that does not answer)
# are served by a process of their own, the way every request was before the pool.
# Written to be tiny: bash reads it in a millisecond, where the API script
# takes a tenth of a second on a small VM.
# =============================================================================
d="${DCS_API_RUN_DIR:-}"
answer() { printf 'HTTP/1.1 %s\r\nContent-Type: application/json\r\nConnection: close\r\n%s\r\n{"error": true, "code": %s, "message": "%s"}\r\n' "$1" "$2" "${1%% *}" "$3"; exit 0; }
[[ -n "$d" && -d "$d" ]] || answer "503 Service Unavailable" $'Retry-After: 2\r\n' "The API is starting"
peer="${SOCAT_PEERADDR:-${NCAT_REMOTE_ADDR:-}}"
# the buffered request lives in the run directory (the API's own, mode 700): a name without starting a process for it
tmp="$d/req-$$-$RANDOM$RANDOM"
( umask 077; : > "$tmp" ) 2>/dev/null || answer "503 Service Unavailable" "" "No room for the request"
trap 'rm -f "$tmp" "$tmp.e"' EXIT
# the request, buffered: the line and the headers (up to the blank line), then the body. socat's -T does nothing for a
# program it runs in its own place (nofork): the patience is here: 10 s a line, 30 s for the whole head, 30 s for the body
cl=0; n=0; req=""; hd=$(( EPOCHSECONDS + 30 ))
IFS= read -r -t 10 line || exit 0
req="$line"$'\n'
while IFS= read -r -t 10 h; do
    req+="$h"$'\n'
    hl="${h%%$'\r'}"
    [[ -z "$hl" ]] && break
    (( ++n > 200 )) && answer "431 Request Header Fields Too Large" "" "Too many headers"
    (( EPOCHSECONDS <= hd )) || answer "408 Request Timeout" "" "The request did not arrive within 30 seconds"
    if [[ "${hl,,}" == content-length:* ]]; then cl="${hl#*:}"; cl="${cl//[[:space:]]/}"; [[ "$cl" =~ ^[0-9]{1,15}$ ]] || cl=0; fi
done
path="${line#* }"; path="${path%% *}"; path="${path%%\?*}"

# An upload (a backup archive, a recovery bundle: up to API_MAX_BACKUP_UPLOAD_SIZE, 20 GB) is never buffered here: a process
# of its own reads the request line and the headers from a pipe and then the body straight from the client, as it arrives,
# once it knows the caller (it refuses a stranger before a byte of the body is read). The body never touches this disk.
if [[ "${line%% *}" == POST ]]; then
    case "$path" in
        /backups/upload|/recovery/upload|/fleet/members/*/backups/upload)
            api="${DCS_API_SELF:-$(dirname "$0")/api-server.sh}"
            [[ -x "$api" ]] || answer "503 Service Unavailable" $'Retry-After: 2\r\n' "The API is starting"
            rm -f "$tmp"; trap - EXIT
            # the reader of the body ends with the request (a client that sends nothing more must not keep it waiting)
            exec {cin}<&0
            exec {up}< <(printf '%s' "$req"; (( cl > 0 )) && exec head -c "$cl" <&"$cin")
            upid=$!
            "$api" --handle-request <&"$up"
            exec {up}<&-
            kill "$upid" 2>/dev/null
            exit 0 ;;
    esac
fi
# before anyone is known, a body is as big as the API takes it (API_MAX_BODY_SIZE, 1 MB); the setup wizard's restore (a
# bundle sent as JSON) is the one bigger (API_MAX_UPLOAD_SIZE, 128 MB), as in the API's own reader
lim="${API_MAX_BODY_SIZE:-1048576}"
case "$path" in /setup/restore) lim="${API_MAX_UPLOAD_SIZE:-134217728}" ;; esac
[[ "$lim" =~ ^[0-9]{1,15}$ ]] || lim=1048576
(( cl <= lim )) || answer "413 Content Too Large" "" "Request body too large. Maximum: $lim bytes"
{ printf 'DCS-PEER %s\r\n' "$peer"; printf '%s' "$req"; } > "$tmp"
if (( cl > 0 )); then timeout 30 head -c "$cl" >> "$tmp" || answer "408 Request Timeout" "" "Request timeout: body not received within 30 seconds"; fi

# a process of its own for this request: the API script reads the request from its stdin (the buffered copy without the
# address line; the address is in the environment socat gave this front)
oneshot() {
    local api="${DCS_API_SELF:-$(dirname "$0")/api-server.sh}"
    [[ -x "$api" ]] || answer "503 Service Unavailable" $'Retry-After: 2\r\n' "Every API worker is busy: try again in a moment"
    tail -n +2 "$tmp" | "$api" --handle-request
    exit 0
}
# a stream stays open: it would take a worker out of the pool for as long as its dashboard is open
case "$path" in */stream) oneshot ;; esac
# The heartbeat (GET /ping) never waits for a worker: one look for a free one (a worker answers it in milliseconds), and
# when every worker is busy the API script's fast path answers it before it parses the rest. Waiting behind a burst of
# slow calls took seconds on a busy small VM, the dashboard's 8 s heartbeat gave up and it showed "Reconnecting" (and
# fetched everything again) while the server was fine.
once=""
case "$path" in /ping|/ping/) once=yes ;; esac

# A worker's socket file is away for a moment between two connections (socat removes it on close, the next one binds it
# again), so the list is read on every round. A burst of dashboard polls is served by the pool one after the other (a
# worker takes a request every few hundredths of a second); a second without a free worker is "all busy" (a budget of time,
# not of rounds: twenty rounds over busy workers' sockets took four or five seconds)
# One front talks to a worker at a time (a lock beside its socket): two fronts that connect in the same instant both land
# in the worker's queue, socat takes one connection and closes the queue, and the other is reset after it sent its
# request — an empty answer for a request nobody read. Under a burst on a small VM that was most of them.
lk=""
command -v flock >/dev/null 2>&1 && lk=yes
start=$RANDOM; t_end="${EPOCHREALTIME/[.,]/}"; [[ -n "$t_end" ]] || t_end=$(date +%s%6N); t_end=$(( t_end + 1000000 ))
while :; do
    t1="${EPOCHREALTIME/[.,]/}"; [[ -n "$t1" ]] || t1=$(date +%s%6N); (( t1 < t_end )) || break
    socks=("$d"/w*.sock); nw=${#socks[@]}
    for (( i = 0; i < nw; i++ )); do
        s="${socks[(start + i) % nw]}"
        [[ -S "$s" ]] || continue
        if [[ -n "$lk" ]]; then
            exec {lfd}>>"$s.lock" 2>/dev/null || continue
            flock -n "$lfd" || { exec {lfd}>&-; continue; }
        fi
        t0="${EPOCHREALTIME/[.,]/}"; [[ -n "$t0" ]] || t0=$(date +%s%6N)
        # -t: the request is sent at once (EOF on the file), then socat must wait for the answer; its default is half a second
        socat -t 900 -T 900 STDIO "UNIX-CONNECT:$s" < "$tmp" 2>"$tmp.e" && exit 0
        [[ -n "$lk" ]] && exec {lfd}>&-
        # refused at connect() (the worker is busy, or between two connections): nothing was exchanged, try the next one —
        # however long the refusal took (on a loaded small VM starting socat alone can take longer than the rule below allows,
        # and the request then ended with an empty answer)
        err=""; read -r err < "$tmp.e" 2>/dev/null
        [[ "$err" == *" E connect("* ]] && continue
        # any other failure that took longer than a refusal had the worker's attention and is not sent again (a POST must
        # not run twice)
        t1="${EPOCHREALTIME/[.,]/}"; [[ -n "$t1" ]] || t1=$(date +%s%6N)
        (( (t1 - t0) / 1000 < 150 )) || exit 0
    done
    [[ -n "$once" ]] && break
    sleep 0.05
done
oneshot
