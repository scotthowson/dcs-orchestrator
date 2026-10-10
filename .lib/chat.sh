#!/bin/bash
# shellcheck shell=bash
# =============================================================================
# Chat — one room per DCS server, for the people signed in to it
#
# What it keeps (all under .data/chat/, private files):
#   messages.jsonl   one message per line: {id, ts, user, role, text, server, edited?, deleted?, deleted_by?}
#                    id is a sequence number (seq), ts epoch seconds. server is null for a message written here;
#                    a relay between servers (later) sets it to the server the message came from.
#   seq              the last id handed out
#   room.json        {cleared_at, cleared_by} once an admin cleared the room
#   live.jsonl       the live feed: one event per line, read by every open /stream (event "chat");
#                    {type: message|edit|delete|clear|typing|state, ...}. Emptied in place when it grows long.
#   (pictures)       a message and a person online carry avatar_url (GET /users/{name}/avatar) or avatar_emoji from the
#                    person's profile (.api-auth/profiles/<user>.json, Settings → Profile); nothing is stored here
#   presence/<user>  touched whenever the person's dashboard is connected (its /stream) or asks the chat anything;
#                    online = touched in the last CHAT_ONLINE_WINDOW seconds. The file holds the role.
#   rate/<user>      the times of the person's recent sends (the per-minute limit)
#   typing/<user>    when the person last said they were typing (one event per 3 s at most)
#
# Rules: any signed-in person (admin, user) reads; admins and users write (CHAT_USERS_CAN_POST=false keeps users to
# reading); bot accounts and API keys stay out. One edits their own message for 15 minutes; one deletes their own, an
# admin any (audited) and may clear the room (audited). The audit never holds a message's text.
# A fleet member (a VM) has no room of its own: its hub's room is the server's room.
#
# A dashboard signed in to several servers keeps each server's room with that server's own session (GET /chat/summary
# for its badge, GET /stream?only=chat for its live events) and merges them on screen only: no server ever reads or
# writes another's room.
#
# Loaded on demand by the router (_chat_lib in api-server.sh) and by /stream. Uses the API's helpers
# (_api_success, _api_error, _api_response, _audit_log, QUERY_PARAMS, AUTH_*).
# =============================================================================

# shellcheck disable=SC2034  # read by the router (_chat_lib in api-server.sh)
CHAT_LIB_LOADED=1
CHAT_DIR="${CHAT_DIR:-$BASE_DIR/.data/chat}"
CHAT_EDIT_WINDOW=900
CHAT_MAX_LENGTH=2000

# ── settings ──────────────────────────────────────────────────────────────────
_chat_enabled() { [[ "${CHAT_ENABLED:-true}" != "false" ]]; }
_chat_int() {   # VALUE DEFAULT MIN MAX
    local v="$1"
    [[ "$v" =~ ^[0-9]{1,9}$ ]] || v="$2"
    (( v < $3 )) && v="$3"
    (( v > $4 )) && v="$4"
    printf '%s' "$v"
}
_chat_retention_days() { _chat_int "${CHAT_RETENTION_DAYS:-}" 30 1 3650; }
_chat_retention_max()  { _chat_int "${CHAT_RETENTION_MAX:-}" 2000 50 100000; }
_chat_rate_limit()     { _chat_int "${CHAT_RATE_LIMIT:-}" 20 1 600; }
_chat_online_window()  { _chat_int "${CHAT_ONLINE_WINDOW:-}" 60 15 3600; }
_chat_users_can_post() { [[ "${CHAT_USERS_CAN_POST:-true}" != "false" ]]; }
_chat_can_post() { [[ "${AUTH_ROLE:-}" == "admin" ]] || { [[ "${AUTH_ROLE:-}" == "user" ]] && _chat_users_can_post; }; }
_chat_cutoff() { printf '%s' $(( $(date +%s) - $(_chat_retention_days) * 86400 )); }

# ── storage ───────────────────────────────────────────────────────────────────
_chat_init() {
    umask 077   # every file of the room is private (this request's process only)
    [[ -d "$CHAT_DIR/presence" && -d "$CHAT_DIR/rate" && -d "$CHAT_DIR/typing" ]] || (umask 077; mkdir -p "$CHAT_DIR/presence" "$CHAT_DIR/rate" "$CHAT_DIR/typing") 2>/dev/null
    [[ -e "$CHAT_DIR/messages.jsonl" ]] || (umask 077; : > "$CHAT_DIR/messages.jsonl") 2>/dev/null
    [[ -e "$CHAT_DIR/live.jsonl" ]] || (umask 077; : > "$CHAT_DIR/live.jsonl") 2>/dev/null
    return 0
}

# a name that can be a file name (accounts are [A-Za-z0-9_-]{3,32}; anything else simply has no presence file)
_chat_safe_name() { [[ "$1" =~ ^[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}$ ]]; }

# run a command holding the room's lock (every write goes through here)
_chat_locked() {
    ( flock -w 5 9 || exit 75; "$@" ) 9>>"$CHAT_DIR/.lock"
}

# every message, oldest first, as one JSON array (a damaged line is skipped, never the whole room)
_chat_all() {
    jq -Rnc --argjson cutoff "$(_chat_cutoff)" '[inputs | fromjson? | select(type == "object" and (.id | type) == "number" and (.ts // 0) >= $cutoff)]' "$CHAT_DIR/messages.jsonl" 2>/dev/null || printf '[]'
}

# one line to the live feed (under the lock). A long feed is emptied in place first: every open stream follows the
# file by name and reads on from its start, and what it held was delivered long ago.
_chat_live_locked() {
    local f="$CHAT_DIR/live.jsonl" n
    n=$(wc -l < "$f" 2>/dev/null || echo 0)
    (( n > 2000 )) && : > "$f"
    printf '%s\n' "$1" >> "$f"
}
_chat_live() { _chat_init; _chat_locked _chat_live_locked "$1"; }

# keep the newest CHAT_RETENTION_MAX messages of the last CHAT_RETENTION_DAYS days (only rewritten when needed)
_chat_rotate_locked() {
    local f="$CHAT_DIR/messages.jsonl" n first max cutoff
    max=$(_chat_retention_max); cutoff=$(_chat_cutoff)
    n=$(wc -l < "$f" 2>/dev/null || echo 0)
    first=$(head -n1 "$f" 2>/dev/null | jq -r '.ts // 0' 2>/dev/null); [[ "$first" =~ ^[0-9]+$ ]] || first=0
    (( n > max || first < cutoff )) || return 0
    jq -Rnc --argjson cutoff "$cutoff" --argjson max "$max" \
        '[inputs | fromjson? | select(type == "object" and (.id | type) == "number" and (.ts // 0) >= $cutoff)] | .[-$max:][]' \
        "$f" > "$f.tmp" 2>/dev/null && chmod 600 "$f.tmp" 2>/dev/null && mv -f "$f.tmp" "$f"
}

# ── presence ──────────────────────────────────────────────────────────────────
# the caller is here now (cheap: one small write)
_chat_touch() {
    local u="${AUTH_USERNAME:-}"
    _chat_safe_name "$u" || return 0
    _chat_init
    printf '%s' "${AUTH_ROLE:-user}" > "$CHAT_DIR/presence/$u" 2>/dev/null || true
}

# who is online: [{user, role, seen}], newest first
_chat_online_json() {
    local now win f u role seen
    now=$(date +%s); win=$(_chat_online_window)
    local -a rows=()
    for f in "$CHAT_DIR"/presence/*; do
        [[ -f "$f" ]] || continue
        seen=$(stat -c %Y "$f" 2>/dev/null) || continue
        (( now - seen <= win )) || continue
        u="${f##*/}"; role=$(head -c 16 "$f" 2>/dev/null); [[ "$role" =~ ^(admin|user)$ ]] || role=user
        rows+=("$u"$'\t'"$role"$'\t'"$seen")
    done
    if (( ${#rows[@]} == 0 )); then printf '[]'; return; fi
    local av
    # shellcheck disable=SC2046  # one word per user name (safe names only)
    av=$(_chat_avatars_json card $(printf '%s\n' "${rows[@]}" | cut -f1))
    printf '%s\n' "${rows[@]}" | jq -Rnc --argjson av "$av" '[inputs | split("\t") | {user: .[0], role: .[1], seen: (.[2] | tonumber)} | . + ($av[.user] // {})] | sort_by(-.seen)'
}

# ── profile pictures ──────────────────────────────────────────────────────────
# What a person set as their picture on their profile (Settings → Profile, POST /settings/profile: `icon`): an uploaded
# picture (a data: URL) is served by GET /users/{name}/avatar and named as avatar_url (with the profile's time, so a new
# picture is a new address); an emoji is avatar_emoji. A picture at an address on another site is never handed to other
# people's browsers (it would tell that site who reads the room): those people get the initials instead.
_chat_profile_file() { printf '%s/%s.json' "${PROFILES_DIR:-$BASE_DIR/.api-auth/profiles}" "$1"; }
# USER [card]: {avatar_url | avatar_emoji}; with "card" also what the person says of themself in Settings → Profile, as
# plain text: display_name (≤ 64), status (≤ 80), status_emoji, bio (≤ 280). Nothing else of the profile (e-mail, time
# zone, looks) ever leaves it.
_chat_avatar_of() {
    local u="$1" f
    f=$(_chat_profile_file "$u")
    if ! _chat_safe_name "$u" || [[ ! -f "$f" ]]; then printf '{}'; return; fi
    jq -c --arg u "$u" --arg v "$(stat -c %Y "$f" 2>/dev/null || echo 0)" --argjson card "$([[ "${2:-}" == card ]] && echo true || echo false)" '
        def txt($k; $n): (.[$k] // "") | if type == "string" then gsub("[\\x{0}-\\x{1F}\\x{7F}\\x{202A}-\\x{202E}\\x{2066}-\\x{2069}]"; " ") | sub("^\\s+"; "") | sub("\\s+$"; "") | .[0:$n] else "" end;
        ((.icon // .avatar // "") | if type == "string" then . else "" end) as $i
        | (if ($i | test("^data:image/(png|jpeg|webp|gif);base64,")) then {avatar_url: "/users/\($u)/avatar?v=\($v)"}
           elif ($i != "" and ($i | length) <= 11 and ($i | test("^(https?:|data:|/)") | not) and ($i | test("[<>\"\\\\]") | not)) then {avatar_emoji: $i}
           else {} end)
        + (if $card then
             {display_name: txt("displayName"; 64), status: txt("statusText"; 80), status_emoji: txt("statusEmoji"; 8), bio: txt("bio"; 280)}
             | with_entries(select(.value != ""))
           else {} end)' "$f" 2>/dev/null || printf '{}'
}

# the pictures (or, with CARD=card first, the cards) of several people: {user: {…}}
_chat_avatars_json() {
    local u out='{}' a mode=""
    [[ "${1:-}" == card ]] && { mode=card; shift; }
    for u in "$@"; do
        a=$(_chat_avatar_of "$u" "$mode"); [[ "$a" == \{* && "$a" != '{}' ]] || continue
        out=$(jq -c --arg u "$u" --argjson a "$a" '. + {($u): $a}' <<< "$out")
    done
    printf '%s' "$out"
}

# a person's picture and card are for people signed in to the dashboard (admins and users), not for bots or API keys
_chat_person_gate() {
    if [[ "${AUTH_VIA_KEY:-}" == "true" || ( "${AUTH_ROLE:-}" != "admin" && "${AUTH_ROLE:-}" != "user" ) ]]; then
        _api_error 403 "Profiles are for people signed in to the dashboard"
        return 1
    fi
}

# GET /users/{name}/profile — What a person shows the others (for anyone signed in): their picture (avatar_url or avatar_emoji), display name, status (≤ 80 characters), status emoji and bio (≤ 280), as plain text, set in Settings → Profile; their role, and whether they are in this server's chat room now
handle_user_profile() {
    local u="$1" users role card online
    _chat_person_gate || return
    _chat_safe_name "$u" || { _api_error 400 "Invalid user name"; return; }
    users=$(_api_read_auth_file "users.json" 2>/dev/null)
    role=$(jq -r --arg u "$u" '[.[]? | select(.username == $u) | .role][0] // empty' <<< "${users:-[]}" 2>/dev/null)
    [[ -n "$role" ]] || { _api_error 404 "No such account"; return; }
    card=$(_chat_avatar_of "$u" card); [[ "$card" == \{* ]] || card='{}'
    online=false
    if _chat_enabled && [[ -f "$CHAT_DIR/presence/$u" ]] && (( $(date +%s) - $(stat -c %Y "$CHAT_DIR/presence/$u" 2>/dev/null || echo 0) <= $(_chat_online_window) )); then online=true; fi
    _api_success "$(jq -c --arg u "$u" --arg r "$role" --argjson on "$online" '{user: $u, role: $r, online: $on} + .' <<< "$card")"
}

# GET /users/{name}/avatar — A person's profile picture (the one uploaded in Settings → Profile), for anyone signed in: the image itself, cacheable; 404 when they have none (or an emoji, or a picture on another site)
handle_user_avatar() {
    local u="$1" f mime tmp size etag magic
    _chat_person_gate || return
    _chat_safe_name "$u" || { _api_error 400 "Invalid user name"; return; }
    f=$(_chat_profile_file "$u")
    [[ -f "$f" ]] || { _api_error 404 "No profile picture"; return; }
    mime=$(jq -r '((.icon // .avatar // "") | if type == "string" then . else "" end) | capture("^data:(?<m>image/(png|jpeg|webp|gif));base64,") | .m' "$f" 2>/dev/null)
    [[ -n "$mime" ]] || { _api_error 404 "No profile picture"; return; }
    etag="\"$(stat -c '%Y-%s' "$f" 2>/dev/null)\""
    tmp=$(mktemp) || { _api_error 500 "No room for the picture"; return; }
    jq -r '(.icon // .avatar) | sub("^data:[^,]*,"; "")' "$f" 2>/dev/null | base64 -d > "$tmp" 2>/dev/null
    size=$(stat -c %s "$tmp" 2>/dev/null || echo 0)
    # what the file starts with must be what it says it is (a picture, at most 4 MiB)
    magic=$(head -c 12 "$tmp" | od -An -tx1 | tr -d ' \n')
    case "$mime" in
        image/png)  [[ "$magic" == 89504e470d0a1a0a* ]] ;;
        image/jpeg) [[ "$magic" == ffd8ff* ]] ;;
        image/gif)  [[ "$magic" == 47494638* ]] ;;
        image/webp) [[ "$magic" == 52494646????????57454250 ]] ;;
    esac || { rm -f "$tmp"; _api_error 404 "No profile picture"; return; }
    if (( size < 8 || size > 4194304 )); then rm -f "$tmp"; _api_error 404 "No profile picture"; return; fi
    printf 'HTTP/1.1 200 OK\r\n'
    printf 'Content-Type: %s\r\n' "$mime"
    printf 'Content-Length: %s\r\n' "$size"
    printf 'Cache-Control: private, max-age=3600\r\n'
    printf 'ETag: %s\r\n' "$etag"
    printf 'X-Content-Type-Options: nosniff\r\n'
    printf "Content-Security-Policy: default-src 'none'\r\n"
    _api_cors_lines
    printf 'Connection: close\r\n\r\n'
    cat "$tmp"
    rm -f "$tmp"
}

# ── gate ──────────────────────────────────────────────────────────────────────
# every chat route asks this first: the room exists here, and the caller is a person who may be in it
_chat_gate() {
    if ! _chat_enabled; then
        _api_response 404 '{"error": true, "code": 404, "reason": "chat_off", "message": "Chat is off on this server"}'
        return 1
    fi
    if declare -F _fleet_is_member >/dev/null && _fleet_is_member; then
        _api_response 404 '{"error": true, "code": 404, "reason": "chat_on_hub", "message": "This server is part of a fleet: its chat room is on the hub"}'
        return 1
    fi
    if [[ "${AUTH_VIA_KEY:-}" == "true" ]]; then
        _api_error 403 "The chat is for people signed in to the dashboard, not for API keys"
        return 1
    fi
    if [[ "${AUTH_ROLE:-}" != "admin" && "${AUTH_ROLE:-}" != "user" ]]; then
        _api_error 403 "Bot accounts do not take part in the chat"
        return 1
    fi
    if [[ -z "${AUTH_USERNAME:-}" ]]; then
        _api_error 401 "Sign in to use the chat"
        return 1
    fi
    _chat_init
    return 0
}

# the text of a request body, cleaned: no control characters (newlines and tabs stay), no direction overrides, \r\n
# becomes \n, trimmed. Prints a JSON string, or nothing when the body has no usable text.
_chat_clean_text() {
    jq -c 'if (type == "object") and ((.text | type) == "string") then .text else empty end
        | gsub("\r\n?"; "\n")
        | gsub("[\\x{0}-\\x{8}\\x{B}-\\x{1F}\\x{7F}\\x{200B}\\x{202A}-\\x{202E}\\x{2066}-\\x{2069}\\x{FEFF}]"; "")
        | sub("^\\s+"; "") | sub("\\s+$"; "")' <<< "$1" 2>/dev/null
}

# the caller's sends in the last minute, and whether one more fits (under the lock). Prints the seconds to wait, 0 = go.
_chat_rate_take_locked() {
    local f="$CHAT_DIR/rate/$1" now limit kept n wait
    now=$(date +%s); limit=$(_chat_rate_limit)
    kept=$(awk -v c=$(( now - 60 )) '$1 + 0 > c' "$f" 2>/dev/null)
    n=0; [[ -n "$kept" ]] && n=$(printf '%s\n' "$kept" | wc -l)
    if (( n >= limit )); then
        wait=$(( $(printf '%s\n' "$kept" | head -n1) + 60 - now )); (( wait < 1 )) && wait=1
        printf '%s' "$wait"; return 0
    fi
    { [[ -n "$kept" ]] && printf '%s\n' "$kept"; printf '%s\n' "$now"; } > "$f.tmp" 2>/dev/null && mv -f "$f.tmp" "$f"
    printf '0'
}
_chat_rate_take() {
    local u="$1" w
    _chat_safe_name "$u" || u="_other"
    w=$(_chat_locked _chat_rate_take_locked "$u") || w=0
    [[ "$w" =~ ^[0-9]+$ ]] || w=0
    if (( w > 0 )); then
        _api_response 429 "$(jq -cn --argjson w "$w" --argjson l "$(_chat_rate_limit)" '{error: true, code: 429, reason: "rate_limited", retry_after: $w, message: "You are sending messages faster than \($l) a minute: wait \($w) s"}')"
        return 1
    fi
    return 0
}

# the room as the caller sees it
_chat_room_json() {
    local online cleared latest
    online=$(_chat_online_json)
    cleared=$(jq -c '{cleared_at: (.cleared_at // null), cleared_by: (.cleared_by // null)}' "$CHAT_DIR/room.json" 2>/dev/null) || cleared='{}'
    [[ "$cleared" == \{* ]] || cleared='{}'
    latest=$(cat "$CHAT_DIR/seq" 2>/dev/null); [[ "$latest" =~ ^[0-9]+$ ]] || latest=0
    jq -cn --arg name "${SERVER_NAME:-Docker Server}" --argjson online "$online" --argjson cleared "$cleared" \
        --argjson days "$(_chat_retention_days)" --argjson max "$(_chat_retention_max)" --argjson rate "$(_chat_rate_limit)" \
        --argjson latest "$latest" --arg me "${AUTH_USERNAME:-}" --arg role "${AUTH_ROLE:-}" \
        --argjson post "$(_chat_can_post && echo true || echo false)" --argjson win "$(_chat_online_window)" \
        '{id: "server", kind: "server", server: null, name: $name,
          members_online: $online, online_window: $win,
          retention: {days: $days, max_messages: $max},
          rate_limit_per_minute: $rate, max_length: 2000, edit_window: 900,
          latest_id: $latest} + $cleared
         + {me: {user: $me, role: $role, can_post: $post, can_moderate: ($role == "admin")}}'
}

# ── handlers ──────────────────────────────────────────────────────────────────

# GET /chat/messages — The server's chat room: messages (?since=<id> for newer ones, or a time in epoch seconds for those sent, edited or deleted after it; ?before=<id> for older, ?limit= up to 500, default 100) and the room (who is online, retention, what the caller may do)
handle_chat_messages() {
    _chat_gate || return
    _chat_touch
    local since="${QUERY_PARAMS[since]:-}" before="${QUERY_PARAMS[before]:-}" limit="${QUERY_PARAMS[limit]:-100}" since_id=null since_ts=null bid=null
    [[ "$limit" =~ ^[0-9]{1,4}$ ]] || limit=100
    (( limit < 1 )) && limit=1; (( limit > 500 )) && limit=500
    if [[ -n "$since" ]]; then
        [[ "$since" =~ ^[0-9]{1,12}$ ]] || { _api_error 400 "since is a message id or a time in epoch seconds"; return; }
        # a message id is a small sequence number; anything from 2001-09-09 on (10 digits) is a time
        if (( since >= 1000000000 )); then since_ts=$since; else since_id=$since; fi
    fi
    if [[ -n "$before" ]]; then
        [[ "$before" =~ ^[0-9]{1,12}$ ]] || { _api_error 400 "before is a message id"; return; }
        bid=$before
    fi
    local msgs room
    msgs=$(_chat_all | jq -c --argjson sid "$since_id" --argjson sts "$since_ts" --argjson bid "$bid" --argjson limit "$limit" '
        map(select(($sid == null or .id > $sid) and ($sts == null or .ts > $sts or (.edited // 0) > $sts or (.deleted_at // 0) > $sts) and ($bid == null or .id < $bid))) as $m
        | {messages: (if ($sid != null or $sts != null) then $m[:$limit] else $m[-$limit:] end), has_more: (($m | length) > $limit)}')
    [[ "$msgs" == \{* ]] || msgs='{"messages": [], "has_more": false}'
    # each message with its writer's picture (read now: a new picture shows on the old messages too)
    local av
    # shellcheck disable=SC2046  # one word per user name (safe names only)
    av=$(_chat_avatars_json $(jq -r '[.messages[].user] | unique | .[]' <<< "$msgs" 2>/dev/null))
    [[ "$av" != '{}' ]] && msgs=$(jq -c --argjson av "$av" '.messages |= map(. + ($av[.user] // {}))' <<< "$msgs")
    room=$(_chat_room_json)
    _api_success "$(jq -c --argjson room "$room" '. + {room: $room}' <<< "$msgs")"
}

_chat_append_locked() {   # USER ROLE TEXT_JSON -> the message
    local seq now msg
    seq=$(cat "$CHAT_DIR/seq" 2>/dev/null); [[ "$seq" =~ ^[0-9]+$ ]] || seq=0
    seq=$(( seq + 1 )); now=$(date +%s)
    msg=$(jq -cn --argjson id "$seq" --argjson ts "$now" --arg u "$1" --arg r "$2" --argjson t "$3" \
        '{id: $id, ts: $ts, user: $u, role: $r, text: $t, server: null}') || exit 1
    printf '%s' "$seq" > "$CHAT_DIR/seq.tmp" && mv -f "$CHAT_DIR/seq.tmp" "$CHAT_DIR/seq"
    printf '%s\n' "$msg" >> "$CHAT_DIR/messages.jsonl"
    _chat_rotate_locked
    # the live event and the answer carry the writer's picture (the stored line does not: it is read with each answer)
    msg=$(jq -c --argjson a "$(_chat_avatar_of "$1")" '. + $a' <<< "$msg")
    _chat_live_locked "$(jq -c '{type: "message", message: .}' <<< "$msg")"
    rm -f "$CHAT_DIR/typing/$1" 2>/dev/null
    printf '%s' "$msg"
}

# POST /chat/messages — Send a message to the server's room ({"text": "…"}, 1-2000 characters of plain text; admins and users, CHAT_RATE_LIMIT a minute)
handle_chat_post() {
    local body="$1" text len msg
    _chat_gate || return
    if ! _chat_can_post; then _api_error 403 "The chat is read-only for your account on this server"; return; fi
    text=$(_chat_clean_text "$body")
    [[ -n "$text" ]] || { _api_error 400 "Send {\"text\": \"…\"} with the message"; return; }
    len=$(jq 'length' <<< "$text")
    (( len >= 1 )) || { _api_error 400 "The message is empty"; return; }
    (( len <= CHAT_MAX_LENGTH )) || { _api_error 400 "A message is at most $CHAT_MAX_LENGTH characters (this one is $len)"; return; }
    _chat_rate_take "$AUTH_USERNAME" || return
    _chat_touch
    msg=$(_chat_locked _chat_append_locked "$AUTH_USERNAME" "$AUTH_ROLE" "$text") || msg=""
    [[ "$msg" == \{* ]] || { _api_error 500 "The message could not be saved"; return; }
    _api_success "{\"message\": $msg}"
}

# rewrite one message under the lock: ID FILTER [jq args…]; prints the message after, or nothing when there is none
_chat_rewrite_locked() {
    local id="$1" filter="$2" f="$CHAT_DIR/messages.jsonl" out
    shift 2
    out=$(jq -Rnc --argjson id "$id" "$@" "[inputs | fromjson? | select(type == \"object\" and (.id | type) == \"number\")] | map(if .id == \$id then ($filter) else . end)" "$f" 2>/dev/null) || return 1
    jq -c '.[]' <<< "$out" > "$f.tmp" 2>/dev/null && chmod 600 "$f.tmp" 2>/dev/null && mv -f "$f.tmp" "$f" || return 1
    jq -c --argjson id "$id" '.[] | select(.id == $id)' <<< "$out"
}
_chat_find() { _chat_all | jq -c --argjson id "$1" '.[] | select(.id == $id)'; }

_chat_edit_locked() {   # ID TEXT_JSON NOW
    local m
    m=$(_chat_rewrite_locked "$1" '.text = $t | .edited = $now' --argjson t "$2" --argjson now "$3") || exit 1
    [[ -n "$m" ]] && _chat_live_locked "$(jq -c '{type: "edit", message: .}' <<< "$m")"
    printf '%s' "$m"
}

# PUT /chat/messages/{id} — Edit one's own message ({"text": "…"}) within 15 minutes of sending it
handle_chat_edit() {
    local id="$1" body="$2" cur owner ts text len now msg
    _chat_gate || return
    [[ "$id" =~ ^[0-9]{1,12}$ ]] || { _api_error 400 "Invalid message id"; return; }
    cur=$(_chat_find "$id")
    [[ -n "$cur" ]] || { _api_error 404 "No such message"; return; }
    owner=$(jq -r '.user' <<< "$cur"); ts=$(jq -r '.ts' <<< "$cur")
    [[ "$(jq -r '.deleted // false' <<< "$cur")" == "true" ]] && { _api_error 404 "That message was deleted"; return; }
    [[ "$owner" == "$AUTH_USERNAME" ]] || { _api_error 403 "Only the person who wrote a message can edit it"; return; }
    if ! _chat_can_post; then _api_error 403 "The chat is read-only for your account on this server"; return; fi
    now=$(date +%s)
    (( now - ts <= CHAT_EDIT_WINDOW )) || { _api_error 409 "A message can be edited for 15 minutes after it was sent"; return; }
    text=$(_chat_clean_text "$body")
    [[ -n "$text" ]] || { _api_error 400 "Send {\"text\": \"…\"} with the new text"; return; }
    len=$(jq 'length' <<< "$text")
    (( len >= 1 )) || { _api_error 400 "The message is empty: delete it instead"; return; }
    (( len <= CHAT_MAX_LENGTH )) || { _api_error 400 "A message is at most $CHAT_MAX_LENGTH characters (this one is $len)"; return; }
    _chat_rate_take "$AUTH_USERNAME" || return
    _chat_touch
    msg=$(_chat_locked _chat_edit_locked "$id" "$text" "$now") || msg=""
    [[ "$msg" == \{* ]] || { _api_error 500 "The message could not be saved"; return; }
    _api_success "{\"message\": $msg}"
}

_chat_delete_locked() {   # ID BY NOW
    local m
    m=$(_chat_rewrite_locked "$1" '.text = "" | .deleted = true | .deleted_by = $by | .deleted_at = $now' --arg by "$2" --argjson now "$3") || exit 1
    [[ -n "$m" ]] && _chat_live_locked "$(jq -c '{type: "delete", message: .}' <<< "$m")"
    printf '%s' "$m"
}

# DELETE /chat/messages/{id} — Delete a message: one's own, or any as an admin (audited, never with the text); it stays as "deleted" in the room
handle_chat_delete() {
    local id="$1" cur owner msg
    _chat_gate || return
    [[ "$id" =~ ^[0-9]{1,12}$ ]] || { _api_error 400 "Invalid message id"; return; }
    cur=$(_chat_find "$id")
    [[ -n "$cur" ]] || { _api_error 404 "No such message"; return; }
    [[ "$(jq -r '.deleted // false' <<< "$cur")" == "true" ]] && { _api_error 404 "That message was deleted already"; return; }
    owner=$(jq -r '.user' <<< "$cur")
    if [[ "$owner" != "$AUTH_USERNAME" && "${AUTH_ROLE:-}" != "admin" ]]; then
        _api_error 403 "You can delete your own messages; an admin can delete any"
        return
    fi
    _chat_touch
    msg=$(_chat_locked _chat_delete_locked "$id" "$AUTH_USERNAME" "$(date +%s)") || msg=""
    [[ "$msg" == \{* ]] || { _api_error 500 "The message could not be deleted"; return; }
    [[ "$owner" != "$AUTH_USERNAME" ]] && _audit_log "chat_message_removed" "${AUTH_USERNAME} removed message #$id by $owner from the chat room"
    _api_success "{\"message\": $msg}"
}

_chat_clear_locked() {   # BY NOW
    : > "$CHAT_DIR/messages.jsonl"
    jq -cn --arg by "$1" --argjson now "$2" '{cleared_at: $now, cleared_by: $by}' > "$CHAT_DIR/room.json.tmp" \
        && chmod 600 "$CHAT_DIR/room.json.tmp" && mv -f "$CHAT_DIR/room.json.tmp" "$CHAT_DIR/room.json"
    _chat_live_locked "$(jq -cn --arg by "$1" --argjson now "$2" '{type: "clear", by: $by, ts: $now}')"
}

# DELETE /chat/messages — Clear the room: every message goes (admin, audited)
handle_chat_clear() {
    _chat_gate || return
    if [[ "${AUTH_ROLE:-}" != "admin" ]]; then _api_error 403 "Admin access required"; return; fi
    local n now
    n=$(_chat_all | jq 'map(select(.deleted != true)) | length' 2>/dev/null || echo 0)
    now=$(date +%s)
    _chat_locked _chat_clear_locked "$AUTH_USERNAME" "$now" || { _api_error 500 "The room could not be cleared"; return; }
    _audit_log "chat_room_cleared" "${AUTH_USERNAME} cleared the chat room ($n messages)"
    _api_success "{\"success\": true, \"cleared_at\": $now, \"removed\": ${n:-0}}"
}

# GET /chat/summary — The room without its messages, for a dashboard that keeps several servers' rooms (the badge and who is online): latest_id, who is online, what the caller may do; ?after=<id> adds unread, the messages after that id from someone else and not deleted. Marks the caller as here
handle_chat_summary() {
    _chat_gate || return
    _chat_touch
    local after="${QUERY_PARAMS[after]:-}" room unread=null
    if [[ -n "$after" ]]; then
        [[ "$after" =~ ^[0-9]{1,12}$ ]] || { _api_error 400 "after is a message id"; return; }
        unread=$(_chat_all | jq --argjson a "$after" --arg me "${AUTH_USERNAME:-}" 'map(select(.id > $a and .user != $me and .deleted != true)) | length' 2>/dev/null)
        [[ "$unread" =~ ^[0-9]+$ ]] || unread=0
    fi
    room=$(_chat_room_json)
    _api_success "$(jq -c --argjson u "$unread" '{room: .} + (if $u == null then {} else {unread: $u} end)' <<< "$room")"
}

# GET /chat/presence — Who is in the room now (dashboard open in the last minute), with their role; marks the caller as here
handle_chat_presence() {
    _chat_gate || return
    _chat_touch
    _api_success "$(jq -cn --argjson o "$(_chat_online_json)" --argjson w "$(_chat_online_window)" '{online: $o, online_window: $w}')"
}

# POST /chat/typing — Tell the room the caller is typing (one live event per 3 s at most; nothing is stored)
handle_chat_typing() {
    _chat_gate || return
    if ! _chat_can_post; then _api_error 403 "The chat is read-only for your account on this server"; return; fi
    local u="$AUTH_USERNAME" f now last
    _chat_touch
    _chat_safe_name "$u" || { _api_success '{"ok": true, "sent": false}'; return; }
    f="$CHAT_DIR/typing/$u"; now=$(date +%s)
    last=$(stat -c %Y "$f" 2>/dev/null || echo 0)
    if (( now - last < 3 )); then _api_success '{"ok": true, "sent": false}'; return; fi
    : > "$f" 2>/dev/null
    _chat_live "$(jq -cn --arg u "$u" --argjson ts "$now" '{type: "typing", user: $u, ts: $ts}')"
    _api_success '{"ok": true, "sent": true}'
}

# ── the live stream ───────────────────────────────────────────────────────────
# /stream calls this once: does this client get the room's events (a person, chat on, not a VM)
_chat_stream_wanted() {
    _chat_enabled || return 1
    [[ "${AUTH_VIA_KEY:-}" == "true" ]] && return 1
    [[ "${AUTH_ROLE:-}" == "admin" || "${AUTH_ROLE:-}" == "user" ]] || return 1
    if declare -F _fleet_is_member >/dev/null && _fleet_is_member; then return 1; fi
    _chat_init
}
