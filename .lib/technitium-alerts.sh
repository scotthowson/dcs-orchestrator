#!/bin/bash
# shellcheck shell=bash
# =============================================================================
# Technitium's safety net — what DCS watches and keeps for the home's resolvers
#
# Alerts: from the minute clock (_tta_tick, in the background so a server that does not answer never holds the clock
# up), each raised once and cleared when it is over, through the notification rules (Discord, ntfy) and the activity
# log: a server not answering (two checks in a row), the two out of step (fingerprints different for 10 minutes and a
# sync that failed), blocklists not updated for 48 hours or failing, the DHCP pool over 80 %, a device seen for the
# first time (one digest when more than 5 come at once), and three that are off by default (a kids' group entering or
# leaving bedtime, a device's block running out, the weekly digest of each kids' group and the house). Their rules are made once, the first time the clock runs, so they
# show (and switch) on the Notifications page like every other event.
#
# What /dns/technitium/status adds per server (_tta_more): the version and whether Technitium has a newer one
# (/api/user/checkForUpdate, asked every 6 hours), each blocklist's health (entries, last update, error: read from
# Technitium's own log, which is the only place it says per list) and the DHCP pool (the primary's scopes and leases).
#
# Backups: Technitium's own zip (GET /api/settings/backup: settings, zones, allowed and blocked names, DHCP scopes, the
# log settings; not its accounts and tokens, the logs, the stats, the downloaded lists or the apps, which are big and come
# back by themselves) of each server into .data/technitium/backups/<server>-<date>.zip, nightly (TECHNITIUM_BACKUP_HOUR, 3 by
# default, "off" = never) and on demand; 14 kept per server. Next to each zip a .json says what the zip leaves out and a
# restore puts back: the blocklist addresses and the apps with their configs. A restore (POST /api/settings/restore)
# leaves the server's own accounts and tokens as they are, so DCS stays connected.
#
# State: .data/technitium/alerts.json (its own file: technitium.sh owns state.json). Loaded with technitium.sh
# (_technitium_lib in api-server.sh).
# =============================================================================

TTA_STATE="$TT_DIR/alerts.json"
TTA_BACKUPS="$TT_DIR/backups"
TTA_KEEP=14
TTA_DOWN_AFTER=2          # minute checks in a row
TTA_SYNC_AFTER=600        # seconds the two may differ before a sync is tried (and, if it fails, said)
TTA_STALE_AFTER=172800    # 48 hours without a blocklist update
TTA_POOL_PCT=80
TTA_DIGEST_OVER=5         # more new devices than this at once: one message
TTA_UPDATE_EVERY=21600    # Technitium's update check, every 6 hours
TTA_LISTS_EVERY=120       # the list health read from Technitium's log, at most every 2 minutes
TTA_BACKUP_RE='^(primary|secondary)-[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{4}\.zip$'
# what Technitium's backup zip holds (and a restore brings back); the blocklists' URLs and the apps travel in the .json. Never its
# accounts (authConfig): they hold its sessions and API tokens, which have no place in a file that goes into DCS's backups, and a
# restore must leave the server's own accounts alone so DCS's token keeps working
TTA_PARTS='blockLists=false&logs=false&scopes=true&apps=false&stats=false&zones=true&allowedZones=true&blockedZones=true&dnsSettings=true&logSettings=true&authConfig=false'
# the events, the rule each gets the first time (on or off), its priority and its name on the Notifications page
TTA_RULES='[
 {"trigger":"technitium_down","enabled":true,"priority":"high","name":"Technitium: a server stopped answering"},
 {"trigger":"technitium_out_of_sync","enabled":true,"priority":"default","name":"Technitium: the secondary is out of step"},
 {"trigger":"technitium_lists_stale","enabled":true,"priority":"default","name":"Technitium: blocklists not updating"},
 {"trigger":"technitium_dhcp_pool","enabled":true,"priority":"high","name":"Technitium: DHCP pool nearly full"},
 {"trigger":"technitium_new_device","enabled":true,"priority":"high","name":"Technitium: a new device on the network"},
 {"trigger":"technitium_bedtime","enabled":false,"priority":"low","name":"Technitium: a group entered or left bedtime"},
 {"trigger":"technitium_device_blocked_expired","enabled":false,"priority":"low","name":"Technitium: a device block ran out"},
 {"trigger":"technitium_weekly_digest","enabled":false,"priority":"low","name":"Technitium: the week of each kids group and the house"}]'

_tta_state() { _api_state_file "$TTA_STATE" '{}' object >/dev/null 2>&1 || true; jq -c . "$TTA_STATE" 2>/dev/null || printf '{}'; }
_tta_set() { mkdir -p "$TT_DIR" 2>/dev/null; _api_state_file "$TTA_STATE" '{}' object >/dev/null 2>&1 || true; _api_jq_update_file "$TTA_STATE" "$@" || true; }

# _tta_curl ROLE PATH OUT [curl args…]: one raw call (a zip, a log) with the token on curl's standard input. TT_CODE, and TT_ERR
# (Technitium's own message when it answered JSON instead of the file); 0 on a 200 that is not an error.
_tta_curl() {
    local role="$1" p="$2" out="$3" url tok st
    shift 3
    TT_CODE=000; TT_ERR=""
    _tt_tok_load "$role"; url=$(_tt_url "$role"); tok="${TT_TOK[$role]}"
    [[ -n "$url" && -n "$tok" ]] || { TT_ERR="The $role Technitium is not connected"; return 1; }
    TT_CODE=$(printf 'header = "Authorization: Bearer %s"\n' "$tok" | curl -s --connect-timeout 3 --max-time "${TT_CALL_TIMEOUT:-60}" -K - -o "$out" -w '%{http_code}' "$@" "$url/api/$p" 2>/dev/null) || true
    [[ "$TT_CODE" =~ ^[0-9]{3}$ ]] || TT_CODE=000
    [[ "$TT_CODE" == 000 ]] && { TT_ERR="The $role Technitium ($url) did not answer"; return 1; }
    # an error is JSON ({"status": "error" | "invalid-token", …}); a file is not
    if [[ "$(head -c 1 "$out" 2>/dev/null)" == "{" ]] && st=$(jq -r '.status // empty' "$out" 2>/dev/null) && [[ -n "$st" && "$st" != ok ]]; then
        TT_ERR="The $role Technitium said: $(jq -r '.errorMessage // .status' "$out" 2>/dev/null)"; return 1
    fi
    [[ "$TT_CODE" == 200 ]] || { TT_ERR="The $role Technitium answered HTTP $TT_CODE"; return 1; }
}

# =============================================================================
# What the status adds per server
# =============================================================================

# _tta_lists ROLE SETTINGS NOW → {lists: [{url, entries, last_updated, error}], total, updated_at, per_list, note}. Technitium says per list
# only in its log ("read block list file (N domain(s) blocked) from: URL", "successfully downloaded block list", "failed to download block
# list …" with the reason on the next line): the last three days of it are read. The total is the dashboard's blockListZones.
_tta_lists() {
    local role="$1" s="$2" now="$3" urls total=null files f log
    urls=$(jq -c '.blockListUrls // []' <<< "$s")
    _tt_api "$role" dashboard/stats/get type=LastHour utc=true && total=$(jq -c '.response.stats.blockListZones // null' <<< "$TT_BODY")
    log=$(mktemp "${TMPDIR:-/tmp}/dcs-tta-log-XXXXXX") || return 1
    if [[ "$urls" != '[]' ]] && _tt_api "$role" logs/list; then
        files=$(jq -r '[.response.logFiles // [] | .[].fileName] | sort | reverse | .[0:3] | .[]' <<< "$TT_BODY" 2>/dev/null)
        for f in $files; do
            [[ "$f" =~ ^[A-Za-z0-9_.-]{1,64}$ ]] || continue
            TT_CALL_TIMEOUT=10 _tta_curl "$role" "logs/download?fileName=$f&limit=1" "$log.part" && cat "$log.part" >> "$log"
        done
        rm -f "$log.part"
    fi
    # shellcheck disable=SC2016
    jq -R -s -c --argjson urls "$urls" --argjson total "$total" --argjson s "$s" --argjson now "$now" '
        def ts: (capture("^\\[(?<d>[0-9]{4}-[0-9]{2}-[0-9]{2}) (?<t>[0-9]{2}:[0-9]{2}:[0-9]{2})") | "\(.d)T\(.t)Z") // null;
        def url: (capture(": (?<u>https?://[^ \r]+)[ \r]*$").u) // null;
        def epoch: if . == null then null else (sub("\\.[0-9]+"; "") | try fromdateiso8601 catch null) end;
        (split("\n")) as $l
        | [range(0; $l | length) as $i | $l[$i] as $x
           | if ($x | test("DNS Server successfully (downloaded block list|checked for a new update of the block list)")) then {u: ($x | url), k: "ok", at: ($x | ts)}
             elif ($x | test("DNS Server failed to download block list")) then {u: ($x | url), k: "err", at: ($x | ts),
                  e: (($l[$i + 1] // "") | sub("^[A-Za-z0-9_.]*Exception: "; "") | sub("[ \r]+$"; "") | .[0:200])}
             elif ($x | test("DNS Server read block list file \\(")) then {u: ($x | url), k: "read", at: ($x | ts), n: ($x | capture("\\((?<n>[0-9]+) domain").n | tonumber)}
             else empty end | select(.u != null)] as $ev
        # Technitium plans the next update when one ran: the one before it is the plan minus the interval
        | (($s.blockListNextUpdatedOn | epoch) as $n | if $n == null or ($urls | length) == 0 then null else $n - (($s.blockListUpdateIntervalHours // 24) * 3600) end) as $planned
        | [$urls[] as $u | [$ev[] | select(.u == $u)] as $e
           | ([$e[] | select(.k == "ok") | .at] | max) as $ok | ([$e[] | select(.k == "err")] | max_by(.at)) as $err
           | {url: $u, entries: ([$e[] | select(.k == "read")] | max_by(.at) | .n // null), last_updated: $ok,
              error: (if $err != null and ($ok == null or $err.at > $ok) then (if ($err.e // "") == "" then "The last download failed" else $err.e end) else null end)}] as $lists
        | ([$lists[].last_updated | epoch | select(. != null)] + (if $planned != null and $planned <= $now then [$planned] else [] end) | max) as $up
        | {lists: $lists, total: $total, per_list: any($lists[]; .entries != null),
           updated_at: (if $up == null then null else ($up | todate) end),
           note: (if ($lists | length) > 0 and (any($lists[]; .entries != null) | not)
                  then "Technitium logs each list as it reads it; nothing about these lists is in its log of the last three days, so only the total is known" else null end)}' "$log"
    rm -f "$log"
}

# the primary's DHCP: {enabled, leases, pool_size, pct} over its scopes that are on (the addresses of their ranges, less the exclusions)
_tta_dhcp() {
    local leases
    _tt_scopes || return 1
    _tt_api primary dhcp/leases/list || return 1
    leases=$(jq -c '.response.leases // []' <<< "$TT_BODY")
    jq -c -n --argjson sc "$TT_SCOPES" --argjson l "$leases" "$TT_IP4_JQ"'
        def size: (.endingAddress | ip2n) - (.startingAddress | ip2n) + 1;
        [$sc[] | select(.enabled == true) | . as $s
         | {pool: (size - ([.exclusions // [] | .[] | (.endingAddress | ip2n) - (.startingAddress | ip2n) + 1] | add // 0)),
            used: ([$l[] | select(.scope == $s.name and (.address | ip4ok) and (.address | ip2n) >= ($s.startingAddress | ip2n) and (.address | ip2n) <= ($s.endingAddress | ip2n))] | length)}] as $on
        | ($on | map(.pool) | add // 0) as $pool | ($on | map(.used) | add // 0) as $used
        | {enabled: (($on | length) > 0), leases: (if ($on | length) > 0 then $used else ($l | length) end), pool_size: $pool,
           pct: (if $pool > 0 then (($used * 100 / $pool) | round) else null end)}'
}

# Technitium's own update check (it asks technitium.com), kept 6 hours in alerts.json → {available, version, current, at}
_tta_update() {
    local role="$1" now="$2" have
    have=$(jq -c --arg r "$role" '.updates[$r] // empty' <<< "$(_tta_state)")
    if [[ -n "$have" ]] && (( now - $(jq -r '.at // 0' <<< "$have") < TTA_UPDATE_EVERY )); then printf '%s' "$have"; return 0; fi
    TT_CALL_TIMEOUT=15 _tt_api "$role" user/checkForUpdate || { [[ -n "$have" ]] && printf '%s' "$have"; return 0; }
    have=$(jq -c --argjson now "$now" '.response | {available: (.updateAvailable == true), version: (.updateVersion // null), current: (.currentVersion // null),
        checks: (.dnsServerEnableCheckForUpdate != false), at: $now}' <<< "$TT_BODY")
    _tta_set --arg r "$role" --argjson u "$have" '.updates[$r] = $u'
    printf '%s' "$have"
}

# _tta_more INSTANCE: the instance's status (technitium.sh) with what the safety net adds: update_available, update_version, lists
# ({lists, total, updated_at, per_list, note}), dhcp (the primary's). The list health is read again at most every 2 minutes.
_tta_more() {
    local inst="$1" role now s urls lists up dhcp=null cache
    role=$(jq -r '.role' <<< "$inst")
    [[ "$(jq -r '.reachable' <<< "$inst")" == true ]] || { printf '%s' "$inst"; return 0; }
    now=$(_tt_now)
    _tt_api "$role" settings/get || { printf '%s' "$inst"; return 0; }
    s=$(jq -c '.response' <<< "$TT_BODY"); urls=$(jq -c '.blockListUrls // []' <<< "$s")
    cache=$(jq -c --arg r "$role" '.lists[$r] // empty' <<< "$(_tta_state)")
    if [[ -n "$cache" ]] && (( now - $(jq -r '.at // 0' <<< "$cache") < TTA_LISTS_EVERY )) && [[ "$(jq -c '.urls' <<< "$cache")" == "$urls" ]]; then
        lists=$(jq -c '.v' <<< "$cache")
    else
        lists=$(_tta_lists "$role" "$s" "$now") || lists='{"lists":[],"total":null}'
        _tta_set --arg r "$role" --argjson v "$lists" --argjson now "$now" --argjson u "$urls" '.lists[$r] = {at: $now, urls: $u, v: $v}'
    fi
    up=$(_tta_update "$role" "$now"); [[ -n "$up" ]] || up=null
    [[ "$role" == primary ]] && { dhcp=$(_tta_dhcp) || dhcp=null; }
    jq -c --argjson l "$lists" --argjson u "$up" --argjson d "$dhcp" \
        '. + {update_available: ($u.available // false), update_version: (if $u.available == true then $u.version else null end), lists: $l, dhcp: $d}' <<< "$inst"
}

# the alerts in force, for the status (and the dashboard's "Needs your attention")
_tta_active() { jq -c '[.active // {} | to_entries[] | .value + {key: .key}] | sort_by(.since)' <<< "$(_tta_state)"; }

# =============================================================================
# Raising and clearing
# =============================================================================

# _tta_raise KEY EVENT SERVER HEADLINE MESSAGE ACTION: once per KEY until it is cleared (audit line, notification, alerts.json)
_tta_raise() {
    local key="$1" ev="$2" srv="$3" head="$4" msg="$5" act="${6:-}"
    jq -e --arg k "$key" '.active[$k] != null' >/dev/null <<< "$(_tta_state)" && return 0
    _tta_set --arg k "$key" --arg e "$ev" --arg s "$srv" --arg h "$head" --arg m "$msg" --arg a "$act" --argjson now "$(_tt_now)" \
        '.active[$k] = {event: $e, server: (if $s == "" then null else $s end), headline: $h, message: $m, action: (if $a == "" then null else $a end), since: $now}'
    _audit_log "$ev" "$head: $msg" 2>/dev/null
    _fire_notifications "$ev" ${srv:+"server=$srv"} "headline=$head" "message=$msg" "status=raised" "fingerprint=$key" 2>/dev/null
    return 0
}
# _tta_clear KEY HEADLINE MESSAGE: the alert is over (said once, when it was raised)
_tta_clear() {
    local key="$1" head="$2" msg="$3" a ev srv
    a=$(jq -c --arg k "$key" '.active[$k] // empty' <<< "$(_tta_state)")
    [[ -n "$a" ]] || return 0
    ev=$(jq -r .event <<< "$a"); srv=$(jq -r '.server // empty' <<< "$a")
    _tta_set --arg k "$key" 'del(.active[$k])'
    _audit_log "$ev" "$head: $msg" 2>/dev/null
    _fire_notifications "$ev" ${srv:+"server=$srv"} "headline=$head" "message=$msg" "status=resolved" "fingerprint=$key" 2>/dev/null
    return 0
}

# the events' rules, each made once (the five that matter on; bedtime, a block running out and the weekly digest off): the
# Notifications page lists and switches them, and a rule deleted there stays deleted (rules_seeded: the events seeded already;
# true from before the list: the first seven)
_tta_seed_rules() {
    local seeded
    seeded=$(jq -c --argjson r "$TTA_RULES" 'if .rules_seeded == true then [$r[:7][].trigger] else (.rules_seeded // []) end' <<< "$(_tta_state)")
    jq -e --argjson r "$TTA_RULES" --argjson d "$seeded" '[$r[].trigger] - $d | length == 0' >/dev/null <<< '{}' && return 0
    _init_notifications_file 2>/dev/null
    _api_jq_update_file "$NOTIFICATIONS_FILE" --argjson r "$TTA_RULES" --argjson d "$seeded" --arg ts "$(_api_now_iso)" '
        (.rules // []) as $have
        | .rules = $have + [$r[] | select(.trigger as $t | ($have | any(.trigger == $t) | not) and ($d | index($t) | not))
            | {id: ("rule_" + .trigger), name, enabled, trigger, target: "*", priority, tags: ["technitium"], title_template: "", message_template: "",
               cooldown_minutes: null, created_at: $ts}]' || return 0
    _tta_set --argjson r "$TTA_RULES" '.rules_seeded = [$r[].trigger]'
}

# =============================================================================
# The minute clock
# =============================================================================

_tta_tick() {
    _tt_configured primary || return 0
    mkdir -p "$TT_DIR" 2>/dev/null || true
    # one at a time: a tick that waits for a server that does not answer is not stacked under the next
    { flock -n 8 || return 0; _tta_tick_locked; } 8>"$TT_DIR/.alerts.lock"
}
_tta_tick_locked() {
    local now role inst more st url fails
    local -A INST=()
    now=$(_tt_now)
    _tta_seed_rules
    for role in $(_tt_roles); do
        inst=$(_tt_instance_status "$role"); url=$(jq -r '.url' <<< "$inst")
        if [[ "$(jq -r '.reachable' <<< "$inst")" == true ]]; then
            _tta_set --arg r "$role" '.down[$r] = 0'
            _tta_clear "technitium_down:$role" "The $role Technitium answers again" "$url answers DCS again."
            more=$(_tta_more "$inst"); INST[$role]="$more"
            _tta_check_lists "$role" "$more" "$now"
            [[ "$role" == primary ]] && _tta_check_pool "$more"
        else
            fails=$(jq -r --arg r "$role" '(.down[$r] // 0) + 1' <<< "$(_tta_state)")
            _tta_set --arg r "$role" --argjson n "$fails" '.down[$r] = $n'
            (( fails >= TTA_DOWN_AFTER )) && _tta_raise "technitium_down:$role" technitium_down "$role" "The $role Technitium is not answering" \
                "$url has not answered DCS for $fails minutes: $(jq -r '.error // "no answer"' <<< "$inst")$([[ "$role" == primary ]] && printf ' Devices fall back to the secondary until it is back.')" page
        fi
    done
    _tta_check_sync "${INST[primary]:-}" "${INST[secondary]:-}" "$now"
    _tta_check_devices "$now"
    _tta_check_bedtime
    _tta_check_blocks "$now"
    _tta_check_digest "$now"
    _tta_backup_nightly "$now"
    _tta_set --argjson now "$now" '.last_tick = $now'
    return 0
}

_tta_check_lists() {
    local role="$1" more="$2" now="$3" v why=""
    v=$(jq -c '.lists // {}' <<< "$more")
    if [[ "$(jq -r '(.lists // []) | length' <<< "$v")" == 0 ]]; then _tta_clear "technitium_lists_stale:$role" "The $role Technitium's blocklists are fine" "It has no blocklists now."; return 0; fi
    why=$(jq -r --argjson now "$now" --argjson max "$TTA_STALE_AFTER" '
        ([.lists[] | select(.error != null)]) as $bad
        | if ($bad | length) > 0 then
            "\($bad | length) of its \(.lists | length) blocklists could not be updated: " + ($bad | map(.url + " (" + .error + ")") | join("; "))
          elif .updated_at != null and ($now - (.updated_at | fromdateiso8601)) > $max then
            "its blocklists were last updated \((($now - (.updated_at | fromdateiso8601)) / 3600) | floor) hours ago (they update every day)"
          else "" end' <<< "$v")
    if [[ -n "$why" ]]; then
        _tta_raise "technitium_lists_stale:$role" technitium_lists_stale "$role" "The $role Technitium's blocklists are out of date" \
            "${why^}. Update the lists now from the Technitium page (Lists), and check that the server can reach the lists' addresses." lists
    else
        _tta_clear "technitium_lists_stale:$role" "The $role Technitium's blocklists are up to date again" "Every blocklist updated."
    fi
}

_tta_check_pool() {
    local d pct
    d=$(jq -c '.dhcp // empty' <<< "$1"); [[ -n "$d" ]] || return 0
    pct=$(jq -r '.pct // empty' <<< "$d")
    if [[ "$(jq -r .enabled <<< "$d")" == true && "$pct" =~ ^[0-9]+$ ]] && (( pct > TTA_POOL_PCT )); then
        _tta_raise technitium_dhcp_pool technitium_dhcp_pool primary "The DHCP pool is nearly full" \
            "$(jq -r '"\(.leases) of its \(.pool_size) addresses are given out (\(.pct) %)"' <<< "$d"): a new device may get no address. Widen the scope or shorten the leases (Technitium page → DHCP)." dhcp
    else
        _tta_clear technitium_dhcp_pool "The DHCP pool has room again" "$(jq -r 'if .enabled then "\(.leases) of \(.pool_size) addresses in use" else "DHCP is off on the primary" end' <<< "$d")."
    fi
}

# both answer and their fingerprints differ: after 10 minutes one sync is tried (every 10 minutes); when it fails, it is said
_tta_check_sync() {
    local p="$1" s="$2" now="$3" since tried
    [[ -n "$p" && -n "$s" ]] || return 0
    if [[ "$(jq -r .hash <<< "$p")" == "$(jq -r .hash <<< "$s")" ]]; then
        _tta_set '.sync = {}'
        _tta_clear technitium_out_of_sync "The two Technitium servers are in step again" "The secondary has what the primary has."
        return 0
    fi
    since=$(jq -r --argjson now "$now" '.sync.differ_since // $now' <<< "$(_tta_state)")
    tried=$(jq -r '.sync.tried // 0' <<< "$(_tta_state)")
    _tta_set --argjson s "$since" '.sync.differ_since = $s'
    (( now - since > TTA_SYNC_AFTER && now - tried >= TTA_SYNC_AFTER )) || return 0
    _tta_set --argjson now "$now" '.sync.tried = $now'
    if _tt_sync; then
        _tta_set '.sync = {}'
        _audit_log technitium_sync "the secondary differed from the primary for $(( (now - since) / 60 )) minutes: synced" 2>/dev/null
    else
        _tta_raise technitium_out_of_sync technitium_out_of_sync "" "The secondary Technitium is out of step" \
            "It has differed from the primary for $(( (now - since) / 60 )) minutes and the sync failed: $TT_SYNC_MSG" sync
    fi
}

# a device of the directory (with a MAC: the LAN saw it) that was never seen before; the first look only learns what is there
_tta_check_devices() {
    local now="$1" known new n link lines msg
    [[ -s "$TT_DEVICES" ]] && jq -e '.last_scan != null' "$TT_DEVICES" >/dev/null 2>&1 || return 0
    known=$(jq -c '.known_devices // null' <<< "$(_tta_state)")
    if [[ "$known" == null ]]; then
        _tta_set --argjson k "$(jq -c '[.devices[]? | .id]' "$TT_DEVICES")" '.known_devices = $k'
        return 0
    fi
    new=$(jq -c --argjson k "$known" '[.devices[]? | select(.mac != null and (.hub // false) != true and (.id as $i | $k | index($i) | not))]' "$TT_DEVICES") || return 0
    n=$(jq 'length' <<< "$new")
    (( n > 0 )) || return 0
    _tta_set --argjson ids "$(jq -c 'map(.id)' <<< "$new")" '.known_devices = ((.known_devices // []) + $ids | unique | .[-5000:])'
    link=$(_dashboard_public_url 2>/dev/null); [[ -n "$link" ]] && link="$link/#/technitium/devices"
    # "Samsung (a4:c3:…), 192.168.2.142, named galaxy-s24 by DHCP"
    lines=$(jq -r '.[] | .mac + "\t" + "\(.vendor // "Unknown vendor") (\(.mac)), \(.ip // "no address yet"), "
        + (if .hostname == null then "no name yet"
           else "named \(.hostname) " + (if (.sources.dhcp // null) != null then "by DHCP" elif (.sources.mdns // null) != null then "over mDNS" else "by reverse DNS" end) end)' <<< "$new")
    if (( n > TTA_DIGEST_OVER )); then
        msg="$n new devices on the network: $(head -n 10 <<< "$lines" | cut -f2 | paste -sd ';' - | sed 's/;/; /g')"
        (( n <= 10 )) || msg+="; and $((n - 10)) more"
        msg+="."
        _audit_log technitium_new_device "$msg" 2>/dev/null
        _fire_notifications technitium_new_device "headline=$n new devices on the network" "message=$msg${link:+ Devices: $link}" ${link:+"link=$link"} "status=new" "fingerprint=digest-$now" 2>/dev/null
        return 0
    fi
    local mac
    while IFS=$'\t' read -r mac msg; do
        [[ -n "$msg" ]] || continue
        _audit_log technitium_new_device "New device on the network: $msg" 2>/dev/null
        _fire_notifications technitium_new_device "headline=New device on the network" "message=New device on the network: $msg.${link:+ Devices: $link}" ${link:+"link=$link"} \
            "status=new" "fingerprint=$mac" 2>/dev/null
    done <<< "$lines"
}

# a kids' group that went into or out of bedtime since the last look (technitium.sh's clock moved it; off by default)
_tta_check_bedtime() {
    local active seen names g name
    active=$(jq -c '.bedtime_active // []' <<< "$(_tt_state)")
    seen=$(jq -c '.bedtime_seen // null' <<< "$(_tta_state)")
    # the groups' names, kept: a group deleted while in bedtime is still named when it leaves it
    names=$(jq -c --argjson k "$(jq -c '.group_names // {}' <<< "$(_tta_state)")" '$k + {house: "House"} + ([.groups[] | {key: .id, value: .name}] | from_entries)' <<< "$(_tt_model)")
    _tta_set --argjson a "$active" --argjson n "$names" '.bedtime_seen = $a | .group_names = $n'
    [[ "$seen" != null && "$seen" != "$active" ]] || return 0
    while IFS=$'\t' read -r g name; do
        [[ -n "$g" ]] || continue
        if jq -e --arg g "$g" 'index($g) != null' >/dev/null <<< "$active"; then
            _fire_notifications technitium_bedtime "group=$name" "headline=$name: bedtime" "message=$name entered bedtime: every name is blocked for its devices." "status=started" 2>/dev/null
        else
            _fire_notifications technitium_bedtime "group=$name" "headline=$name: bedtime is over" "message=$name left bedtime: its devices browse as usual again." "status=ended" 2>/dev/null
        fi
    done < <(jq -r -n --argjson a "$active" --argjson w "$seen" --argjson n "$names" '(($a - $w) + ($w - $a))[] | [., ($n[.] // .)] | @tsv')
}

# a device blocked by hand whose time ran out (a block lifted by hand or moved is not "ran out"; off by default)
_tta_check_blocks() {
    local now="$1" seen cur name
    [[ -s "$TT_DEVICES" ]] || return 0
    seen=$(jq -c '.blocked_seen // {}' <<< "$(_tta_state)")
    cur=$(jq -c --argjson now "$now" '[.devices[]? | select((.blocked_until // 0) > $now) | {key: .id, value: .blocked_until}] | from_entries' "$TT_DEVICES")
    while IFS= read -r name; do
        [[ -n "$name" ]] || continue
        _fire_notifications technitium_device_blocked_expired "device=$name" "headline=$name can browse again" "message=The block on $name ran out: it browses as usual again." "status=ended" 2>/dev/null
    done < <(jq -r --argjson s "$seen" --argjson now "$now" '.devices[]? | select(.id as $i | $s[$i] != null and (.blocked_until // 0) == $s[$i] and $s[$i] <= $now)
        | (.nickname // .hostname // .ip // .id)' "$TT_DEVICES")
    _tta_set --argjson c "$cur" '.blocked_seen = $c'
}

# the weekly digest (technitium_weekly_digest, off by default: nothing is asked of Technitium while its rule is off): on Monday
# from 08:00 (local time) to the next morning, once, one message per kids' group and one for the house (_tt_digest)
_tta_check_digest() {
    local now="${1:-$(_tt_now)}" dow mon out name head msg
    jq -e '[.rules[]? | select(.trigger == "technitium_weekly_digest" and .enabled == true)] | length > 0' "$NOTIFICATIONS_FILE" >/dev/null 2>&1 || return 0
    dow=$(date -d "@$now" +%u)
    mon=$(( now - (dow - 1) * 86400 - 10#$(date -d "@$now" +%H) * 3600 - 10#$(date -d "@$now" +%M) * 60 - 10#$(date -d "@$now" +%S) + 8 * 3600 ))
    (( now >= mon && now < mon + 86400 )) || return 0
    (( $(jq -r '.digest_at // 0' <<< "$(_tta_state)") < mon )) || return 0
    _tta_set --argjson now "$now" '.digest_at = $now'
    out=$(_tt_digest "$now") || return 0
    while IFS=$'\t' read -r name head msg; do
        [[ -n "$name" ]] || continue
        _fire_notifications technitium_weekly_digest "group=$name" "headline=$head" "message=$msg" "status=digest" "fingerprint=digest-$name-$mon" 2>/dev/null
    done < <(jq -r '.[] | [.name, .headline, .message] | @tsv' <<< "$out")
}

# =============================================================================
# Backups
# =============================================================================

# _tta_backup ROLE: Technitium's zip and DCS's note next to it; 14 kept. TTA_FILE is the zip's name, TT_ERR why not.
TTA_FILE=""
_tta_backup() {
    local role="$1" now name tmp s apps='[]' a cfg
    TTA_FILE=""
    _tt_configured "$role" || { TT_ERR="The $role Technitium is not connected"; return 1; }
    (umask 077; mkdir -p "$TTA_BACKUPS") || { TT_ERR="Cannot write $TTA_BACKUPS"; return 1; }
    now=$(_tt_now); name="$role-$(date -d "@$now" +%Y-%m-%d_%H%M).zip"
    tmp="$TTA_BACKUPS/.$name.partial"
    if ! TT_CALL_TIMEOUT=120 _tta_curl "$role" "settings/backup?$TTA_PARTS" "$tmp"; then rm -f "$tmp"; return 1; fi
    if [[ "$(head -c 4 "$tmp" | xxd -p 2>/dev/null)" != 504b0304 ]]; then rm -f "$tmp"; TT_ERR="The $role Technitium's answer is not a zip"; return 1; fi
    _tt_api "$role" settings/get || { rm -f "$tmp"; return 1; }
    s=$(jq -c '.response' <<< "$TT_BODY")
    if _tt_api "$role" apps/list; then
        while IFS= read -r a; do
            [[ -n "$a" ]] || continue
            cfg=""; _tt_app_config "$role" "$a" && cfg="$TT_CFG"
            apps=$(jq -c --arg n "$a" --arg c "$cfg" '. + [{name: $n, config: (if $c == "" then null else ($c | fromjson) end)}]' <<< "$apps")
        done < <(jq -r '.response.apps // [] | .[].name' <<< "$TT_BODY")
    fi
    jq -n --arg r "$role" --arg f "$name" --argjson s "$s" --argjson apps "$apps" --argjson now "$now" --argjson b "$(stat -c %s "$tmp")" \
        '{server: $r, file: $f, created_at: ($now | todate), bytes: $b, version: $s.version, domain: $s.dnsServerDomain,
          block_list_urls: ($s.blockListUrls // []), block_list_update_hours: ($s.blockListUpdateIntervalHours // 24), apps: $apps}' > "$TTA_BACKUPS/${name%.zip}.json" \
        || { rm -f "$tmp"; TT_ERR="Cannot write $TTA_BACKUPS"; return 1; }
    mv -f "$tmp" "$TTA_BACKUPS/$name"
    chmod 600 "$TTA_BACKUPS/$name" "$TTA_BACKUPS/${name%.zip}.json" 2>/dev/null
    # the newest 14 of this server stay
    find "$TTA_BACKUPS" -maxdepth 1 -type f -name "$role-*.zip" -printf '%f\n' 2>/dev/null | grep -E "$TTA_BACKUP_RE" | sort | head -n -"$TTA_KEEP" \
        | while IFS= read -r a; do rm -f -- "${TTA_BACKUPS:?}/$a" "${TTA_BACKUPS:?}/${a%.zip}.json"; done
    TTA_FILE="$name"
}

# every connected server → {files: [...], errors: [...]}
_tta_backup_all() {
    local role files='[]' errs='[]'
    for role in $(_tt_roles); do
        if _tta_backup "$role"; then files=$(jq -c --arg f "$TTA_FILE" '. + [$f]' <<< "$files")
        else errs=$(jq -c --arg r "$role" --arg e "$TT_ERR" '. + [{server: $r, error: $e}]' <<< "$errs"); fi
    done
    jq -nc --argjson f "$files" --argjson e "$errs" '{files: $f, errors: $e}'
}

# once a day at TECHNITIUM_BACKUP_HOUR (local time, 3 by default; off = never); a failure is tried again twice, 30 minutes apart, and said
_tta_backup_nightly() {
    local now="${1:-$(_tt_now)}" hour today st r
    hour=$(envfile_get "$BASE_DIR/.env" TECHNITIUM_BACKUP_HOUR 2>/dev/null) || hour=""
    [[ "$hour" == off ]] && return 0
    [[ "$hour" =~ ^([01]?[0-9]|2[0-3])$ ]] || hour=3
    (( 10#$(date -d "@$now" +%H) >= 10#$hour )) || return 0
    today=$(date -d "@$now" +%F)
    st=$(jq -c '.backup // {}' <<< "$(_tta_state)")
    jq -e --arg d "$today" --argjson n "$now" '.day == $d and (.done == true or (.tries // 0) >= 3 or $n < (.next // 0))' >/dev/null <<< "$st" && return 0
    r=$(_tta_backup_all)
    if [[ "$(jq '.errors | length' <<< "$r")" == 0 ]]; then
        _tta_set --arg d "$today" --argjson r "$r" --argjson now "$now" '.backup = {day: $d, done: true, at: $now, files: $r.files}'
        _audit_log technitium_backup "Technitium backed up: $(jq -r '.files | join(", ")' <<< "$r")" 2>/dev/null
    else
        _tta_set --arg d "$today" --argjson now "$now" --argjson r "$r" \
            '.backup = (if (.backup.day // "") == $d then .backup else {day: $d, tries: 0} end) | .backup.tries += 1 | .backup.next = ($now + 1800) | .backup.errors = $r.errors'
        _audit_log backup_failed "Technitium backup: $(jq -r '.errors | map(.error) | join("; ")' <<< "$r")" 2>/dev/null
        _fire_notifications backup_failed "status=failed" "message=Technitium's nightly backup failed: $(jq -r '.errors | map(.error) | join("; ")' <<< "$r")" 2>/dev/null
    fi
}

# =============================================================================
# Handlers
# =============================================================================

# POST /dns/technitium/backup — Back up every connected Technitium now: its own zip (settings, zones, allowed and blocked names, DHCP scopes; not its accounts and tokens, the logs, the stats, the downloaded lists or the apps) into .data/technitium/backups/<server>-<date>.zip, with a note of the blocklists and the apps' configs; 14 kept per server
handle_technitium_backup() {
    _api_check_admin || { _api_error 403 "Admin access required"; return; }
    _tt_need_primary || return
    local r
    r=$(_tta_backup_all)
    _api_audit_log "${CLIENT_IP:-unknown}" "TECHNITIUM_BACKUP" "${AUTH_USERNAME:-}" "$(jq -r '"made: " + (.files | join(", ")) + (if (.errors | length) > 0 then "; failed: " + (.errors | map(.server) | join(", ")) else "" end)' <<< "$r")"
    if [[ "$(jq '.files | length' <<< "$r")" == 0 ]]; then _api_error 502 "$(jq -r '.errors | map(.error) | join("; ")' <<< "$r")"; return; fi
    _api_success "$(jq -c '{success: true} + . + {message: ("Backed up: " + (.files | join(", ")))}' <<< "$r")"
}

# GET /dns/technitium/backups — The Technitium backups kept in .data/technitium/backups, newest first: the server, the file, when, its size, the Technitium version and what the note next to it holds (blocklists, apps); the nightly hour
handle_technitium_backups() {
    local f list='[]' hour
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        list=$(jq -c --arg f "$f" --argjson b "$(stat -c %s "$TTA_BACKUPS/$f" 2>/dev/null || echo 0)" --argjson n "$(jq -c . "$TTA_BACKUPS/${f%.zip}.json" 2>/dev/null || echo null)" \
            '. + [{file: $f, server: ($f | split("-")[0]), bytes: $b, created_at: ($n.created_at // null), version: ($n.version // null), domain: ($n.domain // null),
                   block_lists: (($n.block_list_urls // []) | length), apps: [($n.apps // [])[].name]}]' <<< "$list")
    done < <(find "$TTA_BACKUPS" -maxdepth 1 -type f -name '*.zip' -printf '%f\n' 2>/dev/null | grep -E "$TTA_BACKUP_RE" | sort -r)
    hour=$(envfile_get "$BASE_DIR/.env" TECHNITIUM_BACKUP_HOUR 2>/dev/null) || hour=""
    [[ "$hour" == off || "$hour" =~ ^([01]?[0-9]|2[0-3])$ ]] || hour=3
    _api_success "$(jq -c -n --argjson l "$list" --arg h "$hour" --argjson st "$(_tta_state)" --argjson k "$TTA_KEEP" \
        '{backups: ($l | sort_by([.created_at // "", .server]) | reverse), keep: $k, nightly_hour: (if $h == "off" then null else ($h | tonumber) end), last_nightly: ($st.backup // null)}')"
}

# POST /dns/technitium/restore — Restore a backup onto a server: {server: primary|secondary, file, confirm: true}. Technitium takes its zip (its own accounts and tokens stay as they are, so DCS stays connected; DHCP scopes only onto the primary), reloads and restarts its DNS service (a few seconds without answers); DCS then puts back the blocklists and the apps with their configs, and a restored primary is copied to the secondary
handle_technitium_restore() {
    _api_check_admin || { _api_error 403 "Admin access required"; return; }
    _tt_need_primary || return
    local body role file note scopes=false a cfg u errs=() sync=null
    _tt_body "${1:-}" || return; body="$TT_REQ"
    role=$(jq -r '.server // "primary" | tostring' <<< "$body"); file=$(jq -r '.file // "" | tostring' <<< "$body")
    _tt_role_ok "$role" || { _api_error 400 "server is primary or secondary"; return; }
    [[ "$file" =~ $TTA_BACKUP_RE && -s "$TTA_BACKUPS/$file" ]] || { _api_error 404 "No backup named \"$file\": GET /dns/technitium/backups lists them"; return; }
    [[ "$(jq -r '.confirm == true' <<< "$body")" == true ]] || { _api_error 400 "A restore replaces the $role Technitium's settings, zones and lists with the backup's: send {\"confirm\": true}"; return; }
    _tt_configured "$role" || { _api_error 409 "The $role Technitium is not connected"; return; }
    # two DHCP servers would hand out the same addresses: the scopes go back onto the primary only
    [[ "$role" == primary ]] && scopes=true
    if ! TT_CALL_TIMEOUT=120 _tta_curl "$role" "settings/restore?${TTA_PARTS/scopes=true/scopes=$scopes}&deleteExistingFiles=true" "$TT_DIR/.restore.out" \
            -X POST -F "file=@$TTA_BACKUPS/$file;type=application/zip"; then
        rm -f "$TT_DIR/.restore.out"; _api_error 502 "The restore failed: $TT_ERR"; return
    fi
    rm -f "$TT_DIR/.restore.out"
    _api_audit_log "${CLIENT_IP:-unknown}" "TECHNITIUM_RESTORE" "${AUTH_USERNAME:-}" "$file restored onto the $role"
    # Technitium restarts its services: a moment before it answers again
    for _ in 1 2 3 4 5 6 7 8 9 10; do _tt_api "$role" settings/get && break; sleep 1; done
    note=$(jq -c . "$TTA_BACKUPS/${file%.zip}.json" 2>/dev/null) || note='{}'
    u=$(jq -r '(.block_list_urls // []) | join(",")' <<< "$note")
    if [[ -n "$u" ]]; then
        _tt_api "$role" settings/set "blockListUrls=$u" "blockListUpdateIntervalHours=$(jq -r '.block_list_update_hours // 24' <<< "$note")" && _tt_api "$role" settings/forceUpdateBlockLists || errs+=("$TT_ERR")
    fi
    while IFS=$'\t' read -r a cfg; do
        [[ -n "$a" ]] || continue
        _tt_app_ensure "$role" "$a" || { errs+=("$TT_ERR"); continue; }
        [[ "$cfg" == null ]] || _tt_app_config_put "$role" "$a" "$cfg" || errs+=("$TT_ERR")
    done < <(jq -r '(.apps // [])[] | [.name, (.config | tojson)] | @tsv' <<< "$note")
    _tta_set 'del(.lists)'
    [[ "$role" == primary ]] && sync=$(_tt_after_write)
    _api_cache_clear 2>/dev/null || true
    _api_success "$(jq -nc --arg r "$role" --arg f "$file" --argjson sync "$sync" --arg e "${errs[*]:-}" '{success: true, server: $r, file: $f, restarted: true, sync: $sync,
        warning: (if $e == "" then null else $e end),
        message: ("Restored " + $f + " onto the " + $r + ". Technitium reloaded its settings and restarted its DNS service (a few seconds without answers)" + (if $e == "" then "." else "; " + $e end))}')"
}

# POST /dns/technitium/lists/update — Every connected Technitium downloads its blocklists again now
handle_technitium_lists_update() {
    _api_check_admin || { _api_error 403 "Admin access required"; return; }
    _tt_need_primary || return
    local role ok=() errs=()
    for role in $(_tt_roles); do
        if _tt_api "$role" settings/forceUpdateBlockLists; then ok+=("$role"); else errs+=("$TT_ERR"); fi
    done
    (( ${#ok[@]} )) || { _api_error 502 "${errs[*]}"; return; }
    _tta_set 'del(.lists)'
    _api_audit_log "${CLIENT_IP:-unknown}" "TECHNITIUM_LISTS" "${AUTH_USERNAME:-}" "lists update asked on ${ok[*]}"
    _api_cache_clear 2>/dev/null || true
    _api_success "$(jq -nc --arg s "${ok[*]}" --arg e "${errs[*]:-}" '{success: true, servers: ($s | split(" ")), warning: (if $e == "" then null else $e end),
        message: "Technitium is downloading its blocklists again: a minute or two"}')"
}
