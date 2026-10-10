#!/bin/bash
# shellcheck shell=bash
# =============================================================================
# Technitium DNS — the home's resolver, run from DCS
#
# What it does: talks to one or two Technitium DNS Servers (a primary and an
# optional secondary, https://technitium.com/dns/) over their HTTP API so the
# owner never opens Technitium's own console: the numbers (queries, blocked,
# top clients and domains), a device's recent queries, block and allow, pause
# blocking, the blocklists, the kids' groups (the Advanced Blocking app: a
# group per child or per set of devices, category lists, a bedtime that blocks
# everything), SafeSearch and YouTube's restricted mode for the whole house,
# a baseline for a fresh instance, and the secondary kept equal to the primary.
#
# Settings: TECHNITIUM_URL and TECHNITIUM_SECONDARY_URL in .env (http://host:5380);
# the API tokens (made in Technitium: your name at the top right → Create API
# Token) are the secrets TECHNITIUM_TOKEN and TECHNITIUM_SECONDARY_TOKEN. A token
# reaches curl on its standard input (a config line), never on a command line,
# in a log or an answer. Every call gives up after 5 seconds.
#
# DCS's own model of the groups is .data/technitium/groups.json; it is rendered
# into the Advanced Blocking app's config (DCS owns that config: what was set
# in Technitium's console for the app is replaced). state.json keeps what the
# minute clock needs (which groups are in bedtime, the pauses), the last sync
# and whether each instance answered.
#
# The device directory (devices.json: every device seen, its nickname, icon and notes) and Technitium's DHCP (the
# scope, the leases, reservations, moving the house's DHCP here) are at the end of this file.
#
# SafeSearch is a house-wide switch, not a group's: Advanced Blocking answers a
# blocked name with fixed addresses only (never a CNAME, and only for lists it
# downloads), so a group cannot be sent to forcesafesearch.google.com. The
# switch makes one Forwarder zone per forced name (its other names resolve as
# usual, "this-server") whose apex is an ANAME to the search engine's safe name.
#
# Loaded on demand (_technitium_lib in api-server.sh).
# =============================================================================

# shellcheck disable=SC2034  # read by the router (_technitium_lib in api-server.sh)
TECHNITIUM_LOADED=1
TT_DIR="$BASE_DIR/.data/technitium"
TT_GROUPS="$TT_DIR/groups.json"
TT_STATE="$TT_DIR/state.json"
TT_TIMEOUT=5
TT_ADV_APP="Advanced Blocking"
TT_QL_APP="Query Logs (Sqlite)"
TT_QL_CLASS="QueryLogsSqlite.App"
# Hagezi's lists in the format Technitium reads best (one domain a line, a domain blocks its subdomains). The domains/ folder
# the lists used to be in is gone (404): wildcard/*-onlydomains.txt is what Hagezi lists for Technitium.
TT_HAGEZI="https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard"
TT_BASE_LISTS="[\"$TT_HAGEZI/pro-onlydomains.txt\",\"$TT_HAGEZI/tif-onlydomains.txt\",\"$TT_HAGEZI/doh-onlydomains.txt\"]"
# the categories a group can block (Hagezi has no dating list: none is offered rather than a list that does something else)
TT_CATEGORIES="[{\"id\":\"adult\",\"name\":\"Adult content\",\"url\":\"$TT_HAGEZI/nsfw-onlydomains.txt\"},
{\"id\":\"gambling\",\"name\":\"Gambling\",\"url\":\"$TT_HAGEZI/gambling-onlydomains.txt\"},
{\"id\":\"social\",\"name\":\"Social networks\",\"url\":\"$TT_HAGEZI/social-onlydomains.txt\"},
{\"id\":\"proxy-vpn\",\"name\":\"VPNs, proxies and other DNS\",\"url\":\"$TT_HAGEZI/doh-vpn-proxy-bypass-onlydomains.txt\"},
{\"id\":\"nosafesearch\",\"name\":\"Search engines without SafeSearch\",\"url\":\"$TT_HAGEZI/nosafesearch-onlydomains.txt\"}]"
# the names SafeSearch and YouTube's restricted mode force (Google's, Microsoft's and DuckDuckGo's documented ones)
TT_SAFESEARCH='{"www.google.com":"forcesafesearch.google.com","www.bing.com":"strict.bing.com","duckduckgo.com":"safe.duckduckgo.com","www.duckduckgo.com":"safe.duckduckgo.com"}'
TT_YOUTUBE_HOSTS='["www.youtube.com","m.youtube.com","youtubei.googleapis.com","youtube.googleapis.com","www.youtube-nocookie.com"]'
# the baseline a fresh instance gets (POST /dns/technitium/bootstrap); forwarders as Technitium writes them back
TT_BASELINE='{"forwarders":["dns.quad9.net:853 (9.9.9.9)","dns.quad9.net:853 (149.112.112.112)","dns.mullvad.net:853 (194.242.2.2)"],
"forwarderProtocol":"Tls","forwarderConcurrency":1,"dnssecValidation":true,"preferIPv6":false,"blockListUpdateIntervalHours":24,
"cacheMaximumEntries":20000,"serveStale":true}'
# what the secondary takes from the primary (dnsServerDomain is each one's own)
TT_SYNC_KEYS='["forwarders","forwarderProtocol","forwarderConcurrency","concurrentForwarding","dnssecValidation","preferIPv6","blockListUrls","blockListUpdateIntervalHours","cacheMaximumEntries","serveStale","blockingType"]'

TT_CODE="000"; TT_BODY=""; TT_ERR=""
declare -gA TT_TOK=()

# =============================================================================
# Settings and the client
# =============================================================================

_tt_role_ok() { [[ "$1" == primary || "$1" == secondary ]]; }
_tt_url_key() { if [[ "$1" == secondary ]]; then printf 'TECHNITIUM_SECONDARY_URL'; else printf 'TECHNITIUM_URL'; fi; }
_tt_secret() { if [[ "$1" == secondary ]]; then printf 'TECHNITIUM_SECONDARY_TOKEN'; else printf 'TECHNITIUM_TOKEN'; fi; }
_tt_url() { local u; u=$(envfile_get "$BASE_DIR/.env" "$(_tt_url_key "$1")" 2>/dev/null) || u=""; printf '%s' "${u%/}"; }
# the token, read once per request into TT_TOK (never in a subshell: the cache must stay)
_tt_tok_load() { [[ -n "${TT_TOK[$1]+x}" ]] || TT_TOK[$1]=$(secrets_get "$(_tt_secret "$1")" 2>/dev/null || true); }
_tt_configured() { _tt_tok_load "$1"; [[ -n "${TT_TOK[$1]}" && -n "$(_tt_url "$1")" ]]; }
# what may stand in a URL DCS keeps (scheme, host or IPv4 or [IPv6], port; no path, no credentials) and in a token (it goes into a curl
# config line between quotes: nothing that could end it)
_tt_url_valid() { [[ "$1" =~ ^https?://([A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?|\[[0-9A-Fa-f:.]{2,45}\])(:[0-9]{1,5})?$ ]]; }
_tt_token_valid() { [[ "$1" =~ ^[A-Za-z0-9._~+/=-]{16,512}$ ]]; }
_tt_domain_valid() { [[ ${#1} -le 253 && "$1" =~ ^([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]]; }
_tt_ip_valid() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[12][0-9]|3[0-2]))?$ || "$1" =~ ^[0-9A-Fa-f:]{2,39}(/[0-9]{1,3})?$ ]]; }
_tt_now() { if [[ "${DCS_TECHNITIUM_NOW:-}" =~ ^[0-9]{9,11}$ ]]; then printf '%s' "$DCS_TECHNITIUM_NOW"; else date +%s; fi; }

# _tt_api ROLE PATH [name=value | name@file]...: one call to the instance (a POST of the form fields when there are any).
# Sets TT_CODE, TT_BODY (JSON, or the text of an export) and TT_ERR (a sentence); 0 when Technitium said "ok".
_tt_api() {
    local role="$1" p="$2" url tok raw a st
    shift 2
    TT_CODE=000; TT_BODY=""; TT_ERR=""
    _tt_tok_load "$role"; url=$(_tt_url "$role"); tok="${TT_TOK[$role]}"
    if [[ -z "$url" || -z "$tok" ]]; then TT_ERR="The $role Technitium is not connected: connect it on the Technitium page first"; return 1; fi
    local args=(-s --connect-timeout 3 --max-time "${TT_CALL_TIMEOUT:-$TT_TIMEOUT}" -K - -w $'\n%{http_code}')
    for a in "$@"; do args+=(--data-urlencode "$a"); done
    raw=$(printf 'header = "Authorization: Bearer %s"\n' "$tok" | curl "${args[@]}" "$url/api/$p" 2>/dev/null) || true
    TT_CODE="${raw##*$'\n'}"; TT_BODY="${raw%$'\n'*}"
    [[ "$raw" == *$'\n'* ]] || TT_BODY=""
    [[ "$TT_CODE" =~ ^[0-9]{3}$ ]] || TT_CODE=000
    if [[ "$TT_CODE" == 000 ]]; then
        TT_ERR="The $role Technitium ($url) did not answer within ${TT_CALL_TIMEOUT:-$TT_TIMEOUT} seconds: is it running, and can this server reach it?"
        return 1
    fi
    st=$(jq -r 'if type == "object" then (.status // "") else "" end' <<< "$TT_BODY" 2>/dev/null) || st="text"
    case "$st" in
        ok) return 0 ;;
        invalid-token) TT_ERR="The $role Technitium refused the API token: make a new one in Technitium (your name at the top right → Create API Token) and connect again"; return 1 ;;
        2fa-required) TT_ERR="The $role Technitium asks for a two-factor code: connect with an API token, not a password"; return 1 ;;
        error) TT_ERR="The $role Technitium said: $(jq -r '.errorMessage // "an error, without a message"' <<< "$TT_BODY" 2>/dev/null)"; return 1 ;;
    esac
    # an export answers its text
    [[ "$TT_CODE" == 200 && ( "$st" == text || ! "$TT_BODY" =~ [^[:space:]] ) ]] && return 0
    TT_ERR="The $role Technitium answered HTTP $TT_CODE${st:+ ($st)} at $url/api/${p%%\?*}: is that address Technitium's web console (port 5380)?"
    return 1
}

# the roles that are connected, primary first
_tt_roles() { local r; for r in primary secondary; do _tt_configured "$r" && printf '%s\n' "$r"; done; return 0; }

_tt_state() { _api_state_file "$TT_STATE" '{}' object >/dev/null 2>&1 || true; cat "$TT_STATE" 2>/dev/null || printf '{}'; }
_tt_state_set() { mkdir -p "$TT_DIR" 2>/dev/null; chmod 700 "$TT_DIR" 2>/dev/null || true; _api_state_file "$TT_STATE" '{}' object >/dev/null 2>&1 || true; _api_jq_update_file "$TT_STATE" "$@" || true; }
_tt_model() {
    mkdir -p "$TT_DIR" 2>/dev/null || true
    _api_state_file "$TT_GROUPS" '{"house":{"safe_search":false,"youtube":"off"},"groups":[]}' object >/dev/null 2>&1 || true
    jq -c '{house: ({safe_search: false, youtube: "off"} + (.house // {})), groups: (.groups // [])}' "$TT_GROUPS" 2>/dev/null \
        || printf '{"house":{"safe_search":false,"youtube":"off"},"groups":[]}'
}
_tt_model_save() { (umask 077; mkdir -p "$TT_DIR"; printf '%s\n' "$1" | jq . > "$TT_GROUPS.tmp") && mv -f "$TT_GROUPS.tmp" "$TT_GROUPS"; }

# =============================================================================
# Apps
# =============================================================================

# _tt_app_ensure ROLE NAME: installs a store app when it is missing (TT_INSTALLED=1 when it was)
TT_INSTALLED=0
_tt_app_ensure() {
    local role="$1" name="$2" url
    TT_INSTALLED=0
    _tt_api "$role" apps/list || return 1
    jq -e --arg n "$name" '.response.apps // [] | any(.name == $n)' >/dev/null 2>&1 <<< "$TT_BODY" && return 0
    TT_CALL_TIMEOUT=30 _tt_api "$role" apps/listStoreApps || return 1
    url=$(jq -r --arg n "$name" '.response.storeApps // [] | map(select(.name == $n))[0].url // empty' <<< "$TT_BODY" 2>/dev/null) || url=""
    if [[ -z "$url" ]]; then TT_ERR="The $role Technitium's app store has no \"$name\" (can it reach download.technitium.com?)"; return 1; fi
    TT_CALL_TIMEOUT=90 _tt_api "$role" apps/downloadAndInstall "name=$name" "url=$url" || return 1
    TT_INSTALLED=1
}

# _tt_app_config ROLE NAME → the app's config (compact JSON) in TT_CFG; empty when it has none
TT_CFG=""
_tt_app_config() {
    TT_CFG=""
    _tt_api "$1" apps/config/get "name=$2" || return 1
    TT_CFG=$(jq -r '.response.config // empty' <<< "$TT_BODY" 2>/dev/null | jq -c . 2>/dev/null) || TT_CFG=""
}

# _tt_app_config_put ROLE NAME JSON: writes it when it differs (TT_DID=1 when it was written)
TT_DID=0
_tt_app_config_put() {
    local role="$1" name="$2" want="$3" have f
    TT_DID=0
    _tt_app_config "$role" "$name" || return 1
    have="$TT_CFG"
    [[ -n "$have" ]] && [[ "$(jq -S -c . <<< "$have")" == "$(jq -S -c . <<< "$want")" ]] && return 0
    f=$(mktemp "${TMPDIR:-/tmp}/dcs-tt-XXXXXX") || return 1
    jq . <<< "$want" > "$f"
    _tt_api "$role" apps/config/set "name=$name" "config@$f" || { rm -f "$f"; return 1; }
    rm -f "$f"; TT_DID=1
}

# =============================================================================
# The kids' groups → the Advanced Blocking app
# =============================================================================

# the ids of the groups in bedtime at NOW (epoch), as a sorted JSON array; a paused bedtime is not in it
_tt_bedtime_now() {
    local now="$1" dow ydow hm
    dow=$(date -d "@$now" +%u); ydow=$(date -d "@$((now - 86400))" +%u); hm=$(date -d "@$now" +%H:%M)
    jq -c --argjson dow "$dow" --argjson ydow "$ydow" --arg hm "$hm" --argjson now "$now" --argjson st "$(_tt_state)" '
        def mins: split(":") | (.[0] | tonumber) * 60 + (.[1] | tonumber);
        ($hm | mins) as $m
        | [.groups[] | select(.bedtime.enabled == true)
           | select((($st.bedtime_paused // {})[.id] // 0) <= $now)
           | (.bedtime.from | mins) as $f | (.bedtime.to | mins) as $t | (.bedtime.days // [1,2,3,4,5,6,7]) as $d
           | select(if $f == $t then false
                    elif $f < $t then ($d | index($dow)) != null and $m >= $f and $m < $t
                    else (($d | index($dow)) != null and $m >= $f) or (($d | index($ydow)) != null and $m < $t) end)
           | .id] | sort' <<< "$(_tt_model)"
}

# the app's config for the groups, with the groups of ACTIVE (a JSON array of ids) in bedtime: everything blocked but the house's own domains
# a device blocked by hand (devices.json blocked_until) is in a group of DCS's own that blocks everything, whatever kids' group it is in
_tt_adv_render() {
    local active="$1" house blocked
    house=$(_domains_all 2>/dev/null | jq -R -s -c 'split("\n") | map(select(length > 0))') || house='[]'
    blocked=$(_tt_blocked_ips "$(_tt_now)")
    jq -c --argjson active "$active" --argjson cats "$TT_CATEGORIES" --argjson house "$house" --argjson blocked "$blocked" --arg bg "$TT_BLOCKED_GROUP" '
        def grp($name; $bed; $lists): {name: $name, enableBlocking: true, allowTxtBlockingReport: true, blockAsNxDomain: true, blockingAddresses: ["0.0.0.0", "::"],
            allowed: (if $bed then $house else [] end), blocked: [], allowListUrls: [], blockListUrls: $lists,
            allowedRegex: [], blockedRegex: (if $bed then ["."] else [] end), regexAllowListUrls: [], regexBlockListUrls: [], adblockListUrls: []};
        {enableBlocking: true, blockingAnswerTtl: 30, blockListUrlUpdateIntervalHours: 24, blockListUrlUpdateIntervalMinutes: 0,
         localEndPointGroupMap: {},
         networkGroupMap: ([.groups[] as $g | $g.devices[]? | {key: .ip, value: $g.name}] + ($blocked | map({key: ., value: $bg})) | from_entries),
         groups: ([.groups[] | (.id as $id | ($active | index($id)) != null) as $bed
                   | grp(.name; $bed; [(.lists // [])[] as $l | $cats[] | select(.id == $l) | .url])]
                  + (if ($blocked | length) > 0 then [grp($bg; true; [])] else [] end))}' <<< "$(_tt_model)"
}

# _tt_groups_apply WHO: renders the groups as they are now and puts the config on every connected instance (the app installed when
# missing). Keeps which groups are in bedtime; writes an audit line for each group that went into or out of it. 0 when the primary took it.
TT_APPLY_MSG=""
_tt_groups_apply() {
    local who="${1:-dcs}" now active was cfg role ok=1 msgs=() g name
    now=$(_tt_now); active=$(_tt_bedtime_now "$now") || active='[]'
    cfg=$(_tt_adv_render "$active") || { TT_APPLY_MSG="Could not render the groups"; return 1; }
    for role in $(_tt_roles); do
        if _tt_app_ensure "$role" "$TT_ADV_APP" && _tt_app_config_put "$role" "$TT_ADV_APP" "$cfg"; then :; else
            msgs+=("$TT_ERR"); [[ "$role" == primary ]] && ok=0
        fi
    done
    TT_APPLY_MSG="${msgs[*]:-}"
    (( ok == 1 )) || return 1
    # the devices blocked by hand: one audit line when a block starts or ends
    local bnow bwas
    bnow=$(_tt_blocked_now "$now"); bwas=$(jq -c '.blocked_active // []' <<< "$(_tt_state)" 2>/dev/null) || bwas='[]'
    if [[ "$bnow" != "$bwas" ]]; then
        while IFS=$'\t' read -r g name; do
            [[ -n "$g" ]] || continue
            _api_audit_log "${CLIENT_IP:-local}" "TECHNITIUM_BLOCK" "$who" "$name: $(jq -e --arg g "$g" 'index($g) != null' >/dev/null <<< "$bnow" && printf 'blocked (every name)' || printf 'block ended')"
        done < <(jq -r --argjson a "$bnow" --argjson w "$bwas" '(($a - $w) + ($w - $a))[] as $id | .devices[] | select(.id == $id) | [.id, (.nickname // .hostname // .ip)] | @tsv' "$TT_DEVICES" 2>/dev/null)
        _tt_state_set --argjson b "$bnow" '.blocked_active = $b'
    fi
    was=$(jq -c '.bedtime_active // []' <<< "$(_tt_state)" 2>/dev/null) || was='[]'
    if [[ "$active" != "$was" ]]; then
        while IFS=$'\t' read -r g name; do
            [[ -n "$g" ]] || continue
            if jq -e --arg g "$g" 'index($g) != null' >/dev/null <<< "$active"; then
                _api_audit_log "${CLIENT_IP:-local}" "TECHNITIUM_BEDTIME" "$who" "$name: bedtime started (every name blocked)"
            else
                _api_audit_log "${CLIENT_IP:-local}" "TECHNITIUM_BEDTIME" "$who" "$name: bedtime ended"
            fi
        done < <(jq -r --argjson a "$active" --argjson w "$was" '(($a - $w) + ($w - $a))[] as $id | .groups[] | select(.id == $id) | [.id, .name] | @tsv' <<< "$(_tt_model)")
        _tt_state_set --argjson a "$active" '.bedtime_active = $a'
    fi
    return 0
}

# the minute clock (_dcs_automation_loop): re-renders only when the groups in bedtime, or the devices blocked by hand, changed since the last render
_tt_tick() {
    [[ -s "$TT_GROUPS" || -s "$TT_DEVICES" ]] || return 0
    _tt_configured primary || return 0
    local now active was bnow bwas
    now=$(_tt_now); active=$(_tt_bedtime_now "$now") || return 0
    bnow=$(_tt_blocked_now "$now")
    was=$(jq -c '.bedtime_active // []' <<< "$(_tt_state)" 2>/dev/null) || was='[]'
    bwas=$(jq -c '.blocked_active // []' <<< "$(_tt_state)" 2>/dev/null) || bwas='[]'
    [[ "$active" == "$was" && "$bnow" == "$bwas" ]] && return 0
    if _tt_groups_apply scheduler; then _api_cache_clear 2>/dev/null || true
    else printf '%s technitium: bedtime not applied: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$TT_APPLY_MSG" >&2; fi
    return 0
}

# =============================================================================
# SafeSearch and YouTube (the whole house): forced names
# =============================================================================

# {host: target} DCS wants now; every host DCS may manage
_tt_forced_want() {
    jq -c --argjson ss "$TT_SAFESEARCH" --argjson yt "$TT_YOUTUBE_HOSTS" '.house as $h
        | (if $h.safe_search == true then $ss else {} end)
        + (if ($h.youtube // "off") == "off" then {} else
             ($yt | map({key: ., value: (if $h.youtube == "moderate" then "restrictmoderate.youtube.com" else "restrict.youtube.com" end)}) | from_entries) end)' <<< "$(_tt_model)"
}
_tt_forced_hosts() { jq -r -n --argjson ss "$TT_SAFESEARCH" --argjson yt "$TT_YOUTUBE_HOSTS" '($ss | keys[]), $yt[]'; }

# _tt_forced_apply ROLE: makes the instance's forced zones what DCS wants (a Forwarder zone per name, its apex an ANAME to the safe name);
# a forced name that is off loses its zone (only a Forwarder zone: a zone of that name the owner made otherwise stays)
_tt_forced_apply() {
    local role="$1" want zones h t have type
    want=$(_tt_forced_want) || want='{}'
    _tt_api "$role" zones/list || return 1
    zones=$(jq -c '[.response.zones // [] | .[] | {key: (.name | ascii_downcase), value: .type}] | from_entries' <<< "$TT_BODY") || zones='{}'
    while IFS= read -r h; do
        [[ -n "$h" ]] || continue
        t=$(jq -r --arg h "$h" '.[$h] // empty' <<< "$want"); type=$(jq -r --arg h "$h" '.[$h] // empty' <<< "$zones")
        if [[ -n "$t" ]]; then
            if [[ -n "$type" ]]; then
                _tt_api "$role" zones/records/get "domain=$h" "zone=$h" || return 1
                have=$(jq -r '[.response.records // [] | .[] | select(.type == "ANAME") | .rData.aname][0] // empty' <<< "$TT_BODY")
                [[ "$type" == Forwarder && "${have,,}" == "$t" ]] && continue
                [[ "$type" == Forwarder ]] || { TT_ERR="The $role Technitium has a $type zone $h of its own: DCS leaves it as it is"; continue; }
                _tt_api "$role" zones/delete "zone=$h" || return 1
            fi
            _tt_api "$role" zones/create "zone=$h" type=Forwarder forwarder=this-server protocol=Udp || return 1
            _tt_api "$role" zones/records/add "zone=$h" "domain=$h" type=ANAME "aname=$t" ttl=300 || return 1
        elif [[ "$type" == Forwarder ]]; then
            _tt_api "$role" zones/delete "zone=$h" || return 1
        fi
    done < <(_tt_forced_hosts)
    TT_ERR=""
    return 0
}

# =============================================================================
# One instance's state, the fingerprint of what the secondary copies, the sync
# =============================================================================

# the export of the allowed or blocked zone as a sorted JSON array in TT_LIST (a variable: TT_ERR must reach the caller)
TT_LIST='[]'
_tt_export() { TT_LIST='[]'; _tt_api "$1" "$2/export" || return 1; TT_LIST=$(printf '%s\n' "$TT_BODY" | tr -d '\r' | awk 'NF' | sort -u | jq -R -s -c 'split("\n") | map(select(length > 0))'); }

# the instance's status (JSON on stdout, never fails): what the page shows, and "hash" (what the sync makes equal)
_tt_instance_status() {
    local role="$1" url s apps zones fz allowed blocked adv fp
    url=$(_tt_url "$role")
    if ! _tt_configured "$role"; then jq -nc --arg r "$role" --arg u "$url" '{role: $r, url: (if $u == "" then null else $u end), configured: false, reachable: false}'; return 0; fi
    if ! _tt_api "$role" settings/get; then
        jq -nc --arg r "$role" --arg u "$url" --arg e "$TT_ERR" '{role: $r, url: $u, configured: true, reachable: false, error: $e}'
        return 0
    fi
    s=$(jq -c '.response' <<< "$TT_BODY")
    apps='[]'; _tt_api "$role" apps/list && apps=$(jq -c '[.response.apps // [] | .[].name]' <<< "$TT_BODY")
    zones='[]'; fz='[]'
    if _tt_api "$role" zones/list; then
        zones=$(jq -c '[.response.zones // [] | .[] | select((.internal // false) != true) | .name | ascii_downcase]' <<< "$TT_BODY")
        fz=$(jq -c '[.response.zones // [] | .[] | select(.type == "Forwarder") | .name | ascii_downcase]' <<< "$TT_BODY")
    fi
    allowed='[]'; _tt_export "$role" allowed && allowed="$TT_LIST"
    blocked='[]'; _tt_export "$role" blocked && blocked="$TT_LIST"
    adv=null
    if jq -e --arg n "$TT_ADV_APP" 'index($n) != null' >/dev/null <<< "$apps"; then _tt_app_config "$role" "$TT_ADV_APP" && [[ -n "$TT_CFG" ]] && adv="$TT_CFG"; fi
    fp=$(jq -S -c -n --argjson s "$s" --argjson keys "$TT_SYNC_KEYS" --argjson a "$allowed" --argjson b "$blocked" --argjson adv "$adv" --argjson z "$fz" \
            --argjson hosts "$(_tt_forced_hosts | jq -R -s -c 'split("\n") | map(select(length > 0))')" \
        '{settings: ($s | with_entries(select(.key as $k | $keys | index($k) != null))), allowed: $a, blocked: $b, adv: $adv,
          forced: ($z | map(select(. as $n | $hosts | index($n) != null)) | sort)}' | sha256sum | cut -c1-16)
    jq -c -n --arg r "$role" --arg u "$url" --argjson s "$s" --argjson apps "$apps" --argjson z "$zones" --argjson a "$allowed" --argjson b "$blocked" \
        --arg fp "$fp" --arg adv "$TT_ADV_APP" --arg ql "$TT_QL_APP" '
        def ts: if type == "string" then (sub("\\.[0-9]+"; "") | sub("Z$"; "Z") | try fromdateiso8601 catch null) else null end;
        {role: $r, url: $u, configured: true, reachable: true, error: null,
         version: $s.version, domain: $s.dnsServerDomain, up_since: $s.uptimestamp,
         blocking: ($s.enableBlocking == true), paused_until: $s.temporaryDisableBlockingTill,
         forwarders: ($s.forwarders // []), forwarder_protocol: $s.forwarderProtocol, dnssec: $s.dnssecValidation,
         block_lists: (($s.blockListUrls // []) | length), list_update_hours: $s.blockListUpdateIntervalHours,
         lists_next_update: $s.blockListNextUpdatedOn,
         lists_last_update: (($s.blockListNextUpdatedOn | ts) as $n | if $n == null or (($s.blockListUrls // []) | length) == 0 then null
                             else ($n - (($s.blockListUpdateIntervalHours // 24) * 3600)) | todate end),
         zones: ($z | length), allowed: ($a | length), blocked: ($b | length),
         apps: {advanced_blocking: ($apps | index($adv) != null), query_logs: ($apps | index($ql) != null)}, hash: $fp}'
}

# POST-free copy of the primary to the secondary: settings, the allowed and blocked zones, the apps and their configs, the forced names.
# Records the outcome in state.json (.last_sync). 0 when the secondary is equal to the primary (or there is no secondary).
TT_SYNC_MSG=""
_tt_sync() {
    TT_SYNC_MSG=""
    _tt_configured secondary || { TT_SYNC_MSG="No secondary is connected"; return 0; }
    local s set=() k v pa sa d f
    _tt_sync_fail() { TT_SYNC_MSG="$1"; _tt_state_set --argjson at "$(date +%s)" --arg m "$1" '.last_sync = {at: $at, ok: false, message: $m}'; return 1; }
    _tt_api primary settings/get || { _tt_sync_fail "$TT_ERR"; return 1; }
    s=$(jq -c '.response' <<< "$TT_BODY")
    while IFS=$'\t' read -r k v; do set+=("$k=$v"); done < <(jq -r --argjson keys "$TT_SYNC_KEYS" '
        . as $s | $keys[] | . as $k | select($s | has($k)) | $s[$k] |
        [$k, (if type == "array" then (if length == 0 then "false" else join(",") end) elif . == null then empty else tostring end)] | @tsv' <<< "$s")
    _tt_api secondary settings/set "${set[@]}" || { _tt_sync_fail "$TT_ERR"; return 1; }
    for d in allowed blocked; do
        _tt_export primary "$d" || { _tt_sync_fail "$TT_ERR"; return 1; }
        pa="$TT_LIST"
        _tt_export secondary "$d" || { _tt_sync_fail "$TT_ERR"; return 1; }
        sa="$TT_LIST"
        f=$(jq -r -n --argjson p "$pa" --argjson s "$sa" '($p - $s) | join(",")')
        if [[ -n "$f" ]]; then _tt_api secondary "$d/import" "${d}Zones=$f" || { _tt_sync_fail "$TT_ERR"; return 1; }; fi
        while IFS= read -r v; do
            [[ -n "$v" ]] || continue
            _tt_api secondary "$d/delete" "domain=$v" || { _tt_sync_fail "$TT_ERR"; return 1; }
        done < <(jq -r -n --argjson p "$pa" --argjson s "$sa" '($s - $p)[]')
    done
    # the apps the primary has (the query log's settings with it), the groups as DCS renders them, the forced names
    _tt_api primary apps/list || { _tt_sync_fail "$TT_ERR"; return 1; }
    if jq -e --arg n "$TT_QL_APP" '.response.apps // [] | any(.name == $n)' >/dev/null <<< "$TT_BODY"; then
        local qc
        qc=""; _tt_app_config primary "$TT_QL_APP" && qc="$TT_CFG"
        _tt_app_ensure secondary "$TT_QL_APP" || { _tt_sync_fail "$TT_ERR"; return 1; }
        if [[ -n "$qc" ]]; then _tt_app_config_put secondary "$TT_QL_APP" "$qc" || { _tt_sync_fail "$TT_ERR"; return 1; }; fi
    fi
    if jq -e '.groups | length > 0' >/dev/null <<< "$(_tt_model)" || jq -e --arg n "$TT_ADV_APP" '.response.apps // [] | any(.name == $n)' >/dev/null <<< "$TT_BODY"; then
        local ac
        ac=""; _tt_app_config primary "$TT_ADV_APP" && ac="$TT_CFG"
        [[ -n "$ac" ]] || ac=$(_tt_adv_render "$(jq -c '.bedtime_active // []' <<< "$(_tt_state)")")
        _tt_app_ensure secondary "$TT_ADV_APP" && _tt_app_config_put secondary "$TT_ADV_APP" "$ac" || { _tt_sync_fail "$TT_ERR"; return 1; }
    fi
    _tt_forced_apply primary || { _tt_sync_fail "$TT_ERR"; return 1; }
    _tt_forced_apply secondary || { _tt_sync_fail "$TT_ERR"; return 1; }
    _tt_state_set --argjson at "$(date +%s)" '.last_sync = {at: $at, ok: true, message: "The secondary has what the primary has"}'
    TT_SYNC_MSG="The secondary has what the primary has"
}

# after a write: the secondary follows (the answer says how it went); the cached answers go
_tt_after_write() {
    _api_cache_clear 2>/dev/null || true
    if _tt_configured secondary; then
        if _tt_sync; then jq -nc --arg m "$TT_SYNC_MSG" '{ok: true, message: $m}'; else jq -nc --arg m "$TT_SYNC_MSG" '{ok: false, message: $m}'; fi
    else
        printf 'null'
    fi
}

# =============================================================================
# Handlers
# =============================================================================

_tt_need_primary() {
    _tt_configured primary && return 0
    _api_response 409 '{"error": true, "code": 409, "reason": "not_connected", "message": "No Technitium is connected: connect the primary on the Technitium page (its address and an API token)."}'
    return 1
}
# the request's JSON object in TT_REQ (a 400 answered, status 1, when it is not one)
TT_REQ='{}'
_tt_body() {
    TT_REQ="${1:-}"
    [[ -n "$TT_REQ" ]] || TT_REQ='{}'
    [[ "$TT_REQ" == \{* ]] && jq -e . >/dev/null 2>&1 <<< "$TT_REQ" || { _api_error 400 "Send a JSON object"; return 1; }
}

# GET /dns/technitium/status — Both Technitium instances: reachable, version, uptime, blocking and its pause, forwarders, lists, zones, apps; whether the secondary has what the primary has (in_sync), the last sync, the groups in bedtime, the house's SafeSearch
handle_technitium_status() {
    local p s st in_sync=null model
    p=$(_tt_instance_status primary); s=$(_tt_instance_status secondary)
    st=$(_tt_state); model=$(_tt_model)
    if [[ "$(jq -r '.reachable' <<< "$p")" == true && "$(jq -r '.reachable' <<< "$s")" == true ]]; then
        in_sync=$(jq -n --argjson p "$p" --argjson s "$s" --argjson st "$st" '$p.hash == $s.hash and (($st.last_sync.ok // true) == true)')
    elif [[ "$(jq -r '.configured' <<< "$s")" == true ]]; then
        in_sync=false
    fi
    _tt_state_set --argjson p "$p" --argjson s "$s" --argjson now "$(date +%s)" \
        '.reachable = {primary: {ok: $p.reachable, error: ($p.error // null), at: $now}, secondary: {ok: $s.reachable, error: ($s.error // null), at: $now}}'
    _api_success "$(jq -c -n --argjson p "$p" --argjson s "$s" --argjson st "$st" --argjson m "$model" --argjson in "$in_sync" '
        {configured: $p.configured, primary: $p, secondary: (if $s.configured or $s.url != null then $s else null end), in_sync: $in,
         last_sync: ($st.last_sync // null), house: $m.house, groups: ($m.groups | length),
         bedtime_active: ($st.bedtime_active // []), bedtime_paused: ($st.bedtime_paused // {})}')"
}

# GET /dns/technitium/stats?range=lastHour|lastDay|lastWeek — Queries, blocked and clients over the range for both instances together: the totals, the series, the top clients (named by their nickname in the device directory or a group's label, else Technitium's name for them; with the device and its icon), domains and blocked domains, the query types
handle_technitium_stats() {
    _tt_need_primary || return
    local range="${QUERY_PARAMS[range]:-lastHour}" type role all='[]' errs='[]' labels
    case "$range" in lastHour) type=LastHour ;; lastDay) type=LastDay ;; lastWeek) type=LastWeek ;; *) _api_error 400 "range is lastHour, lastDay or lastWeek"; return ;; esac
    for role in $(_tt_roles); do
        if _tt_api "$role" dashboard/stats/get "type=$type" utc=true; then
            all=$(jq -c --arg r "$role" --argjson x "$(jq -c '.response' <<< "$TT_BODY")" '. + [$x + {role: $r}]' <<< "$all")
        else
            errs=$(jq -c --arg r "$role" --arg e "$TT_ERR" '. + [{role: $r, error: $e}]' <<< "$errs")
        fi
    done
    if [[ "$all" == '[]' ]]; then _api_error 502 "$(jq -r 'map(.error) | join("; ")' <<< "$errs")"; return; fi
    local dir devs
    dir=$(_tt_dir)
    labels=$(jq -c --argjson d "$dir" '([.groups[] as $g | $g.devices[]? | {key: .ip, value: (.label // $g.name)}] | from_entries)
        + ($d.devices | map(select(.nickname != null and .ip != null) | {key: .ip, value: .nickname}) | from_entries)' <<< "$(_tt_model)") || labels='{}'
    devs=$(jq -c '.devices | map(select(.ip != null) | {key: .ip, value: {id, icon, hostname}}) | from_entries' <<< "$dir") || devs='{}'
    _api_success "$(jq -c --arg range "$range" --argjson errs "$errs" --argjson lab "$labels" --argjson dv "$devs" '
        def ds($n): [.[] | (.mainChartData.labels // []) as $l | ((.mainChartData.datasets // []) | map(select(.label == $n))[0].data // []) as $d
                      | range(0; $l | length) as $i | {t: $l[$i], v: ($d[$i] // 0)}] | group_by(.t) | map({t: .[0].t, v: (map(.v) | add)});
        def merge($k; $f): [.[] | .[$k] // [] | .[]] | group_by(.name) | map({($f): .[0].name, count: (map(.hits) | add), rdns: (map(.domain // empty) | first)})
                           | sort_by(-.count) | .[:10];
        {range: $range, instances: map(.role), unreachable: $errs,
         totals: {queries: (map(.stats.totalQueries // 0) | add), blocked: (map(.stats.totalBlocked // 0) | add),
                  clients: (map(.stats.totalClients // 0) | max), cached: (map(.stats.totalCached // 0) | add),
                  nxdomain: (map(.stats.totalNxDomain // 0) | add)},
         series: (ds("Total") as $q | ds("Blocked") as $b | {labels: ($q | map(.t)), queries: ($q | map(.v)),
                  blocked: ($q | map(.t) | map(. as $t | ($b | map(select(.t == $t))[0].v // 0)))}),
         top_clients: (merge("topClients"; "ip") | map({ip, count, name: ($lab[.ip] // .rdns // $dv[.ip].hostname // null), device_id: ($dv[.ip].id // null), icon: ($dv[.ip].icon // null)})),
         top_domains: (merge("topDomains"; "domain") | map({domain, count})),
         top_blocked: (merge("topBlockedDomains"; "domain") | map({domain, count})),
         query_types: ([.[] | (.queryTypeChartData.labels // []) as $l | (.queryTypeChartData.datasets[0].data // []) as $d
                        | range(0; $l | length) as $i | {type: $l[$i], count: ($d[$i] // 0)}] | group_by(.type)
                        | map({type: .[0].type, count: (map(.count) | add)}) | sort_by(-.count))}' <<< "$all")"
}

# GET /dns/technitium/activity?client=&q=&blocked=1&limit= — A device's recent queries from the Query Logs (Sqlite) app of both instances, newest first: client (an address), q (part of a name), blocked=1 for the blocked ones alone, limit (100, at most 500)
handle_technitium_activity() {
    _tt_need_primary || return
    local client="${QUERY_PARAMS[client]:-}" q="${QUERY_PARAMS[q]:-}" blocked="${QUERY_PARAMS[blocked]:-}" limit="${QUERY_PARAMS[limit]:-100}" role all='[]' missing='[]' args
    [[ -z "$client" ]] || _tt_ip_valid "$client" || { _api_error 400 "client is an IP address"; return; }
    q="${q,,}"; [[ -z "$q" || "$q" =~ ^[a-z0-9._*-]{1,100}$ ]] || { _api_error 400 "q is part of a name: letters, digits, dots and dashes"; return; }
    [[ "$limit" =~ ^[0-9]{1,3}$ ]] && (( 10#$limit >= 1 && 10#$limit <= 500 )) || { _api_error 400 "limit is 1 to 500"; return; }
    limit=$((10#$limit))
    for role in $(_tt_roles); do
        args=("name=$TT_QL_APP" "classPath=$TT_QL_CLASS" pageNumber=1 "entriesPerPage=$limit" descendingOrder=true)
        [[ -n "$client" ]] && args+=("clientIpAddress=$client")
        [[ -n "$q" ]] && args+=("qname=*${q//\*/}*")
        [[ "$blocked" == 1 || "$blocked" == true ]] && args+=(responseType=Blocked)
        if _tt_api "$role" logs/query "${args[@]}"; then
            all=$(jq -c --arg r "$role" --argjson e "$(jq -c '.response.entries // []' <<< "$TT_BODY")" '. + ($e | map(. + {role: $r}))' <<< "$all")
        else
            missing=$(jq -c --arg r "$role" --arg e "$TT_ERR" '. + [{role: $r, error: $e}]' <<< "$missing")
        fi
    done
    if [[ "$all" == '[]' && "$missing" != '[]' && "$(jq 'length' <<< "$missing")" == "$(_tt_roles | wc -l)" ]]; then
        _api_response 502 "$(jq -c '{error: true, code: 502, reason: "no_query_log", message: ((map(.error) | join("; ")) + " (the Query Logs (Sqlite) app keeps the queries: Apply baseline installs it)"), instances: .}' <<< "$missing")"
        return
    fi
    _api_success "$(jq -c --argjson n "$limit" --argjson miss "$missing" '
        {entries: (sort_by(.timestamp) | reverse | .[:$n] | map({time: .timestamp, client: .clientIpAddress, name: .qname, type: .qtype,
          response: .responseType, rcode, answer: (.answer // ""), blocked: ((.responseType // "") | test("Blocked")), instance: .role})),
         unavailable: $miss}' <<< "$all")"
}

# GET /dns/technitium/lists — The primary's blocklist URLs, the custom allowed and blocked names, the categories a group can block and the baseline lists
handle_technitium_lists() {
    _tt_need_primary || return
    local s a b
    _tt_api primary settings/get || { _api_error 502 "$TT_ERR"; return; }
    s=$(jq -c '.response.blockListUrls // []' <<< "$TT_BODY")
    _tt_export primary allowed || { _api_error 502 "$TT_ERR"; return; }
    a="$TT_LIST"
    _tt_export primary blocked || { _api_error 502 "$TT_ERR"; return; }
    b="$TT_LIST"
    _api_success "$(jq -c -n --argjson s "$s" --argjson a "$a" --argjson b "$b" --argjson c "$TT_CATEGORIES" --argjson base "$TT_BASE_LISTS" \
        '{blocklists: $s, allowed: $a, blocked: $b, categories: $c, baseline_lists: $base}')"
}

# POST /dns/technitium/block — Block a name for everyone (Technitium's blocked zone): {domain, remove?: true to take it off}; the secondary follows
handle_technitium_block() { _tt_listed blocked "$1"; }
# POST /dns/technitium/allow — Allow a name for everyone (Technitium's allowed zone, over every blocklist): {domain, remove?: true to take it off}; the secondary follows
handle_technitium_allow() { _tt_listed allowed "$1"; }
_tt_listed() {
    _api_check_admin || { _api_error 403 "Admin access required"; return; }
    _tt_need_primary || return
    local zone="$1" body d rm sync
    _tt_body "${2:-}" || return; body="$TT_REQ"
    d=$(jq -r '(.domain // "") | tostring | ascii_downcase | sub("^\\s+|\\s+$"; ""; "g") | rtrimstr(".")' <<< "$body")
    rm=$(jq -r '.remove == true' <<< "$body")
    _tt_domain_valid "$d" || { _api_error 400 "That is not a name: send {\"domain\": \"ads.example.com\"}"; return; }
    if [[ "$rm" == true ]]; then _tt_api primary "$zone/delete" "domain=$d" || { _api_error 502 "$TT_ERR"; return; }
    else _tt_api primary "$zone/add" "domain=$d" || { _api_error 502 "$TT_ERR"; return; }; fi
    _api_audit_log "${CLIENT_IP:-unknown}" "TECHNITIUM_${zone^^}" "${AUTH_USERNAME:-}" "$([[ "$rm" == true ]] && printf 'removed' || printf 'added') $d"
    sync=$(_tt_after_write)
    _api_success "$(jq -nc --arg d "$d" --arg z "$zone" --argjson rm "$rm" --argjson sync "$sync" \
        '{success: true, domain: $d, list: $z, removed: $rm, sync: $sync, message: ($d + (if $rm then " is off the " else " is on the " end) + $z + " list")}')"
}

# POST /dns/technitium/blocklists — Add or remove a blocklist URL on the primary: {url, remove?: true}; the secondary follows
handle_technitium_blocklists() {
    _api_check_admin || { _api_error 403 "Admin access required"; return; }
    _tt_need_primary || return
    local body u rm cur new sync
    _tt_body "${1:-}" || return; body="$TT_REQ"
    u=$(jq -r '(.url // "") | tostring' <<< "$body"); rm=$(jq -r '.remove == true' <<< "$body")
    [[ ${#u} -le 2048 && "$u" =~ ^https?://[^[:space:],\"\'\<\>]+$ ]] || { _api_error 400 "Send {\"url\": \"https://…\"}: the address of a list (hosts or one name a line)"; return; }
    _tt_api primary settings/get || { _api_error 502 "$TT_ERR"; return; }
    cur=$(jq -c '.response.blockListUrls // []' <<< "$TT_BODY")
    if [[ "$rm" == true ]]; then new=$(jq -c --arg u "$u" 'map(select(. != $u))' <<< "$cur"); else new=$(jq -c --arg u "$u" 'if index($u) then . else . + [$u] end' <<< "$cur"); fi
    if [[ "$new" != "$cur" ]]; then
        _tt_api primary settings/set "blockListUrls=$(jq -r 'if length == 0 then "false" else join(",") end' <<< "$new")" || { _api_error 502 "$TT_ERR"; return; }
        _api_audit_log "${CLIENT_IP:-unknown}" "TECHNITIUM_LISTS" "${AUTH_USERNAME:-}" "$([[ "$rm" == true ]] && printf 'removed' || printf 'added') $u"
    fi
    sync=$(_tt_after_write)
    _api_success "$(jq -nc --argjson l "$new" --argjson sync "$sync" '{success: true, blocklists: $l, sync: $sync}')"
}

# POST /dns/technitium/pause — Pause blocking on every instance for {minutes: 5, 15 or 60}; it comes back by itself
handle_technitium_pause() {
    _api_check_admin || { _api_error 403 "Admin access required"; return; }
    _tt_need_primary || return
    local body m role until="" errs=()
    _tt_body "${1:-}" || return; body="$TT_REQ"
    m=$(jq -r '.minutes // 5 | tostring' <<< "$body")
    [[ "$m" == 5 || "$m" == 15 || "$m" == 60 ]] || { _api_error 400 "minutes is 5, 15 or 60"; return; }
    for role in $(_tt_roles); do
        if _tt_api "$role" settings/temporaryDisableBlocking "minutes=$m"; then
            [[ -n "$until" ]] || until=$(jq -r '.response.temporaryDisableBlockingTill // empty' <<< "$TT_BODY")
        else errs+=("$TT_ERR"); fi
    done
    [[ -n "$until" ]] || { _api_error 502 "${errs[*]}"; return; }
    _api_audit_log "${CLIENT_IP:-unknown}" "TECHNITIUM_PAUSE" "${AUTH_USERNAME:-}" "blocking paused for $m minutes"
    _api_cache_clear 2>/dev/null || true
    _api_success "$(jq -nc --arg u "$until" --argjson m "$m" --arg e "${errs[*]:-}" '{success: true, paused_until: $u, minutes: $m, warning: (if $e == "" then null else $e end)}')"
}

# POST /dns/technitium/resume — Blocking back on now, on every instance
handle_technitium_resume() {
    _api_check_admin || { _api_error 403 "Admin access required"; return; }
    _tt_need_primary || return
    local role errs=()
    for role in $(_tt_roles); do _tt_api "$role" settings/set enableBlocking=true || errs+=("$TT_ERR"); done
    if (( ${#errs[@]} > 0 )) && [[ "${errs[0]}" == *primary* ]]; then _api_error 502 "${errs[*]}"; return; fi
    _api_audit_log "${CLIENT_IP:-unknown}" "TECHNITIUM_PAUSE" "${AUTH_USERNAME:-}" "blocking resumed"
    _api_cache_clear 2>/dev/null || true
    _api_success "$(jq -nc --arg e "${errs[*]:-}" '{success: true, blocking: true, warning: (if $e == "" then null else $e end)}')"
}

# GET /dns/technitium/groups — The kids' groups (devices, category lists, bedtime), which are in bedtime now and until when a bedtime is paused, the categories, the house's SafeSearch and YouTube setting
handle_technitium_groups() {
    local now active
    now=$(_tt_now); active=$(_tt_bedtime_now "$now") || active='[]'
    _api_success "$(jq -c --argjson a "$active" --argjson st "$(_tt_state)" --argjson c "$TT_CATEGORIES" --argjson now "$now" \
        --argjson ss "$TT_SAFESEARCH" --argjson yt "$TT_YOUTUBE_HOSTS" '
        {house: .house, groups: [.groups[] | .id as $id | . + {in_bedtime: ($a | index($id) != null),
            bedtime_paused_until: ((($st.bedtime_paused // {})[$id] // 0) as $p | if $p > $now then ($p | todate) else null end)}],
         categories: ($c | map({id, name})), forced_names: {safe_search: ($ss | keys), youtube: $yt},
         safe_search_scope: "house", now: ($now | todate)}' <<< "$(_tt_model)")"
}

# the group in BODY checked and tidied (JSON on stdout), or the reason it is refused (status 1, the sentence on stdout)
_tt_group_clean() {
    jq -c --argjson cats "$TT_CATEGORIES" '
        def hm: test("^([01][0-9]|2[0-3]):[0-5][0-9]$");
        def ipok: test("^([0-9]{1,3}\\.){3}[0-9]{1,3}(/([0-9]|[12][0-9]|3[0-2]))?$") or test("^[0-9A-Fa-f:]{2,39}(/[0-9]{1,3})?$");
        (.name // "" | tostring | gsub("^\\s+|\\s+$"; "")) as $name
        | if ($name | length) < 1 or ($name | length) > 40 or ($name | test("^[A-Za-z0-9 ._()-]+$") | not) then "A group needs a name: letters, digits, spaces, . _ ( ) and - (40 at most)"
          elif (.devices // [] | type) != "array" or (.devices // [] | length) > 64 then "devices is a list of at most 64 {ip, label}"
          elif (.devices // [] | map(select((.ip // "" | tostring | ipok) | not)) | length) > 0 then "A device needs its address (192.168.2.50, or a network like 192.168.2.0/28)"
          elif (.devices // [] | map(.ip) | length) != (.devices // [] | map(.ip) | unique | length) then "An address is in the group twice"
          elif (.devices // [] | map(select((.label // "" | tostring | length) > 40 or ((.mac // "" | tostring) | (. == "" or test("^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")) | not))) | length) > 0 then "A device label is 40 characters at most, and a MAC address looks like aa:bb:cc:dd:ee:ff"
          elif (.lists // [] | type) != "array" or (.lists // [] | map(select(. as $l | $cats | map(.id) | index($l) | not)) | length) > 0 then "lists are among: \($cats | map(.id) | join(", "))"
          elif .bedtime != null and ((.bedtime | type) != "object" or (.bedtime.from // "20:30" | hm | not) or (.bedtime.to // "07:00" | hm | not)
                or (.bedtime.days // [1,2,3,4,5,6,7] | type) != "array" or (.bedtime.days // [] | map(select(type != "number" or . < 1 or . > 7)) | length) > 0)
            then "bedtime is {enabled, from: \"20:30\", to: \"07:00\", days: [1..7, Monday is 1]}"
          else {id: (.id // null), name: $name,
                devices: (.devices // [] | map({ip: (.ip | tostring), label: (.label // "" | tostring | gsub("^\\s+|\\s+$"; "")), mac: (if (.mac // "") == "" then null else (.mac | ascii_downcase) end)}
                    + (if (.id // "" | tostring | test("^([0-9a-f]{12}|ip-[0-9]{1,3}(\\.[0-9]{1,3}){3})$")) then {id} else {} end))),
                lists: (.lists // [] | unique),
                bedtime: {enabled: (.bedtime.enabled == true), from: (.bedtime.from // "20:30"), to: (.bedtime.to // "07:00"), days: (.bedtime.days // [1,2,3,4,5,6,7] | unique)}}
          end' <<< "$1" 2>/dev/null || printf '"Send a group: {name, devices: [{ip, label}], lists: [], bedtime: {enabled, from, to, days}}"'
}

# POST /dns/technitium/groups — Add a group, or change one ({id} of an existing one): {name, devices: [{ip, label, mac?, id? (the device directory's)}], lists: [adult, gambling, social, proxy-vpn, nosafesearch], bedtime: {enabled, from, to, days}}; Technitium's Advanced Blocking app gets it (installed when missing) and the secondary follows
handle_technitium_group_save() {
    _api_check_admin || { _api_error 403 "Admin access required"; return; }
    _tt_need_primary || return
    local body g id model clash sync
    _tt_body "${1:-}" || return; body="$TT_REQ"
    g=$(_tt_group_clean "$body")
    if [[ "$g" == \"* ]]; then _api_error 400 "$(jq -r . <<< "$g")"; return; fi
    model=$(_tt_model)
    id=$(jq -r '.id // empty' <<< "$g")
    if [[ -n "$id" ]]; then
        jq -e --arg id "$id" 'any(.groups[]; .id == $id)' >/dev/null <<< "$model" || { _api_error 404 "No group $id"; return; }
    else
        id="g$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"; g=$(jq -c --arg id "$id" '.id = $id' <<< "$g")
    fi
    clash=$(jq -r --argjson g "$g" '[.groups[] | select(.id != $g.id) | select((.name | ascii_downcase) == ($g.name | ascii_downcase))] | length' <<< "$model")
    [[ "$clash" == 0 ]] || { _api_error 409 "A group is called that already"; return; }
    clash=$(jq -r --argjson g "$g" '[.groups[] | select(.id != $g.id) as $o | $o.devices[] | select(.ip as $i | $g.devices | any(.ip == $i)) | "\(.ip) (in \($o.name))"] | join(", ")' <<< "$model")
    [[ -z "$clash" ]] || { _api_error 409 "A device is in one group at a time: $clash"; return; }
    model=$(jq -c --argjson g "$g" 'if any(.groups[]; .id == $g.id) then .groups |= map(if .id == $g.id then $g else . end) else .groups += [$g] end' <<< "$model")
    _tt_model_save "$model" || { _api_error 500 "Could not write $TT_GROUPS"; return; }
    if ! _tt_groups_apply "${AUTH_USERNAME:-}"; then
        _api_response 502 "$(jq -nc --arg m "$TT_APPLY_MSG" --argjson g "$g" '{error: true, code: 502, message: ("The group is saved in DCS, but Technitium did not take it: " + $m + " (it is tried again on every change and by the minute clock)"), group: $g}')"
        return
    fi
    _api_audit_log "${CLIENT_IP:-unknown}" "TECHNITIUM_GROUP" "${AUTH_USERNAME:-}" "saved $(jq -r '"\(.name): \(.devices | length) devices"' <<< "$g")"
    sync=$(_tt_after_write)
    _api_success "$(jq -nc --argjson g "$g" --argjson sync "$sync" --arg w "$TT_APPLY_MSG" '{success: true, group: $g, sync: $sync, warning: (if $w == "" then null else $w end)}')"
}

# DELETE /dns/technitium/groups/{id} — Delete a group: its devices go back to the house's blocking
handle_technitium_group_delete() {
    _api_check_admin || { _api_error 403 "Admin access required"; return; }
    _tt_need_primary || return
    local id="$1" model name sync
    model=$(_tt_model)
    name=$(jq -r --arg id "$id" '.groups[] | select(.id == $id) | .name' <<< "$model")
    [[ -n "$name" ]] || { _api_error 404 "No group $id"; return; }
    _tt_model_save "$(jq -c --arg id "$id" '.groups |= map(select(.id != $id))' <<< "$model")" || { _api_error 500 "Could not write $TT_GROUPS"; return; }
    _tt_state_set --arg id "$id" 'del(.bedtime_paused[$id]) | .bedtime_active = ((.bedtime_active // []) - [$id])'
    _tt_groups_apply "${AUTH_USERNAME:-}" || { _api_error 502 "The group is gone from DCS, but Technitium did not take it: $TT_APPLY_MSG"; return; }
    _api_audit_log "${CLIENT_IP:-unknown}" "TECHNITIUM_GROUP" "${AUTH_USERNAME:-}" "deleted $name"
    sync=$(_tt_after_write)
    _api_success "$(jq -nc --arg id "$id" --argjson sync "$sync" '{success: true, deleted: $id, sync: $sync}')"
}

# POST /dns/technitium/groups/{id}/pause-bedtime — Pause a group's bedtime: {minutes: 30 (1 to 240), or 0 to end the pause}
handle_technitium_group_pause() {
    _api_check_admin || { _api_error 403 "Admin access required"; return; }
    _tt_need_primary || return
    local id="$1" body m now until name sync
    _tt_body "${2:-}" || return; body="$TT_REQ"
    name=$(jq -r --arg id "$id" '.groups[] | select(.id == $id) | .name' <<< "$(_tt_model)")
    [[ -n "$name" ]] || { _api_error 404 "No group $id"; return; }
    m=$(jq -r '.minutes // 30 | tostring' <<< "$body")
    [[ "$m" =~ ^[0-9]{1,3}$ ]] && (( 10#$m <= 240 )) || { _api_error 400 "minutes is 0 to 240"; return; }
    now=$(_tt_now); until=$(( now + 10#$m * 60 ))
    if (( 10#$m == 0 )); then _tt_state_set --arg id "$id" 'del(.bedtime_paused[$id])'
    else _tt_state_set --arg id "$id" --argjson u "$until" '.bedtime_paused = ((.bedtime_paused // {}) + {($id): $u})'; fi
    _tt_groups_apply "${AUTH_USERNAME:-}" || { _api_error 502 "$TT_APPLY_MSG"; return; }
    _api_audit_log "${CLIENT_IP:-unknown}" "TECHNITIUM_BEDTIME" "${AUTH_USERNAME:-}" "$name: bedtime $([[ "$m" == 0 ]] && printf 'pause ended' || printf 'paused for %s minutes' "$m")"
    sync=$(_tt_after_write)
    _api_success "$(jq -nc --arg id "$id" --argjson u "$until" --argjson m "$((10#$m))" --argjson sync "$sync" \
        '{success: true, id: $id, paused_until: (if $m == 0 then null else ($u | todate) end), sync: $sync}')"
}

# POST /dns/technitium/safesearch — SafeSearch and YouTube's restricted mode for the whole house: {safe_search: true|false, youtube: off|moderate|strict}. Google, Bing and DuckDuckGo answer their safe names; Technitium cannot do it per group
handle_technitium_safesearch() {
    _api_check_admin || { _api_error 403 "Admin access required"; return; }
    _tt_need_primary || return
    local body model sync
    _tt_body "${1:-}" || return; body="$TT_REQ"
    jq -e '((has("safe_search") | not) or (.safe_search | type) == "boolean") and ((has("youtube") | not) or (.youtube | IN("off", "moderate", "strict")))' >/dev/null <<< "$body" \
        || { _api_error 400 "Send {\"safe_search\": true|false, \"youtube\": \"off\"|\"moderate\"|\"strict\"}"; return; }
    model=$(jq -c --argjson b "$body" '.house += ($b | with_entries(select(.key == "safe_search" or .key == "youtube")))' <<< "$(_tt_model)")
    _tt_model_save "$model" || { _api_error 500 "Could not write $TT_GROUPS"; return; }
    _tt_forced_apply primary || { _api_error 502 "$TT_ERR"; return; }
    _api_audit_log "${CLIENT_IP:-unknown}" "TECHNITIUM_SAFESEARCH" "${AUTH_USERNAME:-}" "$(jq -r '"SafeSearch \(if .house.safe_search then "on" else "off" end), YouTube \(.house.youtube)"' <<< "$model")"
    sync=$(_tt_after_write)
    _api_success "$(jq -nc --argjson h "$(jq -c .house <<< "$model")" --argjson w "$(_tt_forced_want)" --argjson sync "$sync" '{success: true, house: $h, forced: $w, sync: $sync}')"
}

# POST /dns/technitium/sync — Make the secondary what the primary is: settings (forwarders, lists, cache), the allowed and blocked names, the apps and their configs, the forced SafeSearch names
handle_technitium_sync() {
    _api_check_admin || { _api_error 403 "Admin access required"; return; }
    _tt_need_primary || return
    _tt_configured secondary || { _api_error 409 "No secondary is connected: connect it on the Technitium page"; return; }
    _api_cache_clear 2>/dev/null || true
    if _tt_sync; then
        _api_audit_log "${CLIENT_IP:-unknown}" "TECHNITIUM_SYNC" "${AUTH_USERNAME:-}" "secondary synced"
        _api_success "$(jq -nc --arg m "$TT_SYNC_MSG" '{success: true, message: $m}')"
    else
        _api_error 502 "The sync stopped: $TT_SYNC_MSG"
    fi
}

# POST /dns/technitium/connect — Connect an instance: {url: "http://192.168.2.53:5380", token (a Technitium API token; kept as the secret TECHNITIUM_TOKEN or TECHNITIUM_SECONDARY_TOKEN; leave it out to keep the stored one), role: primary|secondary}. Saves, then tests it; url "" disconnects
handle_technitium_connect() {
    _api_check_admin || { _api_error 403 "Admin access required"; return; }
    local body role url tok
    _tt_body "${1:-}" || return; body="$TT_REQ"
    role=$(jq -r '.role // "primary" | tostring' <<< "$body"); url=$(jq -r '.url // "" | tostring' <<< "$body"); tok=$(jq -r '.token // "" | tostring' <<< "$body")
    url="${url%/}"
    _tt_role_ok "$role" || { _api_error 400 "role is primary or secondary"; return; }
    if [[ -z "$url" ]]; then
        _api_env_write "$(_tt_url_key "$role")" "" || { _api_error 500 "Could not write .env"; return; }
        secrets_delete "$(_tt_secret "$role")" >/dev/null 2>&1 || true
        _api_audit_log "${CLIENT_IP:-unknown}" "TECHNITIUM_CONNECT" "${AUTH_USERNAME:-}" "$role disconnected"
        _api_cache_clear 2>/dev/null || true
        _api_success "$(jq -nc --arg r "$role" '{success: true, role: $r, connected: false}')"
        return
    fi
    _tt_url_valid "$url" || { _api_error 400 "The address is http://host:5380 (Technitium's web console: a host or an IP and its port, no path)"; return; }
    if [[ -n "$tok" ]]; then
        _tt_token_valid "$tok" || { _api_error 400 "That is not a Technitium API token: paste the token itself (letters and digits, about 64)"; return; }
    elif _tt_tok_load "$role"; [[ -z "${TT_TOK[$role]}" ]]; then
        _api_error 400 "Paste the API token: in Technitium, your name at the top right → Create API Token"; return
    fi
    _api_env_write "$(_tt_url_key "$role")" "$url" || { _api_error 500 "Could not write .env"; return; }
    if [[ -n "$tok" ]]; then secrets_set "$(_tt_secret "$role")" "$tok" 2>/dev/null || { _api_error 500 "Could not store the token in the secrets store"; return; }; TT_TOK[$role]="$tok"; fi
    _api_audit_log "${CLIENT_IP:-unknown}" "TECHNITIUM_CONNECT" "${AUTH_USERNAME:-}" "$role $url"
    _api_cache_clear 2>/dev/null || true
    if _tt_api "$role" settings/get; then
        _api_success "$(jq -c --arg r "$role" --arg u "$url" '{success: true, role: $r, url: $u, connected: true, reachable: true, version: .response.version, domain: .response.dnsServerDomain,
            message: ("Connected to Technitium " + (.response.version // "") + " (" + (.response.dnsServerDomain // $u) + ")")}' <<< "$TT_BODY")"
    else
        _api_success "$(jq -nc --arg r "$role" --arg u "$url" --arg e "$TT_ERR" '{success: true, role: $r, url: $u, connected: true, reachable: false, error: $e,
            message: ("Saved, but the test failed: " + $e)}')"
    fi
}

# POST /dns/technitium/bootstrap — Apply the house's baseline to an instance (role: primary, secondary, or both by default): Quad9 and Mullvad over TLS, one at a time, DNSSEC validation, no IPv6 preference, Hagezi Pro + TIF + DoH bypass lists updated daily (lists already there stay), the query log for 30 days (Query Logs (Sqlite)), the Advanced Blocking app, dns1/dns2 as its name, a 20000-entry cache. Changes only what differs: a second run changes nothing
handle_technitium_bootstrap() {
    _api_check_admin || { _api_error 403 "Admin access required"; return; }
    _tt_need_primary || return
    local body roles role out='{}' cur want changed set k v new_apps ql qlw errs=()
    _tt_body "${1:-}" || return; body="$TT_REQ"
    roles=$(jq -r '.role // "both"' <<< "$body")
    case "$roles" in both) roles=$(_tt_roles) ;; primary|secondary) _tt_configured "$roles" || { _api_error 409 "The $roles Technitium is not connected"; return; } ;; *) _api_error 400 "role is primary, secondary or both"; return ;; esac
    for role in $roles; do
        new_apps=()
        if ! _tt_api "$role" settings/get; then errs+=("$TT_ERR"); continue; fi
        cur=$(jq -c '.response' <<< "$TT_BODY")
        want=$(jq -c --argjson b "$TT_BASELINE" --argjson lists "$TT_BASE_LISTS" --arg dom "$([[ "$role" == primary ]] && printf dns1 || printf dns2)" \
            '$b + {dnsServerDomain: $dom, blockListUrls: ((.blockListUrls // []) + ($lists - (.blockListUrls // [])))}' <<< "$cur")
        changed=$(jq -c --argjson w "$want" '. as $c | [$w | keys[] | select(($c[.] | tostring) != ($w[.] | tostring))]' <<< "$cur")
        set=()
        while IFS=$'\t' read -r k v; do set+=("$k=$v"); done < <(jq -r --argjson ch "$changed" '. as $w | $ch[] | [., ($w[.] | if type == "array" then join(",") else tostring end)] | @tsv' <<< "$want")
        if (( ${#set[@]} > 0 )); then _tt_api "$role" settings/set "${set[@]}" || { errs+=("$TT_ERR"); continue; }; fi
        _tt_app_ensure "$role" "$TT_QL_APP" || { errs+=("$TT_ERR"); continue; }
        (( TT_INSTALLED == 1 )) && new_apps+=("$TT_QL_APP")
        _tt_app_config "$role" "$TT_QL_APP" || { errs+=("$TT_ERR"); continue; }
        ql="$TT_CFG"
        qlw=$(jq -c '. + {enableLogging: true, maxLogDays: 30, maxLogRecords: 1000000}' <<< "${ql:-{\}}")
        _tt_app_config_put "$role" "$TT_QL_APP" "$qlw" || { errs+=("$TT_ERR"); continue; }
        (( TT_DID == 1 )) && changed=$(jq -c '. + ["query log: 30 days"]' <<< "$changed")
        _tt_app_ensure "$role" "$TT_ADV_APP" || { errs+=("$TT_ERR"); continue; }
        (( TT_INSTALLED == 1 )) && new_apps+=("$TT_ADV_APP")
        _tt_app_config_put "$role" "$TT_ADV_APP" "$(_tt_adv_render "$(_tt_bedtime_now "$(_tt_now)")")" || { errs+=("$TT_ERR"); continue; }
        (( TT_DID == 1 )) && changed=$(jq -c '. + ["advanced blocking: the groups"]' <<< "$changed")
        out=$(jq -c --arg r "$role" --argjson ch "$changed" --argjson in "$(printf '%s\n' "${new_apps[@]}" | jq -R -s -c 'split("\n") | map(select(length > 0))')" \
            '. + {($r): {changed: $ch, installed: $in}}' <<< "$out")
    done
    _api_cache_clear 2>/dev/null || true
    _api_audit_log "${CLIENT_IP:-unknown}" "TECHNITIUM_BOOTSTRAP" "${AUTH_USERNAME:-}" "$(jq -r 'to_entries | map("\(.key): \(.value.changed | length) changed, \(.value.installed | length) installed") | join("; ")' <<< "$out")"
    if (( ${#errs[@]} > 0 )); then
        _api_response 502 "$(jq -nc --argjson r "$out" --arg e "${errs[*]}" '{error: true, code: 502, message: ("The baseline is not complete: " + $e), roles: $r}')"
        return
    fi
    _api_success "$(jq -c '{success: true, roles: ., unchanged: (map(.changed + .installed | length) | add == 0)}' <<< "$out")"
}

# =============================================================================
# The device directory: every device of the house, named once
#
# .data/technitium/devices.json {devices: [...], forgotten: {id: {nickname, icon, notes}}, last_scan, last_sweep}. A device
# is one record keyed by its MAC (id: the 12 hex digits) or, while no MAC is known, by its address (id: ip-<address>):
# {id, ip, mac, mac_random, vendor, hostname, nickname, icon, icon_guessed, notes, static, reserved_ip, blocked_until,
#  first_seen, last_seen, queries_today, blocked_today, hub, sources: {dhcp, arp, mdns, rdns, querylog, manual}} (sources:
# when that source last saw it, epoch seconds). Which kids' group a device is in lives in groups.json (a group device
# carries the directory id), so the two cannot disagree. IPv4 only: an IPv6 client of the query log is not a device here.
#
# The scan (POST /dns/technitium/devices/scan, and the minute clock every 5 minutes) merges: Technitium's DHCP leases and
# reservations; the hub's neighbour table after one ping to each address of its own /24 (a private network only, at most
# once per 5 minutes: the hub is on the LAN, so this finds MACs while the router still does DHCP); names over mDNS
# (avahi-resolve-address, when installed) and reverse DNS on the primary; the clients of the query log (the last 24 hours,
# with how many of their queries were blocked). The vendor comes from the MAC's prefix (.config/oui-common.txt, or IEEE's
# whole list once POST /dns/technitium/devices/oui-update fetched it).
# =============================================================================

TT_DEVICES="$TT_DIR/devices.json"
TT_ICONS='["desktop","laptop","phone","tablet","tv","console","speaker","camera","printer","router","server","iot","lightbulb","thermostat","watch","car","unknown"]'
# the Advanced Blocking group a device blocked by hand is in (a group name of DCS's own: a kids' group cannot have a colon)
TT_BLOCKED_GROUP="DCS: blocked devices"
TT_SWEEP_EVERY=300
TT_DEV_ID_RE='^([0-9a-f]{12}|ip-[0-9]{1,3}(\.[0-9]{1,3}){3})$'

# the icon a device most likely is, from its vendor and its name (a guess until the owner picks one)
# shellcheck disable=SC2016  # jq, not shell
TT_GUESS_JQ='def guess($vv; $hh):
  ($vv // "" | ascii_downcase) as $v | ($hh // "" | ascii_downcase) as $h
  | if ($h | test("xbox|playstation|ps[345]|nintendo|switch|steam-?deck")) or ($v | test("nintendo|playstation|valve")) then "console"
    elif $h | test("ipad|tablet|galaxy-?tab|sm-[tx][0-9]|kindle|fire-?hd|lenovo-?tab|(^|[-_])tab([-_0-9]|$)") then "tablet"
    elif $h | test("iphone|pixel|android|galaxy|oneplus|phone|moto") then "phone"
    elif $h | test("macbook|laptop|notebook|thinkpad|xps|zenbook|chromebook") then "laptop"
    elif ($h | test("watch")) or ($v | test("garmin|fitbit")) then "watch"
    elif ($h | test("(^|[-_.])tv([-_.0-9]|$)|bravia|roku|chromecast|fire-?tv|apple-?tv|shield|webos|tizen")) or ($v | test("\\b(roku|lg|vizio|hisense|tcl|skyworth|vestel|insignia)\\b")) then "tv"
    elif ($h | test("echo|homepod|sonos|speaker|nest-?(mini|audio|hub)|google-?home")) or ($v | test("sonos|bose|denon|yamaha|harman|onkyo")) then "speaker"
    elif ($h | test("cam|doorbell")) or ($v | test("\\b(ring|arlo|wyze|hikvision|dahua|reolink|blink|ezviz|canary)\\b")) then "camera"
    elif ($h | test("print|^brn|^npi|epson|officejet|laserjet")) or ($v | test("\\b(brother|canon|epson|xerox|lexmark|kyocera|ricoh|konica|zebra|dymo)\\b")) then "printer"
    elif ($h | test("router|gateway|unifi|eero|homehub|^hub|access-?point|^ap-")) or ($v | test("\\b(ubiquiti|tp-link|netgear|d-link|linksys|eero|mikrotik|zyxel|tenda|mercusys|arris|sagemcom|technicolor|sercomm|askey|plume|vantiva)\\b")) then "router"
    elif ($h | test("server|nas|pve|proxmox|raspberrypi|^pi[0-9-]|^dns[0-9]")) or ($v | test("raspberry|synology|qnap|proxmox|hardkernel|pine64")) then "server"
    elif ($h | test("bulb|light|hue")) or ($v | test("philips hue|lifx|nanoleaf|sengled|wiz|yeelight|govee|lutron")) then "lightbulb"
    elif ($h | test("thermostat|ecobee")) or ($v | test("ecobee|google nest|honeywell|tado|mysa|netatmo")) then "thermostat"
    elif $v | test("\\b(tesla|ford)\\b") then "car"
    elif $h | test("imac|mac-?mini|desktop|-pc$|^pc-|workstation|gaming") then "desktop"
    elif $v | test("espressif|tuya|shelly|sonoff|meross|aqara|silicon labs|nordic|particle|arduino|irobot|ecovacs|roborock|dreame|dyson|whirlpool|bosch|miele|electrolux|haier|midea|chamberlain|rachio|traeger") then "iot"
    elif ($v | test("microsoft")) and ($h | test("surface")) then "laptop"
    else "unknown" end;'
# IPv4 as a number, a mask's prefix
# shellcheck disable=SC2016
TT_IP4_JQ='def ip4ok: type == "string" and test("^([0-9]{1,3}\\.){3}[0-9]{1,3}$") and (split(".") | all(tonumber <= 255));
def ip2n: split(".") | map(tonumber) | .[0] * 16777216 + .[1] * 65536 + .[2] * 256 + .[3];
def n2ip: [(. / 16777216 | floor) % 256, (. / 65536 | floor) % 256, (. / 256 | floor) % 256, . % 256] | map(tostring) | join(".");'

_tt_dir() {
    mkdir -p "$TT_DIR" 2>/dev/null; chmod 700 "$TT_DIR" 2>/dev/null || true
    _api_state_file "$TT_DEVICES" '{"devices":[],"forgotten":{}}' object >/dev/null 2>&1 || true
    jq -c '{devices: (.devices // []), forgotten: (.forgotten // {}), last_scan: (.last_scan // null), last_sweep: (.last_sweep // 0)}' "$TT_DEVICES" 2>/dev/null \
        || printf '{"devices":[],"forgotten":{},"last_scan":null,"last_sweep":0}'
}
# _tt_dir_update [jq opts] FILTER: one locked change of devices.json
_tt_dir_update() { _tt_dir >/dev/null; _api_jq_update_file "$TT_DEVICES" "$@"; }
_tt_mac_dash() { local m="${1^^}"; printf '%s' "${m//:/-}"; }

# the ids of the devices blocked by hand at NOW, sorted (JSON); their addresses
_tt_blocked_now() { [[ -s "$TT_DEVICES" ]] || { printf '[]'; return 0; }; jq -c --argjson now "$1" '[.devices[]? | select((.blocked_until // 0) > $now and .ip != null) | .id] | sort' "$TT_DEVICES" 2>/dev/null || printf '[]'; }
_tt_blocked_ips() { [[ -s "$TT_DEVICES" ]] || { printf '[]'; return 0; }; jq -c --argjson now "$1" '[.devices[]? | select((.blocked_until // 0) > $now and .ip != null) | .ip] | unique' "$TT_DEVICES" 2>/dev/null || printf '[]'; }

# the hub's own network: "DEV ADDRESS PREFIX GATEWAY" from the default route (status 1 when there is none)
_tt_hub_net() {
    local r dev gw cidr
    r=$(ip -4 route show default 2>/dev/null | head -n1)
    [[ -n "$r" ]] || return 1
    dev=$(awk '{for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit }}' <<< "$r")
    gw=$(awk '{for (i = 1; i < NF; i++) if ($i == "via") { print $(i + 1); exit }}' <<< "$r")
    [[ "$dev" =~ ^[A-Za-z0-9_.@-]{1,32}$ ]] || return 1
    cidr=$(ip -4 -o addr show dev "$dev" 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "inet") { print $(i + 1); exit }}')
    [[ "$cidr" =~ ^([0-9]{1,3}(\.[0-9]{1,3}){3})/([0-9]{1,2})$ ]] || return 1
    printf '%s %s %s %s\n' "$dev" "${BASH_REMATCH[1]}" "${BASH_REMATCH[3]}" "${gw:--}"
}
_tt_private4() { [[ "$1" =~ ^10\. || "$1" =~ ^192\.168\. || "$1" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]]; }

# _tt_neighbours NOW: the LAN as the hub sees it, one "ADDRESS<TAB>MAC<TAB>hub|-" line each (the hub itself included). Pings
# every address of the hub's /24 first (once, 0.2 s each, 64 at a time) when the hub is on a private network and the last
# sweep is 5 minutes old; TT_SWEPT=1 when it did.
TT_SWEPT=0
_tt_neighbours() {
    local now="$1" net dev self prefix last base i mac pids=()
    TT_SWEPT=0
    net=$(_tt_hub_net) || return 0
    read -r dev self prefix _ <<< "$net"
    last=$(jq -r '.last_sweep // 0' "$TT_DEVICES" 2>/dev/null) || last=0
    [[ "$last" =~ ^[0-9]+$ ]] || last=0
    if _tt_private4 "$self" && (( prefix >= 16 && now - last >= TT_SWEEP_EVERY )) && command -v ping >/dev/null 2>&1; then
        base="${self%.*}"
        _tt_dir_update --argjson t "$now" '.last_sweep = $t' >/dev/null 2>&1 || true
        for i in $(seq 1 254); do
            [[ "$base.$i" == "$self" ]] && continue
            timeout 0.2 ping -n -q -c 1 -W 1 "$base.$i" >/dev/null 2>&1 & pids+=("$!")
            (( ${#pids[@]} >= 64 )) && { wait "${pids[@]}"; pids=(); }
        done
        (( ${#pids[@]} > 0 )) && wait "${pids[@]}"
        TT_SWEPT=1
    fi
    mac=$(ip -o link show dev "$dev" 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "link/ether") { print $(i + 1); exit }}')
    printf '%s\t%s\thub\n' "$self" "${mac:--}"
    ip -4 neigh show dev "$dev" 2>/dev/null | awk '{ st = $NF; if (st == "FAILED" || st == "INCOMPLETE") next; for (i = 1; i < NF; i++) if ($i == "lladdr") { print $1 "\t" $(i + 1) "\t-"; next } }'
}

# _tt_vendors MACS (a JSON array) → {"aabbcc": "Apple", …} for the prefixes the table knows
_tt_vendors() {
    local f="$BASE_DIR/.config/oui-common.txt"
    [[ -s "$TT_DIR/oui.txt" ]] && f="$TT_DIR/oui.txt"
    jq -r '.[] | select(test("^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")) | gsub(":"; "") | .[0:6] | ascii_upcase' <<< "$1" | sort -u \
        | awk -F'\t' 'NR == FNR { want[$1] = 1; next } ($1 in want) { print $1 "\t" $2 }' - "$f" 2>/dev/null \
        | jq -R -s -c 'split("\n") | map(select(length > 0) | split("\t")) | map({key: (.[0] | ascii_downcase), value: .[1]}) | from_entries'
}

# the primary's DHCP scopes with their details (JSON array) in TT_SCOPES; status 1 (TT_ERR) when Technitium did not answer
TT_SCOPES='[]'
_tt_scopes() {
    local list s one
    TT_SCOPES='[]'
    _tt_api primary dhcp/scopes/list || return 1
    list=$(jq -c '.response.scopes // []' <<< "$TT_BODY")
    while IFS= read -r s; do
        [[ -n "$s" ]] || continue
        _tt_api primary dhcp/scopes/get "name=$s" || return 1
        one=$(jq -c '.response' <<< "$TT_BODY")
        TT_SCOPES=$(jq -c --argjson l "$list" --arg n "$s" --argjson g "$one" '. + [($l | map(select(.name == $n))[0] // {}) + $g]' <<< "$TT_SCOPES")
    done < <(jq -r '.[].name' <<< "$list")
}

# _tt_scan WHO: one discovery (one at a time: a second waits for the first). TT_SCAN_SUMMARY is what it found (JSON).
TT_SCAN_SUMMARY='{}'
_tt_scan() {
    mkdir -p "$TT_DIR" 2>/dev/null || true
    { flock -w 90 9 || { TT_SCAN_SUMMARY='{"error":"Another scan is still running"}'; return 1; }; _tt_scan_locked "$@"; } 9>"$TT_DIR/.scan.lock"
}
_tt_scan_locked() {
    local who="${1:-dcs}" now obs='[]' serrs='[]' resv='{}' dhcp_ok=false ql_ok=false serving=false role ips ip name n line a m h me
    now=$(_tt_now)
    _tt_dir >/dev/null
    local o; o=$(mktemp "${TMPDIR:-/tmp}/dcs-tt-obs-XXXXXX") || return 1
    # (a) Technitium's DHCP: its leases (the names devices give themselves) and its reservations (static)
    if _tt_configured primary; then
        if _tt_scopes; then
            dhcp_ok=true
            resv=$(jq -c '[.[] | .reservedLeases // [] | .[] | {key: (.hardwareAddress | ascii_downcase | gsub("-"; ":")), value: .address}] | from_entries' <<< "$TT_SCOPES")
            serving=$(jq -c 'any(.[]; .enabled == true)' <<< "$TT_SCOPES")
            if _tt_api primary dhcp/leases/list; then
                jq -c '.response.leases // [] | .[] | {src: "dhcp", ip: .address, mac: .hardwareAddress, hostname: (.hostName // null)}' <<< "$TT_BODY" >> "$o"
            fi
        else
            serrs=$(jq -c --arg e "$TT_ERR" '. + [$e]' <<< "$serrs")
        fi
        # (d) who asked, the last 24 hours, on every server: the queries, and the blocked ones from the query log
        for role in $(_tt_roles); do
            if _tt_api "$role" dashboard/stats/getTop type=LastDay statsType=TopClients limit=1000; then
                ql_ok=true
                jq -c '.response.topClients // [] | .[] | {src: "querylog", ip: .name, hits: (.hits // 0)},
                       (select((.domain // "") != "") | {src: "rdns", ip: .name, hostname: .domain})' <<< "$TT_BODY" >> "$o"
            fi
            if _tt_api "$role" logs/query "name=$TT_QL_APP" "classPath=$TT_QL_CLASS" pageNumber=1 entriesPerPage=10000 descendingOrder=true \
                    responseType=Blocked "start=$(date -u -d "@$((now - 86400))" +%Y-%m-%dT%H:%M:%SZ)"; then
                jq -c '[.response.entries // [] | .[] | .clientIpAddress] | group_by(.) | .[] | {src: "querylog", ip: .[0], blocked: length}' <<< "$TT_BODY" >> "$o"
            fi
        done
    fi
    # (b) the neighbour table, after the sweep
    me=$(hostname -s 2>/dev/null || hostname 2>/dev/null || true)
    _tt_neighbours "$now" > "$o.n"
    while IFS=$'\t' read -r a m h; do
        [[ -n "$a" ]] || continue
        jq -nc --arg ip "$a" --arg mac "$m" --arg h "$h" --arg me "$me" '{src: "arp", ip: $ip, mac: (if $mac == "-" then null else $mac end), hub: ($h == "hub")}
            + (if $h == "hub" and $me != "" then {hostname: $me} else {} end)' >> "$o"
    done < "$o.n"
    rm -f "$o.n"
    obs=$(jq -s -c '
        def ok4: type == "string" and test("^([0-9]{1,3}\\.){3}[0-9]{1,3}$") and (test("^(127\\.|0\\.|169\\.254\\.|22[4-9]\\.|2[3-5][0-9]\\.)") | not) and (endswith(".255") | not);
        map(select(.ip | ok4))' "$o" 2>/dev/null) || obs='[]'
    rm -f "$o"
    # (c) names for the addresses that have none yet: mDNS, then reverse DNS on the primary (24 at most a scan)
    ips=$(jq -r --slurpfile d "$TT_DEVICES" '(map(select(.hostname != null) | .ip) + ($d[0].devices // [] | map(select(.hostname != null) | .ip))) as $named
        | [.[] | select(.src == "arp" or .src == "dhcp") | .ip] | unique | map(select(. as $i | $named | index($i) | not)) | .[]' <<< "$obs")
    if [[ -n "$ips" ]] && command -v avahi-resolve-address >/dev/null 2>&1; then
        # shellcheck disable=SC2086  # one address a word
        while IFS=$'\t' read -r a name; do
            [[ -n "$a" && -n "$name" ]] || continue
            obs=$(jq -c --arg ip "$a" --arg h "$name" '. + [{src: "mdns", ip: $ip, hostname: $h}]' <<< "$obs")
        done < <(timeout 5 avahi-resolve-address $ips 2>/dev/null)
    fi
    if [[ -n "$ips" ]] && _tt_configured primary; then
        n=0
        for ip in $ips; do
            jq -e --arg ip "$ip" 'any(.[]; .ip == $ip and .hostname != null)' >/dev/null <<< "$obs" && continue
            (( n++ < 24 )) || break
            IFS=. read -r a m h line <<< "$ip"
            TT_CALL_TIMEOUT=2 _tt_api primary dnsClient/resolve server=this-server "domain=$line.$h.$m.$a.in-addr.arpa" type=PTR protocol=Udp || continue
            name=$(jq -r '[.response.result.Answer // [] | .[] | .RDATA.Domain // .RDATA.Value // empty][0] // empty' <<< "$TT_BODY" 2>/dev/null)
            [[ -n "$name" ]] && obs=$(jq -c --arg ip "$ip" --arg h "$name" '. + [{src: "rdns", ip: $ip, hostname: $h}]' <<< "$obs")
        done
    fi
    local vend
    vend=$(_tt_vendors "$(jq -c '[.[] | .mac // empty | ascii_downcase | gsub("-"; ":")] | unique' <<< "$obs")") || vend='{}'
    [[ -n "$vend" ]] || vend='{}'
    _tt_dir_update --argjson obs "$obs" --argjson now "$now" --argjson vend "$vend" --argjson resv "$resv" --argjson dhcp_ok "$dhcp_ok" \
        --argjson ql_ok "$ql_ok" --argjson errs "$serrs" --argjson swept "$( ((TT_SWEPT)) && echo true || echo false)" "$TT_GUESS_JQ"'
        def nmac: if . == null or . == "" then null else (ascii_downcase | gsub("-"; ":")) | (if test("^([0-9a-f]{2}:){5}[0-9a-f]{2}$") and . != "00:00:00:00:00:00" then . else null end) end;
        def randmac: . != null and (.[1:2] | test("[26ae]"));
        def vendor_of($m): if $m == null then null elif ($m | randmac) then "Private address" else ($vend[$m | gsub(":"; "") | .[0:6]] // null) end;
        def host: if . == null then null else (rtrimstr(".") | if length == 0 or length > 253 then null else . end) end;
        ($obs | map(.mac |= nmac | .hostname |= host)) as $o
        | ($o | map(select(.mac != null)) | map({key: .ip, value: .mac}) | from_entries) as $ipmac
        | ($o | map(. + {key: (.mac // $ipmac[.ip] // ("ip-" + .ip))}) | group_by(.key) | map({
              mac: (map(.mac // empty) | first // null),
              ip: ((map(select(.src == "dhcp")) + map(select(.src == "arp")) + .) | map(.ip) | first),
              hostname: ((map(select(.src == "dhcp")) + map(select(.src == "mdns")) + map(select(.src == "rdns"))) | map(.hostname // empty) | first // null),
              hits: (map(.hits // 0) | add), blocked: (map(.blocked // 0) | add), hub: (map(.hub // false) | any),
              present: (map(.src) | any(. == "arp" or . == "mdns")), srcs: (map(.src) | unique)})) as $seen
        | .devices as $orig
        | reduce $seen[] as $s (. + {added: 0};
            (if $s.mac then ($s.mac | gsub(":"; "")) else "ip-" + $s.ip end) as $id
            | (.devices | map(.id) | index($id)) as $byid
            | (if $byid == null and $s.mac != null then (.devices | map(.id == ("ip-" + $s.ip)) | index(true)) else null end) as $byaddr
            # an address alone (the query log): the device that had that address before this scan, even if it moved since
            | (if $byid == null and $s.mac == null then ([$orig[] | select(.ip == $s.ip and .mac != null)] | max_by(.last_seen // 0) | .id) as $was
                 | (if $was == null then null else (.devices | map(.id) | index($was)) end) else null end) as $bymacip
            | ($byid // $byaddr // $bymacip) as $i
            # a MAC seen at an address that had a record of its own while no MAC was known: its names carry over
            | (if $s.mac != null then (.devices | map(select(.id == ("ip-" + $s.ip))) | first // {}) else {} end) as $old
            | (.forgotten[$id] // .forgotten["ip-" + $s.ip] // {}) as $f
            | (if $i != null then .devices[$i] else {first_seen: $now, sources: {}} end) as $d
            # seen by another sighting of this scan already: the counts add up; only a sighting on the LAN (neighbours, mDNS, a lease) moves it
            | (($d.sources // {}) | any(.[]; . == $now)) as $touched
            | ($s.present or ($s.srcs | index("dhcp")) != null or $d.ip == null) as $moves
            | ($d + {
                id: (if $s.mac then $id elif $i != null then $d.id else $id end),
                ip: (if $moves then $s.ip else $d.ip end), mac: ($s.mac // $d.mac // null),
                hostname: ($s.hostname // $d.hostname // $old.hostname // null),
                nickname: ($d.nickname // $old.nickname // $f.nickname // null),
                notes: ($d.notes // $old.notes // $f.notes // null),
                icon: ($d.icon // $old.icon // $f.icon // null),
                icon_guessed: (if $d.icon != null then ($d.icon_guessed // false) elif ($old.icon // $f.icon) != null then false else true end),
                last_seen: (if $s.present or $d.last_seen == null then $now else $d.last_seen end),
                queries_today: ((if $touched then ($d.queries_today // 0) else 0 end) + $s.hits),
                blocked_today: ((if $touched then ($d.blocked_today // 0) else 0 end) + $s.blocked), hub: ($s.hub or ($d.hub // false)),
                sources: (($d.sources // {}) + ($s.srcs | map({key: ., value: $now}) | from_entries))}) as $n
            | ($n + {vendor: vendor_of($n.mac), mac_random: ($n.mac | randmac)}) as $n
            | (if $n.icon_guessed then $n + {icon: (if $n.hub then "server" else guess($n.vendor; $n.hostname) end)} else $n end) as $n
            | (if $i != null then .devices[$i] = $n else .devices += [$n] | .added += 1 end)
            | (if $s.mac != null then .devices |= map(select(.id != ("ip-" + $s.ip))) else . end)
            | .forgotten |= del(.[$id], .["ip-" + $s.ip]))
        | .devices |= map(
            (if $ql_ok and ((.sources // {}) | any(.[]; . == $now) | not) then . + {queries_today: 0, blocked_today: 0} else . end)
            | (if $dhcp_ok then . + {static: (.mac != null and $resv[.mac] != null), reserved_ip: (if .mac != null then $resv[.mac] else null end)} else . end))
        | .last_scan = {at: $now, found: ($seen | length), new: .added, devices: (.devices | length), swept: $swept,
                        named_by_dhcp: ([$o[] | select(.src == "dhcp" and .hostname != null)] | length),
                        sources: ($o | group_by(.src) | map({key: .[0].src, value: (map(.ip) | unique | length)}) | from_entries),
                        errors: $errs}
        | del(.added)' >/dev/null || { TT_SCAN_SUMMARY='{"error":"Could not write the device directory"}'; return 1; }
    _tt_state_set --argjson s "$serving" --argjson ok "$dhcp_ok" --argjson now "$now" 'if $ok then .dhcp = {serving: $s, at: $now} else . end'
    TT_SCAN_SUMMARY=$(jq -c '.last_scan' "$TT_DEVICES")
    # a device in a kids' group that moved to another address: the group follows it
    local model new
    model=$(_tt_model)
    new=$(jq -c --slurpfile d "$TT_DEVICES" '($d[0].devices | map({key: .id, value: .ip}) | from_entries) as $ip
        | .groups |= map(.devices |= map(if (.id // null) != null and $ip[.id] != null and $ip[.id] != .ip then .ip = $ip[.id] else . end))' <<< "$model") || new="$model"
    if [[ "$new" != "$model" ]]; then
        _tt_model_save "$new" && { _tt_groups_apply "$who" || printf '%s technitium: a group device moved, not applied: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$TT_APPLY_MSG" >&2; }
    fi
    return 0
}

# the minute clock, every 5 minutes: a scan in the background (the lock keeps two from running at once)
_tt_scan_tick() { _tt_scan scheduler >/dev/null 2>&1 || true; }

# GET /dns/technitium/devices — The device directory: every device seen (address, MAC and vendor, its name on the network, the nickname and icon given, notes, its kids' group, whether its address is reserved, a block until when, first and last seen, queries and blocked in the last 24 hours, which sources saw it), the last scan, whether Technitium hands out addresses, the icons to pick from
handle_technitium_devices() {
    local now
    now=$(_tt_now)
    _api_success "$(jq -c --argjson now "$now" --argjson m "$(_tt_model)" --argjson st "$(_tt_state)" --argjson icons "$TT_ICONS" '
        ([$m.groups[] as $g | $g.devices[] | select((.id // null) != null) | {key: .id, value: {id: $g.id, name: $g.name}}] | from_entries) as $gid
        | ([$m.groups[] as $g | $g.devices[] | {key: .ip, value: {id: $g.id, name: $g.name}}] | from_entries) as $gip
        | {devices: ([.devices[] | ($gid[.id] // $gip[.ip // ""] // null) as $g
              | . + {group_id: ($g.id // null), group_name: ($g.name // null), blocked: ((.blocked_until // 0) > $now)}]
              | sort_by(-(.queries_today // 0), ((.nickname // .hostname // .ip) | ascii_downcase))),
           forgotten: (.forgotten | length), last_scan, dhcp: ($st.dhcp // null), icons: $icons, now: $now}' <<< "$(_tt_dir)")"
}

# POST /dns/technitium/devices/scan — Look for devices now: Technitium's DHCP leases and reservations, the hub's neighbour table after one ping to each address of its own network (at most every 5 minutes), names over mDNS and reverse DNS, the clients of the query log. Answers what it found
handle_technitium_devices_scan() {
    _api_check_admin || { _api_error 403 "Admin access required"; return; }
    if ! _tt_scan "${AUTH_USERNAME:-}"; then _api_error 409 "$(jq -r '.error // "The scan did not finish"' <<< "$TT_SCAN_SUMMARY")"; return; fi
    _api_audit_log "${CLIENT_IP:-unknown}" "TECHNITIUM_SCAN" "${AUTH_USERNAME:-}" "$(jq -r '"\(.found) devices found, \(.new) new"' <<< "$TT_SCAN_SUMMARY")"
    _api_cache_clear 2>/dev/null || true
    _api_success "$(jq -c '{success: true} + . + {message: ("\(.found) device\(if .found == 1 then "" else "s" end) found, \(.named_by_dhcp) named by DHCP")}' <<< "$TT_SCAN_SUMMARY")"
}

# POST /dns/technitium/devices/oui-update — Fetch IEEE's whole list of MAC prefixes (oui.csv, about 6 MB) so every vendor has its name; kept in .data/technitium/oui.txt
handle_technitium_oui_update() {
    _api_check_admin || { _api_error 403 "Admin access required"; return; }
    local url="${DCS_TECHNITIUM_OUI_URL:-https://standards-oui.ieee.org/oui/oui.csv}" tmp n
    mkdir -p "$TT_DIR"; tmp=$(mktemp "$TT_DIR/.oui-XXXXXX") || { _api_error 500 "Could not write in $TT_DIR"; return; }
    if ! curl -sSfL --proto '=https,http' --max-time 120 --max-filesize 40000000 -A "DCS-Orchestrator" -o "$tmp" "$url" 2>/dev/null; then
        rm -f "$tmp"; _api_error 502 "IEEE's list could not be downloaded ($url): can this server reach the internet?"; return
    fi
    if ! head -n1 "$tmp" | grep -q '^Registry,Assignment,Organization Name'; then rm -f "$tmp"; _api_error 502 "That was not IEEE's list of MAC prefixes"; return; fi
    # Registry,Assignment,"Organization Name",…: the assignment and the name (quoted when it has a comma), as "PREFIX<TAB>Name"
    awk 'NR > 1 { a = $0; i = index(a, ","); a = substr(a, i + 1); j = index(a, ","); p = substr(a, 1, j - 1); r = substr(a, j + 1)
             if (substr(r, 1, 1) == "\"") { r = substr(r, 2); k = index(r, "\""); nm = substr(r, 1, k - 1) } else { k = index(r, ","); nm = (k ? substr(r, 1, k - 1) : r) }
             gsub(/[\t\r]/, " ", nm); sub(/^ +/, "", nm); sub(/ +$/, "", nm)
             if (length(p) == 6 && p !~ /[^0-9A-F]/ && nm != "") print p "\t" nm }' "$tmp" | sort -u > "$tmp.txt"
    rm -f "$tmp"
    n=$(wc -l < "$tmp.txt")
    (( n >= 1000 )) || { rm -f "$tmp.txt"; _api_error 502 "IEEE's list had only $n prefixes: kept the one there was"; return; }
    mv -f "$tmp.txt" "$TT_DIR/oui.txt"; chmod 600 "$TT_DIR/oui.txt" 2>/dev/null || true
    _api_audit_log "${CLIENT_IP:-unknown}" "TECHNITIUM_OUI" "${AUTH_USERNAME:-}" "IEEE MAC prefixes updated: $n"
    _api_success "$(jq -nc --argjson n "$n" '{success: true, prefixes: $n, message: "The vendors of \($n) MAC prefixes are known now"}')"
}

# PUT /dns/technitium/devices/{id} — Change a device: {nickname (40 at most, "" clears), icon (desktop, laptop, phone, tablet, tv, console, speaker, camera, printer, router, server, iot, lightbulb, thermostat, watch, car, unknown), notes (280 at most), group_id (a kids' group, or null for none), static (true reserves its address in Technitium's DHCP, false gives it back), blocked_until (epoch seconds within a year: every name blocked for it until then; null lifts it)}
handle_technitium_device_update() {
    _api_check_admin || { _api_error 403 "Admin access required"; return; }
    local id="$1" body d now bad ip mac scope need_apply=0 model gid sync warn="" did=()
    _tt_body "${2:-}" || return; body="$TT_REQ"
    d=$(jq -c --arg id "$id" '.devices[] | select(.id == $id)' <<< "$(_tt_dir)")
    [[ -n "$d" ]] || { _api_error 404 "No device $id: scan the network, or it was forgotten"; return; }
    now=$(_tt_now)
    bad=$(jq -r --argjson icons "$TT_ICONS" --argjson now "$now" '
        def txt($n): type == "string" and length <= $n and (test("[\\x00-\\x1f\\x7f]") | not);
        def note: type == "string" and length <= 280 and (test("[\\x00-\\x08\\x0b-\\x1f\\x7f]") | not);
        (keys - ["nickname", "icon", "notes", "group_id", "static", "blocked_until"]) as $extra
        | if ($extra | length) > 0 then "Not a field of a device: \($extra | join(", "))"
          elif has("nickname") and .nickname != null and ((.nickname | txt(40)) | not) then "A nickname is 40 characters at most, on one line"
          elif has("icon") and ((.icon as $i | $icons | index($i)) == null) then "icon is one of: \($icons | join(", "))"
          elif has("notes") and .notes != null and ((.notes | note) | not) then "Notes are 280 characters at most"
          elif has("group_id") and .group_id != null and ((.group_id | type) != "string" or (.group_id | test("^[A-Za-z0-9_-]{1,40}$") | not)) then "group_id is a kids group id, or null"
          elif has("static") and (.static | type) != "boolean" then "static is true or false"
          elif has("blocked_until") and .blocked_until != null and ((.blocked_until | type) != "number" or .blocked_until <= $now or .blocked_until > $now + 31622400)
            then "blocked_until is a moment within the next year (epoch seconds), or null to lift the block"
          else "" end' <<< "$body")
    [[ -z "$bad" ]] || { _api_error 400 "$bad"; return; }
    ip=$(jq -r '.ip // empty' <<< "$d"); mac=$(jq -r '.mac // empty' <<< "$d")
    if jq -e 'has("group_id") or has("static") or has("blocked_until")' >/dev/null <<< "$body"; then _tt_need_primary || return; fi
    model=$(_tt_model)
    gid=$(jq -r '.group_id // empty' <<< "$body")
    if [[ -n "$gid" ]]; then jq -e --arg g "$gid" 'any(.groups[]; .id == $g)' >/dev/null <<< "$model" || { _api_error 404 "No kids group $gid"; return; }; fi
    if jq -e 'has("group_id") or (.blocked_until != null)' >/dev/null <<< "$body" && [[ -z "$ip" ]]; then _api_error 409 "This device has no address yet: scan the network first"; return; fi
    # static: a reservation in the Technitium scope its address belongs to
    if jq -e 'has("static")' >/dev/null <<< "$body"; then
        [[ -n "$mac" ]] || { _api_error 409 "DCS does not know this device's MAC address yet, and a reservation needs it: scan the network while it is on"; return; }
        _tt_scopes || { _api_error 502 "$TT_ERR"; return; }
        scope=$(jq -r --arg ip "$ip" "$TT_IP4_JQ"'($ip | ip2n) as $a | [.[] | select(($a >= (.networkAddress | ip2n)) and ($a <= (.broadcastAddress | ip2n)))][0].name // empty' <<< "$TT_SCOPES")
        if [[ -z "$scope" ]]; then
            _api_response 409 "$(jq -nc --arg ip "$ip" '{error: true, code: 409, reason: "no_dhcp_scope", message: ("Technitium has no DHCP scope for " + $ip + ": the router still hands out addresses. Move DHCP here first (the DHCP tab), then pin it.")}')"
            return
        fi
        local cur dn
        dn=$(jq -c --argjson b "$body" '. + ($b | with_entries(select(.key == "nickname" and .value != null and .value != "")))' <<< "$d")   # the name being given now
        cur=$(jq -r --arg m "$(_tt_mac_dash "$mac")" --arg s "$scope" '.[] | select(.name == $s) | .reservedLeases // [] | .[] | select(.hardwareAddress == $m) | .address' <<< "$TT_SCOPES")
        if [[ "$(jq -r .static <<< "$body")" == true ]]; then
            if [[ "$cur" != "$ip" ]]; then
                [[ -n "$cur" ]] && { _tt_api primary dhcp/scopes/removeReservedLease "name=$scope" "hardwareAddress=$(_tt_mac_dash "$mac")" || { _api_error 502 "$TT_ERR"; return; }; }
                local hn rargs=("name=$scope" "hardwareAddress=$(_tt_mac_dash "$mac")" "ipAddress=$ip" "comments=DCS: $(jq -r '.nickname // .hostname // .ip' <<< "$dn")")
                hn=$(jq -r '((.nickname // .hostname // "") | ascii_downcase | gsub("[^a-z0-9]+"; "-") | ltrimstr("-") | rtrimstr("-"))[0:63]' <<< "$dn")
                [[ -n "$hn" ]] && rargs+=("hostName=$hn")
                _tt_api primary dhcp/scopes/addReservedLease "${rargs[@]}" || { _api_error 502 "$TT_ERR"; return; }
            fi
            did+=("reserved $ip in $scope")
        elif [[ -n "$cur" ]]; then
            _tt_api primary dhcp/scopes/removeReservedLease "name=$scope" "hardwareAddress=$(_tt_mac_dash "$mac")" || { _api_error 502 "$TT_ERR"; return; }
            did+=("reservation removed")
        fi
    fi
    # the directory's own fields
    _tt_dir_update --arg id "$id" --argjson b "$body" --argjson now "$now" '
        def clean: if . == null then null else (gsub("^\\s+|\\s+$"; "") | if . == "" then null else . end) end;
        .devices |= map(if .id != $id then . else
            . + ($b | with_entries(select(.key == "nickname" or .key == "notes")) | map_values(clean))
              + (if $b | has("icon") then {icon: $b.icon, icon_guessed: false} else {} end)
              + (if $b | has("static") then {static: $b.static, reserved_ip: (if $b.static then .ip else null end)} else {} end)
              + (if $b | has("blocked_until") then {blocked_until: $b.blocked_until} else {} end)
              + {sources: ((.sources // {}) + {manual: $now})} end)' || { _api_error 500 "Could not write $TT_DEVICES"; return; }
    d=$(jq -c --arg id "$id" '.devices[] | select(.id == $id)' "$TT_DEVICES")
    jq -e 'has("nickname")' >/dev/null <<< "$body" && did+=("nickname $(jq -r '.nickname // "cleared"' <<< "$d")")
    jq -e 'has("icon")' >/dev/null <<< "$body" && did+=("icon $(jq -r .icon <<< "$d")")
    jq -e 'has("notes")' >/dev/null <<< "$body" && did+=("notes")
    # its kids' group: out of every group (by id or address), into the one asked for
    if jq -e 'has("group_id")' >/dev/null <<< "$body"; then
        model=$(jq -c --argjson d "$d" --arg g "$gid" '
            .groups |= map(.devices |= map(select(((.id // null) == $d.id or .ip == $d.ip) | not)))
            | if $g == "" then . else .groups |= map(if .id == $g then .devices += [{ip: $d.ip, label: (($d.nickname // (($d.hostname // "") | split(".")[0]) // "") | .[0:40]),
                  mac: $d.mac, id: $d.id}] else . end) end' <<< "$model")
        _tt_model_save "$model" || { _api_error 500 "Could not write $TT_GROUPS"; return; }
        need_apply=1; did+=("group ${gid:-none}")
    fi
    if jq -e 'has("blocked_until")' >/dev/null <<< "$body"; then
        need_apply=1
        did+=("$(jq -r 'if .blocked_until == null then "block lifted" else "blocked until \(.blocked_until | todate)" end' <<< "$body")")
    fi
    if (( need_apply == 1 )); then
        _tt_groups_apply "${AUTH_USERNAME:-}" || warn="Saved in DCS, but Technitium did not take it: $TT_APPLY_MSG (it is tried again by the minute clock)"
    fi
    _api_audit_log "${CLIENT_IP:-unknown}" "TECHNITIUM_DEVICE" "${AUTH_USERNAME:-}" "$(jq -r '.nickname // .hostname // .ip' <<< "$d") ($id): ${did[*]:-nothing}"
    sync=null; (( need_apply == 1 )) && [[ -z "$warn" ]] && sync=$(_tt_after_write)
    _api_cache_clear 2>/dev/null || true
    _api_success "$(jq -nc --argjson d "$d" --argjson sync "${sync:-null}" --arg w "$warn" --argjson m "$(_tt_model)" '
        ([$m.groups[] | select(any(.devices[]; (.id // null) == $d.id or .ip == $d.ip))][0] // null) as $g
        | {success: true, device: ($d + {group_id: ($g.id // null), group_name: ($g.name // null)}), sync: $sync, warning: (if $w == "" then null else $w end)}')"
}

# DELETE /dns/technitium/devices/{id} — Forget a device: it comes back when it is seen again, with the nickname, icon and notes it had (until the forgotten ones are cleared)
handle_technitium_device_forget() {
    _api_check_admin || { _api_error 403 "Admin access required"; return; }
    local id="$1" d
    d=$(jq -c --arg id "$id" '.devices[] | select(.id == $id)' <<< "$(_tt_dir)")
    [[ -n "$d" ]] || { _api_error 404 "No device $id"; return; }
    _tt_dir_update --arg id "$id" --argjson d "$d" '.devices |= map(select(.id != $id))
        | if ($d.nickname // $d.notes // (if $d.icon_guessed then null else $d.icon end)) != null
          then .forgotten[$id] = {nickname: $d.nickname, notes: $d.notes, icon: (if $d.icon_guessed then null else $d.icon end)} else . end' \
        || { _api_error 500 "Could not write $TT_DEVICES"; return; }
    _api_audit_log "${CLIENT_IP:-unknown}" "TECHNITIUM_DEVICE" "${AUTH_USERNAME:-}" "forgot $(jq -r '.nickname // .hostname // .ip' <<< "$d") ($id)"
    _api_success "$(jq -nc --arg id "$id" '{success: true, forgotten: $id}')"
}

# DELETE /dns/technitium/devices/forgotten — Clear what DCS keeps of forgotten devices (their nicknames, icons and notes)
handle_technitium_forgotten_clear() {
    _api_check_admin || { _api_error 403 "Admin access required"; return; }
    local n
    n=$(jq -r '.forgotten | length' <<< "$(_tt_dir)")
    _tt_dir_update '.forgotten = {}' || { _api_error 500 "Could not write $TT_DEVICES"; return; }
    _api_audit_log "${CLIENT_IP:-unknown}" "TECHNITIUM_DEVICE" "${AUTH_USERNAME:-}" "cleared $n forgotten devices"
    _api_success "$(jq -nc --argjson n "$n" '{success: true, cleared: $n}')"
}

# =============================================================================
# DHCP: Technitium's own DHCP server, and moving the house's DHCP to it
# =============================================================================

# the address of an instance when its URL is an IPv4 one (what the devices are told to use)
_tt_url_ip4() { local u; u=$(_tt_url "$1"); u="${u#*://}"; u="${u%%:*}"; [[ "$u" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && printf '%s' "$u"; return 0; }

# GET /dns/technitium/dhcp — Technitium's DHCP: its scopes (range, gateway, DNS servers, lease time, exclusions, reservations, enabled), the leases it gave (with the DNS servers each device was told), whether it hands out addresses, the hub's network and a scope made from it, and how many of the devices seen ask Technitium
handle_technitium_dhcp() {
    _tt_need_primary || return
    local leases net dev self prefix gw sug='null' hub='null'
    _tt_scopes || { _api_error 502 "$TT_ERR"; return; }
    _tt_api primary dhcp/leases/list || { _api_error 502 "$TT_ERR"; return; }
    leases=$(jq -c '.response.leases // []' <<< "$TT_BODY")
    if net=$(_tt_hub_net); then
        read -r dev self prefix gw <<< "$net"
        hub=$(jq -nc --arg ip "$self" --argjson p "$prefix" --arg gw "$gw" --arg dev "$dev" '{ip: $ip, prefix: $p, gateway: (if $gw == "-" then null else $gw end), interface: $dev}')
        sug=$(jq -nc --arg ip "$self" --arg gw "$gw" --arg d1 "$(_tt_url_ip4 primary)" --arg d2 "$(_tt_url_ip4 secondary)" '
            ($ip | split(".")[0:3] | join(".")) as $b
            | {name: "LAN", start: ($b + ".100"), end: ($b + ".199"), mask: "255.255.255.0", router: (if $gw == "-" then ($b + ".1") else $gw end),
               dns: ([$d1, $d2] | map(select(. != ""))), domain: "home", lease_hours: 24, exclusions: [], ping_check: true, reserve_known: true}')
    fi
    _api_success "$(jq -c -n --argjson scopes "$TT_SCOPES" --argjson leases "$leases" --argjson hub "$hub" --argjson sug "$sug" --argjson dir "$(_tt_dir)" \
        --argjson now "$(_tt_now)" --arg d1 "$(_tt_url_ip4 primary)" --arg d2 "$(_tt_url_ip4 secondary)" '
        def mac: ascii_downcase | gsub("-"; ":");
        ($dir.devices | map(select(.mac != null) | {key: .mac, value: .}) | from_entries) as $bymac
        | ($scopes | map({key: .name, value: (.dnsServers // [])}) | from_entries) as $sdns
        | ($dir.devices | map(select(($now - (.last_seen // 0)) < 86400 or (.queries_today // 0) > 0))) as $recent
        | {enabled: any($scopes[]; .enabled == true),
           scopes: [$scopes[] | {name, enabled: (.enabled == true), start: .startingAddress, end: .endingAddress, mask: .subnetMask, network: .networkAddress,
                    broadcast: .broadcastAddress, router: .routerAddress, dns: (if .useThisDnsServer == true then ["this server"] else (.dnsServers // []) end),
                    domain: .domainName, lease_hours: (((.leaseTimeDays // 0) * 24) + (.leaseTimeHours // 0)), exclusions: (.exclusions // []), ping_check: (.pingCheckEnabled == true),
                    reservations: [.reservedLeases // [] | .[] | (.hardwareAddress | mac) as $m
                        | {mac: $m, ip: .address, hostname: .hostName, comments, device_id: ($bymac[$m].id // null), nickname: ($bymac[$m].nickname // null)}]}],
           leases: [$leases[] | (.hardwareAddress | mac) as $m
                    | {scope, type, mac: $m, ip: .address, hostname: .hostName, obtained: .leaseObtained, expires: .leaseExpires, dns: ($sdns[.scope] // []),
                       device_id: ($bymac[$m].id // null), nickname: ($bymac[$m].nickname // null), icon: ($bymac[$m].icon // null)}],
           hub: $hub, suggested: $sug, resolvers: {primary: (if $d1 == "" then null else $d1 end), secondary: (if $d2 == "" then null else $d2 end)},
           devices: {seen: ($recent | length), asking: ($recent | map(select((.queries_today // 0) > 0)) | length),
                     silent: [$recent[] | select((.queries_today // 0) == 0) | {id, ip, nickname, hostname, icon}]}}')"
}

# POST /dns/technitium/dhcp/scope — Make or change the house's DHCP scope in Technitium: {name: "LAN", start, end, mask, router, dns: [the primary, the secondary], domain: "home", lease_hours: 24, exclusions: [{start, end}], ping_check: true (an address that answers a ping is not offered), reserve_known: true (every device of the directory with a MAC keeps its current address: a reservation each, so nothing moves when DHCP does; false leaves them)}. A new scope is left off: POST /dns/technitium/dhcp/enable turns it on
handle_technitium_dhcp_scope() {
    _api_check_admin || { _api_error 403 "Admin access required"; return; }
    _tt_need_primary || return
    local body bad name exists dflt created=false rd=() reserved=0 skipped='[]' row m ip
    _tt_body "${1:-}" || return; body="$TT_REQ"
    bad=$(jq -r "$TT_IP4_JQ"'
        (.mask // "255.255.255.0") as $mask
        | if (.name // "LAN" | type) != "string" or ((.name // "LAN") | test("^[A-Za-z0-9 ._-]{1,40}$") | not) then "name is letters, digits, spaces, . _ and - (40 at most)"
          elif ([.start, .end, .router, $mask] | all(ip4ok) | not) then "start, end and router are IPv4 addresses (and mask, 255.255.255.0 when left out)"
          elif (($mask | ip2n) as $n | ([range(0; 33)] | map(4294967296 - pow(2; 32 - .)) | index($n)) == null) then "mask is a network mask, like 255.255.255.0"
          elif ((.start | ip2n) > (.end | ip2n)) then "start comes before end"
          elif ([.start, .end, .router] | map((ip2n / (4294967296 - ($mask | ip2n))) | floor) | unique | length) != 1 then "start, end and router are in one network"
          elif ((.dns // []) | type) != "array" or ((.dns // []) | length) < 1 or ((.dns // []) | length) > 3 or ((.dns // []) | all(ip4ok) | not) then "dns is one to three IPv4 addresses: the primary first"
          elif ((.domain // "home") | type) != "string" or ((.domain // "home") | test("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$") | not) then "domain is a name like home or lan"
          elif ((.lease_hours // 24) | type) != "number" or (.lease_hours // 24) < 1 or (.lease_hours // 24) > 720 or ((.lease_hours // 24) | floor) != (.lease_hours // 24) then "lease_hours is 1 to 720"
          elif has("ping_check") and (.ping_check | type) != "boolean" then "ping_check is true or false"
          elif has("reserve_known") and (.reserve_known | type) != "boolean" then "reserve_known is true or false"
          elif ((.exclusions // []) | type) != "array" or ((.exclusions // []) | length) > 16
               or ((.exclusions // []) | any((([.start, .end] | all(ip4ok)) | not) or ((.start | ip2n) > (.end | ip2n)))) then "exclusions are up to 16 {start, end}"
          else "" end' <<< "$body" 2>/dev/null) || bad="Send the scope: {start, end, router, dns: [...]}"
    [[ -z "$bad" ]] || { _api_error 400 "$bad"; return; }
    name=$(jq -r '.name // "LAN"' <<< "$body")
    _tt_scopes || { _api_error 502 "$TT_ERR"; return; }
    exists=$(jq -r --arg n "$name" 'any(.[]; .name == $n)' <<< "$TT_SCOPES")
    # a new scope: Technitium turns a scope on when it makes it; its stock "Default" scope is off, so it becomes this one (off) instead
    dflt=$(jq -r --arg n "$name" 'if any(.[]; .name == $n) then "" else ([.[] | select(.name == "Default" and .enabled != true)][0].name // "") end' <<< "$TT_SCOPES")
    local args=("name=${dflt:-$name}")
    [[ -n "$dflt" ]] && args+=("newName=$name")
    while IFS= read -r row; do args+=("$row"); done < <(jq -r '
        "startingAddress=\(.start)", "endingAddress=\(.end)", "subnetMask=\(.mask // "255.255.255.0")", "routerAddress=\(.router)",
        "leaseTimeDays=\(((.lease_hours // 24) / 24) | floor)", "leaseTimeHours=\((.lease_hours // 24) % 24)", "leaseTimeMinutes=0",
        "useThisDnsServer=false", "dnsServers=\(.dns | join(","))", "domainName=\(.domain // "home")", "pingCheckEnabled=\(.ping_check != false)",
        "exclusions=\((.exclusions // []) | map("\(.start)|\(.end)") | join("|"))"' <<< "$body")
    _tt_api primary dhcp/scopes/set "${args[@]}" || { _api_error 502 "$TT_ERR"; return; }
    if [[ "$exists" != true && -z "$dflt" ]]; then
        created=true
        _tt_api primary dhcp/scopes/disable "name=$name" || { _api_error 502 "The scope is made but Technitium did not turn it off: $TT_ERR"; return; }
    fi
    # every device the directory knows (a lease, or only the hub's neighbour table) keeps its address: a reservation each, named or
    # not, so nothing moves when DHCP does (one device an address: the one seen last; the ones already reserved stay as they are)
    if [[ "$(jq -r '.reserve_known != false' <<< "$body")" == true ]]; then
        _tt_scopes || { _api_error 502 "$TT_ERR"; return; }
        while IFS=$'\t' read -r m ip row; do
            [[ -n "$m" ]] || continue
            local ra=("name=$name" "hardwareAddress=$(_tt_mac_dash "$m")" "ipAddress=$ip" "comments=DCS: ${row:-$ip}")
            [[ -n "$row" ]] && ra+=("hostName=$row")
            if _tt_api primary dhcp/scopes/addReservedLease "${ra[@]}"; then
                reserved=$((reserved + 1)); rd+=("$m")
            else
                skipped=$(jq -c --arg ip "$ip" --arg e "$TT_ERR" '. + [{ip: $ip, error: $e}]' <<< "$skipped")
            fi
        done < <(jq -r --arg n "$name" --argjson sc "$TT_SCOPES" "$TT_IP4_JQ"'
            ($sc | map(select(.name == $n))[0]) as $s
            | ($s.reservedLeases // [] | map(.hardwareAddress | ascii_downcase | gsub("-"; ":"))) as $have
            | [.devices[] | select(.mac != null and .ip != null and (.ip | ip4ok))
               | select((.ip | ip2n) > ($s.networkAddress | ip2n) and (.ip | ip2n) < ($s.broadcastAddress | ip2n))]
            | group_by(.ip) | map(max_by(.last_seen // 0)) | .[]
            | select(.mac as $m | $have | index($m) | not)
            | [.mac, .ip, ((.nickname // ((.hostname // "") | split(".")[0]) // "") | ascii_downcase | gsub("[^a-z0-9]+"; "-") | ltrimstr("-") | rtrimstr("-") | .[0:63])] | @tsv' <<< "$(_tt_dir)")
        if (( ${#rd[@]} > 0 )); then
            _tt_dir_update --argjson r "$(printf '%s\n' "${rd[@]}" | jq -R -s -c 'split("\n") | map(select(length > 0))')" \
                '.devices |= map(if (.mac as $m | $r | index($m)) != null then . + {static: true, reserved_ip: .ip} else . end)' || true
        fi
    fi
    _tt_scopes || true
    _api_audit_log "${CLIENT_IP:-unknown}" "TECHNITIUM_DHCP" "${AUTH_USERNAME:-}" "scope $name $( [[ "$exists" == true ]] && printf 'changed' || printf 'made (off)'): $(jq -r '"\(.start)-\(.end), gateway \(.router), DNS \(.dns | join(" "))"' <<< "$body"), $reserved reserved"
    _api_cache_clear 2>/dev/null || true
    _api_success "$(jq -nc --arg n "$name" --argjson sc "$TT_SCOPES" --argjson created "$created" --argjson renamed "$([[ -n "$dflt" ]] && echo true || echo false)" \
        --argjson r "$reserved" --argjson sk "$skipped" '($sc | map(select(.name == $n))[0] // {}) as $s
        | {success: true, scope: $n, created: ($created or $renamed), enabled: ($s.enabled == true), reserved: $r, skipped: $sk,
           message: ("The scope \($n) is " + (if $created or $renamed then "made" else "saved" end) + (if $s.enabled == true then " and hands out addresses" else ", off until you turn it on" end)
                     + (if $r > 0 then "; \($r) device\(if $r == 1 then "" else "s" end) keep their address" else "" end))}')"
}

# POST /dns/technitium/dhcp/enable — Technitium hands out addresses from now on: {name} (the house's scope when left out). Turn the router's DHCP off first
handle_technitium_dhcp_enable() { _tt_dhcp_switch enable "${1:-}"; }
# POST /dns/technitium/dhcp/disable — Technitium stops handing out addresses: {name} (the house's scope when left out)
handle_technitium_dhcp_disable() { _tt_dhcp_switch disable "${1:-}"; }
_tt_dhcp_switch() {
    _api_check_admin || { _api_error 403 "Admin access required"; return; }
    _tt_need_primary || return
    local how="$1" body name
    _tt_body "${2:-}" || return; body="$TT_REQ"
    _tt_scopes || { _api_error 502 "$TT_ERR"; return; }
    name=$(jq -r --argjson b "$body" 'if ($b.name // "") != "" then ([.[] | select(.name == $b.name)][0].name // "")
        elif any(.[]; .name == "LAN") then "LAN" elif length == 1 then .[0].name else "" end' <<< "$TT_SCOPES")
    [[ -n "$name" ]] || { _api_error 404 "No such DHCP scope: name the scope (there is more than one, or none yet)"; return; }
    _tt_api primary "dhcp/scopes/$how" "name=$name" || { _api_error 502 "$TT_ERR"; return; }
    _tt_state_set --argjson s "$([[ "$how" == enable ]] && echo true || echo false)" --argjson now "$(_tt_now)" '.dhcp = {serving: $s, at: $now}'
    _api_audit_log "${CLIENT_IP:-unknown}" "TECHNITIUM_DHCP" "${AUTH_USERNAME:-}" "scope $name ${how}d"
    _api_cache_clear 2>/dev/null || true
    _api_success "$(jq -nc --arg n "$name" --arg h "$how" '{success: true, scope: $n, enabled: ($h == "enable"),
        message: (if $h == "enable" then "Technitium hands out addresses now: devices move over as their leases renew" else "Technitium no longer hands out addresses" end)}')"
}

# DELETE /dns/technitium/dhcp/leases/{mac} — End a lease Technitium gave (the device asks again; a reservation stays)
handle_technitium_dhcp_lease_delete() {
    _api_check_admin || { _api_error 403 "Admin access required"; return; }
    _tt_need_primary || return
    local mac="$1" scope
    _tt_api primary dhcp/leases/list || { _api_error 502 "$TT_ERR"; return; }
    scope=$(jq -r --arg m "$(_tt_mac_dash "$mac")" '[.response.leases // [] | .[] | select((.hardwareAddress | ascii_upcase) == $m)][0].scope // empty' <<< "$TT_BODY")
    [[ -n "$scope" ]] || { _api_error 404 "Technitium has no lease for $mac"; return; }
    _tt_api primary dhcp/leases/remove "name=$scope" "hardwareAddress=$(_tt_mac_dash "$mac")" || { _api_error 502 "$TT_ERR"; return; }
    _api_audit_log "${CLIENT_IP:-unknown}" "TECHNITIUM_DHCP" "${AUTH_USERNAME:-}" "lease of $mac ended ($scope)"
    _api_success "$(jq -nc --arg m "$mac" --arg s "$scope" '{success: true, mac: $m, scope: $s}')"
}
