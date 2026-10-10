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
_tt_adv_render() {
    local active="$1" house
    house=$(_domains_all 2>/dev/null | jq -R -s -c 'split("\n") | map(select(length > 0))') || house='[]'
    jq -c --argjson active "$active" --argjson cats "$TT_CATEGORIES" --argjson house "$house" '
        {enableBlocking: true, blockingAnswerTtl: 30, blockListUrlUpdateIntervalHours: 24, blockListUrlUpdateIntervalMinutes: 0,
         localEndPointGroupMap: {},
         networkGroupMap: ([.groups[] as $g | $g.devices[]? | {key: .ip, value: $g.name}] | from_entries),
         groups: [.groups[] | (.id as $id | ($active | index($id)) != null) as $bed |
           {name, enableBlocking: true, allowTxtBlockingReport: true, blockAsNxDomain: true, blockingAddresses: ["0.0.0.0", "::"],
            allowed: (if $bed then $house else [] end), blocked: [], allowListUrls: [],
            blockListUrls: [(.lists // [])[] as $l | $cats[] | select(.id == $l) | .url],
            allowedRegex: [], blockedRegex: (if $bed then ["."] else [] end),
            regexAllowListUrls: [], regexBlockListUrls: [], adblockListUrls: []}]}' <<< "$(_tt_model)"
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

# the minute clock (_dcs_automation_loop): re-renders only when the set of groups in bedtime changed since the last render
_tt_tick() {
    [[ -s "$TT_GROUPS" ]] || return 0
    _tt_configured primary || return 0
    local now active was
    now=$(_tt_now); active=$(_tt_bedtime_now "$now") || return 0
    was=$(jq -c '.bedtime_active // []' <<< "$(_tt_state)" 2>/dev/null) || was='[]'
    [[ "$active" == "$was" ]] && return 0
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

# GET /dns/technitium/stats?range=lastHour|lastDay|lastWeek — Queries, blocked and clients over the range for both instances together: the totals, the series, the top clients (named after a group's device, else Technitium's name for it), domains and blocked domains, the query types
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
    labels=$(jq -c '[.groups[] as $g | $g.devices[]? | {key: .ip, value: (.label // $g.name)}] | from_entries' <<< "$(_tt_model)") || labels='{}'
    _api_success "$(jq -c --arg range "$range" --argjson errs "$errs" --argjson lab "$labels" '
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
         top_clients: (merge("topClients"; "ip") | map({ip, count, name: ($lab[.ip] // .rdns // null)})),
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
                devices: (.devices // [] | map({ip: (.ip | tostring), label: (.label // "" | tostring | gsub("^\\s+|\\s+$"; "")), mac: (if (.mac // "") == "" then null else (.mac | ascii_downcase) end)})),
                lists: (.lists // [] | unique),
                bedtime: {enabled: (.bedtime.enabled == true), from: (.bedtime.from // "20:30"), to: (.bedtime.to // "07:00"), days: (.bedtime.days // [1,2,3,4,5,6,7] | unique)}}
          end' <<< "$1" 2>/dev/null || printf '"Send a group: {name, devices: [{ip, label}], lists: [], bedtime: {enabled, from, to, days}}"'
}

# POST /dns/technitium/groups — Add a group, or change one ({id} of an existing one): {name, devices: [{ip, label, mac?}], lists: [adult, gambling, social, proxy-vpn, nosafesearch], bedtime: {enabled, from, to, days}}; Technitium's Advanced Blocking app gets it (installed when missing) and the secondary follows
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
