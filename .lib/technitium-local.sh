#!/bin/bash
# shellcheck shell=bash
# =============================================================================
# Technitium: local names (sourced by .lib/technitium.sh)
#
# 1. "Resolve my routes locally" (split horizon, POST /dns/technitium/local {routes: true}): inside the house a route's name
#    answers the hub's LAN address, so jellyfin.howson.dev no longer goes out to Cloudflare and back. One Primary zone PER
#    ROUTE HOST (jellyfin.howson.dev is a zone whose apex is an A record to the hub, TTL 60, comment "dcs-local"), never a
#    zone for the domain: a Primary zone is authoritative, so a howson.dev zone would answer NXDOMAIN for every name DCS does
#    not route; a zone per host leaves anything-else.howson.dev to the forwarders. Only hosts under the domains DCS serves
#    (the proxy's and PROXY_DOMAINS_EXTRA), never the domain's apex. Every route is fronted by the hub's Traefik (a VM's
#    route too: fleet-members.yml), so every host answers the hub's address. Both servers get the zones.
# 2. Names for the house's devices: the DHCP scope registers every lease as <hostname>.<domain> (Technitium's dnsUpdates;
#    it makes the zone itself), and a device's nickname adds <slug>.<domain> (an A record of DCS's, comment "dcs-name", in
#    the same zone, made by DCS when DHCP has not made it). No PTR: a reverse zone here would hide the router's own reverse
#    names, which the device scan reads. The secondary (DNS only, no DHCP) holds that zone as a Secondary zone transferred
#    from the primary (NOTIFY on every change): the lease names reach it too, which copying DCS's own records would not do.
#
# State: .data/technitium/local-zones.json {routes, zones: {primary: {host: ip}, secondary: {…}}, names: {fqdn: ip},
#   zone, transfer, last: {at, ok, message}}. DCS removes only what it tracks there (a zone the owner made stays).
# The minute clock (_tt_local_tick) diffs and writes nothing when nothing changed; a route or domain change runs it at once.
# =============================================================================

# shellcheck disable=SC2034
TECHNITIUM_LOCAL_LOADED=1
TT_LOCAL="$TT_DIR/local-zones.json"
TT_LOCAL_TTL=60
TT_NAME_TTL=300
TT_LOCAL_TAG="dcs-local"
TT_NAME_TAG="dcs-name"
TT_HOST_RE='^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'

_tt_local_state() {
    _api_state_file "$TT_LOCAL" '{}' object >/dev/null 2>&1 || true
    jq -c '{routes: (.routes == true), zones: (.zones // {}), names: (.names // {}), zone: (.zone // "home"), transfer: (.transfer // ""), last: (.last // null)}' \
        "$TT_LOCAL" 2>/dev/null || printf '{"routes":false,"zones":{},"names":{},"zone":"home","transfer":"","last":null}'
}
_tt_local_set() { mkdir -p "$TT_DIR" 2>/dev/null; _tt_local_state >/dev/null; _api_jq_update_file "$TT_LOCAL" "$@"; }

# the hub's LAN address (its default route's), empty when it has none
_tt_local_ip() { local n ip; n=$(_tt_hub_net) || return 0; read -r _ ip _ <<< "$n"; printf '%s' "$ip"; }

# {host: ip} the routes want: every Host(`…`) of the route files under a domain DCS serves (not the domain itself)
_tt_local_want_routes() {
    local ip="$1" dir doms
    [[ -n "$ip" ]] || { printf '{}'; return 0; }
    dir=$(_find_traefik_routes_dir 2>/dev/null)
    [[ -n "$dir" && -d "$dir" ]] || { printf '{}'; return 0; }
    doms=$(_domains_all 2>/dev/null | jq -R -s -c 'split("\n") | map(select(length > 0))') || doms='[]'
    grep -rohsE --include='*.yml' --include='*.yaml' 'Host\(`[^`]+`\)' "$dir" | sed -E 's/^Host\(`//; s/`\)$//' | tr '[:upper:]' '[:lower:]' \
        | jq -R -s -c --argjson doms "$doms" --arg ip "$ip" --arg re "$TT_HOST_RE" '
            split("\n") | map(select(test($re))) | unique
            | map(select(. as $h | any($doms[]; . as $d | $h | endswith("." + $d)))) | map({key: ., value: $ip}) | from_entries'
}

# the zone the house's names live in: the domain of the scope that hands out addresses (else "home")
_tt_local_zone_of() { jq -r '([.[] | select(.enabled == true)][0].domainName // "") | if test("^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$") then . else "home" end' <<< "$1"; }

# {fqdn: ip} the nicknames want: a device with a nickname and an address, unless its "Also answer" switch is off (home_answer false);
# one name a slug (the device seen last wins)
_tt_local_want_names() {
    [[ -s "$TT_DEVICES" ]] || { printf '{}'; return 0; }
    jq -c --arg z "$1" '[.devices[]? | select(.nickname != null and .ip != null and .home_answer != false)
        | {slug: (.nickname | ascii_downcase | gsub("[^a-z0-9]+"; "-") | ltrimstr("-") | rtrimstr("-") | .[0:63] | rtrimstr("-")), ip, seen: (.last_seen // 0)}
        | select(.slug != "")] | group_by(.slug) | map(max_by(.seen)) | map({key: (.slug + "." + $z), value: .ip}) | from_entries' "$TT_DEVICES" 2>/dev/null || printf '{}'
}

# _tt_local_zones ROLE → {name: type} of the instance's zones in TT_ZONES
TT_ZONES='{}'
_tt_local_zones() { TT_ZONES='{}'; _tt_api "$1" zones/list || return 1; TT_ZONES=$(jq -c '[.response.zones // [] | .[] | {key: (.name | ascii_downcase), value: .type}] | from_entries' <<< "$TT_BODY"); }

# _tt_local_routes_role ROLE WANT: the route zones of one instance made what WANT says; the tracked ones that are not wanted go.
# Writes only what differs. TT_LOCAL_WARN collects zones left alone (one of the owner's of that name).
TT_LOCAL_WARN=()
_tt_local_routes_role() {
    local role="$1" want="$2" have h ip type mine
    have=$(jq -c --arg r "$role" '.zones[$r] // {}' <<< "$(_tt_local_state)")
    _tt_local_zones "$role" || return 1
    while IFS=$'\t' read -r h ip; do
        [[ -n "$h" ]] || continue
        type=$(jq -r --arg h "$h" '.[$h] // empty' <<< "$TT_ZONES")
        mine=$(jq -r --arg h "$h" '.[$h] // empty' <<< "$have")
        if [[ -n "$type" && -z "$mine" ]]; then
            # a zone of that name DCS does not track: DCS's own only when its apex carries DCS's tag (a crash before the state was saved)
            _tt_api "$role" zones/records/get "zone=$h" "domain=$h" || return 1
            if [[ "$type" != Primary ]] || ! jq -e --arg t "$TT_LOCAL_TAG" 'any(.response.records[]?; .type == "A" and .comments == $t)' >/dev/null <<< "$TT_BODY"; then
                TT_LOCAL_WARN+=("The $role Technitium has a zone $h of its own: DCS leaves it as it is"); continue
            fi
            mine="?"
        fi
        if [[ -z "$type" ]]; then
            _tt_api "$role" zones/create "zone=$h" type=Primary || return 1
        elif [[ "$mine" == "$ip" ]]; then
            continue
        fi
        _tt_api "$role" zones/records/add "zone=$h" "domain=$h" type=A "ipAddress=$ip" "ttl=$TT_LOCAL_TTL" overwrite=true "comments=$TT_LOCAL_TAG" || return 1
        _tt_local_set --arg r "$role" --arg h "$h" --arg ip "$ip" '.zones[$r][$h] = $ip' || return 1
    done < <(jq -r 'to_entries[] | [.key, .value] | @tsv' <<< "$want")
    while IFS= read -r h; do
        [[ -n "$h" ]] || continue
        type=$(jq -r --arg h "$h" '.[$h] // empty' <<< "$TT_ZONES")
        [[ "$type" == Primary ]] && { _tt_api "$role" zones/delete "zone=$h" || return 1; }
        _tt_local_set --arg r "$role" --arg h "$h" 'del(.zones[$r][$h])' || return 1
    done < <(jq -r --argjson w "$want" 'keys - ($w | keys) | .[]' <<< "$have")
    return 0
}

# the names on the primary: the zone (made when DHCP has not), DCS's records, the scopes' dynamic updates on; the secondary
# transfers the zone. ZONES is the primary's {name: type}.
_tt_local_names_apply() {
    local st zone want have h ip
    _tt_scopes || return 1
    # every scope that hands out addresses registers its leases (an older scope DCS made, or one made in Technitium's console)
    while IFS= read -r h; do
        [[ -n "$h" ]] || continue
        _tt_api primary dhcp/scopes/set "name=$h" dnsUpdates=true || return 1
    done < <(jq -r '.[] | select(.enabled == true and .dnsUpdates != true and (.domainName // "") != "") | .name' <<< "$TT_SCOPES")
    zone=$(_tt_local_zone_of "$TT_SCOPES")
    st=$(_tt_local_state)
    [[ "$(jq -r .zone <<< "$st")" == "$zone" ]] || _tt_local_set --arg z "$zone" '.zone = $z'
    want=$(_tt_local_want_names "$zone")
    have=$(jq -c --arg z "$zone" '.names | with_entries(select(.key | endswith("." + $z)))' <<< "$st")
    _tt_local_zones primary || return 1
    if [[ "$want" != '{}' && -z "$(jq -r --arg z "$zone" '.[$z] // empty' <<< "$TT_ZONES")" ]]; then
        _tt_api primary zones/create "zone=$zone" type=Primary || return 1
        TT_ZONES=$(jq -c --arg z "$zone" '. + {($z): "Primary"}' <<< "$TT_ZONES"); have='{}'
    fi
    if [[ "$(jq -r --arg z "$zone" '.[$z] // empty' <<< "$TT_ZONES")" == Primary ]]; then
        while IFS=$'\t' read -r h ip; do
            [[ -n "$h" ]] || continue
            _tt_api primary zones/records/add "zone=$zone" "domain=$h" type=A "ipAddress=$ip" "ttl=$TT_NAME_TTL" overwrite=true "comments=$TT_NAME_TAG" || return 1
            _tt_local_set --arg h "$h" --arg ip "$ip" '.names[$h] = $ip' || return 1
        done < <(jq -r --argjson h "$have" 'to_entries[] | select($h[.key] != .value) | [.key, .value] | @tsv' <<< "$want")
        while IFS=$'\t' read -r h ip; do
            [[ -n "$h" ]] || continue
            _tt_api primary zones/records/delete "zone=$zone" "domain=$h" type=A "ipAddress=$ip" || return 1
            _tt_local_set --arg h "$h" 'del(.names[$h])' || return 1
        done < <(jq -r --argjson w "$want" 'to_entries[] | select($w[.key] != .value) | [.key, .value] | @tsv' <<< "$have")
    elif [[ "$want" != '{}' ]]; then
        TT_LOCAL_WARN+=("The primary Technitium has a $(jq -r --arg z "$zone" '.[$z]' <<< "$TT_ZONES") zone $zone of its own: the devices' names are not written")
    fi
    # names written for another zone before the scope's domain changed: gone
    while IFS=$'\t' read -r h ip; do
        [[ -n "$h" ]] || continue
        _tt_api primary zones/records/delete "domain=$h" type=A "ipAddress=$ip" || true
        _tt_local_set --arg h "$h" 'del(.names[$h])' || return 1
    done < <(jq -r --arg z "$zone" '.names | to_entries[] | select(.key | endswith("." + $z) | not) | [.key, .value] | @tsv' <<< "$st")
    _tt_local_transfer "$zone"
}

# the secondary holds ZONE as a Secondary zone of the primary's (both connected by an IPv4 address: the transfer and NOTIFY need them)
_tt_local_transfer() {
    local zone="$1" p s want type
    _tt_configured secondary || return 0
    [[ -n "$(jq -r --arg z "$zone" '.[$z] // empty' <<< "$TT_ZONES")" ]] || return 0   # no zone yet (no lease, no nickname)
    p=$(_tt_url_ip4 primary); s=$(_tt_url_ip4 secondary)
    if [[ -z "$p" || -z "$s" ]]; then TT_LOCAL_WARN+=("The secondary gets the $zone zone by a zone transfer: connect both Technitiums by their IPv4 address"); return 0; fi
    want="$zone:$p>$s"
    if [[ "$(jq -r .transfer <<< "$(_tt_local_state)")" != "$want" ]]; then
        _tt_api primary zones/options/set "zone=$zone" zoneTransfer=UseSpecifiedNetworkACL "zoneTransferNetworkACL=$s" notify=SpecifiedNameServers "notifyNameServers=$s" || return 1
        _tt_local_set --arg t "$want" '.transfer = $t' || return 1
    fi
    _tt_local_zones secondary || return 1
    type=$(jq -r --arg z "$zone" '.[$z] // empty' <<< "$TT_ZONES")
    if [[ -z "$type" ]]; then
        _tt_api secondary zones/create "zone=$zone" type=Secondary "primaryNameServerAddresses=$p" || return 1
    elif [[ "$type" != Secondary ]]; then
        TT_LOCAL_WARN+=("The secondary Technitium has a $type zone $zone of its own: it does not get the devices' names")
    fi
    return 0
}

# _tt_local_apply: everything above on every connected instance, one at a time (a lock); the outcome in the state's "last".
# 0 when every instance took it; TT_ERR says why not.
_tt_local_apply() {
    mkdir -p "$TT_DIR" 2>/dev/null || true
    local rc
    { flock -w 60 8 || { TT_ERR="Another update of the local names is still running"; return 1; }; _tt_local_apply_locked; rc=$?; } 8>"$TT_DIR/.local.lock"
    return $rc
}
_tt_local_apply_locked() {
    local st want='{}' ip role err="" ok=true
    TT_LOCAL_WARN=()
    _tt_configured primary || return 0
    st=$(_tt_local_state)
    ip=$(_tt_local_ip)
    [[ "$(jq -r .routes <<< "$st")" == true ]] && want=$(_tt_local_want_routes "$ip")
    for role in $(_tt_roles); do
        _tt_local_routes_role "$role" "$want" || { err="${err:+$err; }$TT_ERR"; ok=false; }
    done
    _tt_local_names_apply || { err="${err:+$err; }$TT_ERR"; ok=false; }
    local msg="$err" w
    for w in "${TT_LOCAL_WARN[@]}"; do msg+="${msg:+; }$w"; done
    _tt_local_set --argjson at "$(date +%s)" --argjson ok "$ok" --arg m "$msg" '.last = {at: $at, ok: $ok, message: (if $m == "" then null else $m end)}' || true
    TT_ERR="$err"
    [[ "$ok" == true ]]
}

# the minute clock (and a route or domain change): nothing without a connected primary; no write when nothing changed
_tt_local_tick() {
    _tt_configured primary || return 0
    _tt_local_apply || printf '%s technitium: local names not applied: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$TT_ERR" >&2
    return 0
}

# the name a device answers to (JSON {id: fqdn}): its nickname's, else the one its Technitium lease registered
_tt_local_device_names() {
    local st zone dyn
    st=$(_tt_local_state); zone=$(jq -r .zone <<< "$st")
    dyn=$(jq -r '.dhcp.serving == true' <<< "$(_tt_state)")
    jq -c --argjson want "$(_tt_local_want_names "$zone")" --arg z "$zone" --argjson dyn "$dyn" '
        ($want | to_entries | map({key: .value, value: .key}) | group_by(.key) | map({key: .[0].key, value: map(.value)}) | from_entries) as $byip
        | [.devices[] | ((if .nickname != null and .home_answer != false then ((.nickname | ascii_downcase | gsub("[^a-z0-9]+"; "-") | ltrimstr("-") | rtrimstr("-") | .[0:63] | rtrimstr("-")) + "." + $z) else null end) as $n
            | if $n != null and $want[$n] == .ip then $n
              elif $dyn and (.sources.dhcp // null) != null and ((.hostname // "") | ascii_downcase | endswith("." + $z)) then (.hostname | ascii_downcase)
              else null end) as $name | select($name != null) | {key: .id, value: $name}] | from_entries' <<< "$(_tt_dir)"
}

# the routes of GET /routes with the address each answers inside the house (lan), when the switch is on
_tt_local_routes_decorate() {
    local st want='{}'
    st=$(_tt_local_state)
    [[ "$(jq -r .routes <<< "$st")" == true ]] && want=$(_tt_local_want_routes "$(_tt_local_ip)")
    jq -c --argjson w "$want" 'map(. + {lan: ($w[(.subdomain // "") | ascii_downcase] // null)})' <<< "$1"
}
_tt_local_summary() {
    jq -c -n --argjson st "$(_tt_local_state)" --arg ip "$(_tt_local_ip)" --argjson c "$(_tt_configured primary && echo true || echo false)" \
        '{available: $c, on: $st.routes, address: (if $ip == "" then null else $ip end), last: $st.last}'
}

# GET /dns/technitium/local — The local names: whether the routes resolve to the hub inside the house (routes), the hub's LAN address, each route host DCS answers (with the instances that have its zone), the devices' names (the zone, whether DHCP registers its leases, DCS's nickname names) and the last update
handle_technitium_local() {
    local st ip want='{}' zone
    st=$(_tt_local_state); ip=$(_tt_local_ip); zone=$(jq -r .zone <<< "$st")
    [[ "$(jq -r .routes <<< "$st")" == true ]] && want=$(_tt_local_want_routes "$ip")
    _api_success "$(jq -c -n --argjson st "$st" --arg ip "$ip" --argjson w "$want" --argjson names "$(_tt_local_want_names "$zone")" \
        --argjson dhcp "$(jq -c '.dhcp // null' <<< "$(_tt_state)")" --argjson c "$(_tt_configured primary && echo true || echo false)" '
        {available: $c, routes: $st.routes, address: (if $ip == "" then null else $ip end), ttl: '"$TT_LOCAL_TTL"',
         hosts: [$w | to_entries[] | .key as $h | {host: $h, ip: .value, instances: [$st.zones | to_entries[] | select(.value[$h] != null) | .key]}],
         names: {zone: $st.zone, dhcp: (($dhcp.serving // false) == true), nicknames: ($names | to_entries | map({name: .key, ip: .value})),
                 secondary: ($st.transfer != "")},
         last: $st.last}')"
}

# POST /dns/technitium/local — Resolve my routes locally: {routes: true|false}. On: every route host under this server's domains gets a zone of its own on both Technitiums whose answer is the hub's LAN address (TTL 60); the other names of the domain still resolve publicly. Off: exactly the zones DCS made go
handle_technitium_local_set() {
    _api_check_admin || { _api_error 403 "Admin access required"; return; }
    _tt_need_primary || return
    local body on
    _tt_body "${1:-}" || return; body="$TT_REQ"
    jq -e '(.routes | type) == "boolean"' >/dev/null <<< "$body" || { _api_error 400 "Send {\"routes\": true|false}"; return; }
    on=$(jq -r .routes <<< "$body")
    if [[ "$on" == true && -z "$(_tt_local_ip)" ]]; then _api_error 409 "This server has no default route, so DCS does not know its LAN address"; return; fi
    _tt_local_set --argjson on "$on" '.routes = $on' || { _api_error 500 "Could not write $TT_LOCAL"; return; }
    _api_audit_log "${CLIENT_IP:-unknown}" "TECHNITIUM_LOCAL" "${AUTH_USERNAME:-}" "routes resolve locally: $([[ "$on" == true ]] && echo on || echo off)"
    local ok=true
    _tt_local_apply || ok=false
    _api_cache_clear 2>/dev/null || true
    local st; st=$(_tt_local_state)
    if [[ "$ok" != true ]]; then
        _api_response 502 "$(jq -nc --arg m "$TT_ERR" --argjson on "$on" '{error: true, code: 502, routes: $on, message: ("Saved, but Technitium did not take it all: " + $m + " (the minute clock tries again)")}')"
        return
    fi
    _api_success "$(jq -c --argjson on "$on" '{success: true, routes: $on, zones: (.zones.primary // {} | length), warning: .last.message,
        message: (if $on then "Your routes resolve to this server inside the house: \(.zones.primary // {} | length) name\(if (.zones.primary // {} | length) == 1 then "" else "s" end)" else "Your routes resolve through the internet again" end)}' <<< "$st")"
}
