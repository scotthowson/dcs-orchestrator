#!/bin/bash
# shellcheck shell=bash
# =============================================================================
# The VPN — chosen containers through a WireGuard tunnel (Gluetun), nothing else
#
# The tunnel is the gluetun service of the networking-security stack, from the vpn-gluetun template (Gluetun's
# "custom" WireGuard provider). POST /vpn/connect fills it for Private Internet Access the way PIA's own
# manual-connections scripts do (Gluetun has no native PIA WireGuard): a token from the account, the regions that
# forward a port (the fastest by connect time when none is chosen), a fresh X25519 key registered with the server
# (addKey on :1337, checked against PIA's CA in .lib/vpn-pia-ca.crt), the answer written to the stack's .env
# (VPN_WG_*, VPN_SERVER_NAME, VPN_REGION) and the private key to the secret VPN_WG_PRIVATE_KEY. Gluetun does PIA's
# port forwarding itself (VPN_PORT_FORWARDING_PROVIDER, the account as SECRETS_VPN_USER / SECRETS_VPN_PASS).
#
# A container goes through it with PUT /containers/{name}/vpn {"on": true}: its service gets network_mode
# "container:Gluetun" (one marked line) in place of its ports, networks, hostname and DNS keys (kept in
# .data/vpn/<stack>--<service>.json and put back byte for byte by "off"), its ports move onto Gluetun (each line
# marked "# moved by DCS for <stack>/<service>", the ${VARS} filled from its own stack's .env), and its Traefik route
# points at Gluetun on the same port. Both files go through the compose policy; only the touched services are
# recreated. The kill switch is Gluetun's: its firewall lets nothing out but the tunnel.
#
# The minute clock (_vpn_tick): Gluetun restarted → the containers behind it restarted (recreated when Gluetun is a
# new container: they hold its old network); the tunnel down for 2 minutes → vpn_down; PIA's forwarded port → into
# qBittorrent (setPreferences listen_port; its login from the secrets QBITTORRENT_USER / QBITTORRENT_PASS when the
# web API asks for one); every 15 minutes a leak check (each container's address seen from outside must be the
# tunnel's) → vpn_leak; the WireGuard clients' route put back when a container lost it.
#
# Secrets reach curl on its standard input (a config), never a command line, a log or an answer.
# Loaded on demand (_vpn_lib in api-server.sh); the feature is VPN_ENABLED (Config → Integrations, off by default).
# =============================================================================

# shellcheck disable=SC2034  # read by the router (_vpn_lib in api-server.sh)
VPN_LOADED=1
VPN_DIR="$BASE_DIR/.data/vpn"
VPN_STATE="$VPN_DIR/state.json"
VPN_STACK="networking-security"
VPN_SERVICE="gluetun"
VPN_CONTAINER="Gluetun"
VPN_DOWN_AFTER=120
VPN_LEAK_EVERY=15                 # minutes
VPN_REKEY_AFTER=600               # down this long with a PIA account: a new key is registered (PIA forgets idle keys)
VPN_PY="$BASE_DIR/.lib/vpn-compose.py"
VPN_PIA_CA="$BASE_DIR/.lib/vpn-pia-ca.crt"
VPN_WG_TABLE=51821
VPN_WG_PREF=5211                  # before the main table's rule (32766): what comes in on wg0 is decided here first
VPN_PRIVATE_NETS="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"
VPN_RULES='[
 {"trigger":"vpn_down","enabled":true,"priority":"high","name":"VPN: the tunnel is down (the containers behind it are cut off)"},
 {"trigger":"vpn_leak","enabled":true,"priority":"high","name":"VPN: a container behind it shows the home address"}]'

_vpn_now() { if [[ "${DCS_VPN_NOW:-}" =~ ^[0-9]{9,11}$ ]]; then printf '%s' "$DCS_VPN_NOW"; else date +%s; fi; }
_vpn_state() { _api_state_file "$VPN_STATE" '{}' object >/dev/null 2>&1 || true; jq -c . "$VPN_STATE" 2>/dev/null || printf '{}'; }
_vpn_set() { (umask 077; mkdir -p "$VPN_DIR") 2>/dev/null; _api_state_file "$VPN_STATE" '{}' object >/dev/null 2>&1 || true; _api_jq_update_file "$VPN_STATE" "$@" || true; }
_vpn_compose_file() { printf '%s' "$COMPOSE_DIR/$VPN_STACK/docker-compose.yml"; }
_vpn_env() { envfile_get "$COMPOSE_DIR/$VPN_STACK/.env" "$1" 2>/dev/null || true; }
# the vpn-gluetun template is in the stack (its service and the line only it has)
_vpn_deployed() { local f; f=$(_vpn_compose_file); grep -qE "^  ${VPN_SERVICE}:[[:space:]]*\$" "$f" 2>/dev/null && grep -q 'WIREGUARD_ENDPOINT_IP=\${VPN_WG_ENDPOINT_IP' "$f" 2>/dev/null; }
_vpn_up() {
    [[ "$1" == "$VPN_STACK" ]] && { _vpn_render_secrets || return 1; secrets_ensure_generated "$(_vpn_compose_file)" "$COMPOSE_DIR/$VPN_STACK/.env" "$BASE_DIR/.env" 2>/dev/null; }
    compose_with_secrets "$COMPOSE_DIR/$1/docker-compose.yml" "$COMPOSE_DIR/$1/.env" up -d --no-deps "${@:2}" >/dev/null 2>&1
}
# Gluetun's App-Data on this machine (the stack's APP_DATA_DIR, ./App-Data by default)
_vpn_appdata() {
    local ad; ad=$(_stack_appdata_override "$VPN_STACK" 2>/dev/null) || ad=$(_vpn_env APP_DATA_DIR)
    [[ -n "$ad" ]] || ad="${APP_DATA_DIR:-./App-Data}"
    [[ "$ad" == ./* ]] && ad="$COMPOSE_DIR/$VPN_STACK/${ad#./}"
    printf '%s/Gluetun-VPN' "${ad%/}"
}
# the secrets Gluetun reads as files (/run/secrets): the WireGuard key, a pre-shared key, PIA's account for the forwarded port.
# Written from DCS's secrets before every start (mode 600, a folder only this server's user and root read); a secret that is
# gone takes its file with it.
_vpn_render_secrets() {
    local d n v
    d="$(_vpn_appdata)/secrets"
    (umask 077; mkdir -p "$d") 2>/dev/null || return 1
    chmod 700 "$d" 2>/dev/null
    for n in wireguard_private_key:VPN_WG_PRIVATE_KEY wireguard_preshared_key:VPN_WG_PRESHARED_KEY \
             vpn_port_forwarding_username:VPN_USER vpn_port_forwarding_password:VPN_PASS; do
        if v=$(secrets_get "${n#*:}" 2>/dev/null) && [[ -n "$v" ]]; then
            (umask 077; printf '%s' "$v" > "$d/${n%%:*}.tmp") && mv -f "$d/${n%%:*}.tmp" "$d/${n%%:*}" || return 1
        else rm -f -- "${d:?}/${n%%:*}"; fi
    done
    return 0
}
_vpn_saved_file() { printf '%s/%s--%s.json' "$VPN_DIR" "$1" "$2"; }
_vpn_attached() { jq -c '(.attached // [])' <<< "$(_vpn_state)"; }
# a value that goes into a curl config between double quotes
_vpn_cq() { local v="$1"; v=${v//\\/\\\\}; printf '%s' "${v//\"/\\\"}"; }

_vpn_audit() { _audit_log "$1" "$2" 2>/dev/null || true; }

# =============================================================================
# Gluetun's control server (127.0.0.1:VPN_CONTROL_PORT, the key VPN_CONTROL_KEY)
# =============================================================================
VPN_CODE=000; VPN_BODY=""
_vpn_ctl() {
    local p="$1" m="${2:-GET}" b="${3:-}" key port raw
    VPN_CODE=000; VPN_BODY=""
    key=$(secrets_get VPN_CONTROL_KEY 2>/dev/null) || key=""
    port=$(_vpn_env VPN_CONTROL_PORT); [[ "$port" =~ ^[0-9]{1,5}$ ]] || port=8899
    local args=(-s --connect-timeout 2 --max-time 5 -K - -X "$m" -w $'\n%{http_code}')
    [[ -n "$b" ]] && args+=(-H 'Content-Type: application/json' --data-binary "$b")
    raw=$(printf 'header = "X-API-Key: %s"\n' "$(_vpn_cq "$key")" | curl "${args[@]}" "http://127.0.0.1:$port$p" 2>/dev/null) || true
    VPN_CODE="${raw##*$'\n'}"; [[ "$VPN_CODE" =~ ^[0-9]{3}$ ]] || VPN_CODE=000
    [[ "$raw" == *$'\n'* ]] && VPN_BODY="${raw%$'\n'*}"
    [[ "$VPN_CODE" == 200 ]]
}

# _vpn_gluetun → "running id startedAt ip-on-its-first-network network" (or "absent")
_vpn_gluetun() {
    docker inspect --type container --format '{{.State.Running}} {{.Id}} {{.State.StartedAt}}{{range $n, $e := .NetworkSettings.Networks}} {{$e.IPAddress}} {{$n}}{{break}}{{end}}' "$VPN_CONTAINER" 2>/dev/null || echo absent
}

# the live view: {vpn_status, connected, public_ip, country, region, city, forwarded_port}
_vpn_live() {
    local st="" ip="" pf=""
    _vpn_ctl /v1/vpn/status && st=$(jq -r '.status // ""' <<< "$VPN_BODY" 2>/dev/null)
    _vpn_ctl /v1/publicip/ip && ip=$(jq -c 'if type == "object" then . else {} end' <<< "$VPN_BODY" 2>/dev/null)
    if _vpn_ctl /v1/portforward || _vpn_ctl /v1/openvpn/portforwarded; then pf=$(jq -c '(.port // null) | if . == 0 then null else . end' <<< "$VPN_BODY" 2>/dev/null); fi
    [[ -n "$ip" ]] || ip='{}'; [[ -n "$pf" ]] || pf=null
    jq -nc --arg st "$st" --argjson ip "$ip" --argjson pf "$pf" '{
        vpn_status: (if $st == "" then null else $st end),
        public_ip: ($ip.public_ip // null), country: ($ip.country // null), region: ($ip.region // null), city: ($ip.city // null),
        forwarded_port: $pf,
        connected: ($st == "running")}'
}

# =============================================================================
# Attach / detach
# =============================================================================

# _vpn_facts CONTAINER → sets VF_STACK VF_SERVICE VF_IMAGE (or VF_ERR)
_vpn_facts() {
    local c="$1" wd
    VF_STACK="" VF_SERVICE="" VF_IMAGE="" VF_ERR=""
    docker inspect --type container "$c" >/dev/null 2>&1 || { VF_ERR="No container named $c"; return 1; }
    wd=$(_container_label "$c" com.docker.compose.project.working_dir); wd="${wd%/}"
    VF_SERVICE=$(_container_label "$c" com.docker.compose.service)
    VF_IMAGE=$(docker inspect --format '{{.Config.Image}}' "$c" 2>/dev/null)
    VF_STACK="${wd##*/}"
    if [[ -z "$VF_SERVICE" || "$wd" != "$COMPOSE_DIR/$VF_STACK" || ! -f "$COMPOSE_DIR/$VF_STACK/docker-compose.yml" ]]; then
        VF_ERR="$c is not a service of a DCS stack: only those can be put through the VPN"; return 1
    fi
    [[ "$c" == "$VPN_CONTAINER" ]] && { VF_ERR="$c is the VPN itself"; return 1; }
    return 0
}

# _vpn_py OP ARGS… → the helper's JSON in VPN_PY_OUT; 1 with VPN_PY_ERR when it refused
_vpn_py() {
    VPN_PY_ERR=""
    VPN_PY_OUT=$(env -u PYTHONPATH -u PYTHONHOME python3 -I "$VPN_PY" "$@" 2>/dev/null) && [[ "$VPN_PY_OUT" == \{* ]] && return 0
    VPN_PY_ERR=$(jq -r '.error // empty' <<< "$VPN_PY_OUT" 2>/dev/null); [[ -n "$VPN_PY_ERR" ]] || VPN_PY_ERR="the compose file could not be edited (python3 is needed)"
    return 1
}
# _vpn_write FILE < CONTENT: in place, atomically, keeping its mode (the content from stdin: a trailing newline survives)
_vpn_write() { local tmp; tmp=$(mktemp "$(dirname "$1")/.dcs-files.XXXXXX") || return 1; cat > "$tmp" && chmod --reference="$1" "$tmp" 2>/dev/null; mv -f "$tmp" "$1"; }
# _vpn_backup FILE → a copy to put back (in VPN_DIR; _vpn_restore or _vpn_done removes it)
_vpn_backup() { (umask 077; mkdir -p "$VPN_DIR"); local b; b=$(mktemp "$VPN_DIR/.backup.XXXXXX") && cp -p "$1" "$b" && printf '%s' "$b"; }

# the Traefik route of a service: its url line follows the container (to Gluetun and back); prints the old url line
_vpn_route_follow() {
    local stack="$1" svc="$2" from="$3" to="$4" dir f
    dir=$(_find_traefik_routes_dir 2>/dev/null) || return 0
    f="$dir/$stack/$svc.yml"
    [[ -n "$dir" && -f "$f" ]] || return 0
    grep -q "://$from:" "$f" || return 0
    sed -i "s|://$from:|://$to:|" "$f" && touch "$dir/.reload" 2>/dev/null
    [[ "$to" == "$VPN_CONTAINER" ]] && { docker network connect proxy "$VPN_CONTAINER" >/dev/null 2>&1 || true; }
    printf '%s' "$f"
}

# every attached container again after Gluetun became a new container (they still hold the old one's network)
_vpn_recreate_attached() {
    local skip="${1:-}" row st svc c
    while IFS=$'\t' read -r st svc c; do
        [[ -n "$st" && "$c" != "$skip" ]] || continue
        _container_mark_intended "$c" 2>/dev/null
        _vpn_up "$st" --force-recreate "$svc" || _vpn_audit vpn_error "$c could not be recreated behind the VPN"
    done < <(jq -r '.[] | [.stack, .service, .container] | @tsv' <<< "$(_vpn_attached)")
    _vpn_set --arg g "$(_vpn_gluetun)" '.gluetun = $g'
}

# PUT /containers/{name}/vpn — Put a container through the VPN or take it out {"on": true|false}: its service's ports move onto Gluetun, its network becomes Gluetun's (a kill switch), its route follows; only the touched services are recreated
handle_vpn_container() {
    local c="$1" body="$2" on
    _api_check_admin || { _api_error 403 "Admin access required"; return; }
    on=$(jq -r 'if .on == true then "true" elif .on == false then "false" else "" end' <<< "$body" 2>/dev/null)
    [[ -n "$on" ]] || { _api_error 400 "on is true or false"; return; }
    _vpn_deployed || { _api_error 409 "The VPN is not set up: deploy it on Security → VPN first"; return; }
    if [[ "$on" == true ]]; then _vpn_attach "$c"; else _vpn_detach "$c"; fi
}

_vpn_restore() { _vpn_write "$1" < "$2"; _vpn_write "$3" < "$4"; rm -f -- "$2" "$4"; }
_vpn_done() { rm -f -- "$@"; }

_vpn_attach() {
    local c="$1" app vpnf app0 vpn0 tag saved targets clash route ans
    _vpn_facts "$c" || { _api_error 400 "$VF_ERR"; return; }
    if jq -e --arg c "$c" 'any(.[]; .container == $c)' <<< "$(_vpn_attached)" >/dev/null; then
        _api_success "$(jq -nc --arg c "$c" '{success: true, container: $c, on: true, message: "\($c) already goes through the VPN"}')"; return
    fi
    app="$COMPOSE_DIR/$VF_STACK/docker-compose.yml"; vpnf=$(_vpn_compose_file); tag="$VF_STACK/$VF_SERVICE"
    _vpn_py attach "$app" "$VF_SERVICE" "$VPN_CONTAINER" "$tag" "$COMPOSE_DIR/$VF_STACK/.env" "$BASE_DIR/.env" || { _api_error 400 "$VPN_PY_ERR"; return; }
    saved="$VPN_PY_OUT"; targets=$(jq -c '.targets' <<< "$saved")
    # two containers in one network cannot both listen on a port, and 8000 is Gluetun's own
    clash=$(jq -r --argjson t "$targets" '[.[] | .targets[]?] + [8000] | map(select(. as $p | $t | index($p))) | first // empty' <<< "$(_vpn_attached)")
    [[ -z "$clash" ]] || { _api_error 409 "$c listens on port $clash, which another container behind the VPN (or Gluetun) already uses"; return; }
    app0=$(_vpn_backup "$app") && vpn0=$(_vpn_backup "$vpnf") || { _api_error 500 "Could not keep a copy of the compose files"; return; }
    jq -j .content <<< "$saved" | _vpn_write "$app" || { _vpn_done "$app0" "$vpn0"; _api_error 500 "Could not write $app"; return; }
    # (the same file when the container is in the VPN's own stack: it was just written)
    _vpn_py add-ports "$vpnf" "$VPN_SERVICE" "$tag" "$(jq -c .ports <<< "$saved")" || { _vpn_restore "$app" "$app0" "$vpnf" "$vpn0"; _api_error 400 "$VPN_PY_ERR"; return; }
    jq -j .content <<< "$VPN_PY_OUT" | _vpn_write "$vpnf"
    if ! _compose_policy_check "$app" "$VF_STACK" || ! _compose_policy_check "$vpnf" "$VPN_STACK"; then
        _vpn_restore "$app" "$app0" "$vpnf" "$vpn0"; _api_policy_refuse "putting $c through the VPN"; return
    fi
    route=$(_vpn_route_follow "$VF_STACK" "$VF_SERVICE" "$c" "$VPN_CONTAINER")
    (umask 077; mkdir -p "$VPN_DIR"; jq -c --arg st "$VF_STACK" --arg sv "$VF_SERVICE" --arg c "$c" --arg i "$VF_IMAGE" --arg r "$route" --argjson now "$(_vpn_now)" \
        '{stack: $st, service: $sv, container: $c, image: $i, saved: .saved, ports: .ports, targets: .targets, route: (if $r == "" then null else $r end), since: $now}' \
        <<< "$saved" > "$(_vpn_saved_file "$VF_STACK" "$VF_SERVICE")")
    _vpn_set --arg st "$VF_STACK" --arg sv "$VF_SERVICE" --arg c "$c" --arg i "$VF_IMAGE" --argjson t "$targets" --argjson now "$(_vpn_now)" \
        '.attached = ((.attached // []) + [{stack: $st, service: $sv, container: $c, image: $i, targets: $t, since: $now}]) | .last_change = $now'
    _container_mark_intended "$c" "$VPN_CONTAINER" 2>/dev/null
    # the container lets go of its ports, Gluetun publishes them (a new container), then everything behind it joins the new one
    compose_with_secrets "$app" "$COMPOSE_DIR/$VF_STACK/.env" stop "$VF_SERVICE" >/dev/null 2>&1
    if ! _vpn_up "$VPN_STACK" "$VPN_SERVICE" || ! _vpn_up "$VF_STACK" --force-recreate "$VF_SERVICE"; then
        _vpn_restore "$app" "$app0" "$vpnf" "$vpn0"
        [[ -n "$route" ]] && _vpn_route_follow "$VF_STACK" "$VF_SERVICE" "$VPN_CONTAINER" "$c" >/dev/null
        rm -f "$(_vpn_saved_file "$VF_STACK" "$VF_SERVICE")"
        _vpn_set --arg c "$c" '.attached = [(.attached // [])[] | select(.container != $c)]'
        _vpn_up "$VPN_STACK" "$VPN_SERVICE"; _vpn_up "$VF_STACK" --force-recreate "$VF_SERVICE"; _vpn_recreate_attached
        _api_error 500 "$c could not be started behind the VPN (is Gluetun running? a port already taken?): it is back as it was"; return
    fi
    _vpn_done "$app0" "$vpn0"
    _vpn_recreate_attached "$c"
    _vpn_audit vpn_attach "$c ($tag) now goes through the VPN, by ${AUTH_USERNAME:-unknown}"
    _api_policy_audit "putting $c through the VPN"
    _api_cache_clear 2>/dev/null || true
    ans=$(jq -nc --arg c "$c" --argjson t "$targets" --argjson p "$(_api_policy_json)" --arg r "$route" \
        '{success: true, container: $c, on: true, ports: $t, route_follows: ($r != ""), policy: $p,
          message: "\($c) goes through the VPN: it reaches the internet only through the tunnel, and its web page is now on Gluetun"}')
    _api_success "$ans"
}

_vpn_detach() {
    local c="$1" row st svc app vpnf app0 vpn0 sf route
    row=$(jq -c --arg c "$c" 'map(select(.container == $c)) | first // empty' <<< "$(_vpn_attached)")
    [[ -n "$row" ]] || { _api_success "$(jq -nc --arg c "$c" '{success: true, container: $c, on: false, message: "\($c) does not go through the VPN"}')"; return; }
    st=$(jq -r .stack <<< "$row"); svc=$(jq -r .service <<< "$row")
    app="$COMPOSE_DIR/$st/docker-compose.yml"; vpnf=$(_vpn_compose_file); sf=$(_vpn_saved_file "$st" "$svc")
    [[ -f "$sf" ]] || { _api_error 500 "What $c had before is missing ($sf): put its ports and networks back by hand in $app"; return; }
    app0=$(_vpn_backup "$app") && vpn0=$(_vpn_backup "$vpnf") || { _api_error 500 "Could not keep a copy of the compose files"; return; }
    _vpn_py detach "$app" "$svc" "$(jq -c .saved "$sf")" || { _vpn_done "$app0" "$vpn0"; _api_error 400 "$VPN_PY_ERR"; return; }
    jq -j .content <<< "$VPN_PY_OUT" | _vpn_write "$app"
    _vpn_py remove-ports "$vpnf" "$st/$svc" && jq -j .content <<< "$VPN_PY_OUT" | _vpn_write "$vpnf"
    if ! _compose_policy_check "$app" "$st" || ! _compose_policy_check "$vpnf" "$VPN_STACK"; then
        _vpn_restore "$app" "$app0" "$vpnf" "$vpn0"; _api_policy_refuse "taking $c out of the VPN"; return
    fi
    _vpn_done "$app0" "$vpn0"
    route=$(jq -r '.route // empty' "$sf")
    [[ -n "$route" ]] && _vpn_route_follow "$st" "$svc" "$VPN_CONTAINER" "$c" >/dev/null
    _vpn_set --arg c "$c" --argjson now "$(_vpn_now)" '.attached = [(.attached // [])[] | select(.container != $c)] | .last_change = $now'
    _container_mark_intended "$c" "$VPN_CONTAINER" 2>/dev/null
    # Gluetun lets go of the ports first (a new container: the others behind it join it again), then the container takes them back
    _vpn_up "$VPN_STACK" "$VPN_SERVICE" && _vpn_recreate_attached
    rm -f "$sf"
    _vpn_up "$st" --force-recreate "$svc" || { _api_error 500 "The files are back as they were, but $c did not start: start $st from the Stacks page"; return; }
    _vpn_audit vpn_detach "$c ($st/$svc) no longer goes through the VPN, by ${AUTH_USERNAME:-unknown}"
    _api_cache_clear 2>/dev/null || true
    _api_success "$(jq -nc --arg c "$c" '{success: true, container: $c, on: false, message: "\($c) uses the normal connection again, with its own ports"}')"
}

# =============================================================================
# Status, pause, leaks
# =============================================================================

# GET /vpn/status — The VPN: connected, exit address and country, region and server, the forwarded port, Gluetun's uptime, the containers behind it, the alerts
handle_vpn_status() {
    local g live state now attached='[]' row c running
    g=$(_vpn_gluetun); state=$(_vpn_state); now=$(_vpn_now)
    live='{"connected":false}'
    [[ "$g" == true\ * ]] && live=$(_vpn_live)
    while IFS= read -r row; do
        [[ -n "$row" ]] || continue
        c=$(jq -r .container <<< "$row")
        running=$(docker inspect --format '{{.State.Running}}' "$c" 2>/dev/null || echo false)
        attached=$(jq -c --argjson r "$row" --arg run "$running" --argjson s "$state" \
            '. + [$r + {running: ($run == "true"), qbittorrent: ($r.image | test("qbittorrent"; "i")),
                        leak_test: ($s.leaks[$r.container] // null)}]' <<< "$attached")
    done < <(jq -c '.[]' <<< "$(_vpn_attached)")
    _api_success "$(jq -nc --arg g "$g" --argjson live "$live" --argjson s "$state" --argjson a "$attached" --argjson now "$now" \
        --arg region "$(_vpn_env VPN_REGION)" --arg server "$(_vpn_env VPN_SERVER_NAME)" --arg pf "$(_vpn_env VPN_PORT_FORWARDING)" \
        --arg dep "$(_vpn_deployed && echo true || echo false)" --arg acct "$(secrets_exists VPN_USER 2>/dev/null && secrets_exists VPN_PASS 2>/dev/null && echo true || echo false)" \
        --arg key "$(secrets_exists VPN_WG_PRIVATE_KEY 2>/dev/null && echo true || echo false)" '
        ($g | split(" ")) as $gl
        | {enabled: true, deployed: ($dep == "true"), account_set: ($acct == "true"), configured: ($key == "true"),
           running: ($gl[0] == "true"), paused: ($s.paused // false), container: "Gluetun", stack: "networking-security",
           started_at: (if $gl[0] == "true" then $gl[2] else null end),
           uptime_s: (if $gl[0] == "true" then ($now - (($gl[2] | sub("\\.[0-9]+"; "") | sub("Z$"; "Z")) | try fromdateiso8601 catch $now)) else null end),
           region_name: (if $region == "" then null else $region end), server_name: (if $server == "" then null else $server end),
           port_forwarding: ($pf != "off"), qbittorrent_port: ($s.qbit_port // null), qbittorrent_error: ($s.qbit_error // null),
           attached: $a, last_change: ($s.last_change // null), down_since: ($s.down_since // null),
           alerts: [($s.active // {}) | to_entries[] | .value + {key: .key}],
           wireguard_clients: ($s.wg_clients // {on: false})} + $live')"
}

# POST /vpn/pause — Stop the tunnel (Gluetun): the containers behind it have no network at all until it is resumed
handle_vpn_pause() {
    _api_check_admin || { _api_error 403 "Admin access required"; return; }
    _vpn_deployed || { _api_error 409 "The VPN is not set up"; return; }
    _vpn_set '.paused = true'
    local -a behind=(); mapfile -t behind < <(jq -r '.[].container' <<< "$(_vpn_attached)")
    _container_mark_intended "$VPN_CONTAINER" "${behind[@]}" 2>/dev/null
    compose_with_secrets "$(_vpn_compose_file)" "$COMPOSE_DIR/$VPN_STACK/.env" stop "$VPN_SERVICE" >/dev/null 2>&1 || { _vpn_set '.paused = false'; _api_error 500 "Gluetun did not stop"; return; }
    _vpn_audit vpn_pause "the VPN was paused by ${AUTH_USERNAME:-unknown}: the containers behind it are offline"
    _api_success '{"success": true, "paused": true, "message": "The VPN is paused: the containers behind it are offline until you resume it"}'
}

# POST /vpn/resume — Start the tunnel again; the containers behind it rejoin it
handle_vpn_resume() {
    _api_check_admin || { _api_error 403 "Admin access required"; return; }
    _vpn_deployed || { _api_error 409 "The VPN is not set up"; return; }
    _vpn_up "$VPN_STACK" "$VPN_SERVICE" || { _api_error 500 "Gluetun did not start: look at its logs"; return; }
    _vpn_recreate_attached
    _vpn_set '.paused = false | .down_since = null'
    _vpn_audit vpn_resume "the VPN was resumed by ${AUTH_USERNAME:-unknown}"
    _api_success '{"success": true, "paused": false, "message": "The VPN is running again"}'
}

# _vpn_fetch_ip CONTAINER|"" → the address the outside sees (the host's own with ""), empty when there is no internet
_vpn_fetch_ip() {
    local url="${VPN_IP_ECHO_URL:-https://ipinfo.io/ip}" out
    if [[ -z "$1" ]]; then out=$(curl -fsS -m 8 "$url" 2>/dev/null)
    else out=$(timeout 15 docker exec "$1" sh -c 'wget -qO- -T 8 "$1" 2>/dev/null || curl -fsS -m 8 "$1" 2>/dev/null' sh "$url" 2>/dev/null); fi
    out=$(printf '%s' "$out" | tr -d '[:space:]')
    [[ "$out" =~ ^[0-9A-Fa-f:.]{3,45}$ ]] && printf '%s' "$out"
    return 0
}

# _vpn_leaks → [{container, ip, verdict}]: tunnel (the tunnel's address), leak (the home address), offline, unknown; raises/clears vpn_leak
_vpn_leaks() {
    local home exit res='[]' c ip v now leaked=""
    now=$(_vpn_now); home=$(_vpn_fetch_ip "")
    _vpn_ctl /v1/publicip/ip && exit=$(jq -r '.public_ip // empty' <<< "$VPN_BODY")
    while IFS= read -r c; do
        [[ -n "$c" ]] || continue
        ip=$(_vpn_fetch_ip "$c")
        if [[ -z "$ip" ]]; then v=offline
        elif [[ -n "$home" && "$ip" == "$home" ]]; then v=leak; leaked+="$c "
        elif [[ -n "${exit:-}" && "$ip" == "$exit" ]]; then v=tunnel
        else v=unknown; fi
        res=$(jq -c --arg c "$c" --arg ip "$ip" --arg v "$v" '. + [{container: $c, ip: (if $ip == "" then null else $ip end), verdict: $v}]' <<< "$res")
    done < <(jq -r '.[].container' <<< "$(_vpn_attached)")
    _vpn_set --argjson r "$res" --argjson now "$now" '.leaks = (($r | map({key: .container, value: (. + {at: $now})}) | from_entries))'
    if [[ -n "$leaked" ]]; then
        _vpn_raise vpn_leak vpn_leak "A container behind the VPN shows the home address" \
            "${leaked% } reached the internet with this home's address ($home), not the tunnel's: take it out of the VPN and back in, and look at its compose file."
    else
        _vpn_clear vpn_leak "No leak any more" "Every container behind the VPN shows the tunnel's address (or has no internet)."
    fi
    printf '%s' "$res"
}

# POST /vpn/leak-test — Ask the outside world which address each container behind the VPN has: the tunnel's (good), the home's (a leak), none (the kill switch)
handle_vpn_leak_test() {
    local r home
    _api_check_admin || { _api_error 403 "Admin access required"; return; }
    _vpn_deployed || { _api_error 409 "The VPN is not set up"; return; }
    r=$(_vpn_leaks)
    _vpn_ctl /v1/publicip/ip && home=$(jq -c 'if type == "object" then . else {} end' <<< "$VPN_BODY" 2>/dev/null)
    [[ -n "${home:-}" ]] || home='{}'
    _api_success "$(jq -nc --argjson r "$r" --argjson ip "$home" \
        '{success: true, exit_ip: ($ip.public_ip // null), results: $r, leaks: ([$r[] | select(.verdict == "leak")] | length)}')"
}

# =============================================================================
# Alerts (like Technitium's: raised once, cleared once, through the notification rules)
# =============================================================================
_vpn_raise() {
    local key="$1" ev="$2" head="$3" msg="$4"
    jq -e --arg k "$key" '.active[$k] != null' >/dev/null <<< "$(_vpn_state)" && return 0
    _vpn_set --arg k "$key" --arg e "$ev" --arg h "$head" --arg m "$msg" --argjson now "$(_vpn_now)" '.active[$k] = {event: $e, headline: $h, message: $m, since: $now}'
    _vpn_audit "$ev" "$head: $msg"
    _fire_notifications "$ev" "headline=$head" "message=$msg" "status=raised" "fingerprint=$key" >/dev/null 2>&1 || true
}
_vpn_clear() {
    local key="$1" head="$2" msg="$3" a ev
    a=$(jq -c --arg k "$key" '.active[$k] // empty' <<< "$(_vpn_state)"); [[ -n "$a" ]] || return 0
    ev=$(jq -r .event <<< "$a")
    _vpn_set --arg k "$key" 'del(.active[$k])'
    _vpn_audit "$ev" "$head: $msg"
    _fire_notifications "$ev" "headline=$head" "message=$msg" "status=resolved" "fingerprint=$key" >/dev/null 2>&1 || true
}
_vpn_seed_rules() {
    jq -e '.rules_seeded == true' >/dev/null <<< "$(_vpn_state)" && return 0
    _init_notifications_file 2>/dev/null
    _api_jq_update_file "$NOTIFICATIONS_FILE" --argjson r "$VPN_RULES" --arg ts "$(_api_now_iso)" '
        (.rules // []) as $have
        | .rules = $have + [$r[] | select(.trigger as $t | $have | any(.trigger == $t) | not)
            | {id: ("rule_" + .trigger), name, enabled, trigger, target: "*", priority, tags: ["vpn"], title_template: "", message_template: "",
               cooldown_minutes: null, created_at: $ts}]' || return 0
    _vpn_set '.rules_seeded = true'
}

# =============================================================================
# qBittorrent gets the forwarded port
# =============================================================================

# _vpn_qbit_set CONTAINER PORT → 0 when qBittorrent took it (QB_ERR otherwise)
_vpn_qbit_set() {
    local c="$1" port="$2" row web hp jar code u p
    QB_ERR=""
    row=$(jq -c --arg c "$c" 'map(select(.container == $c)) | first // {}' <<< "$(_vpn_attached)")
    web=$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$c" 2>/dev/null | sed -n 's/^WEBUI_PORT=//p' | head -1)
    [[ "$web" =~ ^[0-9]+$ ]] || web=$(jq -r '[.targets[]? | select(. != 6881)] | first // 8080' <<< "$row")
    hp=$(docker port "$VPN_CONTAINER" "$web/tcp" 2>/dev/null | head -1); hp="${hp##*:}"
    [[ "$hp" =~ ^[0-9]+$ ]] || { QB_ERR="qBittorrent's web page (port $web) is not published on Gluetun"; return 1; }
    local url="http://127.0.0.1:$hp/api/v2" prefs
    prefs=$(jq -nc --argjson p "$port" '{listen_port: $p, random_port: false, upnp: false}')
    code=$(curl -s -o /dev/null -w '%{http_code}' -m 8 --data-urlencode "json=$prefs" "$url/app/setPreferences" 2>/dev/null) || code=000
    [[ "$code" == 200 ]] && return 0
    if [[ "$code" == 401 || "$code" == 403 ]]; then
        u=$(secrets_get QBITTORRENT_USER 2>/dev/null) || u=""; p=$(secrets_get QBITTORRENT_PASS 2>/dev/null) || p=""
        [[ -n "$u" && -n "$p" ]] || { QB_ERR="qBittorrent asks for its login: store it as the secrets QBITTORRENT_USER and QBITTORRENT_PASS (or let it trust this machine's address)"; return 1; }
        jar=$(mktemp "${TMPDIR:-/tmp}/dcs-qb-XXXXXX") || return 1
        code=$(printf 'data-urlencode = "username=%s"\ndata-urlencode = "password=%s"\n' "$(_vpn_cq "$u")" "$(_vpn_cq "$p")" \
            | curl -s -o /dev/null -w '%{http_code}' -m 8 -c "$jar" -K - "$url/auth/login" 2>/dev/null) || code=000
        if [[ "$code" == 200 ]] && grep -q SID "$jar"; then
            code=$(curl -s -o /dev/null -w '%{http_code}' -m 8 -b "$jar" --data-urlencode "json=$prefs" "$url/app/setPreferences" 2>/dev/null) || code=000
        else QB_ERR="qBittorrent refused the login in QBITTORRENT_USER / QBITTORRENT_PASS"; rm -f "$jar"; return 1; fi
        rm -f "$jar"
        [[ "$code" == 200 ]] && return 0
    fi
    QB_ERR="qBittorrent's web API answered HTTP $code"
    return 1
}

# =============================================================================
# PIA: the WireGuard key and the regions
# =============================================================================
_vpn_pia_serverlist() {
    local f="$VPN_DIR/pia-servers.json" age
    age=$(( $(date +%s) - $(stat -c %Y "$f" 2>/dev/null || echo 0) ))
    if (( age > 86400 )) || [[ ! -s "$f" ]]; then
        local raw; raw=$(curl -fsS -m 15 "${DCS_VPN_PIA_SERVERLIST_URL:-https://serverlist.piaservers.net/vpninfo/servers/v6}" 2>/dev/null | head -1)
        jq -e '.regions | length > 0' <<< "$raw" >/dev/null 2>&1 && { mkdir -p "$VPN_DIR"; printf '%s\n' "$raw" > "$f.tmp" && mv -f "$f.tmp" "$f"; }
    fi
    [[ -s "$f" ]] && cat "$f"
}

# GET /vpn/regions — Private Internet Access's regions that forward a port (WireGuard), Canada's first
handle_vpn_regions() {
    local s; s=$(_vpn_pia_serverlist)
    [[ -n "$s" ]] || { _api_error 502 "PIA's server list could not be fetched"; return; }
    _api_success "$(jq -c '{regions: ([.regions[] | select(.port_forward == true and ((.servers.wg // []) | length) > 0)
        | {id, name, country, geo: (.geo // false)}] | sort_by((if .country == "CA" then 0 else 1 end), .name))}' <<< "$s")"
}

# _vpn_pia_pick REGION_ID|auto SERVERLIST → the region's JSON (auto: the lowest connect time to its meta server)
_vpn_pia_pick() {
    local want="$1" list="$2" best="" bt=99 ip id t
    if [[ "$want" != auto ]]; then
        jq -c --arg r "$want" '.regions[] | select(.id == $r and .port_forward == true and ((.servers.wg // []) | length) > 0)' <<< "$list" | head -1; return
    fi
    while read -r ip id; do
        t=$(curl -o /dev/null -s --connect-timeout 1 -w '%{time_connect}' "http://$ip:443" 2>/dev/null) || t=""
        [[ "$t" =~ ^0\.[0-9]+$ ]] || continue
        if awk -v a="$t" -v b="$bt" 'BEGIN{exit !(a < b)}'; then bt="$t"; best="$id"; fi
    done < <(jq -r '.regions[] | select(.port_forward == true and ((.servers.wg // []) | length) > 0) | "\(.servers.meta[0].ip // "") \(.id)"' <<< "$list")
    # none answered (a firewall in the way): Canada's first
    [[ -n "$best" ]] || best=$(jq -r '[.regions[] | select(.port_forward == true and ((.servers.wg // []) | length) > 0)] | sort_by(if .country == "CA" then 0 else 1 end) | first | .id // empty' <<< "$list")
    jq -c --arg r "$best" '.regions[] | select(.id == $r)' <<< "$list" | head -1
}

# _vpn_pia_register REGION_ID|auto [USER PASS] → writes the stack's .env and VPN_WG_PRIVATE_KEY (the stored account without USER PASS);
# VPN_ERR on failure
_vpn_pia_register() {
    local want="$1" u="${2:-}" p="${3:-}" list region tok pem priv pub cn ip wj
    VPN_ERR=""
    if [[ -z "$u" ]]; then u=$(secrets_get VPN_USER 2>/dev/null) || u=""; p=$(secrets_get VPN_PASS 2>/dev/null) || p=""; fi
    [[ -n "$u" && -n "$p" ]] || { VPN_ERR="Your PIA account is not stored: enter it on the VPN page"; return 1; }
    list=$(_vpn_pia_serverlist); [[ -n "$list" ]] || { VPN_ERR="PIA's server list could not be fetched (is the internet reachable from this server?)"; return 1; }
    region=$(_vpn_pia_pick "$want" "$list"); [[ -n "$region" ]] || { VPN_ERR="No PIA region $want that forwards a port"; return 1; }
    tok=$(printf 'form = "username=%s"\nform = "password=%s"\n' "$(_vpn_cq "$u")" "$(_vpn_cq "$p")" \
        | curl -s -m 15 -K - -X POST "${DCS_VPN_PIA_TOKEN_URL:-https://www.privateinternetaccess.com/api/client/v2/token}" 2>/dev/null | jq -r '.token // empty' 2>/dev/null)
    [[ "$tok" =~ ^[A-Za-z0-9._~+/=-]{8,1024}$ ]] || { VPN_ERR="PIA did not accept the account (user name p1234567 and its password)"; return 1; }
    pem=$(openssl genpkey -algorithm X25519 2>/dev/null) || { VPN_ERR="openssl could not make a WireGuard key"; return 1; }
    priv=$(openssl pkey -outform DER <<< "$pem" 2>/dev/null | tail -c 32 | base64 -w0)
    pub=$(openssl pkey -pubout -outform DER <<< "$pem" 2>/dev/null | tail -c 32 | base64 -w0)
    [[ ${#priv} == 44 && ${#pub} == 44 ]] || { VPN_ERR="openssl could not make a WireGuard key"; return 1; }
    cn=$(jq -r '.servers.wg[0].cn' <<< "$region"); ip=$(jq -r '.servers.wg[0].ip' <<< "$region")
    [[ "$cn" =~ ^[A-Za-z0-9.-]+$ && "$ip" =~ ^[0-9.]+$ ]] || { VPN_ERR="PIA's server list has no WireGuard server for this region"; return 1; }
    if [[ -n "${DCS_VPN_PIA_ADDKEY_URL:-}" ]]; then
        wj=$(printf 'data-urlencode = "pt=%s"\ndata-urlencode = "pubkey=%s"\n' "$tok" "$pub" | curl -s -m 15 -G -K - "$DCS_VPN_PIA_ADDKEY_URL" 2>/dev/null)
    else
        wj=$(printf 'data-urlencode = "pt=%s"\ndata-urlencode = "pubkey=%s"\n' "$tok" "$pub" \
            | curl -s -m 15 -G -K - --connect-to "$cn::$ip:" --cacert "$VPN_PIA_CA" "https://$cn:1337/addKey" 2>/dev/null)
    fi
    [[ "$(jq -r '.status // empty' <<< "$wj" 2>/dev/null)" == OK ]] || { VPN_ERR="PIA's server $cn did not take the WireGuard key"; return 1; }
    local sk sp sip peer
    sk=$(jq -r '.server_key // empty' <<< "$wj"); sp=$(jq -r '.server_port // empty' <<< "$wj")
    sip=$(jq -r '.server_ip // empty' <<< "$wj"); peer=$(jq -r '.peer_ip // empty' <<< "$wj")
    [[ "$sk" =~ ^[A-Za-z0-9+/=]{44}$ && "$sp" =~ ^[0-9]+$ && "$sip" =~ ^[0-9.]+$ && "$peer" =~ ^[0-9.]+$ ]] || { VPN_ERR="PIA's answer was not a WireGuard peer"; return 1; }
    secrets_set VPN_WG_PRIVATE_KEY "$priv" >/dev/null 2>&1 || { VPN_ERR="the key could not be stored in the secrets"; return 1; }
    secrets_exists VPN_CONTROL_KEY 2>/dev/null || secrets_set VPN_CONTROL_KEY "$(openssl rand -hex 24)" >/dev/null 2>&1
    _env_file_write "$COMPOSE_DIR/$VPN_STACK/.env" VPN_WG_ENDPOINT_IP "$sip" VPN_WG_ENDPOINT_PORT "$sp" VPN_WG_PUBLIC_KEY "$sk" \
        VPN_WG_ADDRESSES "$peer/32" VPN_SERVER_NAME "$cn" VPN_REGION "$(jq -r .name <<< "$region")" VPN_REGION_ID "$want" \
        || { VPN_ERR="the stack's .env could not be written"; return 1; }
    VPN_REGION_JSON=$(jq -c --arg cn "$cn" '{id, name, country, server: $cn}' <<< "$region")
    return 0
}

# POST /vpn/connect — Connect with Private Internet Access {username?, password?, region: "auto" | a region id}: the account into the secrets, a WireGuard key registered with the fastest (or the chosen) region that forwards a port, Gluetun restarted with it
handle_vpn_connect() {
    local body="$1" u p region
    _api_check_admin || { _api_error 403 "Admin access required"; return; }
    _vpn_deployed || { _api_error 409 "Deploy the VPN template (vpn-gluetun) first"; return; }
    u=$(jq -r '.username // empty | strings' <<< "$body" 2>/dev/null); p=$(jq -r '.password // empty | strings' <<< "$body" 2>/dev/null)
    region=$(jq -r '.region // "auto" | strings' <<< "$body" 2>/dev/null); [[ -n "$region" ]] || region=auto
    [[ "$region" =~ ^[A-Za-z0-9_-]{1,64}$ ]] || { _api_error 400 "region is auto or a region id from GET /vpn/regions"; return; }
    if [[ -n "$u$p" ]]; then
        [[ -n "$u" && -n "$p" ]] || { _api_error 400 "Give both the PIA user name and its password"; return; }
        [[ ${#u} -le 128 && ${#p} -le 256 && "$u$p" != *[$'\n\r']* ]] || { _api_error 400 "The user name or password is not valid"; return; }
    fi
    _vpn_pia_register "$region" "$u" "$p" || { _api_error 502 "$VPN_ERR"; return; }
    # the account is kept once PIA took it
    if [[ -n "$u" ]] && ! { secrets_set VPN_USER "$u" >/dev/null 2>&1 && secrets_set VPN_PASS "$p" >/dev/null 2>&1; }; then
        _api_error 500 "The account could not be stored in the secrets"; return
    fi
    _container_mark_intended "$VPN_CONTAINER" 2>/dev/null
    _vpn_up "$VPN_STACK" --force-recreate "$VPN_SERVICE" || { _api_error 500 "The key is registered, but Gluetun did not start: look at its logs"; return; }
    _vpn_recreate_attached
    _vpn_set --argjson now "$(_vpn_now)" '.paused = false | .down_since = null | .last_change = $now | .rekeyed_at = $now | del(.qbit_port)'
    _vpn_audit vpn_connect "the VPN connected to PIA $(jq -r '"\(.name) (\(.server))"' <<< "$VPN_REGION_JSON"), by ${AUTH_USERNAME:-unknown}"
    _api_cache_clear 2>/dev/null || true
    _api_success "$(jq -nc --argjson r "$VPN_REGION_JSON" '{success: true, region: $r, message: "Connecting to \($r.name) (\($r.server)): the tunnel is up in a few seconds"}')"
}

# =============================================================================
# The WireGuard clients (wg-easy) out through the tunnel
# =============================================================================
# The WireGuard server container stays on its own network (its UDP port and its replies keep the home address); it
# joins Gluetun's network as well, and a policy route sends what comes in on wg0 (and is not for a private address)
# to Gluetun: ip rule iif wg0 → table 51821 (default via Gluetun), masqueraded onto Gluetun's network. Gluetun
# forwards it into the tunnel (rules in /iptables/post-rules.txt, applied when it starts, and at once by docker exec).
_vpn_wg_container() { local c; c=$(jq -r '.wg_clients.container // empty' <<< "$(_vpn_state)"); printf '%s' "${c:-${VPN_WG_CLIENTS_CONTAINER:-WireGuard}}"; }
_vpn_wgx() { timeout 15 docker exec "$1" sh -c "$2" 2>&1; }

# the WireGuard clients' subnet: wg-easy's WG_DEFAULT_ADDRESS (10.8.0.x), linuxserver's INTERNAL_SUBNET, or wg0's own address
_vpn_wg_subnet() {
    local c="$1" envs a
    envs=$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$c" 2>/dev/null)
    a=$(sed -n 's/^WG_DEFAULT_ADDRESS=//p; s/^INTERNAL_SUBNET=//p' <<< "$envs" | head -1)
    [[ -n "$a" ]] || a=$(_vpn_wgx "$c" "ip -o -4 addr show wg0" | awk '{print $4}' | head -1)
    a="${a%%/*}"; a="${a//x/0}"
    [[ "$a" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)\.[0-9]+$ ]] || return 1
    printf '%s.%s.%s.0/24' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"
}

_vpn_on_net() { docker inspect --format '{{range $n, $e := .NetworkSettings.Networks}}{{$n}} {{end}}' "$1" 2>/dev/null | grep -qw -- "$2"; }
# _vpn_wg_apply → 0 when the route is in place; VPN_ERR otherwise. Idempotent (the minute clock calls it).
_vpn_wg_apply() {
    local c g gnet gip sub wip wif gif home cur rules
    VPN_ERR=""
    c=$(_vpn_wg_container)
    [[ "$(docker inspect --format '{{.State.Running}}' "$c" 2>/dev/null)" == true ]] || { VPN_ERR="The WireGuard server ($c) is not running"; return 1; }
    g=$(_vpn_gluetun); read -r _ _ _ gip gnet <<< "$g"
    [[ "$g" == true\ * && -n "$gip" && -n "$gnet" ]] || { VPN_ERR="Gluetun is not running"; return 1; }
    sub=$(_vpn_wg_subnet "$c") || { VPN_ERR="The WireGuard clients' subnet of $c could not be read"; return 1; }
    home=$(jq -r '.wg_clients.home_gw // empty' <<< "$(_vpn_state)")
    if ! _vpn_on_net "$c" "$gnet"; then
        [[ -n "$home" ]] || home=$(_vpn_wgx "$c" "ip route show default" | awk '/^default via/ {print $3; exit}')
        # (a disconnect a moment ago can leave Docker saying the endpoint still exists: then it is there)
        docker network connect "$gnet" "$c" >/dev/null 2>&1 || { sleep 2; _vpn_on_net "$c" "$gnet"; } || { VPN_ERR="$c could not join Gluetun's network $gnet"; return 1; }
        _vpn_set --arg h "$home" '.wg_clients.joined = true | .wg_clients.home_gw = (if $h == "" then null else $h end)'
    fi
    # a second network may take the container's default route (Docker picks one by name, again at every restart): its own (the
    # way the clients' UDP answers go back) stays the one it had before DCS joined it
    cur=$(_vpn_wgx "$c" "ip route show default" | awk '/^default via/ {print $3; exit}')
    [[ "$home" =~ ^[0-9.]+$ && "$cur" != "$home" ]] && _vpn_wgx "$c" "ip route replace default via $home" >/dev/null
    wip=$(docker inspect --format "{{(index .NetworkSettings.Networks \"$gnet\").IPAddress}}" "$c" 2>/dev/null)
    wif=$(_vpn_wgx "$c" "ip -o -4 addr" | awk -v ip="$wip" 'index($4, ip "/") == 1 {print $2; exit}')
    gif=$(_vpn_wgx "$VPN_CONTAINER" "ip -o -4 addr" | awk -v ip="$gip" 'index($4, ip "/") == 1 {print $2; exit}')
    [[ "$wip" =~ ^[0-9.]+$ && "$wif" =~ ^[A-Za-z0-9@._-]+$ && "$gif" =~ ^[A-Za-z0-9@._-]+$ ]] || { VPN_ERR="The addresses on Gluetun's network could not be read"; return 1; }
    wif="${wif%@*}"; gif="${gif%@*}"
    local n s="" t="$VPN_WG_TABLE"
    for n in $VPN_PRIVATE_NETS; do s+="ip rule show | grep -q 'from all to $n iif wg0 lookup main' || ip rule add iif wg0 to $n lookup main pref $((VPN_WG_PREF - 1)); "; done
    rules="ip route replace default via $gip dev $wif table $t && \
        { ip rule show | grep -q 'iif wg0 lookup $t' || ip rule add iif wg0 lookup $t pref $VPN_WG_PREF; } && $s \
        { iptables -t nat -C POSTROUTING -s $sub -o $wif -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s $sub -o $wif -j MASQUERADE; }"
    _vpn_wgx "$c" "$rules" >/dev/null || true
    _vpn_wgx "$c" "ip rule show" | grep -q "iif wg0 lookup $t" || { VPN_ERR="$c did not take the route (it needs NET_ADMIN, ip and iptables)"; return 1; }
    # Gluetun's side: forward what comes from the WireGuard server into the tunnel, and its answers back
    local post="iptables -A FORWARD -i $gif -o tun0 -s $wip -j ACCEPT
iptables -A FORWARD -i tun0 -o $gif -d $wip -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -t nat -A POSTROUTING -o tun0 -s $wip -j MASQUERADE"
    local pdir; pdir=$(_vpn_appdata)/iptables
    mkdir -p "$pdir" 2>/dev/null && printf '%s\n' "$post" > "$pdir/post-rules.txt"
    while IFS= read -r n; do
        _vpn_wgx "$VPN_CONTAINER" "${n/-A /-C } 2>/dev/null || $n" >/dev/null
    done <<< "$post"
    _vpn_set --arg c "$c" --arg sub "$sub" --arg wip "$wip" --arg gip "$gip" --arg net "$gnet" --argjson now "$(_vpn_now)" \
        '.wg_clients = ((.wg_clients // {}) + {on: true, container: $c, subnet: $sub, wg_ip: $wip, gluetun_ip: $gip, network: $net, applied_at: $now})'
    return 0
}
_vpn_wg_remove() {
    local w c sub wip gip net t="$VPN_WG_TABLE" n s=""
    w=$(jq -c '.wg_clients // {}' <<< "$(_vpn_state)")
    c=$(jq -r '.container // empty' <<< "$w"); sub=$(jq -r '.subnet // empty' <<< "$w"); wip=$(jq -r '.wg_ip // empty' <<< "$w"); net=$(jq -r '.network // empty' <<< "$w")
    if [[ -n "$c" ]]; then
        for n in $VPN_PRIVATE_NETS; do s+="ip rule del iif wg0 to $n lookup main 2>/dev/null; "; done
        _vpn_wgx "$c" "ip rule del iif wg0 lookup $t 2>/dev/null; $s ip route flush table $t 2>/dev/null; \
            for i in \$(ip -o -4 addr | awk '{print \$2}' | sort -u); do iptables -t nat -D POSTROUTING -s $sub -o \$i -j MASQUERADE 2>/dev/null; done; true" >/dev/null
        local home; home=$(jq -r '.home_gw // empty' <<< "$w")
        [[ "$home" =~ ^[0-9.]+$ ]] && _vpn_wgx "$c" "ip route replace default via $home" >/dev/null
        [[ "$(jq -r '.joined // false' <<< "$w")" == true && -n "$net" ]] && docker network disconnect "$net" "$c" >/dev/null 2>&1
    fi
    : > "$(_vpn_appdata)/iptables/post-rules.txt" 2>/dev/null
    if [[ -n "$wip" ]]; then
        gip=$(_vpn_wgx "$VPN_CONTAINER" "iptables -S FORWARD; iptables -t nat -S POSTROUTING" | grep -F -- "$wip/32" || true)
        while IFS= read -r n; do [[ -n "$n" ]] && _vpn_wgx "$VPN_CONTAINER" "iptables ${n/-A /-D }; iptables -t nat ${n/-A /-D }" >/dev/null; done <<< "$gip"
    fi
    _vpn_set --arg c "$c" '.wg_clients = {on: false, container: (if $c == "" then null else $c end)}'
}

# PUT /vpn/wireguard-clients — Route the WireGuard server's clients (wg-easy) out through the VPN, or not {"on": true|false, "container": "WireGuard"}: the server itself keeps the home address, so they can still connect from outside
handle_vpn_wg_clients() {
    local body="$1" on c
    _api_check_admin || { _api_error 403 "Admin access required"; return; }
    _vpn_deployed || { _api_error 409 "The VPN is not set up"; return; }
    on=$(jq -r 'if .on == true then "true" elif .on == false then "false" else "" end' <<< "$body" 2>/dev/null)
    [[ -n "$on" ]] || { _api_error 400 "on is true or false"; return; }
    c=$(jq -r '.container // empty | strings' <<< "$body" 2>/dev/null)
    if [[ -n "$c" ]]; then _api_validate_resource_name "$c" container || return; _vpn_set --arg c "$c" '.wg_clients.container = $c'; fi
    if [[ "$on" == true ]]; then
        if ! _vpn_wg_apply; then _vpn_set '.wg_clients.on = false'; _api_error 409 "$VPN_ERR"; return; fi
        _vpn_audit vpn_wireguard_clients "the WireGuard clients of $(_vpn_wg_container) now leave through the VPN, by ${AUTH_USERNAME:-unknown}"
        _api_success "$(jq -c '{success: true} + .wg_clients + {message: "The WireGuard clients reach the internet through the VPN; they still connect to this home'"'"'s address"}' <<< "$(_vpn_state)")"
    else
        _vpn_wg_remove
        _vpn_audit vpn_wireguard_clients "the WireGuard clients use the home connection again, by ${AUTH_USERNAME:-unknown}"
        _api_success '{"success": true, "on": false, "message": "The WireGuard clients use the home connection again"}'
    fi
}

# =============================================================================
# The minute clock
# =============================================================================
_vpn_tick() {
    _vpn_deployed || return 0
    _vpn_seed_rules
    local now g st was gid gstart n=0 live qb port c minute
    now=$(_vpn_now); minute=$(( now / 60 ))
    g=$(_vpn_gluetun); st=$(_vpn_state)
    was=$(jq -r '.gluetun // ""' <<< "$st")
    if [[ "$g" == true\ * && "$g" != "$was" ]]; then
        read -r _ gid gstart _ <<< "$g"
        if [[ -n "$was" && "$was" != absent ]]; then
            # Gluetun restarted (or is a new container): the containers behind it lost their network
            while IFS=$'\t' read -r sts svc c; do
                [[ -n "$c" ]] || continue
                _container_mark_intended "$c" 2>/dev/null
                if [[ "$was" == *" $gid "* ]]; then docker restart "$c" >/dev/null 2>&1; else _vpn_up "$sts" --force-recreate "$svc"; fi
                n=$((n + 1))
            done < <(jq -r '.[] | [.stack, .service, .container] | @tsv' <<< "$(_vpn_attached)")
            (( n > 0 )) && _vpn_audit vpn_restart_dependents "Gluetun restarted ($gstart): $n container(s) behind it restarted"
        fi
        _vpn_set --arg g "$g" '.gluetun = $g'
    fi
    [[ "$(jq -r '.wg_clients.on // false' <<< "$st")" == true && "$g" == true\ * ]] && { _vpn_wg_apply || _vpn_audit vpn_error "the WireGuard clients' route: $VPN_ERR"; }
    [[ "$(jq -r '.paused // false' <<< "$st")" == true ]] && { _vpn_set '.down_since = null'; _vpn_clear vpn_down "The VPN is paused" "Paused on purpose."; return 0; }
    live='{"connected":false}'; [[ "$g" == true\ * ]] && live=$(_vpn_live)
    if [[ "$(jq -r .connected <<< "$live")" == true ]]; then
        _vpn_set '.down_since = null'
        _vpn_clear vpn_down "The VPN is up again" "The tunnel is up ($(jq -r '.public_ip' <<< "$live")): the containers behind it are online."
        port=$(jq -r '.forwarded_port // empty' <<< "$live")
        qb=$(jq -r '[.[] | select(.image | test("qbittorrent"; "i")) | .container] | first // empty' <<< "$(_vpn_attached)")
        if [[ "$port" =~ ^[0-9]+$ && -n "$qb" && "$port" != "$(jq -r '.qbit_port // ""' <<< "$st")" ]]; then
            if _vpn_qbit_set "$qb" "$port"; then
                _vpn_set --argjson p "$port" '.qbit_port = $p | del(.qbit_error)'; _vpn_audit vpn_port_forward "qBittorrent listens on PIA's forwarded port $port"
            else _vpn_set --arg e "$QB_ERR" '.qbit_error = $e'; fi
        fi
        (( minute % VPN_LEAK_EVERY == 0 )) && [[ "$(_vpn_attached)" != '[]' ]] && _vpn_leaks >/dev/null
    else
        local since; since=$(jq -r '.down_since // empty' <<< "$st")
        [[ -n "$since" ]] || { since=$now; _vpn_set --argjson n "$now" '.down_since = $n'; }
        if (( now - since >= VPN_DOWN_AFTER )); then
            local who; who=$(jq -r '[.[].container] | join(", ")' <<< "$(_vpn_attached)")
            _vpn_raise vpn_down vpn_down "The VPN is down" \
                "The tunnel has been down for $(( (now - since) / 60 )) minutes${who:+: $who are cut off from the internet by the kill switch until it is back}."
        fi
        # PIA forgets a key it has not seen for a while: a new one, at most every 30 minutes
        if (( now - since >= VPN_REKEY_AFTER )) && secrets_exists VPN_USER 2>/dev/null \
            && (( now - $(jq -r '.rekeyed_at // 0' <<< "$st") >= 1800 )); then
            _vpn_set --argjson n "$now" '.rekeyed_at = $n'
            if _vpn_pia_register "$(_vpn_env VPN_REGION_ID | sed 's/^$/auto/')"; then
                _vpn_up "$VPN_STACK" --force-recreate "$VPN_SERVICE" && _vpn_recreate_attached
                _vpn_audit vpn_rekey "the VPN was down: a new WireGuard key was registered with PIA"
            else _vpn_audit vpn_error "the VPN was down and a new key could not be registered: $VPN_ERR"; fi
        fi
    fi
    return 0
}
