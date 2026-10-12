#!/bin/bash
# shellcheck shell=bash
# =============================================================================
# The VPN's traffic, history, speed check, server switch and per-container policy (sourced by .lib/vpn.sh)
#
# Traffic. The tunnel's bytes are tun0's counters in Gluetun's /proc/net/dev (one docker exec a minute; a tunnel Gluetun
# rebuilt inside, a new tun0 with a new ifindex, counts from zero, as does a new Gluetun container). The containers
# behind it share Gluetun's network namespace, so their own /proc/net/dev is the same tunnel: their share is counted by
# the kernel instead, in Gluetun's mangle table. A rule per container matches what its processes send (the socket's
# cgroup, -m cgroup --path) and marks the connection (CONNMARK, the top byte); a rule in INPUT counts what comes back on
# a marked connection. The WireGuard clients (routed through Gluetun) are counted in FORWARD by the WireGuard server's
# address. The cgroup paths are only visible from the host's cgroup namespace, so the rules are written by a short-lived
# helper (Gluetun's own image, --network container:Gluetun --cgroupns host, NET_ADMIN only), again whenever Gluetun or a
# container behind it is a new container. The minute clock keeps the deltas in .data/vpn/traffic.json: per minute for
# 24 h, per hour for 30 days, per day for a year, each with the minutes the tunnel was up (paused minutes do not count).
#
# History. .data/vpn/history.json keeps the last 500 events: connect, disconnect (with Gluetun's last error line),
# reconnect, restart, server change, pause, resume, rekey, the forwarded port, leak and speed tests, the stop/restart
# policy. GET /vpn/history adds uptime (24 h, 30 days), the current session and the forwarded port's history.
# =============================================================================

VPN_TRAFFIC="$VPN_DIR/traffic.json"
VPN_HISTORY="$VPN_DIR/history.json"
VPN_LIVE="$VPN_DIR/traffic-live.json"
VPN_LATENCY="$VPN_DIR/latency.json"
VPN_SPEED_EVERY=300               # seconds between two speed checks
VPN_SPEED_URL_DEFAULT="https://speed.cloudflare.com/__down?bytes=20000000"
VPN_NAME_RE='^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$'

# _vpn_event KIND MESSAGE [JSON]: one line in the history (the newest last, 500 kept)
_vpn_event() {
    (umask 077; mkdir -p "$VPN_DIR") 2>/dev/null
    _api_state_file "$VPN_HISTORY" '{"events":[]}' object >/dev/null 2>&1 || true
    _api_jq_update_file "$VPN_HISTORY" --arg k "$1" --arg m "$2" --argjson x "${3:-null}" --argjson now "$(_vpn_now)" \
        '.events = ((.events // []) + [{t: $now, kind: $k, message: $m} + ($x // {})])[-500:]' || true
}

# =============================================================================
# Counters
# =============================================================================

# _vpn_counters → {"rx","tx","c":{name:{rx,tx}},"if"} read in Gluetun now, or nothing when it cannot be read
_vpn_counters() {
    local raw
    raw=$(timeout 10 docker exec "$VPN_CONTAINER" sh -c 'cat /proc/net/dev; for i in tun0 wg0; do [ -r /sys/class/net/$i/ifindex ] && { echo "ifindex $(cat /sys/class/net/$i/ifindex)"; break; }; done; for c in DCSVPN_OUT DCSVPN_IN DCSVPN_FWD; do iptables -t mangle -nvxL $c 2>/dev/null; done' 2>/dev/null) || return 1
    awk '
        /^ifindex [0-9]+$/ { ix=$2; next }
        /^ *(tun0|wg0):/ && !ifc { l=$0; sub(/:/, " ", l); split(l, f, " "); ifc=f[1]; rx=f[2]; tx=f[10]; next }
        match($0, /\/\* dcs:(rx|tx):[^ ]+ \*\//) {
            s=substr($0, RSTART+7, RLENGTH-10); dir=substr(s, 1, 2); name=substr(s, 4)
            split($0, f, " "); b[name, dir]+=f[2]; names[name]=1
        }
        END {
            if (!ifc) exit 1
            printf "{\"if\":\"%s\",\"ix\":%d,\"rx\":%.0f,\"tx\":%.0f,\"c\":{", ifc, ix, rx, tx
            sep=""; for (n in names) { printf "%s\"%s\":{\"rx\":%.0f,\"tx\":%.0f}", sep, n, b[n, "rx"], b[n, "tx"]; sep="," }
            printf "}}\n"
        }' <<< "$raw"
}

# _vpn_cgroup CONTAINER → its cgroup v2 path as the host sees it (/proc/PID/cgroup, or the driver's usual place)
_vpn_cgroup() {
    local id pid p drv
    read -r id pid < <(docker inspect --format '{{.Id}} {{.State.Pid}}' "$1" 2>/dev/null) || return 1
    [[ "$id" =~ ^[0-9a-f]{64}$ ]] || return 1
    p=$(sed -n 's/^0:://p' "/proc/$pid/cgroup" 2>/dev/null | head -1)
    # a /proc of another PID namespace (DCS in a container) can hold someone else's PID: only a path naming the container counts
    if [[ "$p" != *"$id"* ]]; then
        drv=$(docker info --format '{{.CgroupDriver}}' 2>/dev/null)
        if [[ "$drv" == systemd ]]; then p="/system.slice/docker-$id.scope"; else p="/docker/$id"; fi
    fi
    [[ "$p" =~ ^/[A-Za-z0-9_.@:/-]+$ ]] && printf '%s' "$p"
}

# _vpn_acct_ensure: the counting rules match the containers behind the VPN now (rewritten only when one of them, or Gluetun, changed)
_vpn_acct_ensure() {
    local g gid sig="" ids="" c id row wip img script n=0 p
    g=$(_vpn_gluetun); [[ "$g" == true\ * ]] || return 0
    read -r _ gid _ <<< "$g"
    while IFS= read -r c; do
        [[ "$c" =~ $VPN_NAME_RE ]] || continue
        id=$(docker inspect --format '{{.Id}}' "$c" 2>/dev/null) || continue
        ids+="$c=$id "
    done < <(jq -r '.[] | select(.running != false) | .container' <<< "$(_vpn_attached)")
    wip=$(jq -r 'if .wg_clients.on == true then .wg_clients.wg_ip // "" else "" end' <<< "$(_vpn_state)")
    sig="$gid|$ids|$wip"
    [[ "$sig" == "$(jq -r '.acct.sig // ""' <<< "$(_vpn_state)")" ]] && return 0
    script='T="iptables -t mangle"; for c in DCSVPN_OUT DCSVPN_IN DCSVPN_FWD; do $T -N $c 2>/dev/null || $T -F $c; done
$T -C OUTPUT -o tun0 -j DCSVPN_OUT 2>/dev/null || $T -A OUTPUT -o tun0 -j DCSVPN_OUT
$T -C INPUT -i tun0 -j DCSVPN_IN 2>/dev/null || $T -A INPUT -i tun0 -j DCSVPN_IN
$T -C FORWARD -j DCSVPN_FWD 2>/dev/null || $T -A FORWARD -j DCSVPN_FWD
'
    for row in $ids; do
        c="${row%%=*}"; n=$((n + 1)); (( n < 255 )) || break
        p=$(_vpn_cgroup "$c") || continue
        printf -v script '%sif $T -A DCSVPN_OUT -m cgroup --path %s -m comment --comment "dcs:tx:%s" -j CONNMARK --set-xmark 0x%02x000000/0xff000000 2>/dev/null && $T -A DCSVPN_IN -m connmark --mark 0x%02x000000/0xff000000 -m comment --comment "dcs:rx:%s"; then echo "counted %s"; else $T -D DCSVPN_OUT -m cgroup --path %s -m comment --comment "dcs:tx:%s" -j CONNMARK --set-xmark 0x%02x000000/0xff000000 2>/dev/null; echo "uncounted %s"; fi\n' \
            "$script" "$p" "$c" "$n" "$n" "$c" "$c" "$p" "$c" "$n" "$c"
    done
    [[ "$wip" =~ ^[0-9.]+$ ]] && script+="\$T -A DCSVPN_FWD -o tun0 -s $wip -m comment --comment dcs:tx:@wg; \$T -A DCSVPN_FWD -i tun0 -d $wip -m comment --comment dcs:rx:@wg
"
    img=$(docker inspect --format '{{.Image}}' "$VPN_CONTAINER" 2>/dev/null) || return 0
    local out
    if out=$(timeout 60 docker run --rm --network "container:$VPN_CONTAINER" --cgroupns host --cap-add NET_ADMIN --user 0 \
        --label dcs.helper=vpn-traffic --entrypoint /bin/sh "$img" -c "$script" 2>/dev/null); then
        # a kernel without the cgroup or connmark match (a minimal custom build) still counts the tunnel, not each container
        local un; un=$(sed -n 's/^uncounted //p' <<< "$out" | paste -sd, -)
        _vpn_set --arg s "$sig" --argjson now "$(_vpn_now)" --arg un "$un" '.acct = {sig: $s, at: $now}
            + (if $un == "" then {} else {uncounted: ($un | split(",")), error: "This server'"'"'s kernel cannot count each container (netfilter'"'"'s cgroup and connmark matches, xt_cgroup and xt_connmark, are missing): the tunnel'"'"'s total is still counted"} end)'
    else
        _vpn_set --argjson now "$(_vpn_now)" '.acct = {sig: "", at: $now, error: "the counting rules could not be written in Gluetun"}'
    fi
}

# _vpn_traffic_sample STATUS: the minute's deltas into traffic.json (STATUS u up, d down, p paused)
_vpn_traffic_sample() {
    local s="$1" cur="null" now gid asig
    now=$(_vpn_now)
    if [[ "$s" != p ]]; then _vpn_acct_ensure; cur=$(_vpn_counters) || cur="null"; fi
    [[ -n "$cur" ]] || cur="null"
    read -r _ gid _ <<< "$(_vpn_gluetun)"
    asig=$(jq -r '.acct.sig // ""' <<< "$(_vpn_state)")
    (umask 077; mkdir -p "$VPN_DIR") 2>/dev/null
    _api_state_file "$VPN_TRAFFIC" '{}' object >/dev/null 2>&1 || true
    _api_jq_update_file "$VPN_TRAFFIC" --argjson cur "$cur" --argjson now "$now" --arg s "$s" --arg gid "${gid:-}" --arg asig "$asig" \
        --arg day "$(date -d "@$now" +%F)" '
        def d(c; l): if l == null or c < l then c else c - l end;
        def addc(a; b): reduce ((b // {}) | to_entries[]) as $e (a // {}; .[$e.key] = [((.[$e.key][0]) // 0) + $e.value[0], ((.[$e.key][1]) // 0) + $e.value[1]]);
        (.last // null) as $l
        | (if $cur == null or $l == null then {rx: 0, tx: 0, c: {}}
           elif $l.gid != $gid or ($l.ix // 0) != ($cur.ix // 0) then {rx: $cur.rx, tx: $cur.tx, c: ($cur.c | map_values([.rx, .tx]))}
           else {rx: d($cur.rx; $l.rx), tx: d($cur.tx; $l.tx),
                 c: ($cur.c | with_entries(.key as $k | .value = (if $l.asig == $asig then [d(.value.rx; $l.c[$k].rx), d(.value.tx; $l.c[$k].tx)] else [.value.rx, .value.tx] end)))}
           end) as $d
        | (if $s == "u" then 1 else 0 end) as $up | (if $s == "p" then 0 else 1 end) as $n
        | def bump(key): if length > 0 and .[-1].k == key
              then .[:-1] + [.[-1] | .rx += $d.rx | .tx += $d.tx | .c = addc(.c; $d.c) | .up += $up | .n += $n]
              else . + [{k: key, rx: $d.rx, tx: $d.tx, c: addc({}; $d.c), up: $up, n: $n}] end;
        .v = 1
        | .minutes = ((.minutes // []) | bump(($now / 60 | floor) * 60) | map(select(.k > $now - 86400)))
        | .hours = ((.hours // []) | bump(($now / 3600 | floor) * 3600) | map(select(.k > $now - 2592000)))
        | .days = ((.days // []) | bump($day) | .[-366:])
        | if $cur == null then . else .last = {t: $now, gid: $gid, ix: $cur.ix, asig: $asig, rx: $cur.rx, tx: $cur.tx, c: $cur.c, if: $cur.if} end' || true
}

# GET /vpn/traffic — The tunnel's traffic: the rates now, today and this month (down and up), 24 hours in 5-minute steps, 30 days by the hour, a year by the day, and each container behind it with its share
handle_vpn_traffic() {
    local cur live prev now t
    _vpn_deployed || { _api_error 409 "The VPN is not set up"; return; }
    _api_state_file "$VPN_TRAFFIC" '{}' object >/dev/null 2>&1 || true
    now=$(_vpn_now); t="${EPOCHREALTIME:-$now}"
    live='null'
    if [[ "$(_vpn_gluetun)" == true\ * ]] && cur=$(_vpn_counters) && [[ -n "$cur" ]]; then
        prev=$(cat "$VPN_LIVE" 2>/dev/null); jq -e . <<< "$prev" >/dev/null 2>&1 || prev='null'
        live=$(jq -nc --argjson c "$cur" --argjson p "$prev" --arg t "$t" '
            ($t | tonumber) as $t
            | if $p != null and ($t - $p.t) >= 1.5 and ($t - $p.t) <= 120 and $c.rx >= $p.rx and $c.tx >= $p.tx
              then {rx_bps: ((($c.rx - $p.rx) / ($t - $p.t)) | floor), tx_bps: ((($c.tx - $p.tx) / ($t - $p.t)) | floor), window_s: (($t - $p.t) * 10 | round / 10)}
              else null end')
        (umask 077; jq -nc --argjson c "$cur" --arg t "$t" '{t: ($t | tonumber), rx: $c.rx, tx: $c.tx}' > "$VPN_LIVE.tmp" && mv -f "$VPN_LIVE.tmp" "$VPN_LIVE") 2>/dev/null
    fi
    _api_success "$(jq -c --argjson live "$live" --argjson now "$now" --arg day "$(date -d "@$now" +%F)" --arg month "$(date -d "@$now" +%Y-%m)" \
        --argjson att "$(_vpn_attached)" --argjson st "$(_vpn_state)" '
        def sum(f): reduce .[] as $x (0; . + ($x | f));
        def tot: {rx: sum(.rx), tx: sum(.tx)};
        def ctot(name): {rx: sum(.c[name][0] // 0), tx: sum(.c[name][1] // 0)};
        (.minutes // []) as $m | (.hours // []) as $h | (.days // []) as $dy | (.last // null) as $last
        | [$dy[] | select(.k == $day)] as $today | [$dy[] | select(.k | startswith($month))] as $mon
        | ($mon | tot) as $mt | ($m[-1] // null) as $lm
        | {measured: ($last != null), interface: ($last.if // null), updated_at: ($last.t // null),
           live: ($live // (if $lm != null and $lm.k >= $now - 180 then {rx_bps: ($lm.rx / 60 | floor), tx_bps: ($lm.tx / 60 | floor), window_s: 60} else null end)),
           totals: {today: ($today | tot), month: $mt, last_24h: ($m | tot)},
           per_5min: ($m | group_by(.k / 300 | floor) | map([(.[0].k / 300 | floor) * 300, sum(.rx), sum(.tx)])),
           hourly: ($h | map([.k, .rx, .tx])), daily: ($dy | map([.k, .rx, .tx])),
           uptime: {last_24h: (($m | sum(.n)) as $n | if $n > 0 then (($m | sum(.up)) * 1000 / $n | round / 10) else null end),
                    last_30d: (($h | sum(.n)) as $n | if $n > 0 then (($h | sum(.up)) * 1000 / $n | round / 10) else null end)},
           containers: [$att[] | .container as $c
                | ($mon | ctot($c)) as $cm
                | {container: $c, today: ($today | ctot($c)), month: $cm, last_24h: ($m | ctot($c)),
                   share: (if ($mt.rx + $mt.tx) > 0 then ((($cm.rx + $cm.tx) / ($mt.rx + $mt.tx) * 1000 | round) / 1000) else null end),
                   measured: (($last.c // {}) | has($c))}],
           wireguard_clients: (if ($st.wg_clients.on // false) or (($last.c // {}) | has("@wg")) then
                {today: ($today | ctot("@wg")), month: ($mon | ctot("@wg")), last_24h: ($m | ctot("@wg"))} else null end),
           counting_error: ($st.acct.error // null)}' "$VPN_TRAFFIC")"
}

# =============================================================================
# History
# =============================================================================

# _vpn_gluetun_reason SINCE → Gluetun's last error or warning line since then (its time stamp and level cut off), or nothing
_vpn_gluetun_reason() {
    docker logs --since "$1" --tail 300 "$VPN_CONTAINER" 2>&1 | grep -E 'ERROR|WARN|unhealthy|restarting' | tail -1 \
        | sed -E 's/^[0-9TZ:.+-]+ +//; s/^(ERROR|WARN) +//' | tr -cd '[:print:]' | cut -c1-200 || true
}

# _vpn_link UP(true|false|paused) LIVE: the link's transitions into the history (the minute clock)
_vpn_link() {
    local up="$1" live="$2" now st was since cause reason down_s
    now=$(_vpn_now); st=$(_vpn_state)
    was=$(jq -r '.link.up | if . == null then "none" else tostring end' <<< "$st"); since=$(jq -r '.link.since // 0' <<< "$st"); cause=$(jq -r '.link.cause // ""' <<< "$st")
    if [[ "$up" == "$was" ]]; then
        # a DCS action that never showed as a drop (Gluetun back within the minute) still ends here
        [[ "$up" == true && -n "$cause" ]] && { _vpn_event connect "The tunnel is up ($(jq -r '.public_ip // "?"' <<< "$live")) after $cause" "$(jq -nc --arg ip "$(jq -r '.public_ip // ""' <<< "$live")" --arg s "$(_vpn_env VPN_SERVER_NAME)" '{ip: $ip, server: $s}')"; _vpn_set '.link.cause = null'; }
        return 0
    fi
    case "$up" in
        true)
            if [[ "$was" == false && -z "$cause" ]]; then
                down_s=$((now - since))
                _vpn_event reconnect "The tunnel is back after $(_vpn_dur "$down_s") down ($(jq -r '.public_ip // "?"' <<< "$live"))" "$(jq -nc --argjson d "$down_s" --arg ip "$(jq -r '.public_ip // ""' <<< "$live")" '{down_s: $d, ip: $ip}')"
                _fire_notifications vpn_reconnected "headline=The VPN reconnected" "message=The tunnel is back after $(_vpn_dur "$down_s") down." "status=info" "fingerprint=vpn_reconnected" >/dev/null 2>&1 || true
            else
                _vpn_event connect "The tunnel is up ($(jq -r '.public_ip // "?"' <<< "$live"))${cause:+ after $cause}" "$(jq -nc --arg ip "$(jq -r '.public_ip // ""' <<< "$live")" --arg s "$(_vpn_env VPN_SERVER_NAME)" '{ip: $ip, server: $s}')"
            fi ;;
        false)
            if [[ "$was" == true ]]; then
                if [[ "$(_vpn_gluetun)" == true\ * ]]; then reason=$(_vpn_gluetun_reason "$((now - 180))"); else reason="Gluetun is not running"; fi
                [[ -n "$cause" ]] && reason="$cause"
                _vpn_event disconnect "The tunnel went down${reason:+: $reason}" "$(jq -nc --arg r "$reason" '{reason: (if $r == "" then null else $r end)}')"
            fi ;;
    esac
    # a DCS action explains one transition only
    _vpn_set --argjson u "$( [[ "$up" == paused ]] && echo '"paused"' || echo "$up")" --argjson now "$now" \
        '.link = {up: $u, since: $now, cause: (if $u == true then null else .link.cause end)}'
}
# _vpn_cause TEXT: what DCS did to the tunnel (the next transition says so instead of guessing)
_vpn_cause() { _vpn_set --arg c "$1" '.link.cause = $c'; }

_vpn_dur() {
    local s="$1"
    if (( s < 90 )); then printf '%d s' "$s"; elif (( s < 5400 )); then printf '%d min' $(( (s + 30) / 60 ));
    elif (( s < 172800 )); then printf '%d h' $(( (s + 1800) / 3600 )); else printf '%d days' $(( (s + 43200) / 86400 )); fi
}

# GET /vpn/history — What the tunnel did: connects, disconnects with the reason, reconnects, server changes, pauses, the forwarded port, leak and speed tests (newest first), uptime over 24 hours and 30 days, the current session
handle_vpn_history() {
    _vpn_deployed || { _api_error 409 "The VPN is not set up"; return; }
    _api_state_file "$VPN_HISTORY" '{"events":[]}' object >/dev/null 2>&1 || true
    _api_state_file "$VPN_TRAFFIC" '{}' object >/dev/null 2>&1 || true
    _api_success "$(jq -nc --slurpfile h "$VPN_HISTORY" --slurpfile tr "$VPN_TRAFFIC" --argjson st "$(_vpn_state)" --argjson now "$(_vpn_now)" '
        def sum(f): reduce .[] as $x (0; . + ($x | f));
        def pct(a): (a | sum(.n)) as $n | if $n > 0 then ((a | sum(.up)) * 1000 / $n | round / 10) else null end;
        ($h[0].events // []) as $e | ($tr[0] // {}) as $t
        | ([$e[] | select(.kind == "port")]) as $p
        | {events: ($e | reverse | .[:200]),
           uptime: {last_24h: pct($t.minutes // []), last_30d: pct($t.hours // [])},
           session: (if ($st.link.up // null) == true then {up: true, since: $st.link.since, length_s: ($now - $st.link.since)}
                     else {up: false, since: ($st.link.since // null), length_s: null, paused: (($st.link.up // null) == "paused")} end),
           reconnects_24h: ([$e[] | select(.kind == "reconnect" and .t > $now - 86400)] | length),
           ports: ([range(0; $p | length) as $i | {port: $p[$i].port, from: $p[$i].t, to: ($p[$i + 1].t // null)}] | reverse),
           last_leak_test: ($st.last_leak // null),
           speed_tests: ([$e[] | select(.kind == "speed_test") | {t, mbps, latency_ms, bytes, seconds, host}] | reverse | .[:20])}')"
}

# =============================================================================
# Speed check
# =============================================================================

# POST /vpn/speed-test — Download a test file through the tunnel from inside Gluetun (VPN_SPEEDTEST_URL, 20 MB from Cloudflare by default) and ping its host: Mbps and the latency, kept in the history; one every 5 minutes
handle_vpn_speed_test() {
    local url host last now raw n a b ping secs mbps lat res
    _api_check_admin || { _api_error 403 "Admin access required"; return; }
    _vpn_deployed || { _api_error 409 "The VPN is not set up"; return; }
    [[ "$(_vpn_gluetun)" == true\ * ]] || { _api_error 409 "Gluetun is not running"; return; }
    now=$(_vpn_now); last=$(jq -r '.speed.at // 0' <<< "$(_vpn_state)")
    if (( now - last < VPN_SPEED_EVERY )); then
        _api_response 429 "$(jq -nc --argjson r "$((VPN_SPEED_EVERY - (now - last)))" '{error: true, code: 429, retry_after: $r, message: "One speed check every 5 minutes: try again in \(($r + 59) / 60 | floor) min"}')"; return
    fi
    url=$(envfile_get "$BASE_DIR/.env" VPN_SPEEDTEST_URL 2>/dev/null) || url=""; [[ -n "$url" ]] || url="$VPN_SPEED_URL_DEFAULT"
    [[ "$url" =~ ^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~%/?=\&+-]*)?$ ]] || { _api_error 400 "VPN_SPEEDTEST_URL is not a plain http(s) address"; return; }
    host="${url#*://}"; host="${host%%[/:]*}"
    _vpn_set --argjson now "$now" '.speed.at = $now'
    # /proc/uptime on both sides of the download: the time inside Gluetun, without docker exec's own start-up
    raw=$(timeout 90 docker exec "$VPN_CONTAINER" sh -c '
        u=$1; h=$2
        set -- $(cat /proc/uptime); a=$1
        n=$(wget -qO- -T 60 "$u" 2>/dev/null | wc -c)
        set -- $(cat /proc/uptime); b=$1
        p=$(ping -c 3 -W 2 "$h" 2>/dev/null | sed -n "s|.*= [0-9.]*/\([0-9.]*\)/.*|\1|p")
        echo "$n $a $b ${p:-}"' sh "$url" "$host" 2>/dev/null | tail -1) || raw=""
    read -r n a b ping <<< "$raw"
    [[ "$n" =~ ^[0-9]+$ ]] && (( n >= 100000 )) || { _vpn_event speed_test_failed "The speed check could not download $host through the tunnel"; _api_error 502 "The test file could not be downloaded through the tunnel (from $host)"; return; }
    secs=$(awk -v a="$a" -v b="$b" 'BEGIN { s = b - a; if (s < 0.01) s = 0.01; printf "%.2f", s }')
    mbps=$(awk -v n="$n" -v s="$secs" 'BEGIN { printf "%.1f", n * 8 / s / 1000000 }')
    [[ "$ping" =~ ^[0-9]+(\.[0-9]+)?$ ]] && lat=$(awk -v p="$ping" 'BEGIN { printf "%.0f", p }') || lat=null
    res=$(jq -nc --argjson n "$n" --argjson s "$secs" --argjson m "$mbps" --argjson l "$lat" --arg h "$host" --argjson now "$now" \
        '{at: $now, bytes: $n, seconds: $s, mbps: $m, latency_ms: $l, host: $h}')
    _vpn_set --argjson r "$res" '.speed = $r'
    local msg="Speed check: $mbps Mbps down"; [[ "$lat" != null ]] && msg+=", $lat ms to $host"
    _vpn_event speed_test "$msg" "$(jq -c 'del(.at)' <<< "$res")"
    _api_success "$(jq -c '{success: true} + . + {message: "\(.mbps) Mbps through the tunnel\(if .latency_ms then ", \(.latency_ms) ms to \(.host)" else "" end)"}' <<< "$res")"
}

# =============================================================================
# Server switching (the stored account)
# =============================================================================

# _vpn_pia_latencies SERVERLIST → {region id: ms} (every region that forwards a port, measured at once; .data/vpn/latency.json)
_vpn_pia_latencies() {
    local list="$1" d ip id port="${DCS_VPN_PIA_PROBE_PORT:-443}" out
    d=$(mktemp -d "${TMPDIR:-/tmp}/dcs-vpnlat-XXXXXX") || return 1
    while read -r ip id; do
        [[ "$ip" =~ ^[0-9.]+$ && "$id" =~ ^[A-Za-z0-9_-]+$ ]] || continue
        { curl -o /dev/null -s --connect-timeout 2 -w '%{time_connect}' "http://$ip:$port" > "$d/$id" 2>/dev/null || rm -f "$d/$id"; } &
    done < <(jq -r '.regions[] | select(.port_forward == true and ((.servers.wg // []) | length) > 0) | "\(.servers.meta[0].ip // "") \(.id)"' <<< "$list")
    wait
    out=$(for f in "$d"/*; do [[ -f "$f" ]] && printf '%s %s\n' "${f##*/}" "$(cat "$f")"; done \
        | awk '$2 ~ /^[0-9.]+$/ { printf "%s\"%s\":%d", (n++ ? "," : "{"), $1, $2 * 1000 + 0.5 } END { printf "%s", (n ? "}" : "{}") }')
    rm -rf -- "$d"
    (umask 077; jq -nc --argjson m "$out" --argjson now "$(_vpn_now)" '{at: $now, ms: $m}' > "$VPN_LATENCY.tmp" && mv -f "$VPN_LATENCY.tmp" "$VPN_LATENCY") 2>/dev/null
    printf '%s' "$out"
}

# POST /vpn/server — Move the tunnel to another PIA server with the stored account {region: a region id | "fastest"}: fastest measures every region that forwards a port now and takes the quickest; a new key is registered there and Gluetun restarted
handle_vpn_server() {
    local body="$1" want lat="" id ms
    _api_check_admin || { _api_error 403 "Admin access required"; return; }
    _vpn_deployed || { _api_error 409 "The VPN is not set up"; return; }
    want=$(jq -r '.region // empty | strings' <<< "$body" 2>/dev/null) || want=""
    [[ "$want" =~ ^[A-Za-z0-9_-]{1,64}$ ]] || { _api_error 400 "region is \"fastest\" or a region id from GET /vpn/regions"; return; }
    secrets_exists VPN_USER 2>/dev/null && secrets_exists VPN_PASS 2>/dev/null || { _api_error 409 "Connect with your PIA account first"; return; }
    if [[ "$want" == fastest ]]; then
        local list; list=$(_vpn_pia_serverlist) || list=""; [[ -n "$list" ]] || { _api_error 502 "PIA's server list could not be fetched"; return; }
        lat=$(_vpn_pia_latencies "$list") || lat='{}'
        id=$(jq -r 'to_entries | sort_by(.value) | first.key // empty' <<< "$lat")
        [[ -n "$id" ]] || { _api_error 502 "No PIA server answered the latency probe: pick a region"; return; }
        want="$id"
    fi
    _vpn_cause "the switch to another server"
    _vpn_pia_register "$want" || { _vpn_set '.link.cause = null'; _api_error 502 "$VPN_ERR"; return; }
    _container_mark_intended "$VPN_CONTAINER" 2>/dev/null
    _vpn_up "$VPN_STACK" --force-recreate "$VPN_SERVICE" || { _api_error 500 "The key is registered, but Gluetun did not start: look at its logs"; return; }
    _vpn_recreate_attached
    _vpn_set --argjson now "$(_vpn_now)" '.paused = false | .down_since = null | .last_change = $now | .rekeyed_at = $now | del(.qbit_port)'
    ms=$(jq -r --arg r "$want" '.ms[$r] // empty' "$VPN_LATENCY" 2>/dev/null) || ms=""
    _vpn_event server_change "Moved to $(jq -r '"\(.name) (\(.server))"' <<< "$VPN_REGION_JSON") by ${AUTH_USERNAME:-unknown}${ms:+, $ms ms}" "$(jq -c --arg ms "$ms" '{region: .id, server: .server, latency_ms: ($ms | tonumber? // null)}' <<< "$VPN_REGION_JSON")"
    _vpn_audit vpn_server "the VPN moved to PIA $(jq -r '"\(.name) (\(.server))"' <<< "$VPN_REGION_JSON"), by ${AUTH_USERNAME:-unknown}"
    _api_cache_clear 2>/dev/null || true
    _api_success "$(jq -nc --argjson r "$VPN_REGION_JSON" --arg ms "$ms" '{success: true, region: $r, latency_ms: ($ms | tonumber? // null),
        message: "Moving to \($r.name) (\($r.server))\(if $ms != "" then ", \($ms) ms away" else "" end): the tunnel is back in a few seconds"}')"
}

# =============================================================================
# Per-container policy: stop it while the tunnel is down, start it again when it is back
# =============================================================================

# PUT /vpn/containers/{name} — What a container behind the VPN does when the tunnel goes down {stop_when_down: true|false, restart_when_up: true|false}: stopped after 2 minutes down (the kill switch already cuts it off; this stops the errors piling up), started again when the tunnel is back
handle_vpn_container_policy() {
    local c="$1" body="$2" sd ru
    _api_check_admin || { _api_error 403 "Admin access required"; return; }
    jq -e --arg c "$c" 'any(.[]; .container == $c)' <<< "$(_vpn_attached)" >/dev/null || { _api_error 404 "$c does not go through the VPN"; return; }
    sd=$(jq -r 'if has("stop_when_down") then (if .stop_when_down | type == "boolean" then .stop_when_down else "bad" end) else "keep" end' <<< "$body" 2>/dev/null) || sd=bad
    ru=$(jq -r 'if has("restart_when_up") then (if .restart_when_up | type == "boolean" then .restart_when_up else "bad" end) else "keep" end' <<< "$body" 2>/dev/null) || ru=bad
    [[ "$sd" =~ ^(true|false|keep)$ && "$ru" =~ ^(true|false|keep)$ && "$sd$ru" != keepkeep ]] || { _api_error 400 "stop_when_down and restart_when_up are true or false"; return; }
    _vpn_set --arg c "$c" --arg sd "$sd" --arg ru "$ru" '.attached = [(.attached // [])[] | if .container == $c then
        (if $sd == "keep" then . else .stop_when_down = ($sd == "true") end) | (if $ru == "keep" then . else .restart_when_up = ($ru == "true") end) else . end]'
    _vpn_audit vpn_policy "$c behind the VPN: stop when the tunnel is down $(jq -r --arg c "$c" '.[] | select(.container == $c) | "\(.stop_when_down // false), restart when it is back \(.restart_when_up // false)"' <<< "$(_vpn_attached)"), by ${AUTH_USERNAME:-unknown}"
    _api_cache_clear 2>/dev/null || true
    _api_success "$(jq -c --arg c "$c" '.[] | select(.container == $c) | {success: true, container: $c, stop_when_down: (.stop_when_down // false), restart_when_up: (.restart_when_up // false)}' <<< "$(_vpn_attached)")"
}

# _vpn_policy_down: the tunnel has been down long enough: stop the containers that asked for it
_vpn_policy_down() {
    local st svc c gid
    read -r _ gid _ <<< "$(_vpn_gluetun)"
    while IFS=$'\t' read -r st svc c; do
        [[ -n "$c" ]] || continue
        jq -e --arg c "$c" '(.policy_stopped // {}) | has($c)' <<< "$(_vpn_state)" >/dev/null && continue
        [[ "$(docker inspect --format '{{.State.Running}}' "$c" 2>/dev/null)" == true ]] || continue
        _container_mark_intended "$c" 2>/dev/null
        docker stop "$c" >/dev/null 2>&1 || continue
        _vpn_set --arg c "$c" --arg g "${gid:-}" '.policy_stopped[$c] = $g'
        _vpn_event policy_stop "$c stopped while the tunnel is down" "$(jq -nc --arg c "$c" '{container: $c}')"
    done < <(jq -r '.[] | select(.stop_when_down == true) | [.stack, .service, .container] | @tsv' <<< "$(_vpn_attached)")
}
# _vpn_policy_up: the tunnel is back: start what the policy stopped (and asked to be started), recreated when Gluetun is a new container
_vpn_policy_up() {
    local ps c row st svc gid was
    ps=$(jq -c '.policy_stopped // {}' <<< "$(_vpn_state)"); [[ "$ps" != '{}' ]] || return 0
    read -r _ gid _ <<< "$(_vpn_gluetun)"
    while IFS=$'\t' read -r c was; do
        row=$(jq -c --arg c "$c" 'map(select(.container == $c)) | first // empty' <<< "$(_vpn_attached)")
        _vpn_set --arg c "$c" 'del(.policy_stopped[$c])'
        [[ -n "$row" ]] || continue
        if [[ "$(jq -r '.restart_when_up // false' <<< "$row")" != true ]]; then
            _vpn_event policy_kept "$c stays stopped (the tunnel is back; start it from Containers)" "$(jq -nc --arg c "$c" '{container: $c}')"; continue
        fi
        [[ "$(docker inspect --format '{{.State.Running}}' "$c" 2>/dev/null)" == true ]] && continue
        st=$(jq -r .stack <<< "$row"); svc=$(jq -r .service <<< "$row")
        _container_mark_intended "$c" 2>/dev/null
        if [[ "$was" == "$gid" ]]; then docker start "$c" >/dev/null 2>&1; else _vpn_up "$st" --force-recreate "$svc"; fi \
            && _vpn_event policy_start "$c started again: the tunnel is back" "$(jq -nc --arg c "$c" '{container: $c}')" \
            || _vpn_audit vpn_error "$c could not be started again after the tunnel came back"
    done < <(jq -r 'to_entries[] | [.key, .value] | @tsv' <<< "$ps")
}

# =============================================================================
# The weekly line (vpn_weekly_digest, a rule that is off until it is switched on)
# =============================================================================
_vpn_digest() {
    local now wk msg
    now=$(_vpn_now)
    [[ "$(date -d "@$now" +%u)" == 1 ]] && (( 10#$(date -d "@$now" +%H) >= 8 )) || return 0
    wk=$(date -d "@$now" +%G-W%V)
    [[ "$(jq -r '.digest_week // ""' <<< "$(_vpn_state)")" != "$wk" ]] || return 0
    _vpn_set --arg w "$wk" '.digest_week = $w'
    [[ -s "$VPN_TRAFFIC" ]] || return 0
    msg=$(jq -r --argjson now "$now" --slurpfile h <(cat "$VPN_HISTORY" 2>/dev/null || echo '{}') '
        def gb: . / 1e9 | . * 10 | round / 10 | tostring + " GB";
        def sum(f): reduce .[] as $x (0; . + ($x | f));
        [(.hours // [])[] | select(.k > $now - 604800)] as $w
        | ($w | sum(.n)) as $n
        | "Last 7 days: \($w | sum(.rx) | gb) down, \($w | sum(.tx) | gb) up"
          + (if $n > 0 then ", up \(($w | sum(.up)) * 1000 / $n | round / 10) % of the time" else "" end)
          + ", \([($h[0].events // [])[] | select(.kind == "reconnect" and .t > $now - 604800)] | length) reconnect(s)"
          + ([($h[0].events // [])[] | select(.kind == "speed_test")] | last | if . then ", last speed check \(.mbps) Mbps" else "" end) + "."' "$VPN_TRAFFIC" 2>/dev/null) || return 0
    _fire_notifications vpn_weekly_digest "headline=The VPN this week" "message=$msg" "status=info" "fingerprint=vpn_weekly_digest_$wk" >/dev/null 2>&1 || true
}
