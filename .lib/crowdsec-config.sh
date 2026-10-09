#!/bin/bash
# shellcheck shell=bash
# =============================================================================
# CrowdSec page — the ban profile and the Discord notifications
#
# Two files decide what CrowdSec does with an attack: profiles.yaml (how long a
# ban lasts, which scenario gets its own length, whether repeat offenders are
# banned longer, who is told) and notifications/http.yaml (the Discord message).
# This file writes both from settings the page edits, and does it safely:
#   1. the candidate files are built from the settings (no YAML library needed),
#   2. CrowdSec itself checks them (`crowdsec -t` on an alternate config, and a
#      dry run of the notification plugin against a dead address),
#   3. the live files are backed up, replaced, the container restarted and
#      watched until it is healthy again,
#   4. anything that goes wrong puts the backups back and restarts once more.
# The settings live in .data/crowdsec/{settings,notify}.json; the profile file
# also carries them in its header, so it explains itself.
#
# Sourced on demand by _crowdsec_cfg_lib (api-server.sh), after crowdsec.sh.
# =============================================================================

# shellcheck disable=SC2034  # read by the router (_crowdsec_cfg_lib in api-server.sh)
CROWDSEC_CFG_LOADED=1
CS_PROFILES_PATH="/etc/crowdsec/profiles.yaml"
CS_HTTP_PATH="/etc/crowdsec/notifications/http.yaml"
CS_SETTINGS_FILE="$CROWDSEC_STATE_DIR/settings.json"
CS_NOTIFY_FILE="$CROWDSEC_STATE_DIR/notify.json"
CS_NOTIFY_STATUS="$CROWDSEC_STATE_DIR/notify-status.json"
CS_BACKUP_DIR="$CROWDSEC_STATE_DIR/backups"
CS_WEBHOOK_SECRET="CROWDSEC_DISCORD_WEBHOOK"
# automatic bans may last as long as a manual one: ten years (effectively permanent)
CS_MAX_AUTO_SECONDS=315360000
CS_CFG_ERR=""

# a JSON object from a file, or the given default
_cs_json_file() {
    local f="$1" d="${2:-\{\}}" j
    if [[ -s "$f" ]] && j=$(jq -c 'if type == "object" then . else empty end' "$f" 2>/dev/null) && [[ -n "$j" ]]; then printf '%s' "$j"; else printf '%s' "$d"; fi
}
# write a JSON object atomically, private
_cs_json_save() {
    local f="$1" tmp
    mkdir -p "$(dirname "$f")" 2>/dev/null
    tmp=$(umask 077; mktemp "$f.XXXXXX") || return 1
    cat > "$tmp" && chmod 600 "$tmp" && mv -f "$tmp" "$f"
}

# =============================================================================
# The live files
# =============================================================================

# _cs_live_file PATH — the file as it is in the container (empty when absent)
_cs_live_file() { timeout 10 docker exec "$CS_NAME" cat "$1" 2>/dev/null </dev/null; }

# =============================================================================
# profiles.yaml: reading what is there
# =============================================================================

# JSON view of a profiles file: which profiles, what durations, who is notified, and whether DCS wrote it or it is untouched stock
#   mode: dcs (written here) | stock (CrowdSec's or DCS's shipped file, nothing else) | custom (anything else) | missing
_cs_profile_inspect() {
    local raw="$1" hdr
    if [[ -z "${raw//[[:space:]]/}" ]]; then printf '{"mode":"missing","profiles":[],"ip_duration":null,"range_duration":null,"escalate":false,"notified":false,"header":null}'; return; fi
    hdr=$(printf '%s\n' "$raw" | sed -n '1,6s/^# dcs-settings: //p' | head -n 1)
    printf '%s\n' "$raw" | awk '
        BEGIN { doc = 0 }
        /^---[[:space:]]*$/ { doc++; sect=""; next }
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*$/ { next }
        /^[A-Za-z_]+:/ { key=$0; sub(/:.*/, "", key); val=$0; sub(/^[A-Za-z_]+:[[:space:]]*/, "", val); sub(/[[:space:]]+#.*$/, "", val); sect=key; print doc "\tkey\t" key "\t" val; next }
        sect != "" && /^[[:space:]]+-[[:space:]]+/ { item=$0; sub(/^[[:space:]]+-[[:space:]]+/, "", item); sub(/[[:space:]]+#.*$/, "", item); print doc "\titem\t" sect "\t" item; next }
        sect == "decisions" && /^[[:space:]]+[A-Za-z_]+:/ { k=$0; sub(/^[[:space:]]+/, "", k); v=k; sub(/:.*/, "", k); sub(/^[^:]*:[[:space:]]*/, "", v); sub(/[[:space:]]+#.*$/, "", v); print doc "\tdec\t" k "\t" v; next }
        { print doc "\tother\t" sect "\t" $0 }' \
        | jq -Rsc --arg hdr "${hdr:-null}" '
            def unq: if (startswith("\"") and endswith("\"")) or (startswith("'"'"'") and endswith("'"'"'")) then .[1:-1] else . end;
            [ split("\n")[] | select(length > 0) | split("\t") ] as $rows
            | ([ $rows[] | .[0] | tonumber ] | unique) as $docs
            | [ $docs[] | . as $d | ($rows | map(select(.[0] == ($d | tostring)))) as $r
                | { keys: ($r | map(select(.[1] == "key")) | map({key: .[2], value: (.[3] // "")}) ),
                    filters: ($r | map(select(.[1] == "item" and .[2] == "filters")) | map(.[3] | unq)),
                    notifications: ($r | map(select(.[1] == "item" and .[2] == "notifications")) | map(.[3] | unq)),
                    types: ($r | map(select(.[1] == "item" and .[2] == "decisions" and (.[3] | startswith("type:")))) | map(.[3] | sub("^type:[[:space:]]*"; "") | unq)
                             + ($r | map(select(.[1] == "dec" and .[2] == "type")) | map(.[3] | unq))),
                    durations: ($r | map(select(.[1] == "item" and .[2] == "decisions" and (.[3] | startswith("duration:")))) | map(.[3] | sub("^duration:[[:space:]]*"; "") | unq)
                               + ($r | map(select(.[1] == "dec" and .[2] == "duration")) | map(.[3] | unq))),
                    others: ($r | map(select(.[1] == "other" or (.[1] == "dec" and (.[2] != "type" and .[2] != "duration"))))| length) } ] as $p
            | ($p | map(.keys | map(select(.key == "name")) | .[0].value // "" | unq)) as $names
            | ("default_ip_remediation" ) as $ipn | ("default_range_remediation") as $rgn
            | ($p | map(select((.keys | map(select(.key == "name")) | .[0].value // "" | unq) == $ipn)) | .[0]) as $ip
            | ($p | map(select((.keys | map(select(.key == "name")) | .[0].value // "" | unq) == $rgn)) | .[0]) as $rg
            | def keyset: (.keys | map(.key));
              def expr_of: (.keys | map(select(.key == "duration_expr")) | .[0].value // "" | unq);
              def stock_ok($f):
                (.filters == [$f]) and (.types == ["ban"]) and ((.durations | length) == 1) and (.others == 0)
                and ((keyset - ["name", "filters", "decisions", "notifications", "on_success", "duration_expr"]) == [])
                and (((.keys | map(select(.key == "on_success")) | .[0].value // "break") | unq) == "break")
                and ((.notifications - ["http_default"]) == [])
                and ((expr_of == "") or (expr_of | test("^Sprintf\\((\"|'"'"')%dh(\"|'"'"'), \\(GetDecisionsCount\\(Alert\\.GetValue\\(\\)\\) \\+ 1\\) \\* [0-9]+\\)$")));
              ($hdr != "null") as $hasdcs
            | { profiles: $names,
                mode: (if $hasdcs then "dcs"
                       elif ($p | length) >= 1 and ($p | length) <= 2 and (($names - [$ipn, $rgn]) == [])
                            and (if $ip != null then ($ip | stock_ok("Alert.Remediation == true && Alert.GetScope() == \"Ip\"")) else true end)
                            and (if $rg != null then ($rg | stock_ok("Alert.Remediation == true && Alert.GetScope() == \"Range\"")) else true end)
                       then "stock" else "custom" end),
                ip_duration: ($ip.durations[0] // null), range_duration: ($rg.durations[0] // null),
                escalate: ((($ip // {keys: []}) | expr_of) != "" or (($rg // {keys: []}) | expr_of) != ""),
                notified: ($p | map(.notifications | index("http_default") != null) | any),
                header: (if $hasdcs then ($hdr | fromjson? // null) else null end) }'
}

# =============================================================================
# profiles.yaml: the settings, and the file they make
# =============================================================================

_CS_PROFILE_DEFAULTS='{"duration":"4h","range_duration":"4h","escalate":{"enabled":false,"max":"720h"},"overrides":[],"appsec_ban":true}'
_CS_NOTIFY_FILTER_DEFAULTS='{"enabled":true,"events":{"bans":true,"simulated":true,"detect_only":false},"filters":{"min_events":0,"only":[],"ignore":[]}}'

# The settings the live file stands for: DCS's own header, or what the stock/shipped file says. $1 = _cs_profile_inspect JSON
_cs_profile_live_settings() {
    jq -c --argjson d "$_CS_PROFILE_DEFAULTS" '
        if .header != null and (.header.profile // null) != null then ($d * .header.profile)
        else . as $i | $d
             | (if $i.ip_duration != null then .duration = $i.ip_duration else . end)
             | (if $i.range_duration != null then .range_duration = $i.range_duration else . end)
             | (if $i.escalate then .escalate.enabled = true else . end) end' <<< "$1"
}

# _cs_profile_merge BASE PATCH — the patch over the base (escalate merges key by key, overrides are replaced as a list)
_cs_profile_merge() {
    jq -nc --argjson b "$1" --argjson p "$2" '
        $b * ($p | del(.escalate, .overrides))
        | .escalate = (($b.escalate // {}) * ($p.escalate // {}))
        | .overrides = (if ($p | has("overrides")) then $p.overrides else ($b.overrides // []) end)'
}

# _cs_profile_validate JSON — the normalised settings land in CS_OUT (not on stdout: a subshell would lose CS_CFG_ERR); a problem sets CS_CFG_ERR and returns 1
_cs_profile_validate() {
    local j="$1" v secs i n pat dur out
    CS_CFG_ERR=""
    jq -e 'type == "object" and (.escalate | type == "object") and (.overrides | type == "array")' >/dev/null 2>&1 <<< "$j" || { CS_CFG_ERR="The ban profile settings are malformed"; return 1; }
    local d rd
    d=$(_cs_norm_duration "$(jq -r '.duration | tostring' <<< "$j")") || { CS_CFG_ERR="The default ban duration is not valid: use 30m, 4h, 7d or 2w"; return 1; }
    rd=$(jq -r '(.range_duration // .duration) | tostring' <<< "$j")
    rd=$(_cs_norm_duration "$rd") || { CS_CFG_ERR="The range ban duration is not valid: use 30m, 4h, 7d or 2w"; return 1; }
    for v in "$d" "$rd"; do
        secs=$(_cs_duration_seconds "$v")
        (( secs <= CS_MAX_AUTO_SECONDS )) || { CS_CFG_ERR="Automatic bans can last at most ten years (3650d). Use a manual ban for longer."; return 1; }
    done
    local esc_on esc_max
    esc_on=$(jq -r 'if .escalate.enabled == true then "true" else "false" end' <<< "$j")
    esc_max=$(_cs_norm_duration "$(jq -r '(.escalate.max // "720h") | tostring' <<< "$j")") || { CS_CFG_ERR="The longest repeat-offender ban is not valid: use 7d, 30d or 90d"; return 1; }
    secs=$(_cs_duration_seconds "$esc_max")
    (( secs <= CS_MAX_AUTO_SECONDS )) || { CS_CFG_ERR="The longest repeat-offender ban can be ten years (3650d) at most"; return 1; }
    n=$(jq '.overrides | length' <<< "$j")
    (( n <= 12 )) || { CS_CFG_ERR="At most 12 scenario overrides"; return 1; }
    local -a ovr=(); local -A seen=()
    for (( i = 0; i < n; i++ )); do
        pat=$(jq -r ".overrides[$i].pattern | tostring" <<< "$j")
        _cs_valid_pattern "$pat" || { CS_CFG_ERR="Override $(( i + 1 )): the scenario \"${pat:0:60}\" is not valid. Use a name like crowdsecurity/ssh-bf or a prefix like crowdsecurity/ssh*"; return 1; }
        [[ -z "${seen[$pat]:-}" ]] || { CS_CFG_ERR="The scenario $pat has two overrides"; return 1; }
        seen[$pat]=1
        dur=$(_cs_norm_duration "$(jq -r ".overrides[$i].duration | tostring" <<< "$j")") || { CS_CFG_ERR="Override $(( i + 1 )) ($pat): the duration is not valid: use 30m, 4h, 7d or 2w"; return 1; }
        secs=$(_cs_duration_seconds "$dur")
        (( secs <= CS_MAX_AUTO_SECONDS )) || { CS_CFG_ERR="Override $(( i + 1 )) ($pat): automatic bans can last at most ten years"; return 1; }
        ovr+=("$(jq -nc --arg p "$pat" --arg d "$dur" '{pattern: $p, duration: $d}')")
    done
    if [[ "$esc_on" == true ]]; then
        (( $(_cs_duration_seconds "$esc_max") >= $(_cs_duration_seconds "$d") )) || { CS_CFG_ERR="The longest repeat-offender ban ($esc_max) is shorter than the default ban ($d)"; return 1; }
    fi
    local ab
    ab=$(jq -r 'if .appsec_ban == false then "false" else "true" end' <<< "$j")
    out=$( ( [[ ${#ovr[@]} -gt 0 ]] && printf '%s\n' "${ovr[@]}" || true ) | jq -sc --arg d "$d" --arg rd "$rd" --argjson eo "$esc_on" --arg em "$esc_max" --argjson ab "$ab" '{duration: $d, range_duration: $rd, escalate: {enabled: $eo, max: $em}, overrides: ., appsec_ban: $ab}')
    CS_OUT="$out"
}

# The jq that turns (settings, notify) into profiles.yaml. Filters are single-quoted YAML scalars; the header carries the settings.
# jq 1.7 (Debian 13's) binds `as` tighter than `+`: `A + B as $x | rest` is `A + (B as $x | rest)` there (jq 1.8 reads it as `(A + B) as $x`),
# so a sum that is bound to a name is kept in parentheses. Without them the overrides array was added to the finished file text.
_CS_JQ_PROFILES='
def sq: "'"'"'" + gsub("'"'"'"; "'"'"''"'"'") + "'"'"'";
def secs($d): ($d | capture("^(?<n>[0-9]+)(?<u>[mh])$") | (.n | tonumber) * (if .u == "h" then 3600 else 60 end));
def scen_match($p): if ($p | endswith("*")) then "Alert.GetScenario() startsWith " + ($p | rtrimstr("*") | @json) else "Alert.GetScenario() == " + ($p | @json) end;
def any_match($ps): "(" + ($ps | map(scen_match(.)) | join(" || ")) + ")";
def dur_expr($d; $max):
  (secs($d)) as $b | (secs($max)) as $m
  | if $b % 3600 == 0 and $m % 3600 == 0
    then "Sprintf(\"%dh\", min((GetDecisionsCount(Alert.GetValue()) + 1) * \($b / 3600), \($m / 3600)))"
    else "Sprintf(\"%ds\", min((GetDecisionsCount(Alert.GetValue()) + 1) * \($b), \($m)))" end;
def emit($name; $cond; $dur; $expr; $notify; $on_success):
  "name: " + $name + "\nfilters:\n  - " + ($cond | sq) + "\ndecisions:\n  - type: ban\n    duration: " + $dur + "\n"
  + (if $expr != "" then "duration_expr: " + ($expr | sq) + "\n" else "" end)
  + (if $notify then "notifications:\n  - http_default\n" else "" end)
  + "on_success: " + $on_success + "\n";
. as $in
| $in.profile as $p | $in.notify as $n | $in.notify_on as $on
| ([ (if ($n.filters.min_events // 0) > 1 then "Alert.GetEventsCount() >= \($n.filters.min_events)" else empty end),
     (if (($n.filters.only // []) | length) > 0 then any_match($n.filters.only) else empty end),
     (if (($n.filters.ignore // []) | length) > 0 then "!" + any_match($n.filters.ignore) else empty end) ]) as $base_nf
| ($base_nf + (if $n.events.simulated == false then ["(Alert.Simulated == nil || !Alert.Simulated)"] else [] end) | join(" && ")) as $nf
| ($base_nf | join(" && ")) as $nf_detect
| ([ ($p.overrides // [])[] | . as $o | {name: ("dcs_override_" + (($p.overrides | map(.pattern) | index($o.pattern)) + 1 | tostring)), cond: ("Alert.Remediation == true && " + scen_match($o.pattern)), dur: $o.duration} ]
  + (if $p.appsec_ban == true then
       [ {name: "dcs_appsec_ip", cond: "Alert.Remediation == false && (Alert.Simulated == nil || !Alert.Simulated) && Alert.GetScope() == \"Ip\" && (Alert.GetScenario() startsWith \"crowdsecurity/vpatch\" || Alert.GetScenario() startsWith \"crowdsecurity/appsec\")", dur: $p.duration},
         {name: "dcs_appsec_range", cond: "Alert.Remediation == false && (Alert.Simulated == nil || !Alert.Simulated) && Alert.GetScope() == \"Range\" && (Alert.GetScenario() startsWith \"crowdsecurity/vpatch\" || Alert.GetScenario() startsWith \"crowdsecurity/appsec\")", dur: $p.range_duration} ]
     else [] end)
  + [ {name: "default_ip_remediation", cond: "Alert.Remediation == true && Alert.GetScope() == \"Ip\"", dur: $p.duration},
      {name: "default_range_remediation", cond: "Alert.Remediation == true && Alert.GetScope() == \"Range\"", dur: $p.range_duration} ]) as $groups
| [ $groups[] | . as $g
    | (if $p.escalate.enabled then dur_expr($g.dur; $p.escalate.max) else "" end) as $expr
    | if $on and ($n.events.bans != false) then
        (if $nf != "" then emit($g.name + "_notify"; $g.cond + " && " + $nf; $g.dur; $expr; true; "break") + "---\n" + emit($g.name; $g.cond; $g.dur; $expr; false; "break")
         else emit($g.name; $g.cond; $g.dur; $expr; true; "break") end)
      else emit($g.name; $g.cond; $g.dur; $expr; false; "break") end ] as $blocks
| ($blocks + (if $on and ($n.events.detect_only == true) then
      ["name: dcs_notify_detect_only\nfilters:\n  - " + (("Alert.Remediation == false" + (if $nf_detect != "" then " && " + $nf_detect else "" end)) | sq) + "\nnotifications:\n  - http_default\non_success: continue\n"] else [] end)) as $all
| "# Managed by DCS: the CrowdSec page writes this file (Settings and Discord tabs). Change it there; a backup of the previous file is kept.\n"
  + "# dcs-settings: " + ({v: 1, profile: $p, notify: {enabled: $n.enabled, events: $n.events, filters: $n.filters}} | tojson) + "\n"
  + ($all | join("---\n"))
'

# _cs_profiles_render PROFILE_JSON NOTIFY_JSON NOTIFY_ON(true|false) — the profiles.yaml text
_cs_profiles_render() {
    jq -nc --argjson profile "$1" --argjson notify "$2" --argjson notify_on "$3" '{profile: $profile, notify: $notify, notify_on: $notify_on}' \
        | jq -j "$_CS_JQ_PROFILES"
}

# =============================================================================
# Trying a candidate before it goes live
# =============================================================================

# _cs_validate_candidates PROFILES_TEXT HTTP_TEXT — CrowdSec's own verdict on candidate files, in a scratch directory of the container.
# PROFILES_TEXT / HTTP_TEXT may be empty (that file is unchanged). Sets CS_CFG_ERR and returns 1 when CrowdSec would not accept them.
_cs_validate_candidates() {
    local prof="$1" http="$2" tmp out rc cfg="/tmp/dcs-vtest"
    CS_CFG_ERR=""
    tmp=$(mktemp -d "${TMPDIR:-/tmp}/dcs-cs-val.XXXXXX") || { CS_CFG_ERR="no temporary directory"; return 1; }
    # two plain commands, never a shell string
    { timeout 10 docker exec "$CS_NAME" rm -rf "$cfg" && timeout 10 docker exec "$CS_NAME" mkdir -p "$cfg/notifications"; } >/dev/null 2>&1 </dev/null || { CS_CFG_ERR="could not prepare a scratch directory in the container"; rm -rf "$tmp"; return 1; }
    local live_cfg
    live_cfg=$(_cs_live_file /etc/crowdsec/config.yaml)
    [[ -n "$live_cfg" ]] || { CS_CFG_ERR="could not read CrowdSec's config.yaml"; rm -rf "$tmp"; return 1; }
    [[ -n "$prof" ]] || prof=$(_cs_live_file "$CS_PROFILES_PATH")
    printf '%s\n' "$prof" > "$tmp/profiles.yaml"
    printf '%s\n' "$live_cfg" | sed -e "s#^\([[:space:]]*profiles_path:\).*#\1 $cfg/profiles.yaml#" -e "s#^\([[:space:]]*notification_dir:\).*#\1 $cfg/notifications/#" > "$tmp/config.yaml"
    # the other plugin files stay as they are; the candidate http.yaml points at a dead address with short timeouts (a dry run must never post anything)
    local f
    while IFS= read -r f; do
        [[ "$f" == http.yaml ]] && continue
        [[ "$f" =~ ^[a-z_]+\.yaml$ ]] || continue
        _cs_live_file "/etc/crowdsec/notifications/$f" > "$tmp/notifications-$f"
        timeout 10 docker cp "$tmp/notifications-$f" "$CS_NAME:$cfg/notifications/$f" >/dev/null 2>&1 || true
    done < <(timeout 10 docker exec "$CS_NAME" ls -1 /etc/crowdsec/notifications 2>/dev/null </dev/null)
    if [[ -z "$http" ]]; then http=$(_cs_live_file "$CS_HTTP_PATH"); fi
    if [[ -n "$http" ]]; then
        printf '%s\n' "$http" | sed -e 's#^url:.*#url: http://127.0.0.1:9/dcs-validate#' -e 's#^max_retry:.*#max_retry: 1#' -e 's#^timeout:.*#timeout: 2s#' -e '/^group_wait:/d' -e 's#^group_threshold:.*#group_threshold: 1#' > "$tmp/http.yaml"
        timeout 10 docker cp "$tmp/http.yaml" "$CS_NAME:$cfg/notifications/http.yaml" >/dev/null 2>&1 || { CS_CFG_ERR="could not stage the notification file"; rm -rf "$tmp"; return 1; }
    fi
    timeout 10 docker cp "$tmp/profiles.yaml" "$CS_NAME:$cfg/profiles.yaml" >/dev/null 2>&1 || { CS_CFG_ERR="could not stage the profiles file"; rm -rf "$tmp"; return 1; }
    timeout 10 docker cp "$tmp/config.yaml" "$CS_NAME:$cfg/config.yaml" >/dev/null 2>&1 || { CS_CFG_ERR="could not stage the test configuration"; rm -rf "$tmp"; return 1; }
    out=$(timeout 60 docker exec "$CS_NAME" crowdsec -t -c "$cfg/config.yaml" 2>&1 </dev/null); rc=$?
    if (( rc != 0 )); then
        CS_CFG_ERR=$(printf '%s\n' "$out" | grep -E 'level=(fatal|error)' | tail -n 1 | sed -e 's/.*msg="//' -e 's/"[^"]*$//' -e 's/\\"/"/g' -e 's/\\n.*//' | cut -c1-400)
        [[ -n "$CS_CFG_ERR" ]] || CS_CFG_ERR="CrowdSec's configuration test failed"
        CS_CFG_ERR="CrowdSec would not accept the profiles: $CS_CFG_ERR"
    elif [[ -n "$http" ]] && grep -q '^type: http' <<< "$http"; then
        # The plugin dry run. A template that does not compile is reported as "format alerts for notification"; one that does is seen
        # trying the (dead) address. cscli sometimes leaves before the plugin has said either, so an unclear run is repeated.
        local verdict=""
        for _ in 1 2 3 4; do
            out=$(timeout 60 docker exec "$CS_NAME" cscli -c "$cfg/config.yaml" notifications test http_default 2>&1 </dev/null)
            if grep -q 'format alerts for notification' <<< "$out"; then
                CS_CFG_ERR="The Discord message template does not compile: $(printf '%s\n' "$out" | grep 'format alerts for notification' | head -n 1 | sed -e 's/.*format alerts for notification: //' -e 's/ plugin:=.*//' -e 's/"$//' | cut -c1-300)"
                verdict=bad; break
            elif grep -qE 'Failed to make HTTP request|connection refused|non 200 status|delivery failed|notify attempt failed' <<< "$out"; then
                verdict=good; break
            fi
            sleep 1
        done
        if [[ "$verdict" == bad ]]; then rc=1
        elif [[ "$verdict" != good ]]; then CS_CFG_ERR="Could not verify the Discord message template (the notification plugin did not answer)"; rc=1; fi
    fi
    timeout 10 docker exec "$CS_NAME" rm -rf "$cfg" >/dev/null 2>&1 </dev/null
    rm -rf "$tmp"
    return $(( rc != 0 ))
}

# =============================================================================
# Putting a candidate live: back up, write, restart, watch, roll back
# =============================================================================

# _cs_wait_healthy SECONDS — 0 when the container is running, healthy and the local API answers
_cs_wait_healthy() {
    local limit="${1:-90}" i st out
    for (( i = 0; i < limit; i += 2 )); do
        st=$(timeout 8 docker inspect -f '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$CS_NAME" 2>/dev/null </dev/null)
        if [[ "$st" == "running|healthy" || "$st" == "running|none" ]]; then
            if _cs_run out lapi status; then return 0; fi
        fi
        sleep 2
    done
    return 1
}

# _cs_copy_in TEXT DEST MODE — write TEXT to DEST inside the container (docker cp of a private temp file)
_cs_copy_in() {
    local text="$1" dest="$2" mode="$3" tmp rc
    tmp=$(umask 077; mktemp "${TMPDIR:-/tmp}/dcs-cs-cp.XXXXXX") || return 1
    printf '%s\n' "$text" > "$tmp"; chmod "$mode" "$tmp"
    timeout 20 docker cp "$tmp" "$CS_NAME:$dest" >/dev/null 2>&1; rc=$?
    rm -f "$tmp"
    return $rc
}

# The locked part of _cs_config_apply
CS_APPLY_MSG=""; CS_APPLY_CHANGED=0; CS_APPLY_ROLLED_BACK=0; CS_APPLY_BACKUP=""
_cs_config_apply_locked() {
    local prof="$1" http="$2" live_p live_h cp=0 ch=0 ts hexist=0 pexist=0 failed=""
    CS_APPLY_MSG=""; CS_APPLY_CHANGED=0; CS_APPLY_ROLLED_BACK=0; CS_APPLY_BACKUP=""
    live_p=$(_cs_live_file "$CS_PROFILES_PATH"); live_h=$(_cs_live_file "$CS_HTTP_PATH")
    [[ -n "$live_p" ]] && pexist=1; [[ -n "$live_h" ]] && hexist=1
    if [[ -n "$prof" && "$prof" != "$live_p" ]]; then cp=1; else prof=""; fi
    if [[ -n "$http" && "$http" != "$live_h" ]]; then ch=1; else http=""; fi
    if (( cp + ch == 0 )); then CS_APPLY_MSG="CrowdSec already has these settings"; return 0; fi
    # CrowdSec's own verdict first: nothing is touched when it says no
    if ! _cs_validate_candidates "$prof" "$http"; then CS_APPLY_MSG="$CS_CFG_ERR"; return 4; fi
    # the way back
    ts=$(date -u +%Y%m%dT%H%M%SZ)
    mkdir -p "$CS_BACKUP_DIR" && chmod 700 "$CS_BACKUP_DIR" 2>/dev/null
    (( cp )) && [[ $pexist == 1 ]] && { printf '%s\n' "$live_p" > "$CS_BACKUP_DIR/profiles-$ts.yaml"; chmod 600 "$CS_BACKUP_DIR/profiles-$ts.yaml"; CS_APPLY_BACKUP="profiles-$ts.yaml"; }
    (( ch )) && [[ $hexist == 1 ]] && { printf '%s\n' "$live_h" > "$CS_BACKUP_DIR/http-$ts.yaml"; chmod 600 "$CS_BACKUP_DIR/http-$ts.yaml"; }
    # write, restart, watch
    if (( cp )); then _cs_copy_in "$prof" "$CS_PROFILES_PATH" 644 || failed="could not write $CS_PROFILES_PATH"; fi
    if [[ -z "$failed" ]] && (( ch )); then _cs_copy_in "$http" "$CS_HTTP_PATH" 600 || failed="could not write $CS_HTTP_PATH"; fi
    if [[ -z "$failed" ]]; then
        timeout 120 docker restart "$CS_NAME" >/dev/null 2>&1 </dev/null || failed="docker could not restart the container"
    fi
    if [[ -z "$failed" ]] && ! _cs_wait_healthy 90; then failed="CrowdSec did not come back healthy within 90 seconds"; fi
    if [[ -z "$failed" ]]; then
        # the files must read back exactly as written, and the notification plugin must have picked http.yaml up
        if (( cp )) && [[ "$(_cs_live_file "$CS_PROFILES_PATH")" != "$prof" ]]; then failed="the profiles file did not read back as written"; fi
        if [[ -z "$failed" ]] && (( ch )) && [[ "$(_cs_live_file "$CS_HTTP_PATH")" != "$http" ]]; then failed="the notification file did not read back as written"; fi
    fi
    if [[ -z "$failed" ]]; then CS_APPLY_CHANGED=1; CS_APPLY_MSG="Applied. CrowdSec restarted and is healthy."; return 0; fi
    # something went wrong: put the old files back and restart once more
    local log; log=$(_cs_log_tail 6 | tr '\n' ' ' | cut -c1-500)
    (( cp )) && { if [[ $pexist == 1 ]]; then _cs_copy_in "$live_p" "$CS_PROFILES_PATH" 644; else timeout 10 docker exec "$CS_NAME" rm -f "$CS_PROFILES_PATH" >/dev/null 2>&1; fi; }
    (( ch )) && { if [[ $hexist == 1 ]]; then _cs_copy_in "$live_h" "$CS_HTTP_PATH" 600; else timeout 10 docker exec "$CS_NAME" rm -f "$CS_HTTP_PATH" >/dev/null 2>&1; fi; }
    timeout 120 docker restart "$CS_NAME" >/dev/null 2>&1 </dev/null
    if _cs_wait_healthy 90; then
        CS_APPLY_ROLLED_BACK=1; CS_APPLY_MSG="$failed. The previous files are back and CrowdSec is healthy again.${log:+ Log: $log}"; return 5
    fi
    CS_APPLY_MSG="$failed, and CrowdSec did not come back after the previous files were restored. Look at the log on the CrowdSec page.${log:+ Log: $log}"
    return 6
}

# _cs_config_apply PROFILES_TEXT HTTP_TEXT — see above. Returns 0 ok · 3 busy · 4 CrowdSec rejected the files (nothing changed) · 5 failed, rolled back · 6 failed, could not roll back
_cs_config_apply() {
    local rc
    mkdir -p "$CROWDSEC_STATE_DIR" 2>/dev/null
    {
        flock -w 8 9 || { CS_APPLY_MSG="Another CrowdSec configuration change is running. Try again in a minute."; return 3; }
        _cs_config_apply_locked "$1" "$2"; rc=$?
    } 9>"$CROWDSEC_STATE_DIR/apply.lock"
    _cs_cache_clear
    return $rc
}

# the HTTP status a failed apply maps to
_cs_apply_http() { case "$1" in 3) echo 409 ;; 4) echo 422 ;; *) echo 502 ;; esac; }
# _cs_fail CODE MESSAGE [EXTRA_JSON] — record an error for the caller to send (returns 1)
CS_ERR_CODE=500; CS_ERR_BODY=""
_cs_fail() {
    local extra="${3:-}"; [[ -n "$extra" ]] || extra='{}'
    CS_ERR_CODE="$1"
    CS_ERR_BODY=$(jq -nc --arg m "$2" --argjson c "$1" --argjson x "$extra" '{error: true, code: $c, message: $m} + $x')
    return 1
}
# _cs_apply_error RC — record the failure of a _cs_config_apply (returns 1)
_cs_apply_error() {
    local rc="$1"
    _cs_fail "$(_cs_apply_http "$rc")" "$CS_APPLY_MSG" "$(jq -nc --argjson rb "$CS_APPLY_ROLLED_BACK" --argjson rc "$rc" '{rolled_back: ($rb == 1), stage: (if $rc == 4 then "validation" elif $rc == 3 then "busy" else "apply" end)}')"
}
_cs_apply_fail() { _cs_apply_error "$1"; _api_response "$CS_ERR_CODE" "$CS_ERR_BODY"; }

# GET-side view of the backups DCS kept: [{name, kind, created_at, size}]
_cs_backups_json() {
    local f name kind ts
    [[ -d "$CS_BACKUP_DIR" ]] || { printf '[]'; return; }
    for f in "$CS_BACKUP_DIR"/profiles-*.yaml "$CS_BACKUP_DIR"/http-*.yaml; do
        [[ -f "$f" ]] || continue
        name="${f##*/}"; kind="${name%%-*}"; ts="${name#*-}"; ts="${ts%.yaml}"
        jq -nc --arg n "$name" --arg k "$kind" --arg t "$ts" --argjson s "$(stat -c %s "$f" 2>/dev/null || echo 0)" '{name: $n, kind: $k, created_at: ($t | sub("^(?<d>[0-9]{4})(?<m>[0-9]{2})(?<dd>[0-9]{2})T(?<h>[0-9]{2})(?<mi>[0-9]{2})(?<s>[0-9]{2})Z$"; "\(.d)-\(.m)-\(.dd)T\(.h):\(.mi):\(.s)Z")), size: $s}'
    done | jq -sc 'sort_by(.created_at) | reverse | .[0:20]'
}

# =============================================================================
# Discord notifications: the settings
# =============================================================================

# What an untouched install sends (the same message as the shipped notifications-discord.yaml): one embed per address
# and batch, compact, with the attempts per scenario. CrowdSec gathers what arrives within group_wait (30 s) into one
# batch, at most group_threshold (50) alerts.
_CS_NOTIFY_DEFAULTS='{
 "v": 2, "enabled": true,
 "webhook": {"mode": "global"},
 "identity": {"name": "CrowdSec", "avatar_url": "https://raw.githubusercontent.com/scotthowson/dcs-orchestrator-ui/v2.0.0/brand/discord/crowdsec-avatar.png"},
 "embed": {"color_mode": "auto", "color": "#e11d48"},
 "mention": {"mode": "none", "id": "", "text": ""},
 "events": {"bans": true, "simulated": true, "detect_only": false},
 "filters": {"min_events": 0, "only": [], "ignore": []},
 "delivery": {"group_by": "address", "group_wait": 30, "group_threshold": 50, "max_retry": 3, "timeout": 10},
 "message": {
   "title": "🛡️ {ip}{source_tag}",
   "description": "**{attempts}**{ban_tag}\n{scenarios}{targets_line}{requests_line}",
   "footer": "CrowdSec · {domain}{machine_tag}",
   "link": "{cti_url}",
   "timestamp": false,
   "fields": [
     {"name": "Lookup", "value": "[CrowdSec CTI]({cti_url}) · [AbuseIPDB]({abuseipdb_url})", "inline": true}
   ]
 }
}'

# What DCS shipped before the messages were grouped (one embed per alert). Settings saved with exactly this message and
# delivery are an untouched install: they move to the defaults above (_cs_notify_upgrade). A message someone wrote stays.
_CS_NOTIFY_V1='{
 "delivery": {"group_wait": 5, "group_threshold": 10},
 "message": {
   "title": "🛡️ {label}",
   "description": "**{ip}**{country_tag}{as_tag}\n{events} hits → **{decision}**{for_duration}{target_tag}",
   "footer": "CrowdSec · {domain}{machine_tag}",
   "link": "{cti_url}",
   "timestamp": false,
   "fields": [
     {"name": "Scenario", "value": "`{scenario_short}`", "inline": true},
     {"name": "Scope", "value": "{scope}{origin_tag}", "inline": true},
     {"name": "Lookup", "value": "[CrowdSec CTI]({cti_url}) · [AbuseIPDB]({abuseipdb_url})", "inline": true},
     {"name": "First request", "value": "{path_code}", "inline": false}
   ]
 }
}'

# The placeholders a message may use: name, group, meaning, an example. Anything else in braces is refused.
_CS_PLACEHOLDERS='[
 {"name":"ip","group":"Source","label":"Address","example":"89.248.165.10","description":"The address (or network) that was banned."},
 {"name":"scope","group":"Source","label":"Scope","example":"Ip","description":"Ip for a single address, Range for a network."},
 {"name":"range","group":"Source","label":"Network","example":"89.248.165.0/24","description":"The network the address belongs to (empty when unknown)."},
 {"name":"country","group":"Source","label":"Country code","example":"NL","description":"Two-letter country code (empty when unknown)."},
 {"name":"flag","group":"Source","label":"Flag","example":":flag_nl:","description":"The Discord flag emoji of the country (empty when unknown)."},
 {"name":"country_tag","group":"Source","label":"Flag and country","example":" :flag_nl: NL","description":"Flag and code with a space in front; empty when the country is unknown, so no stray separators."},
 {"name":"flag_emoji","group":"Source","label":"Flag (emoji)","example":"🇳🇱","description":"The flag as an emoji: unlike :flag_nl: it is drawn in the title too (empty when the country is unknown)."},
 {"name":"source_tag","group":"Source","label":"Flag, country and network","example":" · 🇳🇱 NL · IP Volume inc","description":"\" · flag code · network\": whatever is known of the two, nothing when neither is."},
 {"name":"as_number","group":"Source","label":"AS number","example":"202425","description":"Autonomous system number (empty when unknown)."},
 {"name":"as_name","group":"Source","label":"Network name","example":"IP Volume inc","description":"Who runs the network the address is in (empty when unknown)."},
 {"name":"as_tag","group":"Source","label":"Network name (with separator)","example":" · IP Volume inc","description":"The network name with a dot in front; empty when unknown."},
 {"name":"scenario","group":"Detection","label":"Scenario","example":"crowdsecurity/http-probing","description":"The full scenario name."},
 {"name":"scenario_short","group":"Detection","label":"Scenario (short)","example":"http-probing","description":"The scenario without the crowdsecurity/ prefix."},
 {"name":"label","group":"Detection","label":"Attack type","example":"Web probing","description":"The scenario in plain words (SSH brute force, Exploit attempt, Web probing …); for an address with several, the one it tried most."},
 {"name":"events","group":"Detection","label":"Events","example":"13","description":"How many log lines added up to the detection (all the alerts of the address in this message)."},
 {"name":"attempts","group":"Detection","label":"Attempts","example":"47 attempts in 7s","description":"How many requests the address made in this message and over how long; \"one request\" when it was one."},
 {"name":"scenarios","group":"Detection","label":"What it tried","example":"Exploit attempt CVE-2025-29927 ×41 · Exploit attempt CVE-2024-4577 ×4 · Attack blocked appsec-vpatch ×2","description":"Every attack the address tried, the most frequent first, with how often (six, then \"+2 more\")."},
 {"name":"alerts","group":"Detection","label":"Alerts","example":"47","description":"How many alerts of the address this message holds."},
 {"name":"span","group":"Detection","label":"Time span","example":"7s","description":"The time from its first to its last request (empty when unknown)."},
 {"name":"alert_id","group":"Detection","label":"Alert id","example":"42","description":"CrowdSec'"'"'s alert number (see the Alerts tab)."},
 {"name":"message","group":"Detection","label":"CrowdSec message","example":"Ip 89.248.165.10 performed crowdsecurity/http-probing (13 events over 4s)","description":"CrowdSec'"'"'s own one-line summary of the alert."},
 {"name":"sim_tag","group":"Detection","label":"Simulation marker","example":" (simulation)","description":"\" (simulation)\" when the scenario only alerts without banning; empty otherwise."},
 {"name":"decision","group":"Decision","label":"Decision","example":"ban","description":"What was decided: ban (or simulated ban when the scenario is in simulation mode)."},
 {"name":"duration","group":"Decision","label":"Duration","example":"4h","description":"How long the ban lasts (empty when there is no decision)."},
 {"name":"for_duration","group":"Decision","label":"\"for 4h\"","example":" for 4h","description":"\" for <duration>\", empty when there is none."},
 {"name":"ban","group":"Decision","label":"Ban in words","example":"banned 4 hours","description":"The longest decision in plain words: banned 10 years, captcha for 4 hours, would be banned 4 hours (simulation). Empty when there was none."},
 {"name":"ban_tag","group":"Decision","label":"\" → banned …\"","example":" → **banned 4 hours**","description":"The ban in bold with an arrow in front; empty when there was no decision."},
 {"name":"origin","group":"Decision","label":"Origin","example":"crowdsec","description":"Where the decision came from: crowdsec (a detection) or cscli (a manual ban)."},
 {"name":"origin_tag","group":"Decision","label":"Origin (with separator)","example":" · crowdsec","description":"The origin with a dot in front; empty when unknown."},
 {"name":"target","group":"Request","label":"Host attacked","example":"app.example.com","description":"The site the first request was aimed at (from Traefik'"'"'s log; empty otherwise)."},
 {"name":"target_tag","group":"Request","label":"\"aimed at …\"","example":" · aimed at **app.example.com**","description":"\" · aimed at <site>\", empty when unknown."},
 {"name":"targets","group":"Request","label":"Hosts attacked","example":"cloud.example.com, app.example.com","description":"Every site the address aimed at (three, then \"and 2 more\")."},
 {"name":"targets_line","group":"Request","label":"\"Aimed at …\" line","example":"\nAimed at **cloud.example.com**","description":"A line of its own naming the sites in bold; nothing (not even the line break) when unknown."},
 {"name":"path","group":"Request","label":"First request path","example":"/wp-login.php","description":"The path of the first request (empty for non-web detections)."},
 {"name":"path_code","group":"Request","label":"First request path (as code)","example":"`/wp-login.php`","description":"The path between backticks so Discord shows it as code; empty (so the field is left out) when there is none."},
 {"name":"last_path","group":"Request","label":"Last request path","example":"/.env","description":"The path of the last request of the address in this message."},
 {"name":"last_path_code","group":"Request","label":"Last request path (as code)","example":"`/.env`","description":"The last path between backticks; empty when there is none."},
 {"name":"requests_line","group":"Request","label":"First and last request line","example":"\nFirst `/_next/static/chunks/main.js` · last `/.env`","description":"A line of its own with the first and the last path (one when they are the same); nothing for non-web detections."},
 {"name":"user_agent","group":"Request","label":"User agent","example":"Mozilla/5.0 (compatible; scanner/1.0)","description":"The user agent of the first request (empty when unknown)."},
 {"name":"machine","group":"Where and when","label":"Engine","example":"localhost","description":"The CrowdSec engine that raised the alert."},
 {"name":"machine_tag","group":"Where and when","label":"Engine (with separator)","example":" · localhost","description":"The engine with a dot in front; empty when unknown."},
 {"name":"domain","group":"Where and when","label":"Your domain","example":"example.com","description":"Your DCS domain (or DCS when none is set)."},
 {"name":"server","group":"Where and when","label":"Server name","example":"home-server","description":"The name of this DCS server."},
 {"name":"time","group":"Where and when","label":"Time","example":"<t:1790705765:R>","description":"Discord'"'"'s live \"x minutes ago\" stamp of when the message was made (works in the description and in fields, not in the title)."},
 {"name":"cti_url","group":"Links","label":"CrowdSec CTI link","example":"https://app.crowdsec.net/cti/89.248.165.10","description":"The address'"'"'s page on CrowdSec'"'"'s threat intelligence."},
 {"name":"abuseipdb_url","group":"Links","label":"AbuseIPDB link","example":"https://www.abuseipdb.com/check/89.248.165.10","description":"The address'"'"'s page on AbuseIPDB."}
]'

# Sample alerts, in the shape CrowdSec hands a notification plugin (and cscli alerts inspect -d prints)
_CS_NOTIFY_SAMPLES='{
 "probe": {"id": 42, "scenario": "crowdsecurity/http-probing", "message": "Ip 89.248.165.10 performed crowdsecurity/http-probing (13 events over 4s)", "events_count": 13, "machine_id": "localhost", "kind": "crowdsec", "simulated": false,
   "start_at": "2026-10-07T21:14:03Z", "stop_at": "2026-10-07T21:14:07Z",
   "source": {"scope": "Ip", "value": "89.248.165.10", "ip": "89.248.165.10", "range": "89.248.165.0/24", "cn": "NL", "as_number": "202425", "as_name": "IP Volume inc"},
   "decisions": [{"type": "ban", "duration": "4h", "origin": "crowdsec", "simulated": false}],
   "events": [{"meta": [{"key": "target_fqdn", "value": "app.example.com"}, {"key": "http_path", "value": "/wp-login.php"}, {"key": "http_user_agent", "value": "Mozilla/5.0 (compatible; scanner/1.0)"}]}]},
 "ssh": {"id": 43, "scenario": "crowdsecurity/ssh-bf", "message": "Ip 61.177.172.128 performed crowdsecurity/ssh-bf (6 events over 19s)", "events_count": 6, "machine_id": "localhost", "kind": "crowdsec", "simulated": false,
   "start_at": "2026-10-07T21:13:41Z", "stop_at": "2026-10-07T21:14:00Z",
   "source": {"scope": "Ip", "value": "61.177.172.128", "ip": "61.177.172.128", "range": "61.177.172.0/24", "cn": "CN", "as_number": "4134", "as_name": "CHINANET-BACKBONE"},
   "decisions": [{"type": "ban", "duration": "4h", "origin": "crowdsec", "simulated": false}], "events": []},
 "exploit": {"id": 44, "scenario": "crowdsecurity/CVE-2017-9841", "message": "Ip 194.26.135.7 performed crowdsecurity/CVE-2017-9841 (1 events over 0s)", "events_count": 1, "machine_id": "localhost", "kind": "crowdsec", "simulated": false,
   "source": {"scope": "Ip", "value": "194.26.135.7", "ip": "194.26.135.7", "range": "194.26.135.0/24", "cn": "RU", "as_number": "216368", "as_name": "Petersburg Internet Network ltd."},
   "decisions": [{"type": "ban", "duration": "4h", "origin": "crowdsec", "simulated": false}],
   "events": [{"meta": [{"key": "target_fqdn", "value": "cloud.example.com"}, {"key": "http_path", "value": "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"}, {"key": "http_user_agent", "value": "python-requests/2.28"}]}]},
 "manual": {"id": 45, "scenario": "Banned from DCS by admin", "message": "", "events_count": 1, "machine_id": "localhost", "kind": "cscli", "simulated": false,
   "source": {"scope": "Ip", "value": "198.51.100.7", "ip": "198.51.100.7", "range": "", "cn": "", "as_number": "", "as_name": ""},
   "decisions": [{"type": "ban", "duration": "24h", "origin": "cscli", "simulated": false}], "events": []},
 "simulated": {"id": 46, "scenario": "crowdsecurity/http-crawl-non_statics", "message": "Ip 185.220.101.5 performed crowdsecurity/http-crawl-non_statics (40 events over 9s)", "events_count": 40, "machine_id": "localhost", "kind": "crowdsec", "simulated": true,
   "start_at": "2026-10-07T21:12:51Z", "stop_at": "2026-10-07T21:13:00Z",
   "source": {"scope": "Ip", "value": "185.220.101.5", "ip": "185.220.101.5", "range": "185.220.101.0/24", "cn": "DE", "as_number": "60729", "as_name": "Stiftung Erneuerbare Freiheit"},
   "decisions": [{"type": "ban", "duration": "4h", "origin": "crowdsec", "simulated": true}],
   "events": [{"meta": [{"key": "target_fqdn", "value": "app.example.com"}, {"key": "http_path", "value": "/"}]}]},
 "burst": {"batch": {"start": "2026-10-07T21:14:03Z", "seconds": 7, "machine_id": "localhost", "target": "cloud.example.com", "user_agent": "Mozilla/5.0 (X11; Linux x86_64)",
   "source": {"scope": "Ip", "value": "194.26.135.7", "ip": "194.26.135.7", "range": "194.26.135.0/24", "cn": "RU", "as_number": "216368", "as_name": "Petersburg Internet Network ltd."},
   "decisions": [{"type": "ban", "duration": "4h", "origin": "crowdsec", "simulated": false}],
   "runs": [{"scenario": "crowdsecurity/vpatch-CVE-2025-29927", "times": 41, "path": "/_next/static/chunks/main.js"},
            {"scenario": "crowdsecurity/vpatch-CVE-2024-4577", "times": 4, "path": "/php-cgi/php-cgi.exe?%ADd+allow_url_include%3d1"},
            {"scenario": "crowdsecurity/appsec-vpatch", "times": 2, "path": "/.env"}]}},
 "crowd": {"of": ["probe", "ssh", "exploit"]}
}'

# A sample as the alerts it stands for: one alert, or a batch ("burst": one address firing many alerts in a few seconds;
# "crowd": three addresses in the same batch)
_CS_JQ_SAMPLE='
def sample_alerts($all):
  if type == "object" and has("batch") then .batch as $b
    | ([ $b.runs[] | . as $r | range($r.times) | $r ]) as $seq
    | ($seq | length) as $n | ($b.start | iso_secs) as $t0
    | [ $seq | to_entries[] | .key as $k | .value as $r
        | (($t0 + (if $n > 1 then ($k * $b.seconds / ($n - 1) | floor) else 0 end)) | todate) as $at
        | {id: (1000 + $k), scenario: $r.scenario, message: "Ip \($b.source.value) performed \($r.scenario) (1 events over 0s)", events_count: 1, machine_id: $b.machine_id,
           kind: "crowdsec", simulated: false, start_at: $at, stop_at: $at, source: $b.source, decisions: $b.decisions,
           events: [{meta: [{key: "target_fqdn", value: $b.target}, {key: "http_path", value: $r.path}, {key: "http_user_agent", value: $b.user_agent}]}]} ]
  elif type == "object" and has("of") then [ .of[] as $k | $all[$k] ]
  else . end;'
# _cs_notify_sample NAME — the alert (or the list of alerts) a sample stands for
_cs_notify_sample() { jq -c --arg s "$1" "$_CS_JQ_DEFS$_CS_JQ_SAMPLE"' . as $all | .[$s] | sample_alerts($all)' <<< "$_CS_NOTIFY_SAMPLES"; }

# The validation, in jq: prints the normalised settings, or {"error": "…"}
_CS_JQ_NOTIFY_VALIDATE='
def bad($m): error($m);
def num($v; $lo; $hi; $what): (if ($v | type) == "string" and ($v | test("^[0-9]+$")) then ($v | tonumber) else $v end) as $n
  | if ($n | type) == "number" and $n == ($n | floor) and $n >= $lo and $n <= $hi then $n else bad($what + " must be a whole number from " + ($lo | tostring) + " to " + ($hi | tostring)) end;
def oneline($s; $what; $max): if ($s | type) != "string" then bad($what + " must be text")
  elif ($s | test("[\\x00-\\x1f\\x7f]")) then bad($what + " must be a single line without control characters")
  elif ($s | length) > $max then bad($what + " is too long (" + ($max | tostring) + " characters at most)") else $s end;
def multiline($s; $what; $max): if ($s | type) != "string" then bad($what + " must be text")
  elif ($s | test("[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]")) then bad($what + " must not contain control characters")
  elif ($s | length) > $max then bad($what + " is too long (" + ($max | tostring) + " characters at most)") else $s end;
def placeholders($s): [ $s | match("\\{([A-Za-z0-9_]+)\\}"; "g") | .captures[0].string ];
def check_ph($s; $what): (placeholders($s) - $known) as $u | if ($u | length) > 0 then bad($what + " uses {" + $u[0] + "}, which is not a placeholder. Pick one from the list.") else $s end;
def pattern_ok: type == "string" and test("^[A-Za-z0-9][A-Za-z0-9._/@:+-]{0,119}\\*?$");
. as $s
| try (
    if ($s.enabled | type) != "boolean" then bad("enabled must be true or false") else . end
    | if (["global", "custom", "keep"] | index($s.webhook.mode)) == null then bad("The webhook source must be global, custom or keep") else . end
    | (oneline($s.identity.name; "The sender name"; 80)) as $name
    | if ($name | length) < 1 then bad("The sender name is empty") elif ($name | test("discord|clyde|[@#:]|```"; "i")) then bad("Discord refuses sender names that contain \"discord\", \"clyde\", @, # or :") else . end
    | if ($s.identity.avatar_url | type) != "string" or ($s.identity.avatar_url != "" and ($s.identity.avatar_url | test("^https://[^\\s\"\\\\<>]{1,300}$") | not)) then bad("The avatar must be an https:// address (or empty)") else . end
    | if (["auto", "fixed"] | index($s.embed.color_mode)) == null then bad("The colour mode must be auto or fixed") else . end
    | if ($s.embed.color | type) != "string" or ($s.embed.color | test("^#[0-9a-fA-F]{6}$") | not) then bad("The colour must look like #e11d48") else . end
    | if (["none", "role", "user", "here", "everyone"] | index($s.mention.mode)) == null then bad("The mention must be none, role, user, here or everyone") else . end
    | if (($s.mention.mode == "role" or $s.mention.mode == "user") and (($s.mention.id | tostring) | test("^[0-9]{15,21}$") | not)) then bad("The role or user id is the long number Discord shows in developer mode (17-19 digits)") else . end
    | multiline(($s.mention.text | tostring); "The text next to the mention"; 300) as $mt
    | if ([$s.events.bans, $s.events.simulated, $s.events.detect_only] | map(type == "boolean") | all | not) then bad("The event switches must be true or false") else . end
    | num($s.filters.min_events; 0; 1000; "The minimum number of events") as $me
    | if ([$s.filters.only, $s.filters.ignore] | map(type == "array" and length <= 20 and all(.[]; pattern_ok)) | all | not) then bad("The scenario lists take up to 20 names such as crowdsecurity/ssh-bf or a prefix such as crowdsecurity/ssh*") else . end
    | if (["address", "alert"] | index($s.delivery.group_by // "address")) == null then bad("The grouping must be address (one block per address) or alert (one block per alert)") else . end
    | num($s.delivery.group_wait; 1; 600; "The grouping wait (seconds)") as $gw
    | num($s.delivery.group_threshold; 1; 100; "The number of alerts in one message") as $gt
    | num($s.delivery.max_retry; 0; 10; "The number of retries") as $mr
    | num($s.delivery.timeout; 1; 60; "The request timeout (seconds)") as $to
    | oneline($s.message.title; "The title"; 200) as $title | check_ph($title; "The title") as $_t
    | multiline($s.message.description; "The description"; 1500) as $desc | check_ph($desc; "The description") as $_d
    | oneline($s.message.footer; "The footer"; 200) as $footer | check_ph($footer; "The footer") as $_f
    | oneline($s.message.link; "The title link"; 300) as $link | check_ph($link; "The title link") as $_l
    | if ($s.message.timestamp | type) != "boolean" then bad("timestamp must be true or false") else . end
    | if ($s.message.fields | type) != "array" or ($s.message.fields | length) > 8 then bad("A message has up to 8 fields") else . end
    | ($s.message.fields | to_entries | map(
          .key as $i | .value as $f
          | if ($f | type) != "object" then bad("Field " + (($i + 1) | tostring) + " is malformed") else . end
          | oneline($f.name; "Field " + (($i + 1) | tostring) + " name"; 100) as $fn
          | multiline($f.value; "Field " + (($i + 1) | tostring) + " value"; 500) as $fv
          | if ($fn | length) == 0 or ($fv | length) == 0 then bad("Field " + (($i + 1) | tostring) + " needs a name and a value (empty fields are left out of the message)") else . end
          | check_ph($fn; "Field " + (($i + 1) | tostring) + " name") | check_ph($fv; "Field " + (($i + 1) | tostring) + " value")
          | {name: $fn, value: $fv, inline: ($f.inline == true)} )) as $fields
    | if ($title | length) == 0 and ($desc | length) == 0 and ($fields | length) == 0 then bad("The message would be empty: give it a title, a description or a field") else . end
    | {v: 2, enabled: $s.enabled, webhook: {mode: $s.webhook.mode}, identity: {name: $name, avatar_url: $s.identity.avatar_url},
       embed: {color_mode: $s.embed.color_mode, color: ($s.embed.color | ascii_downcase)}, mention: {mode: $s.mention.mode, id: (if ($s.mention.mode == "role" or $s.mention.mode == "user") then ($s.mention.id | tostring) else "" end), text: $mt},
       events: {bans: $s.events.bans, simulated: $s.events.simulated, detect_only: $s.events.detect_only},
       filters: {min_events: $me, only: ($s.filters.only | unique), ignore: ($s.filters.ignore | unique)},
       delivery: {group_by: ($s.delivery.group_by // "address"), group_wait: $gw, group_threshold: $gt, max_retry: $mr, timeout: $to},
       message: {title: $title, description: $desc, footer: $footer, link: $link, timestamp: $s.message.timestamp, fields: $fields}}
  ) catch {error: (if type == "string" then . else "The notification settings are not valid" end)}
'

# _cs_notify_merge BASE PATCH — the patch over the base, section by section (lists are replaced whole)
_cs_notify_merge() { jq -nc --argjson b "$1" --argjson p "$2" '$b * $p'; }

# _cs_notify_validate JSON — the normalised settings land in CS_OUT, or CS_CFG_ERR is set and the status is 1. The known placeholders are the ones in the table.
_cs_notify_validate() {
    local out
    out=$(jq -c --argjson known "$(jq -c 'map(.name)' <<< "$_CS_PLACEHOLDERS")" "$_CS_JQ_NOTIFY_VALIDATE" <<< "$1" 2>&1) || { CS_CFG_ERR="The notification settings could not be checked"; return 1; }
    if jq -e 'type == "object" and has("error")' >/dev/null 2>&1 <<< "$out"; then CS_CFG_ERR=$(jq -r '.error' <<< "$out"); return 1; fi
    CS_OUT="$out"
}

# The settings in force: the defaults, then what was saved. (Without a saved file the live state decides, see _cs_notify_effective.)
_cs_notify_saved() { _cs_notify_merge "$_CS_NOTIFY_DEFAULTS" "$(_cs_notify_upgrade "$(_cs_json_file "$CS_NOTIFY_FILE" '{}')")"; }

# _cs_notify_upgrade SAVED — settings an older DCS saved: the message and the delivery it shipped with become today's
# defaults (grouped by address, 30 s / 50 alerts); a message or a delivery someone changed stays as it is
_cs_notify_upgrade() {
    jq -c --argjson old "$_CS_NOTIFY_V1" --argjson d "$_CS_NOTIFY_DEFAULTS" '
        if (.v // 1) >= 2 then . else
          (if .message == $old.message then .message = $d.message else . end)
          | (if (.delivery.group_wait // 5) == $old.delivery.group_wait and (.delivery.group_threshold // 10) == $old.delivery.group_threshold
             then .delivery.group_wait = $d.delivery.group_wait | .delivery.group_threshold = $d.delivery.group_threshold else . end)
          | .v = 2 end' <<< "$1" 2>/dev/null || printf '%s' "$1"
}

# =============================================================================
# The webhook: never shown in full
# =============================================================================

# …/api/webhooks/<id>/<token> → …/api/webhooks/<id>/••••<last four of the token>
_cs_webhook_mask() {
    local u="$1" id tok
    [[ "$u" =~ ^(https://[a-z.]*discord(app)?\.com/api/webhooks/)([0-9]+)/([A-Za-z0-9_-]+)$ ]] || { [[ -n "$u" ]] && printf '(a webhook)'; return; }
    id="${BASH_REMATCH[3]}"; tok="${BASH_REMATCH[4]}"
    printf '%s%s/••••%s' "${BASH_REMATCH[1]}" "$id" "${tok: -4}"
}

# the URL CrowdSec posts to right now (from the live file); empty when there is none
_cs_webhook_live() { _cs_live_file "$CS_HTTP_PATH" | sed -n 's/^url:[[:space:]]*//p' | head -n 1 | tr -d '"'"'"' \r'; }

# _cs_webhook_resolve MODE — the URL that mode stands for (secret: keep it out of answers and logs)
_cs_webhook_resolve() {
    local mode="$1" u=""
    case "$mode" in
        custom) u=$(secrets_get "$CS_WEBHOOK_SECRET" 2>/dev/null) || u="" ;;
        global) u=$(_discord_webhook 2>/dev/null) || u="" ;;
        keep) u=$(_cs_webhook_live) ;;
    esac
    [[ "$u" =~ ^\$\{SECRETS[._]([A-Za-z_][A-Za-z0-9_]*)\}$ ]] && u=$(secrets_get "${BASH_REMATCH[1]}" 2>/dev/null)
    _discord_is_webhook "$u" && printf '%s' "$u"
    return 0
}

# =============================================================================
# Discord notifications: the Go template CrowdSec's http plugin renders
#
# The message is built from the settings by concatenation: text you typed only
# ever becomes a Go *string literal* (never template code), the placeholders
# become variables, and every value goes through toJson — so a quote or a brace
# in an attacker's user agent cannot break the message, and nothing you type
# can inject template code.
#
# One message per batch CrowdSec hands over (group_wait / group_threshold), one
# embed per source address in it (delivery.group_by "address", the default) or
# per alert ("alert"): a scanner that fires 50 alerts in a few seconds is ONE
# embed that counts its attempts per scenario. Discord takes 10 embeds and 6000
# characters a message: more than 10 addresses make 9 embeds and a tenth that
# lists the rest, and every part is cut to fit (characters, never half a one).
# =============================================================================

# The fixed part of the template. @@NAME@@ marks what is filled in below (jq split/join: no regex, no & surprises).
_CS_GOTPL_HEAD='{{- /* Managed by DCS: the CrowdSec page writes this file. Change the message on the Discord tab. */ -}}
@@STATICVARS@@
{{- /* 1. the batch, gathered: one group per address (or per alert) with its attempts per scenario, the hosts and paths
       it asked for, the longest decision and the time from its first to its last request */ -}}
{{- $epoch := toDate "2006-01-02" "2000-01-01" }}
{{- $groups := dict }}{{ $order := list }}
{{- range $i, $alert := . }}
  {{- $ip := "" }}{{ with $alert.Source }}{{ with .Value }}{{ $ip = (. | trim) }}{{ end }}{{ end }}
  {{- $key := printf "#%d" $i }}{{ if and $by_address (ne $ip "") }}{{ $key = print "ip " $ip }}{{ end }}
  {{- if not (hasKey $groups $key) }}
    {{- $_ := set $groups $key (dict "first" $alert "alerts" 0 "events" 0 "n" 0 "rank" 0 "scen" (dict) "order" (list) "raw" (dict) "label" (dict) "targets" (list) "path0" "" "path1" "" "ua" "" "t0" 0 "t1" 0 "dsecs" -1 "dtype" "" "ddur" "" "dorigin" "" "dsim" "") }}
    {{- $order = append $order $key }}
  {{- end }}
  {{- $g := get $groups $key }}
  {{- $sc := "" }}{{ with $alert.Scenario }}{{ $sc = (. | trim | replace "@" "@​") }}{{ end }}
  {{- $lb := "Attack blocked" }}{{ $rank := 2 }}
  @@CHAIN@@
  {{- $sid := trimPrefix "crowdsecurity/" $sc }}{{ $cve := regexFind "(?i)cve-[0-9]{4}-[0-9]+" $sc }}{{ if $cve }}{{ $sid = upper $cve }}{{ end }}
  {{- $item := $lb }}{{ if $sid }}{{ $item = print $lb " " $sid }}{{ end }}
  {{- $ev := 0 }}{{ with $alert.EventsCount }}{{ $ev = (. | int) }}{{ end }}
  {{- $_ := set $g "alerts" (add1 (get $g "alerts")) }}{{ $_ := set $g "events" (add (get $g "events") $ev) }}{{ $_ := set $g "n" (add (get $g "n") (max $ev 1)) }}
  {{- if gt $rank (get $g "rank") }}{{ $_ := set $g "rank" $rank }}{{ end }}
  {{- $scn := get $g "scen" }}
  {{- if not (hasKey $scn $item) }}{{ $_ := set $g "order" (append (get $g "order") $item) }}{{ $_ := set $scn $item 0 }}{{ $_ := set (get $g "raw") $item $sc }}{{ $_ := set (get $g "label") $item $lb }}{{ end }}
  {{- $_ := set $scn $item (add (get $scn $item) (max $ev 1)) }}
  {{- with $alert.StartAt }}{{ $t := (toDate "2006-01-02T15:04:05Z07:00" .).Unix }}{{ if and (gt $t 0) (or (eq (get $g "t0") 0) (lt $t (get $g "t0"))) }}{{ $_ := set $g "t0" $t }}{{ end }}{{ end }}
  {{- with $alert.StopAt }}{{ $t := (toDate "2006-01-02T15:04:05Z07:00" .).Unix }}{{ if gt $t (get $g "t1") }}{{ $_ := set $g "t1" $t }}{{ end }}{{ end }}
  {{- range $e := $alert.Events }}{{ range $m := $e.Meta }}{{ with $m.Key }}{{ $k := (. | trim) }}
    {{- if eq $k "target_fqdn" }}{{ with $m.Value }}{{ $v := (. | trim | trunc 200 | replace "@" "@​") }}{{ if and $v (not (has $v (get $g "targets"))) }}{{ $_ := set $g "targets" (append (get $g "targets") $v) }}{{ end }}{{ end }}
    {{- else if eq $k "http_path" }}{{ with $m.Value }}{{ $v := (. | trim | trunc 200 | replace "@" "@​") }}{{ if $v }}{{ if not (get $g "path0") }}{{ $_ := set $g "path0" $v }}{{ end }}{{ $_ := set $g "path1" $v }}{{ end }}{{ end }}
    {{- else if and (eq $k "http_user_agent") (not (get $g "ua")) }}{{ with $m.Value }}{{ $_ := set $g "ua" (. | trim | trunc 200 | replace "@" "@​") }}{{ end }}
    {{- end }}
  {{- end }}{{ end }}{{ end }}
  {{- range $d := $alert.Decisions }}
    {{- $dd := "" }}{{ with $d.Duration }}{{ $dd = (. | trim) }}{{ end }}
    {{- $secs := sub (dateModify $dd $epoch).Unix $epoch.Unix }}
    {{- if gt $secs (get $g "dsecs") }}
      {{- $_ := set $g "dsecs" $secs }}{{ $_ := set $g "ddur" $dd }}
      {{- $t := "ban" }}{{ with $d.Type }}{{ $t = (. | trim) }}{{ end }}{{ $_ := set $g "dtype" $t }}
      {{- $o := "" }}{{ with $d.Origin }}{{ $o = (. | trim) }}{{ end }}{{ $_ := set $g "dorigin" $o }}
      {{- $s := "" }}{{ with $d.Simulated }}{{ $s = (ternary "1" "" .) }}{{ end }}{{ $_ := set $g "dsim" $s }}
    {{- end }}
  {{- end }}
{{- end }}
{{- /* 2. each group its scenarios, the most attempts first */ -}}
{{- range $key := $order }}{{ $g := get $groups $key }}
  {{- $sorted := list }}{{ range $si, $it := get $g "order" }}{{ $sorted = append $sorted (printf "%09d|%04d|%s" (sub 999999999 (get (get $g "scen") $it)) $si $it) }}{{ end }}
  {{- $_ := set $g "sorted" (sortAlpha $sorted) }}
{{- end }}
{{- /* 3. Discord takes 10 embeds: more addresses make 9 and a tenth that lists the rest. Its 6000 characters are shared out: every
       embed gets the same budget, its title, footer and fields a share of it (cut by characters, never half of one), the description the rest */ -}}
{{- $shown := $order }}{{ $rest := list }}
{{- if gt (len $order) 10 }}{{ $shown = slice $order 0 9 }}{{ $rest = slice $order 9 }}{{ end }}
{{- $n_embeds := len $shown }}{{ if $rest }}{{ $n_embeds = add1 $n_embeds }}{{ end }}
{{- $budget := div 5400 $n_embeds }}
{{- $capT := min 256 (max 20 (div $budget 5)) }}{{ $capF := min 2048 (max 20 (div $budget 5)) }}
{{- $capFN := min 256 (max 10 (div $budget @@NF5@@)) }}{{ $capFV := min 1024 (max 20 (div (mul $budget 2) @@NF5@@)) }}
{{- $ri := dict "A" "🇦" "B" "🇧" "C" "🇨" "D" "🇩" "E" "🇪" "F" "🇫" "G" "🇬" "H" "🇭" "I" "🇮" "J" "🇯" "K" "🇰" "L" "🇱" "M" "🇲" "N" "🇳" "O" "🇴" "P" "🇵" "Q" "🇶" "R" "🇷" "S" "🇸" "T" "🇹" "U" "🇺" "V" "🇻" "W" "🇼" "X" "🇽" "Y" "🇾" "Z" "🇿" }}
{{- $units := dict "y" "year" "mo" "month" "d" "day" "h" "hour" "m" "minute" "s" "second" }}
{
  "username": @@USERNAME@@,
  @@AVATAR@@
  @@CONTENT@@
  "allowed_mentions": @@MENTIONS@@,
  "embeds": [
    {{- range $gi, $key := $shown }}
    {{- $g := get $groups $key }}{{ $a := get $g "first" }}
    {{- $p_ip := "" }}{{ with $a.Source }}{{ with .Value }}{{ $p_ip = (. | trim) }}{{ end }}{{ end }}
    {{- $p_scope := "" }}{{ with $a.Source }}{{ with .Scope }}{{ $p_scope = (. | trim) }}{{ end }}{{ end }}
    {{- $p_range := "" }}{{ with $a.Source }}{{ with .Range }}{{ $p_range = (. | trim) }}{{ end }}{{ end }}
    {{- $p_country := "" }}{{ with $a.Source }}{{ with .Cn }}{{ $p_country = (. | trim) }}{{ end }}{{ end }}
    {{- $p_as_number := "" }}{{ with $a.Source }}{{ with .AsNumber }}{{ $p_as_number = (. | trim) }}{{ end }}{{ end }}
    {{- $p_as_name := "" }}{{ with $a.Source }}{{ with .AsName }}{{ $p_as_name = (. | trim | replace "@" "@​") }}{{ end }}{{ end }}
    {{- $p_machine := "" }}{{ with $a.MachineID }}{{ $p_machine = (. | trim) }}{{ end }}
    {{- $p_message := "" }}{{ with $a.Message }}{{ $p_message = (. | trim | replace "@" "@​") }}{{ end }}
    {{- $p_alert_id := printf "%d" ($a.ID | int) }}
    {{- $p_events := printf "%d" (get $g "events") }}{{ $p_alerts := printf "%d" (get $g "alerts") }}{{ $nn := get $g "n" }}
    {{- $sorted := get $g "sorted" }}{{ $top := (splitn "|" 3 (first $sorted))._2 }}
    {{- $p_scenario := print (get (get $g "raw") $top) }}{{ $p_label := print (get (get $g "label") $top) }}
    {{- $p_scenario_short := trimPrefix "crowdsecurity/" $p_scenario }}
    {{- $items := list }}{{ range $j, $s := $sorted }}{{ if lt $j 6 }}{{ $it := (splitn "|" 3 $s)._2 }}{{ $items = append $items (printf "%s ×%d" $it (get (get $g "scen") $it)) }}{{ end }}{{ end }}
    {{- $p_scenarios := join " · " $items }}{{ if gt (len $sorted) 6 }}{{ $p_scenarios = printf "%s · +%d more" $p_scenarios (sub (len $sorted) 6) }}{{ end }}
    {{- $sim := "" }}{{ with $a.Simulated }}{{ $sim = (ternary "1" "" .) }}{{ end }}{{ if get $g "dsim" }}{{ $sim = "1" }}{{ end }}
    {{- $hasdec := ge (get $g "dsecs") 0 }}
    {{- $dtype := "ban" }}{{ $p_duration := "" }}{{ $p_origin := "" }}
    {{- if $hasdec }}{{ $dtype = print (get $g "dtype") }}{{ $p_duration = print (get $g "ddur") }}{{ $p_origin = print (get $g "dorigin") }}{{ end }}
    {{- $color := 15942494 }}{{ $rk := get $g "rank" }}{{ if eq $rk 4 }}{{ $color = 10979578 }}{{ else if eq $rk 1 }}{{ $color = 16098851 }}{{ end }}
    {{- if eq $dtype "captcha" }}{{ $color = 2282478 }}{{ end }}
    {{- $human := "" }}{{ if $p_duration }}{{ $dr := durationRound $p_duration }}{{ if ne $dr "0s" }}{{ $num := regexFind "^[0-9]+" $dr }}{{ $human = print $num " " (get $units (trimPrefix $num $dr)) }}{{ if ne $num "1" }}{{ $human = print $human "s" }}{{ end }}{{ end }}{{ end }}
    {{- $p_ban := "" }}
    {{- if $hasdec }}
      {{- if eq $dtype "ban" }}{{ $p_ban = "banned" }}{{ if $human }}{{ $p_ban = print "banned " $human }}{{ end }}{{ if $sim }}{{ $p_ban = print "would be " $p_ban " (simulation)" }}{{ end }}
      {{- else }}{{ $p_ban = $dtype }}{{ if $human }}{{ $p_ban = print $dtype " for " $human }}{{ end }}{{ if $sim }}{{ $p_ban = print "simulated " $p_ban }}{{ end }}{{ end }}
    {{- end }}
    {{- $p_ban_tag := "" }}{{ if $p_ban }}{{ $p_ban_tag = print " → **" $p_ban "**" }}{{ end }}
    {{- $p_span := "" }}{{ $t0 := get $g "t0" }}{{ $t1 := get $g "t1" }}
    {{- if and (gt $t0 0) (ge $t1 $t0) }}{{ $s := sub $t1 $t0 }}
      {{- if lt $s 1 }}{{ $p_span = "under a second" }}
      {{- else if lt $s 60 }}{{ $p_span = printf "%ds" $s }}
      {{- else if lt $s 3600 }}{{ $p_span = printf "%dm" (div $s 60) }}{{ if mod $s 60 }}{{ $p_span = printf "%s %ds" $p_span (mod $s 60) }}{{ end }}
      {{- else if lt $s 86400 }}{{ $p_span = printf "%dh" (div $s 3600) }}{{ if div (mod $s 3600) 60 }}{{ $p_span = printf "%s %dm" $p_span (div (mod $s 3600) 60) }}{{ end }}
      {{- else }}{{ $p_span = printf "%dd" (div $s 86400) }}{{ if div (mod $s 86400) 3600 }}{{ $p_span = printf "%s %dh" $p_span (div (mod $s 86400) 3600) }}{{ end }}{{ end }}
    {{- end }}
    {{- $p_attempts := "one request" }}{{ if ne $nn 1 }}{{ $p_attempts = printf "%d attempts" $nn }}{{ if $p_span }}{{ $p_attempts = printf "%s in %s" $p_attempts $p_span }}{{ end }}{{ end }}
    {{- $tg := get $g "targets" }}{{ $p_target := "" }}{{ $p_targets := "" }}{{ $p_targets_line := "" }}
    {{- if $tg }}{{ $p_target = print (first $tg) }}{{ $tl := list }}{{ $bl := list }}
      {{- range $j, $t := $tg }}{{ if lt $j 3 }}{{ $tl = append $tl $t }}{{ $bl = append $bl (print "**" $t "**") }}{{ end }}{{ end }}
      {{- $more := "" }}{{ if gt (len $tg) 3 }}{{ $more = printf " and %d more" (sub (len $tg) 3) }}{{ end }}
      {{- $p_targets = print (join ", " $tl) $more }}{{ $p_targets_line = print "\nAimed at " (join ", " $bl) $more }}
    {{- end }}
    {{- $p_path := print (get $g "path0") }}{{ $p_last_path := print (get $g "path1") }}{{ $p_user_agent := print (get $g "ua") }}
    {{- $p_path_code := "" }}{{ if $p_path }}{{ $p_path_code = print "`" (replace "`" "'"'"'" $p_path) "`" }}{{ end }}
    {{- $p_last_path_code := "" }}{{ if $p_last_path }}{{ $p_last_path_code = print "`" (replace "`" "'"'"'" $p_last_path) "`" }}{{ end }}
    {{- $p_requests_line := "" }}
    {{- if $p_path }}{{ $c0 := $p_path }}{{ if gt (len (regexFindAll "(?s)." $c0 -1)) 100 }}{{ $c0 = print (regexFind "^(?s).{0,99}" $c0) "…" }}{{ end }}
      {{- $c1 := $p_last_path }}{{ if gt (len (regexFindAll "(?s)." $c1 -1)) 100 }}{{ $c1 = print (regexFind "^(?s).{0,99}" $c1) "…" }}{{ end }}
      {{- if eq $p_path $p_last_path }}{{ $p_requests_line = print "\nRequest `" (replace "`" "'"'"'" $c0) "`" }}
      {{- else }}{{ $p_requests_line = print "\nFirst `" (replace "`" "'"'"'" $c0) "` · last `" (replace "`" "'"'"'" $c1) "`" }}{{ end }}
    {{- end }}
    {{- $p_decision := $dtype }}{{ if $sim }}{{ $p_decision = print "simulated " $dtype }}{{ end }}
    {{- $p_sim_tag := "" }}{{ if $sim }}{{ $p_sim_tag = " (simulation)" }}{{ end }}
    {{- $p_flag := "" }}{{ $p_country_tag := "" }}{{ $p_flag_emoji := "" }}{{ $p_source_tag := "" }}
    {{- if eq (len $p_country) 2 }}{{ $p_flag = print ":flag_" (lower $p_country) ":" }}{{ $p_country_tag = print " " $p_flag " " $p_country }}{{ $uc := upper $p_country }}{{ $p_flag_emoji = print (get $ri (substr 0 1 $uc)) (get $ri (substr 1 2 $uc)) }}
      {{- $p_source_tag = print " · " $p_country }}{{ if $p_flag_emoji }}{{ $p_source_tag = print " · " $p_flag_emoji " " $p_country }}{{ end }}{{ end }}
    {{- if $p_as_name }}{{ $p_source_tag = print $p_source_tag " · " $p_as_name }}{{ end }}
    {{- $p_as_tag := "" }}{{ if $p_as_name }}{{ $p_as_tag = print " · " $p_as_name }}{{ end }}
    {{- $p_for_duration := "" }}{{ if $p_duration }}{{ $p_for_duration = print " for " $p_duration }}{{ end }}
    {{- $p_target_tag := "" }}{{ if $p_target }}{{ $p_target_tag = print " · aimed at **" $p_target "**" }}{{ end }}
    {{- $p_origin_tag := "" }}{{ if $p_origin }}{{ $p_origin_tag = print " · " $p_origin }}{{ end }}
    {{- $p_machine_tag := "" }}{{ if $p_machine }}{{ $p_machine_tag = print " · " $p_machine }}{{ end }}
    {{- $p_cti_url := print "https://app.crowdsec.net/cti/" $p_ip }}
    {{- $p_abuseipdb_url := print "https://www.abuseipdb.com/check/" $p_ip }}
    {{- $p_time := print "<t:" (now | unixEpoch) ":R>" }}
    {{- $title := @@TITLE@@ }}{{ if gt (len (regexFindAll "(?s)." $title -1)) $capT }}{{ $title = print (regexFind (print "^(?s)" (repeat (int (div (sub $capT 1) 1000)) ".{0,1000}") (printf ".{0,%d}" (mod (sub $capT 1) 1000))) $title) "…" }}{{ end }}
    {{- $footer := @@FOOTER@@ }}{{ if gt (len (regexFindAll "(?s)." $footer -1)) $capF }}{{ $footer = print (regexFind (print "^(?s)" (repeat (int (div (sub $capF 1) 1000)) ".{0,1000}") (printf ".{0,%d}" (mod (sub $capF 1) 1000))) $footer) "…" }}{{ end }}
    {{- $link := @@LINK@@ }}
    {{- $used := add (len (regexFindAll "(?s)." $title -1)) (len (regexFindAll "(?s)." $footer -1)) }}
    @@FIELDVARS@@
    {{- $desc := @@DESC@@ }}
    {{- $dmax := min 4096 (max 50 (sub $budget $used)) }}
    {{- if gt (len (regexFindAll "(?s)." $desc -1)) $dmax }}{{ $desc = print (regexFind (print "^(?s)" (repeat (int (div (sub $dmax 1) 1000)) ".{0,1000}") (printf ".{0,%d}" (mod (sub $dmax 1) 1000))) $desc) "…" }}{{ end }}
    {{- if $gi }},{{ end }}
    {
      "title": {{ $title | toJson }},
      "color": @@COLOR@@,
      "description": {{ $desc | toJson }},
      "fields": [
        {{- $sep := "" }}
        @@FIELDS@@
      ]
      {{- if $link }},
      "url": {{ $link | toJson }}
      {{- end }}
      {{- if $footer }},
      "footer": {"text": {{ $footer | toJson }}}
      {{- end }}
      @@TIMESTAMP@@
    }
    {{- end }}
    {{- if $rest }},
    {{- $lines := list }}{{ $rrank := 0 }}
    {{- range $key := $rest }}{{ $g := get $groups $key }}{{ $a := get $g "first" }}
      {{- $ip := "" }}{{ with $a.Source }}{{ with .Value }}{{ $ip = (. | trim) }}{{ end }}{{ end }}
      {{- $cn := "" }}{{ with $a.Source }}{{ with .Cn }}{{ $cn = (. | trim) }}{{ end }}{{ end }}
      {{- $where := "" }}{{ if eq (len $cn) 2 }}{{ $uc := upper $cn }}{{ $fe := print (get $ri (substr 0 1 $uc)) (get $ri (substr 1 2 $uc)) }}{{ $where = print " " $cn }}{{ if $fe }}{{ $where = print " " $fe " " $cn }}{{ end }}{{ end }}
      {{- $top := (splitn "|" 3 (first (get $g "sorted")))._2 }}{{ $nn := get $g "n" }}
      {{- $att := "one request" }}{{ if ne $nn 1 }}{{ $att = printf "%d attempts" $nn }}{{ end }}
      {{- if gt (get $g "rank") $rrank }}{{ $rrank = get $g "rank" }}{{ end }}
      {{- $lines = append $lines (print "`" $ip "`" $where " · " (get (get $g "label") $top) " · " $att) }}
    {{- end }}
    {{- $rcolor := 15942494 }}{{ if eq $rrank 4 }}{{ $rcolor = 10979578 }}{{ else if eq $rrank 1 }}{{ $rcolor = 16098851 }}{{ end }}
    {{- $rtitle := printf "🛡️ %d more %s" (len $rest) (ternary "addresses" "alerts" $by_address) }}
    {{- $rdesc := join "\n" $lines }}{{ $dmax := min 4096 (max 50 (sub $budget (len (regexFindAll "(?s)." $rtitle -1)))) }}
    {{- if gt (len (regexFindAll "(?s)." $rdesc -1)) $dmax }}{{ $rdesc = print (regexFind (print "^(?s)" (repeat (int (div (sub $dmax 1) 1000)) ".{0,1000}") (printf ".{0,%d}" (mod (sub $dmax 1) 1000))) $rdesc) "…" }}{{ end }}
    {
      "title": {{ $rtitle | toJson }},
      "color": @@RESTCOLOR@@,
      "description": {{ $rdesc | toJson }}
      @@TIMESTAMP@@
    }
    {{- end }}
  ]
}'

# _cs_notify_go_template SETTINGS DOMAIN SERVER — the template text
_cs_notify_go_template() {
    local s="$1" domain="$2" server="$3" ph
    ph=$(jq -c 'map(.name)' <<< "$_CS_PLACEHOLDERS")
    jq -nr --argjson s "$s" --arg domain "$domain" --arg server "$server" --arg head "$_CS_GOTPL_HEAD" --argjson known "$ph" "$_CS_JQ_LABELS"'
        def gostr: @json;
        def toks($str): [ ($str // "") | scan("\\{[a-z_]+\\}|[^{]+|\\{") ];
        def gexpr($str):
          (toks($str) | map(if test("^\\{[a-z_]+\\}$") and ((.[1:-1]) as $n | $known | index($n)) != null then "$p_" + .[1:-1] else gostr end)) as $parts
          | if ($parts | length) == 0 then "\"\"" elif ($parts | length) == 1 then $parts[0] else "(print " + ($parts | join(" ")) + ")" end;
        def lit($v): "{{ " + ($v | gostr) + " | toJson }}";
        def rank($fam): {"exploit": 4, "bruteforce": 3, "probe": 1}[$fam] // 2;
        # a variable cut to CAP characters (CAP may be up to 4096: Go regexps repeat at most 1000 times, so the pattern is built in pieces)
        def gocut($v; $cap): "{{ if gt (len (regexFindAll \"(?s).\" \($v) -1)) \($cap) }}{{ \($v) = print (regexFind (print \"^(?s)\" (repeat (int (div (sub \($cap) 1) 1000)) \".{0,1000}\") (printf \".{0,%d}\" (mod (sub \($cap) 1) 1000))) \($v)) \"…\" }}{{ end }}";
        # the label table, then the same guesses scen_row makes for a scenario the table does not know
        ( [ label_table | to_entries[] | .key as $i | .value as $r
            | (if $i == 0 then "{{- if hasPrefix " else "{{- else if hasPrefix " end) + ($r[0] | gostr) + " $sc }}{{ $lb = " + ($r[1] | gostr) + " }}{{ $rank = " + (rank($r[2]) | tostring) + " }}" ]
          + [ "{{- else if regexMatch \"(?i)cve\" $sc }}{{ $lb = \"Exploit attempt\" }}{{ $rank = 4 }}",
              "{{- else if regexMatch \"(?i)(^|[-_/])bf($|[-_])|brute\" $sc }}{{ $lb = \"Brute force\" }}{{ $rank = 3 }}",
              "{{- else if regexMatch \"(?i)spam\" $sc }}{{ $lb = \"Spam\" }}{{ $rank = 2 }}",
              "{{- end }}" ] | join("\n  ") ) as $chain
        | ( [ $s.message.fields | to_entries[] | .key as $i | .value as $f
              | "{{- $fn\($i) := \(gexpr($f.name)) }}{{ $fv\($i) := \(gexpr($f.value)) }}{{ $fon\($i) := and (ne (trim $fn\($i)) \"\") (ne (trim $fv\($i)) \"\") }}"
                + "{{ if $fon\($i) }}" + gocut("$fn\($i)"; "$capFN") + gocut("$fv\($i)"; "$capFV")
                + "{{ $used = add $used (len (regexFindAll \"(?s).\" $fn\($i) -1)) (len (regexFindAll \"(?s).\" $fv\($i) -1)) }}{{ end }}" ] | join("\n    ") ) as $fieldvars
        | ( [ $s.message.fields | to_entries[] | .key as $i | .value as $f
              | "{{- if $fon\($i) }}{{ $sep }}\n        {\"name\": {{ $fn\($i) | toJson }}, \"value\": {{ $fv\($i) | toJson }}, \"inline\": \(if $f.inline then "true" else "false" end)}{{ $sep = \",\" }}{{ end }}" ] | join("\n        ") ) as $fields
        | ( if $s.mention.mode == "role" then "<@&" + $s.mention.id + ">" elif $s.mention.mode == "user" then "<@" + $s.mention.id + ">"
            elif $s.mention.mode == "here" then "@here" elif $s.mention.mode == "everyone" then "@everyone" else "" end ) as $mtag
        | ( [$mtag, $s.mention.text] | map(select(length > 0)) | join(" ") ) as $content
        | ( if $s.mention.mode == "role" then "{\"roles\": [" + ($s.mention.id | @json) + "]}" elif $s.mention.mode == "user" then "{\"users\": [" + ($s.mention.id | @json) + "]}"
            elif $s.mention.mode == "here" or $s.mention.mode == "everyone" then "{\"parse\": [\"everyone\"]}" else "{\"parse\": []}" end ) as $mentions
        | ( $s.embed.color | ltrimstr("#") | explode | map(if . >= 97 then . - 87 elif . >= 65 then . - 55 else . - 48 end) | reduce .[] as $d (0; . * 16 + $d) ) as $color_int
        | $head
        | split("@@STATICVARS@@") | join("{{- $p_domain := \($domain | gostr) }}{{ $p_server := \($server | gostr) }}{{ $by_address := \(if ($s.delivery.group_by // "address") == "address" then "true" else "false" end) }}")
        | split("@@USERNAME@@") | join(lit($s.identity.name))
        | split("@@AVATAR@@") | join(if $s.identity.avatar_url != "" then "\"avatar_url\": " + lit($s.identity.avatar_url) + "," else "" end)
        | split("@@CONTENT@@") | join(if $content != "" then "\"content\": " + lit($content) + "," else "" end)
        | split("@@MENTIONS@@") | join($mentions)
        | split("@@CHAIN@@") | join($chain)
        | split("@@TITLE@@") | join(gexpr($s.message.title))
        | split("@@DESC@@") | join(gexpr($s.message.description))
        | split("@@FOOTER@@") | join(gexpr($s.message.footer))
        | split("@@LINK@@") | join(gexpr($s.message.link))
        | split("@@COLOR@@") | join(if $s.embed.color_mode == "fixed" then ($color_int | tostring) else "{{ $color }}" end)
        | split("@@RESTCOLOR@@") | join(if $s.embed.color_mode == "fixed" then ($color_int | tostring) else "{{ $rcolor }}" end)
        | split("@@FIELDVARS@@") | join($fieldvars)
        | split("@@NF5@@") | join(([($s.message.fields | length), 1] | max) * 5 | tostring)
        | split("@@FIELDS@@") | join($fields)
        | split("@@TIMESTAMP@@") | join(if $s.message.timestamp then "{{- if true }},\n      \"timestamp\": {{ dateInZone \"2006-01-02T15:04:05Z\" now \"UTC\" | toJson }}\n      {{- end }}" else "" end)'
}

# The layout of the message the file holds: 2 = one embed per address (or alert) with the grouped placeholders; 1 = one embed per alert (older DCS)
CS_NOTIFY_LAYOUT=2

# _cs_notify_render_yaml SETTINGS URL — the whole notifications/http.yaml
_cs_notify_render_yaml() {
    local s="$1" url="$2" domain server tpl
    domain=$(_find_traefik_domain 2>/dev/null); [[ -n "$domain" ]] || domain="${PROXY_DOMAIN:-DCS}"
    server="${SERVER_NAME:-}"; [[ -n "$server" ]] || server=$(hostname 2>/dev/null || echo DCS)
    tpl=$(_cs_notify_go_template "$s" "$domain" "$server") || return 1
    jq -nr --argjson s "$s" --arg url "$url" --arg tpl "$tpl" --argjson v "$CS_NOTIFY_LAYOUT" '
        "# Managed by DCS: the CrowdSec page writes this file (Discord tab). Change it there; a backup of the previous file is kept.\n"
        + "# dcs-notify: " + ({v: $v, settings: $s} | tojson) + "\n"
        + "type: http\nname: http_default\nlog_level: info\n"
        + "group_wait: \($s.delivery.group_wait)s\ngroup_threshold: \($s.delivery.group_threshold)\nmax_retry: \($s.delivery.max_retry)\ntimeout: \($s.delivery.timeout)s\n"
        + "format: |\n" + ($tpl | split("\n") | map("  " + .) | join("\n")) + "\n"
        + "url: " + $url + "\nmethod: POST\nheaders:\n  Content-Type: application/json"'
}

# =============================================================================
# Discord notifications: the same message rendered by DCS (preview and test message)
#
# CrowdSec renders the Go template above when a real batch arrives. The preview
# and the test message need the same result without one, so this jq program
# builds the identical payload from alerts in the shape `cscli alerts inspect
# -d -o json` prints (one alert, or a list: a batch). tests/smoke.sh pins the
# two together with payloads captured from a real CrowdSec.
# =============================================================================

_CS_JQ_RENDER='
def san: gsub("@"; "@​");
def trm: gsub("^\\s+|\\s+$"; "");
def cut($l): if length > $l then .[0:$l - 1] + "…" else . end;
def first_meta($metas; $k): ([ $metas[] | select(.key == $k) | .value | tostring | trm | select(length > 0) ] | .[0]) // "";
def flag_emoji: ascii_upcase | explode | map(if . >= 65 and . <= 90 then [127397 + .] | implode else "" end) | join("");
# sprig durationRound: the largest unit the length is MORE than, rounded down
def dround: if . > 31536000 then "\(. / 31536000 | floor)y" elif . > 2592000 then "\(. / 2592000 | floor)mo" elif . > 86400 then "\(. / 86400 | floor)d"
  elif . > 3600 then "\(. / 3600 | floor)h" elif . > 60 then "\(. / 60 | floor)m" elif . > 1 then "\(. | floor)s" else "0s" end;
def human_len: dround as $d | if $d == "0s" then "" else ($d | capture("^(?<n>[0-9]+)(?<u>[a-z]+)$")) as $c
  | $c.n + " " + {"y": "year", "mo": "month", "d": "day", "h": "hour", "m": "minute", "s": "second"}[$c.u] + (if $c.n != "1" then "s" else "" end) end;
def span_words: if . < 1 then "under a second" elif . < 60 then "\(.)s"
  elif . < 3600 then "\(. / 60 | floor)m" + (if . % 60 > 0 then " \(. % 60)s" else "" end)
  elif . < 86400 then "\(. / 3600 | floor)h" + (if ((. % 3600) / 60 | floor) > 0 then " \((. % 3600) / 60 | floor)m" else "" end)
  else "\(. / 86400 | floor)d" + (if ((. % 86400) / 3600 | floor) > 0 then " \((. % 86400) / 3600 | floor)h" else "" end) end;
def rank_of($fam): {"exploit": 4, "bruteforce": 3, "probe": 1}[$fam] // 2;
def rank_color: if . == 4 then 10979578 elif . == 1 then 16098851 else 15942494 end;
def path_cut: if length > 100 then .[0:99] + "…" else . end;
def code: "`" + gsub("`"; "'"'"'") + "`";
# the batch, gathered as the template gathers it: [{first, alerts, events, n, rank, counts: {item: n}, order, raw, label, targets, path0, path1, ua, t0, t1, dec}]
def gather($alerts; $by_addr):
  reduce ($alerts | to_entries[]) as $e ({keys: [], g: {}};
    $e.value as $a
    | (($a.source // {}).value // "" | tostring | trm) as $ip
    | (if $by_addr and $ip != "" then "ip " + $ip else "#\($e.key)" end) as $key
    | (if .g[$key] == null then .keys += [$key] | .g[$key] = {first: $a, alerts: 0, events: 0, n: 0, rank: 0, counts: {}, order: [], raw: {}, label: {}, targets: [], path0: "", path1: "", ua: "", t0: 0, t1: 0, dec: null} else . end)
    | ($a.scenario // "" | tostring | trm | san) as $sc
    | ($sc | scen_row) as $row
    | ($row[1]) as $lb | rank_of($row[2]) as $rank
    | ([$sc | match("(?i)cve-[0-9]{4}-[0-9]+")] | .[0].string // "") as $cve
    | (if $cve != "" then ($cve | ascii_upcase) else ($sc | ltrimstr("crowdsecurity/")) end) as $sid
    | (if $sid != "" then $lb + " " + $sid else $lb end) as $item
    | (($a.events_count // 0) | floor) as $ev | ([$ev, 1] | max) as $n1
    | .g[$key] |= (
        .alerts += 1 | .events += $ev | .n += $n1 | (if $rank > .rank then .rank = $rank else . end)
        | (if .counts[$item] == null then .order += [$item] | .counts[$item] = 0 | .raw[$item] = $sc | .label[$item] = $lb else . end)
        | .counts[$item] += $n1
        | (($a.start_at // "") | iso_secs) as $t | (if $t > 0 and (.t0 == 0 or $t < .t0) then .t0 = $t else . end)
        | (($a.stop_at // "") | iso_secs) as $t | (if $t > .t1 then .t1 = $t else . end)
        | reduce ([ ($a.events // [])[] | (.meta // [])[] ][]) as $m (.;
            (($m.key // "") | tostring | trm) as $k | (($m.value // "") | tostring | trm | .[0:200] | san) as $v
            | if $k == "target_fqdn" then (if $v != "" and (.targets | index($v)) == null then .targets += [$v] else . end)
              elif $k == "http_path" then (if $v != "" then (if .path0 == "" then .path0 = $v else . end) | .path1 = $v else . end)
              elif $k == "http_user_agent" and .ua == "" then .ua = $v
              else . end)
        | reduce (($a.decisions // [])[]) as $d (.;
            (($d.duration // "") | tostring | trm) as $dd | ($dd | dur_secs | floor) as $secs
            | if .dec == null or $secs > .dec.secs then
                .dec = {secs: $secs, dur: $dd, type: (if $d.type == null then "ban" else ($d.type | tostring | trm) end), origin: (($d.origin // "") | tostring | trm),
                        sim: (if $d.simulated == null then false else $d.simulated end)}
              else . end)
      ))
  | . as $st | [ $st.keys[] | $st.g[.] ]
  | map(. as $g | .sorted = ([ $g.order | to_entries[] | {item: .value, i: .key, c: $g.counts[.value]} ] | sort_by(-.c, .i) | map(.item)));
def attempts_words($n; $span): if $n == 1 then "one request" else "\($n) attempts" + (if $span != "" then " in " + $span else "" end) end;
def vals($g; $domain; $server; $now):
  ($g.first) as $a | ($a.source // {}) as $src
  | ($g.sorted[0]) as $top
  | ($g.raw[$top] // "") as $scenario
  | ($g.dec != null) as $hasdec
  | (if $hasdec then $g.dec.type else "ban" end) as $dtype
  | ((($a.simulated // false) == true) or ($hasdec and $g.dec.sim == true)) as $sim
  | (if $hasdec then $g.dec.dur else "" end) as $dur
  | (if $hasdec then $g.dec.origin else "" end) as $origin
  | (if $dur != "" then ($dur | dur_secs | human_len) else "" end) as $human
  | (if $hasdec | not then ""
     elif $dtype == "ban" then (if $human != "" then "banned " + $human else "banned" end) | (if $sim then "would be " + . + " (simulation)" else . end)
     else (if $human != "" then $dtype + " for " + $human else $dtype end) | (if $sim then "simulated " + . else . end) end) as $ban
  | (if $g.t0 > 0 and $g.t1 >= $g.t0 then ($g.t1 - $g.t0 | span_words) else "" end) as $span
  | (($src.cn // "") | tostring | trm) as $cn
  | (if ($cn | length) == 2 then ($cn | flag_emoji) else "" end) as $fe
  | (($src.as_name // "") | tostring | trm | san) as $asname
  | (($src.value // $src.ip // "") | tostring | trm) as $ip
  | (($a.machine_id // "") | tostring | trm) as $machine
  | ($g.targets) as $tg
  | (if ($tg | length) > 3 then " and \(($tg | length) - 3) more" else "" end) as $more
  | ($g.path0) as $path | ($g.path1) as $lpath
  | { ip: $ip, scope: (($src.scope // "") | tostring | trm), range: (($src.range // "") | tostring | trm), country: $cn,
      flag: (if ($cn | length) == 2 then ":flag_" + ($cn | ascii_downcase) + ":" else "" end),
      country_tag: (if ($cn | length) == 2 then " :flag_" + ($cn | ascii_downcase) + ": " + $cn else "" end),
      flag_emoji: $fe,
      source_tag: ((if ($cn | length) == 2 then " · " + (if $fe != "" then $fe + " " else "" end) + $cn else "" end) + (if $asname != "" then " · " + $asname else "" end)),
      as_number: (($src.as_number // "") | tostring | trm), as_name: $asname, as_tag: (if $asname != "" then " · " + $asname else "" end),
      scenario: $scenario, scenario_short: ($scenario | ltrimstr("crowdsecurity/")), label: ($g.label[$top] // "Attack blocked"),
      scenarios: (([ $g.sorted[0:6][] as $it | "\($it) ×\($g.counts[$it])" ] | join(" · ")) + (if ($g.sorted | length) > 6 then " · +\(($g.sorted | length) - 6) more" else "" end)),
      events: ($g.events | tostring), alerts: ($g.alerts | tostring), attempts: attempts_words($g.n; $span), span: $span,
      alert_id: (($a.id // 0) | tostring), message: (($a.message // "") | tostring | trm | san), sim_tag: (if $sim then " (simulation)" else "" end),
      decision: (if $sim then "simulated " + $dtype else $dtype end), duration: $dur, for_duration: (if $dur != "" then " for " + $dur else "" end),
      ban: $ban, ban_tag: (if $ban != "" then " → **" + $ban + "**" else "" end),
      origin: $origin, origin_tag: (if $origin != "" then " · " + $origin else "" end),
      target: ($tg[0] // ""), target_tag: (if ($tg | length) > 0 then " · aimed at **" + $tg[0] + "**" else "" end),
      targets: (if ($tg | length) > 0 then ($tg[0:3] | join(", ")) + $more else "" end),
      targets_line: (if ($tg | length) > 0 then "\nAimed at " + ($tg[0:3] | map("**" + . + "**") | join(", ")) + $more else "" end),
      path: $path, path_code: (if $path != "" then ($path | code) else "" end), last_path: $lpath, last_path_code: (if $lpath != "" then ($lpath | code) else "" end),
      requests_line: (if $path == "" then "" elif $path == $lpath then "\nRequest " + ($path | path_cut | code) else "\nFirst " + ($path | path_cut | code) + " · last " + ($lpath | path_cut | code) end),
      user_agent: $g.ua,
      machine: $machine, machine_tag: (if $machine != "" then " · " + $machine else "" end),
      domain: $domain, server: $server, time: ("<t:" + ($now | tostring) + ":R>"),
      cti_url: ("https://app.crowdsec.net/cti/" + $ip), abuseipdb_url: ("https://www.abuseipdb.com/check/" + $ip),
      _color: (if $dtype == "captcha" then 2282478 else ($g.rank | rank_color) end) };
def fill($t; $v): ($t // "") | gsub("\\{(?<k>[a-z_]+)\\}"; ($v[.k]) // ("{" + .k + "}"));
def fixed_color($s): $s.embed.color | ltrimstr("#") | explode | map(if . >= 97 then . - 87 elif . >= 65 then . - 55 else . - 48 end) | reduce .[] as $d (0; . * 16 + $d);
def payload($s; $alerts_in; $domain; $server; $now):
  ($alerts_in | if type == "array" then . else [.] end) as $alerts
  | (($s.delivery.group_by // "address") == "address") as $by_addr
  | gather($alerts; $by_addr) as $groups
  | (if ($groups | length) > 10 then {shown: $groups[0:9], rest: $groups[9:]} else {shown: $groups, rest: []} end) as $split
  | (($split.shown | length) + (if ($split.rest | length) > 0 then 1 else 0 end)) as $ne
  | ((5400 / $ne) | floor) as $budget
  | (([($s.message.fields | length), 1] | max) * 5) as $nf5
  | ([256, ([20, ($budget / 5 | floor)] | max)] | min) as $capT | ([2048, ([20, ($budget / 5 | floor)] | max)] | min) as $capF
  | ([256, ([10, ($budget / $nf5 | floor)] | max)] | min) as $capFN | ([1024, ([20, ($budget * 2 / $nf5 | floor)] | max)] | min) as $capFV
  | ( if $s.mention.mode == "role" then "<@&" + $s.mention.id + ">" elif $s.mention.mode == "user" then "<@" + $s.mention.id + ">"
      elif $s.mention.mode == "here" then "@here" elif $s.mention.mode == "everyone" then "@everyone" else "" end ) as $mtag
  | ( [$mtag, $s.mention.text] | map(select(length > 0)) | join(" ") ) as $content
  | [ $split.shown[] | vals(.; $domain; $server; $now) as $v
      | (fill($s.message.title; $v) | cut($capT)) as $title
      | (fill($s.message.footer; $v) | cut($capF)) as $footer
      | fill($s.message.link; $v) as $link
      | [ $s.message.fields[] | {name: fill(.name; $v), value: fill(.value; $v), inline: .inline} | select((.name | trm | length) > 0 and (.value | trm | length) > 0)
          | .name |= cut($capFN) | .value |= cut($capFV) ] as $fields
      | (($title | length) + ($footer | length) + ([ $fields[] | (.name | length) + (.value | length) ] | add // 0)) as $used
      | ([4096, ([50, $budget - $used] | max)] | min) as $dmax
      | { title: $title, color: (if $s.embed.color_mode == "fixed" then fixed_color($s) else $v._color end), description: (fill($s.message.description; $v) | cut($dmax)), fields: $fields }
        + (if $link != "" then {url: $link} else {} end)
        + (if $footer != "" then {footer: {text: $footer}} else {} end)
        + (if $s.message.timestamp then {timestamp: ($now | todate)} else {} end) ] as $embeds
  | ( if ($split.rest | length) == 0 then [] else
        ( [ $split.rest[] | . as $g | ($g.first.source // {}) as $src | (($src.value // "") | tostring | trm) as $ip | (($src.cn // "") | tostring | trm) as $cn
            | (if ($cn | length) == 2 then (($cn | flag_emoji) as $fe | if $fe != "" then " " + $fe + " " + $cn else " " + $cn end) else "" end) as $where
            | "`" + $ip + "`" + $where + " · " + $g.label[$g.sorted[0]] + " · " + attempts_words($g.n; "") ] | join("\n") ) as $rdesc
        | ("🛡️ \($split.rest | length) more " + (if $by_addr then "addresses" else "alerts" end)) as $rtitle
        | ([4096, ([50, $budget - ($rtitle | length)] | max)] | min) as $dmax
        | [ { title: $rtitle, color: (if $s.embed.color_mode == "fixed" then fixed_color($s) else ([ $split.rest[].rank ] | max | rank_color) end), description: ($rdesc | cut($dmax)) }
            + (if $s.message.timestamp then {timestamp: ($now | todate)} else {} end) ] end ) as $restembed
  | { username: $s.identity.name }
    + (if $s.identity.avatar_url != "" then {avatar_url: $s.identity.avatar_url} else {} end)
    + (if $content != "" then {content: $content} else {} end)
    + { allowed_mentions: (if $s.mention.mode == "role" then {roles: [$s.mention.id]} elif $s.mention.mode == "user" then {users: [$s.mention.id]}
                           elif $s.mention.mode == "here" or $s.mention.mode == "everyone" then {parse: ["everyone"]} else {parse: []} end),
        embeds: ($embeds + $restembed) };
'

# _cs_notify_render_payload SETTINGS ALERTS_JSON — the Discord payload for one alert or a batch of them (JSON on stdout)
_cs_notify_render_payload() {
    local domain server
    domain=$(_find_traefik_domain 2>/dev/null); [[ -n "$domain" ]] || domain="${PROXY_DOMAIN:-DCS}"
    server="${SERVER_NAME:-}"; [[ -n "$server" ]] || server=$(hostname 2>/dev/null || echo DCS)
    jq -c --argjson s "$1" --arg domain "${CS_RENDER_DOMAIN:-$domain}" --arg server "${CS_RENDER_SERVER:-$server}" --argjson now "${CS_RENDER_NOW:-$(date +%s)}" \
        "$_CS_JQ_DEFS$_CS_JQ_RENDER"' . as $a | payload($s; $a; $domain; $server; $now)' <<< "$2"
}

# =============================================================================
# Handlers: the ban profile
# =============================================================================

_CS_DURATION_PRESETS='["30m","1h","4h","12h","24h","3d","7d","30d"]'

# Everything the profile handlers need to know about the live state, as globals:
# CS_LIVE_PROFILES (text), CS_INSPECT (JSON), CS_LIVE_SETTINGS (JSON), CS_NOTIFY_EFF (JSON, effective, not validated for a webhook)
_cs_profile_state() {
    CS_LIVE_PROFILES=$(_cs_live_file "$CS_PROFILES_PATH")
    CS_INSPECT=$(_cs_profile_inspect "$CS_LIVE_PROFILES")
    CS_LIVE_SETTINGS=$(_cs_profile_live_settings "$CS_INSPECT")
    CS_NOTIFY_EFF=$(_cs_notify_effective "$CS_INSPECT")
}

# sha256 of a text (drift detection)
_cs_sha() { printf '%s\n' "$1" | sha256sum | cut -d' ' -f1; }

# The notification settings in force: saved ones over the defaults; without a saved file the live profiles decide whether they are on
_cs_notify_effective() {
    local insp="$1" saved
    if [[ -s "$CS_NOTIFY_FILE" ]]; then
        _cs_notify_saved
    else
        saved="$_CS_NOTIFY_DEFAULTS"
        saved=$(jq -c --argjson on "$(jq '.notified' <<< "$insp")" '.enabled = $on' <<< "$saved")
        # an install whose Discord alerts already work keeps posting where it posts: the live URL, unless a server-wide webhook exists
        if [[ -z "$(_cs_webhook_resolve global)" && -n "$(_cs_webhook_resolve keep)" ]]; then saved=$(jq -c '.webhook.mode = "keep"' <<< "$saved"); fi
        printf '%s' "$saved"
    fi
}

# GET-side view of the ban profile
_cs_settings_view() {
    local drift=false saved raw=""
    saved=$(_cs_json_file "$CS_SETTINGS_FILE" '{}')
    if [[ "$(jq -r '.mode' <<< "$CS_INSPECT")" == dcs ]]; then
        local want; want=$(jq -r '.applied_profile_sha // ""' <<< "$saved")
        [[ -n "$want" && "$want" != "$(_cs_sha "$CS_LIVE_PROFILES")" ]] && drift=true
    fi
    # a hand-written profile file is shown to admins only (it can hold anything, including notification wiring)
    if [[ "$(jq -r '.mode' <<< "$CS_INSPECT")" == custom ]] && _api_check_admin; then raw="${CS_LIVE_PROFILES:0:20000}"; fi
    jq -nc --argjson insp "$CS_INSPECT" --argjson live "$CS_LIVE_SETTINGS" --argjson saved "$saved" --argjson presets "$_CS_DURATION_PRESETS" --argjson defaults "$_CS_PROFILE_DEFAULTS" \
        --argjson drift "$drift" --arg raw "$raw" --arg manual "$(_cs_manual_default_duration)" --argjson backups "$(_cs_backups_json)" --argjson ret "$(_cs_retention_days)" '
        { mode: $insp.mode, editable: ($insp.mode != "custom"), custom: ($insp.mode == "custom"), profile: $live, manual_duration: $manual, defaults: $defaults, presets: $presets,
          limits: {auto_max: "3650d", manual_max: "10 years", overrides_max: 12},
          live: {file: "/etc/crowdsec/profiles.yaml", profiles: $insp.profiles, notified: $insp.notified, escalate: $insp.escalate, ip_duration: $insp.ip_duration, range_duration: $insp.range_duration},
          drift: $drift, backups: $backups, raw: (if $raw == "" then null else $raw end), retention_days: $ret,
          help: { duration: "How long CrowdSec bans an address it caught by itself. Bans you add by hand choose their own length.",
                  escalate: "Repeat offenders are banned longer each time: the length is the default times (number of earlier bans + 1), up to the cap. CrowdSec remembers earlier bans for its alert retention time.",
                  overrides: "A scenario can have its own length: SSH brute force for a day, known exploits for a week. The first matching row wins; a * at the end matches a prefix." } }'
}

# GET /crowdsec/settings — The default ban length CrowdSec uses, repeat-offender escalation and per-scenario lengths; says whether DCS can edit the file safely
handle_crowdsec_settings() {
    _cs_target || return
    _cs_profile_state
    _api_success "$(_cs_settings_view)"
}

# PUT /crowdsec/settings — Change the ban profile: {profile: {duration, range_duration, escalate: {enabled, max}, overrides: [{pattern, duration}]}, manual_duration, take_over}; validates with CrowdSec, restarts it and rolls back on failure
handle_crowdsec_settings_set() {
    _api_check_admin || { _api_error 403 "Admin access required"; return; }
    local body="$1" patch base merged norm md take notify_on new_prof rc mode saved
    [[ "$body" == \{* ]] && jq -e . >/dev/null 2>&1 <<< "$body" || { _api_error 400 "Send a JSON body: {\"profile\": {\"duration\": \"12h\"}}"; return; }
    patch=$(jq -c '(.profile // {})' <<< "$body"); jq -e 'type == "object"' >/dev/null 2>&1 <<< "$patch" || { _api_error 400 "profile must be an object"; return; }
    take=$(jq -r 'if .take_over == true then "yes" else "no" end' <<< "$body")
    md=$(jq -r '(.manual_duration // "") | tostring' <<< "$body")
    if [[ -n "$md" ]]; then md=$(_cs_norm_duration "$md") || { _api_error 400 "The default length for manual bans is not valid: use 30m, 4h, 7d or 2w"; return; }; fi
    _cs_target || return
    _cs_profile_state
    mode=$(jq -r '.mode' <<< "$CS_INSPECT")
    if [[ "$patch" != '{}' && "$mode" == custom && "$take" != yes ]]; then
        _api_response 409 "$(jq -nc '{error: true, code: 409, reason: "custom_profile", message: "profiles.yaml has profiles DCS did not write. Saving here would replace the whole file (a backup is kept). Send take_over: true to do that."}')"; return
    fi
    base="$CS_LIVE_SETTINGS"; [[ "$mode" == custom ]] && base="$_CS_PROFILE_DEFAULTS"
    merged=$(_cs_profile_merge "$base" "$patch")
    _cs_profile_validate "$merged" || { _api_error 400 "$CS_CFG_ERR"; return; }
    norm="$CS_OUT"
    local applied='{"changed":false}'
    if [[ "$patch" != '{}' ]]; then
        notify_on=false
        [[ "$(jq -r '.enabled' <<< "$CS_NOTIFY_EFF")" == true && -n "$(_cs_webhook_resolve "$(jq -r '.webhook.mode' <<< "$CS_NOTIFY_EFF")")" ]] && notify_on=true
        new_prof=$(_cs_profiles_render "$norm" "$CS_NOTIFY_EFF" "$notify_on")
        _cs_config_apply "$new_prof" ""; rc=$?
        applied=$(jq -nc --argjson rc "$rc" --arg m "$CS_APPLY_MSG" --argjson ch "$CS_APPLY_CHANGED" --arg b "$CS_APPLY_BACKUP" '{changed: ($ch == 1), message: $m, backup: (if $b == "" then null else $b end)}')
        if (( rc != 0 )); then
            _api_audit_log "${CLIENT_IP:-unknown}" "CROWDSEC_SETTINGS" "${AUTH_USERNAME:-}" "failed ($rc): ${CS_APPLY_MSG:0:120}"
            _cs_apply_fail "$rc"
            return
        fi
    fi
    saved=$(_cs_json_file "$CS_SETTINGS_FILE" '{}')
    saved=$(jq -c --argjson p "$norm" --arg md "$md" --arg sha "$(_cs_sha "$(_cs_live_file "$CS_PROFILES_PATH")")" --argjson touched "$([[ "$patch" != '{}' ]] && echo true || echo false)" \
        '.v = 1 | .profile = $p | (if $md != "" then .manual_duration = $md else . end) | (if $touched then .applied_profile_sha = $sha else . end)' <<< "$saved")
    printf '%s' "$saved" | _cs_json_save "$CS_SETTINGS_FILE"
    _cs_cache_clear
    _api_audit_log "${CLIENT_IP:-unknown}" "CROWDSEC_SETTINGS" "${AUTH_USERNAME:-}" "ban length $(jq -r '.duration' <<< "$norm")${md:+, manual $md}: ${CS_APPLY_MSG:-saved}"
    _cs_profile_state
    _api_success "$(_cs_settings_view | jq -c --argjson a "$applied" '. + {success: true, applied: $a}')"
}

# =============================================================================
# Handlers: Discord notifications
# =============================================================================

# _cs_status_set KEY JSON — remember the last test / apply outcome
_cs_status_set() {
    local key="$1" val="$2" cur
    cur=$(_cs_json_file "$CS_NOTIFY_STATUS" '{}')
    jq -c --arg k "$key" --argjson v "$val" '.[$k] = $v' <<< "$cur" | _cs_json_save "$CS_NOTIFY_STATUS"
}

# delivery problems the running plugin reported (CrowdSec logs failures, not successes): [{time, message}]
_cs_delivery_errors() {
    local raw out
    [[ -n "$CS_NAME" ]] || { printf '[]'; return; }
    raw=$(timeout 15 docker logs --since 24h --tail 3000 "$CS_NAME" 2>&1 </dev/null | grep -E 'http-plugin|http_default|delivery failed|notify attempt failed|format alerts for notification' | grep -E 'level=(warning|error)' | tail -n 40)
    out=$(printf '%s\n' "$raw" | jq -Rsc '[ split("\n")[] | select(length > 0) | capture("^time=\"(?<t>[^\"]+)\" level=(?<l>[a-z]+) msg=\"(?<m>(?:\\\\.|[^\"\\\\])*)\"")? | {time: .t, message: (.m | gsub("\\\\\""; "\""))} ] | reverse | unique_by(.message) | sort_by(.time) | reverse | .[0:5]' 2>/dev/null)
    [[ "$out" == \[* ]] || out='[]'
    # a failed post quotes the URL it tried: the token part of a webhook is a secret and never leaves here
    out=$(jq -c 'map(.message |= gsub("(?<a>/api/webhooks/[0-9]+/)[A-Za-z0-9_.~-]+"; "\(.a)••••"))' <<< "$out" 2>/dev/null) || out='[]'
    printf '%s' "$out"
}

# The webhook as the page may see it: never the URL
_cs_webhook_view() {
    local mode="$1" g c k eff="none" u
    g=$(_cs_webhook_resolve global); c=$(_cs_webhook_resolve custom); k=$(_cs_webhook_resolve keep)
    u=$(_cs_webhook_resolve "$mode"); [[ -n "$u" ]] && eff="$mode"
    jq -nc --arg mode "$mode" --arg eff "$eff" --arg gm "$(_cs_webhook_mask "$g")" --arg cm "$(_cs_webhook_mask "$c")" --arg km "$(_cs_webhook_mask "$k")" --arg um "$(_cs_webhook_mask "$u")" \
        '{mode: $mode, configured: ($um != ""), masked: (if $um == "" then null else $um end),
          sources: {global: {configured: ($gm != ""), masked: (if $gm == "" then null else $gm end)}, custom: {configured: ($cm != ""), masked: (if $cm == "" then null else $cm end)}, keep: {configured: ($km != ""), masked: (if $km == "" then null else $km end)}}}'
}

# GET-side view of the notifications: settings in force, what is wired, the placeholders, the last outcomes
_cs_notify_view() {
    local eff="$1" insp="$2" status wired plugin drift=false mode file_mode hraw sha_want errs layout=0
    status=$(_cs_json_file "$CS_NOTIFY_STATUS" '{}')
    hraw=$(_cs_live_file "$CS_HTTP_PATH")
    file_mode=missing
    if [[ -n "$hraw" ]]; then
        if grep -q '^# dcs-notify:' <<< "$hraw"; then
            file_mode=dcs
            # the layout the file was written with (1 = one embed per alert, before the messages were grouped)
            layout=$(sed -n 's/^# dcs-notify: //p' <<< "$hraw" | head -n 1 | jq -r '(.v // 1) | tostring' 2>/dev/null); [[ "$layout" =~ ^[0-9]+$ ]] || layout=1
        else file_mode=other; fi
    fi
    sha_want=$(jq -r '.applied_http_sha // ""' <<< "$status")
    [[ "$file_mode" == dcs && -n "$sha_want" && "$sha_want" != "$(_cs_sha "$hraw")" ]] && drift=true
    wired=$(jq -r '.notified' <<< "$insp")
    plugin=false
    timeout 15 docker exec "$CS_NAME" cscli notifications list 2>/dev/null </dev/null | grep -E '^[[:space:]]*[^[:space:]]+[[:space:]]+http_default[[:space:]]' | grep -q '✔' && plugin=true
    errs=$(_cs_delivery_errors)
    jq -nc --argjson eff "$eff" --argjson insp "$insp" --argjson status "$status" --argjson wired "$wired" --argjson plugin "$plugin" --arg fm "$file_mode" --argjson drift "$drift" \
        --argjson webhook "$(_cs_webhook_view "$(jq -r '.webhook.mode' <<< "$eff")")" --argjson ph "$_CS_PLACEHOLDERS" --argjson defaults "$_CS_NOTIFY_DEFAULTS" --argjson errs "$errs" \
        --argjson samples "$(jq -c 'keys' <<< "$_CS_NOTIFY_SAMPLES")" --arg profmode "$(jq -r '.mode' <<< "$insp")" --argjson layout "$layout" --argjson want "$CS_NOTIFY_LAYOUT" \
        --argjson digest "$(_cs_digest_view)" '
        { settings: $eff, webhook: $webhook, defaults: $defaults, placeholders: $ph, samples: $samples, digest: $digest,
          state: { enabled: $eff.enabled, wired: $wired, plugin_active: $plugin, file: $fm, profile_mode: $profmode, drift: $drift,
                   working: ($eff.enabled and $wired and $plugin and $webhook.configured),
                   # the file is DCS'"'"'s but older than the grouped messages: saving (even unchanged) writes the new layout
                   layout: $layout, layout_outdated: ($fm == "dcs" and $layout < $want) },
          status: { last_test: ($status.last_test // null), last_apply: ($status.last_apply // null), delivery_errors: $errs,
                    note: "CrowdSec logs a failed delivery but not a successful one, so DCS can only show the problems the plugin reports and the result of the last test message." },
          limits: { title: 200, description: 1500, footer: 200, fields: 8, group_threshold_max: 100, embeds_per_message: 10 },
          info: { unban: "CrowdSec cannot announce a lifted ban. Unbans made from DCS raise the crowdsec_unban event: add a rule for it on the Notifications page to hear about them." } }'
}

# GET /crowdsec/notifications — The Discord alert settings in force (webhook masked), what is wired, the placeholders for the message, and the last test/delivery outcome
handle_crowdsec_notify_get() {
    _cs_target || return
    _cs_profile_state
    _api_success "$(_cs_notify_view "$CS_NOTIFY_EFF" "$CS_INSPECT")"
}

# _cs_notify_apply EFFECTIVE_SETTINGS PROFILE_SETTINGS INSPECT — render both files from the settings and put them live. Returns _cs_config_apply's status.
_cs_notify_apply() {
    local eff="$1" prof="$2" insp="$3" url notify_on=false http_text="" prof_text rc
    url=$(_cs_webhook_resolve "$(jq -r '.webhook.mode' <<< "$eff")")
    if [[ "$(jq -r '.enabled' <<< "$eff")" == true && -n "$url" ]]; then notify_on=true; http_text=$(_cs_notify_render_yaml "$eff" "$url"); fi
    prof_text=$(_cs_profiles_render "$prof" "$eff" "$notify_on")
    _cs_config_apply "$prof_text" "$http_text"; rc=$?
    CS_APPLY_HTTP_SHA=""; [[ -n "$http_text" ]] && CS_APPLY_HTTP_SHA=$(_cs_sha "$http_text")
    CS_APPLY_PROF_SHA=$(_cs_sha "$prof_text")
    return $rc
}
CS_APPLY_HTTP_SHA=""; CS_APPLY_PROF_SHA=""

# _cs_notify_set_core BODY — save and apply the Discord alert settings. 0 = done (CS_RESULT holds the view), 1 = refused (CS_ERR_CODE / CS_ERR_BODY)
CS_RESULT=""
_cs_notify_set_core() {
    local body="$1" patch eff merged url_in prof mode take rc clear had_custom=""
    [[ "$body" == \{* ]] && jq -e . >/dev/null 2>&1 <<< "$body" || { _cs_fail 400 "Send a JSON body: {\"settings\": {\"enabled\": true}}"; return 1; }
    patch=$(jq -c '(.settings // {})' <<< "$body"); jq -e 'type == "object"' >/dev/null 2>&1 <<< "$patch" || { _cs_fail 400 "settings must be an object"; return 1; }
    url_in=$(jq -r '(.webhook_url // "") | tostring' <<< "$body"); clear=$(jq -r 'if .clear_custom_webhook == true then "yes" else "no" end' <<< "$body")
    take=$(jq -r 'if .take_over == true then "yes" else "no" end' <<< "$body")
    if [[ -n "$url_in" ]]; then
        [[ "$url_in" =~ ^https://[A-Za-z0-9.]+/api/webhooks/[0-9]{5,25}/[A-Za-z0-9_-]{10,200}$ ]] && _discord_is_webhook "$url_in" || { _cs_fail 400 "That is not a Discord webhook address (https://discord.com/api/webhooks/<id>/<token>)"; return 1; }
    fi
    CS_NAME=$(_crowdsec_container) || CS_NAME=""
    [[ -n "$CS_NAME" ]] || { _cs_fail 404 "CrowdSec is not running"; return 1; }
    _cs_profile_state
    mode=$(jq -r '.mode' <<< "$CS_INSPECT")
    if [[ "$mode" == custom && "$take" != yes ]]; then
        _cs_fail 409 "profiles.yaml has profiles DCS did not write. Saving here would replace the whole file (a backup is kept). Send take_over: true to do that." '{"reason":"custom_profile"}'; return 1
    fi
    merged=$(_cs_notify_merge "$CS_NOTIFY_EFF" "$patch")
    [[ -n "$url_in" ]] && merged=$(jq -c '.webhook.mode = "custom"' <<< "$merged")
    _cs_notify_validate "$merged" || { _cs_fail 400 "$CS_CFG_ERR"; return 1; }
    eff="$CS_OUT"
    prof="$CS_LIVE_SETTINGS"; [[ "$mode" == custom ]] && prof="$_CS_PROFILE_DEFAULTS"
    _cs_profile_validate "$prof" || { _cs_fail 500 "The ban profile in force is not valid: $CS_CFG_ERR"; return 1; }
    prof="$CS_OUT"
    # the webhook: a new custom one is stored first (and put back if the change fails)
    had_custom=$(secrets_get "$CS_WEBHOOK_SECRET" 2>/dev/null) || had_custom=""
    if [[ "$clear" == yes ]]; then secrets_delete "$CS_WEBHOOK_SECRET" >/dev/null 2>&1 || true; fi
    if [[ -n "$url_in" ]]; then secrets_set "$CS_WEBHOOK_SECRET" "$url_in" || { _cs_fail 500 "Could not store the webhook"; return 1; }; fi
    _cs_webhook_undo() {
        if [[ -n "$url_in" || "$clear" == yes ]]; then
            if [[ -n "$had_custom" ]]; then secrets_set "$CS_WEBHOOK_SECRET" "$had_custom" >/dev/null 2>&1; else secrets_delete "$CS_WEBHOOK_SECRET" >/dev/null 2>&1 || true; fi
        fi
    }
    if [[ "$(jq -r '.enabled' <<< "$eff")" == true && -z "$(_cs_webhook_resolve "$(jq -r '.webhook.mode' <<< "$eff")")" ]]; then
        _cs_webhook_undo
        _cs_fail 400 "There is no Discord webhook to post to: add one here, or set DISCORD_WEBHOOK_URL under Config → Notifications"; return 1
    fi
    _cs_notify_apply "$eff" "$prof" "$CS_INSPECT"; rc=$?
    if (( rc != 0 )); then
        _cs_webhook_undo
        _cs_status_set last_apply "$(jq -nc --arg m "$CS_APPLY_MSG" --argjson at "$(date +%s)" '{at: $at, ok: false, message: $m}')"
        _api_audit_log "${CLIENT_IP:-unknown}" "CROWDSEC_NOTIFY" "${AUTH_USERNAME:-}" "failed ($rc): ${CS_APPLY_MSG:0:120}"
        _cs_apply_error "$rc"; return 1
    fi
    printf '%s' "$eff" | _cs_json_save "$CS_NOTIFY_FILE"
    local st; st=$(_cs_json_file "$CS_SETTINGS_FILE" '{}')
    jq -c --argjson p "$prof" --arg sha "$CS_APPLY_PROF_SHA" '.v = 1 | .profile = $p | .applied_profile_sha = $sha' <<< "$st" | _cs_json_save "$CS_SETTINGS_FILE"
    _cs_status_set last_apply "$(jq -nc --arg m "$CS_APPLY_MSG" --argjson at "$(date +%s)" '{at: $at, ok: true, message: $m}')"
    if [[ -n "$CS_APPLY_HTTP_SHA" ]]; then
        jq -c --arg sha "$CS_APPLY_HTTP_SHA" '.applied_http_sha = $sha' <<< "$(_cs_json_file "$CS_NOTIFY_STATUS" '{}')" | _cs_json_save "$CS_NOTIFY_STATUS"
    fi
    _cs_cache_clear
    _api_audit_log "${CLIENT_IP:-unknown}" "CROWDSEC_NOTIFY" "${AUTH_USERNAME:-}" "$( [[ "$(jq -r '.enabled' <<< "$eff")" == true ]] && echo on || echo off )${url_in:+, webhook changed}: ${CS_APPLY_MSG:0:100}"
    _cs_profile_state
    CS_RESULT=$(_cs_notify_view "$CS_NOTIFY_EFF" "$CS_INSPECT" | jq -c --arg m "$CS_APPLY_MSG" --argjson ch "$CS_APPLY_CHANGED" '. + {success: true, applied: {changed: ($ch == 1), message: $m}}')
    return 0
}

# PUT /crowdsec/notifications — Save and apply the Discord alert settings: {settings: {…any part…}, webhook_url?: "https://discord.com/api/webhooks/…", clear_custom_webhook?: true}; the URL is stored as a secret and never sent back
handle_crowdsec_notify_set() {
    _api_check_admin || { _api_error 403 "Admin access required"; return; }
    if _cs_notify_set_core "$1"; then _api_success "$CS_RESULT"; else _api_response "$CS_ERR_CODE" "$CS_ERR_BODY"; fi
}

# POST /crowdsec/notifications/preview — Render the message for a sample alert (probe, ssh, exploit, manual, simulated) or a real one (alert_id) with the settings you are editing: {settings?, sample?, alert_id?}
handle_crowdsec_notify_preview() {
    local body="$1" patch sample alert_id alert merged out eff
    [[ "$body" == \{* ]] && jq -e . >/dev/null 2>&1 <<< "$body" || body='{}'
    patch=$(jq -c '(.settings // {})' <<< "$body"); jq -e 'type == "object"' >/dev/null 2>&1 <<< "$patch" || { _api_error 400 "settings must be an object"; return; }
    sample=$(jq -r '(.sample // "probe") | tostring' <<< "$body"); alert_id=$(jq -r '(.alert_id // "") | tostring' <<< "$body")
    _cs_target || return
    _cs_profile_state
    merged=$(_cs_notify_merge "$CS_NOTIFY_EFF" "$patch")
    if ! _cs_notify_validate "$merged"; then
        _api_success "$(jq -nc --arg m "$CS_CFG_ERR" '{valid: false, error: $m, payload: null}')"; return
    fi
    eff="$CS_OUT"
    if [[ -n "$alert_id" ]]; then
        [[ "$alert_id" =~ ^[0-9]{1,12}$ ]] || { _api_error 400 "alert_id must be a number"; return; }
        _cs_run out alerts inspect "$alert_id" -d -o json || { _api_error 404 "No alert $alert_id"; return; }
        alert=$(jq -c '.' <<< "$out")
        sample="alert $alert_id"
    else
        [[ "$sample" =~ ^[a-z]{3,12}$ ]] && jq -e --arg s "$sample" 'has($s)' >/dev/null 2>&1 <<< "$_CS_NOTIFY_SAMPLES" || { _api_error 400 "sample must be one of: $(jq -r 'keys | join(", ")' <<< "$_CS_NOTIFY_SAMPLES")"; return; }
        alert=$(_cs_notify_sample "$sample")
    fi
    _api_success "$(jq -nc --arg s "$sample" --argjson p "$(_cs_notify_render_payload "$eff" "$alert")" --argjson a "$alert" \
        '{valid: true, sample: $s, payload: $p, alert: ($a | if type == "array" then {id: .[0].id, scenario: .[0].scenario, count: length} else {id: .id, scenario: .scenario, count: 1} end)}')"
}

# _cs_discord_post URL PAYLOAD — post to a Discord webhook; the address travels on curl's standard input, not its command line.
# Sets CS_HTTP_CODE (000 when nothing answered), CS_HTTP_BODY, CS_CURL_ERR.
CS_HTTP_CODE=000; CS_HTTP_BODY=""; CS_CURL_ERR=""
_cs_discord_post() {
    local url="$1" payload="$2" body errf pf
    body=$(mktemp "${TMPDIR:-/tmp}/dcs-cs-http.XXXXXX"); errf=$(mktemp "${TMPDIR:-/tmp}/dcs-cs-http.XXXXXX"); pf=$(mktemp "${TMPDIR:-/tmp}/dcs-cs-http.XXXXXX")
    printf '%s' "$payload" > "$pf"
    CS_HTTP_CODE=$(printf 'url = "%s"\n' "$url" | curl -sS -K - -o "$body" -w '%{http_code}' --max-time 15 -H 'Content-Type: application/json' --data-binary "@$pf" 2>"$errf")
    [[ "$CS_HTTP_CODE" =~ ^[0-9]{3}$ ]] || CS_HTTP_CODE=000
    CS_HTTP_BODY=$(head -c 2000 "$body" 2>/dev/null); CS_CURL_ERR=$(head -c 300 "$errf" 2>/dev/null | tr '\n' ' ')
    rm -f "$body" "$errf" "$pf"
    [[ "$CS_HTTP_CODE" =~ ^2 ]]
}

# what Discord's answer means
_cs_discord_explain() {
    local code="$1" body="$2" m ra
    m=$(jq -r '.message // empty' <<< "$body" 2>/dev/null)
    case "$code" in
        2??) printf 'Delivered (Discord answered %s).' "$code" ;;
        400) printf 'Discord rejected the message (400)%s. Check the mention, the sender name and the field texts.' "${m:+: $m}" ;;
        401|403|404) printf 'Discord says this webhook does not exist (%s): it was deleted, or the address is wrong. Create a new webhook in the channel settings.' "$code" ;;
        429) ra=$(jq -r '.retry_after // empty' <<< "$body" 2>/dev/null); printf 'Discord is rate limiting this webhook (429)%s. Try again in a moment.' "${ra:+, retry after ${ra}s}" ;;
        5??) printf 'Discord is having trouble right now (%s). Try again later.' "$code" ;;
        000) printf 'Could not reach Discord%s.' "${CS_CURL_ERR:+ ($CS_CURL_ERR)}" ;;
        *) printf 'Discord answered %s%s.' "$code" "${m:+: $m}" ;;
    esac
}

# _cs_notify_test_core BODY — post the sample. 0 = the message was sent (delivered or not: CS_RESULT says which), 1 = refused (CS_ERR_*)
_cs_notify_test_core() {
    local body="$1" patch sample url_in url merged eff alert payload ok=false msg inc
    [[ "$body" == \{* ]] && jq -e . >/dev/null 2>&1 <<< "$body" || body='{}'
    patch=$(jq -c '(.settings // {})' <<< "$body"); jq -e 'type == "object"' >/dev/null 2>&1 <<< "$patch" || { _cs_fail 400 "settings must be an object"; return 1; }
    sample=$(jq -r '(.sample // "probe") | tostring' <<< "$body"); url_in=$(jq -r '(.webhook_url // "") | tostring' <<< "$body"); inc=$(jq -r 'if .include_mention == true then "yes" else "no" end' <<< "$body")
    [[ "$sample" =~ ^[a-z]{3,12}$ ]] && jq -e --arg s "$sample" 'has($s)' >/dev/null 2>&1 <<< "$_CS_NOTIFY_SAMPLES" || { _cs_fail 400 "sample must be one of: $(jq -r 'keys | join(", ")' <<< "$_CS_NOTIFY_SAMPLES")"; return 1; }
    if [[ -n "$url_in" ]]; then [[ "$url_in" =~ ^https://[A-Za-z0-9.]+/api/webhooks/[0-9]{5,25}/[A-Za-z0-9_-]{10,200}$ ]] && _discord_is_webhook "$url_in" || { _cs_fail 400 "That is not a Discord webhook address"; return 1; }; fi
    CS_NAME=$(_crowdsec_container) || CS_NAME=""
    [[ -n "$CS_NAME" ]] || { _cs_fail 404 "CrowdSec is not running"; return 1; }
    _cs_profile_state
    merged=$(_cs_notify_merge "$CS_NOTIFY_EFF" "$patch")
    _cs_notify_validate "$merged" || { _cs_fail 400 "$CS_CFG_ERR"; return 1; }
    eff="$CS_OUT"
    url="$url_in"; [[ -n "$url" ]] || url=$(_cs_webhook_resolve "$(jq -r '.webhook.mode' <<< "$eff")")
    [[ -n "$url" ]] || { _cs_fail 400 "There is no Discord webhook to post to: add one first"; return 1; }
    alert=$(_cs_notify_sample "$sample")
    payload=$(_cs_notify_render_payload "$eff" "$alert")
    if [[ "$inc" != yes ]]; then payload=$(jq -c 'del(.content) | .allowed_mentions = {parse: []} | .embeds |= map(.footer.text = ((.footer.text // "") + " · test message"))' <<< "$payload"); fi
    if _cs_discord_post "$url" "$payload"; then ok=true; fi
    msg=$(_cs_discord_explain "$CS_HTTP_CODE" "$CS_HTTP_BODY")
    _cs_status_set last_test "$(jq -nc --argjson at "$(date +%s)" --argjson ok "$ok" --argjson c "${CS_HTTP_CODE:-0}" --arg m "$msg" --arg s "$sample" '{at: $at, ok: $ok, http: $c, message: $m, sample: $s}')"
    _api_audit_log "${CLIENT_IP:-unknown}" "CROWDSEC_NOTIFY_TEST" "${AUTH_USERNAME:-}" "$sample: HTTP $CS_HTTP_CODE"
    CS_RESULT=$(jq -nc --argjson ok "$ok" --argjson c "${CS_HTTP_CODE:-0}" --arg m "$msg" --arg s "$sample" --argjson at "$(date +%s)" --arg masked "$(_cs_webhook_mask "$url")" '{success: $ok, delivered: $ok, http: $c, message: $m, sample: $s, at: $at, webhook: $masked}')
    return 0
}

# POST /crowdsec/notifications/test — Post a real sample message to Discord and say what Discord answered: {sample?, settings?, webhook_url?, include_mention?}; a test never pings anyone unless include_mention is true
handle_crowdsec_notify_test() {
    _api_check_admin || { _api_error 403 "Admin access required"; return; }
    if _cs_notify_test_core "$1"; then _api_success "$CS_RESULT"; else _api_response "$CS_ERR_CODE" "$CS_ERR_BODY"; fi
}

# POST /crowdsec/notifications/reset — Back to the message CrowdSec ships with (title, text, fields, colours, delivery); the webhook and the on/off switch stay
handle_crowdsec_notify_reset() {
    _api_check_admin || { _api_error 403 "Admin access required"; return; }
    local body="${1:-}" take=false
    [[ "$body" == \{* ]] && [[ "$(jq -r 'if .take_over == true then "yes" else "no" end' <<< "$body" 2>/dev/null)" == yes ]] && take=true
    _cs_target || return
    _cs_profile_state
    local keep_enabled keep_webhook
    keep_enabled=$(jq -c '.enabled' <<< "$CS_NOTIFY_EFF"); keep_webhook=$(jq -c '.webhook' <<< "$CS_NOTIFY_EFF")
    if _cs_notify_set_core "$(jq -nc --argjson d "$_CS_NOTIFY_DEFAULTS" --argjson e "$keep_enabled" --argjson w "$keep_webhook" --argjson t "$take" '{settings: ($d | .enabled = $e | .webhook = $w), take_over: $t}')"; then
        _api_success "$CS_RESULT"
    else _api_response "$CS_ERR_CODE" "$CS_ERR_BODY"; fi
}

# POST /crowdsec/notifications — Send CrowdSec's alerts to Discord: {webhook?, test?}. Turns the alerts on with the message settings in force (the shipped message on a fresh install), stores a webhook you pass, restarts CrowdSec and optionally posts a test message.
handle_crowdsec_notifications_apply() {
    if ! _api_check_admin; then _api_error 403 "Admin access required"; return; fi
    local body="$1" webhook test domain req
    [[ "$body" == \{* ]] || body='{}'
    webhook=$(jq -r '(.webhook // "") | tostring' <<< "$body" 2>/dev/null); test=$(jq -r 'if .test == true then "true" else "false" end' <<< "$body" 2>/dev/null)
    _cs_target || return
    if [[ -z "$webhook" ]] && [[ -z "$(_cs_webhook_resolve global)" && -z "$(_cs_webhook_resolve custom)" ]]; then
        # the webhook the template was deployed with, else the one CrowdSec already posts to
        local proj; proj=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project.working_dir"}}' "$CS_NAME" 2>/dev/null)
        [[ -n "$proj" && -f "$proj/.env" ]] && webhook=$(sed -n 's/^DISCORD_WEBHOOK_URL=//p' "$proj/.env" | head -1 | tr -d '"'"'"'')
        [[ "$webhook" =~ ^\$\{SECRETS[._]([A-Za-z_][A-Za-z0-9_]*)\}$ ]] && webhook=$(secrets_get "${BASH_REMATCH[1]}" 2>/dev/null || true)
        _discord_is_webhook "$webhook" || webhook=""
        [[ -n "$webhook" || -n "$(_cs_webhook_resolve keep)" ]] || { _api_error 400 "No Discord webhook: pass {\"webhook\": \"https://discord.com/api/webhooks/…\"}, set one under Config → Notifications, or deploy the crowdsec template with one"; return; }
    fi
    req=$(jq -nc --arg w "$webhook" '{settings: {enabled: true}} + (if $w != "" then {webhook_url: $w} else {} end)')
    if ! _cs_notify_set_core "$req"; then _api_response "$CS_ERR_CODE" "$CS_ERR_BODY"; return; fi
    domain=$(_find_traefik_domain); [[ -n "$domain" ]] || domain="${PROXY_DOMAIN:-DCS}"
    local tested=false test_out=""
    if [[ "$test" == "true" ]]; then
        if _cs_notify_test_core '{}'; then tested=$(jq -r '.delivered' <<< "$CS_RESULT"); test_out=$(jq -r '.message' <<< "$CS_RESULT"); fi
    fi
    _audit_log "CROWDSEC_NOTIFICATIONS" "Discord alerts configured on $CS_NAME for $domain${tested:+ (test message sent)}"
    _api_success "$(jq -nc --arg c "$CS_NAME" --arg d "$domain" --argjson t "${tested:-false}" --arg o "$test_out" '{success: true, container: $c, domain: $d, restarted: true, tested: $t, test_output: $o}')"
}

# =============================================================================
# The daily summary: the last 24 hours in one Discord message
#
# Once a day at CROWDSEC_DIGEST_HOUR (local time, 8 by default, off turns it
# off) the API's minute clock (_crowdsec_digest_tick in api-server.sh) posts
# what CrowdSec blocked: how many attempts from how many addresses, the top
# addresses and attacks, and what happened to the bans. It goes to the webhook
# of the CrowdSec alerts while those are on. digest.json remembers the day it
# went out, so a restart or a second process never sends it twice.
# =============================================================================

CS_DIGEST_STATE="$CROWDSEC_STATE_DIR/digest.json"
CS_DIGEST_DEFAULT_HOUR=8

# _cs_digest_hour_of VALUE — the hour (0-23) a CROWDSEC_DIGEST_HOUR value stands for, "off", or nothing when it is not a value
_cs_digest_hour_of() {
    local h="${1//[[:space:]]/}"
    if [[ -z "$h" || "${h,,}" == off ]]; then printf 'off'
    elif [[ "$h" =~ ^[0-9]{1,2}$ ]] && (( 10#$h <= 23 )); then printf '%d' $(( 10#$h ))
    fi
}
# the hour in force (unset = the default; a value that is no hour counts as off)
_cs_digest_hour() {
    local h
    if [[ -z "${CROWDSEC_DIGEST_HOUR+x}" ]]; then printf '%d' "$CS_DIGEST_DEFAULT_HOUR"; return; fi
    h=$(_cs_digest_hour_of "$CROWDSEC_DIGEST_HOUR"); printf '%s' "${h:-off}"
}

# The jq program: alerts (cscli alerts list --since 24h), active decisions (decision_rows), the hand-lifted count and the
# community count → the Discord payload and the numbers behind it
_CS_JQ_DIGEST='
def commas: tostring | if test("^[0-9]+$") then (explode | reverse | [ range(0; length) as $i | (if $i > 0 and $i % 3 == 0 then [44] else [] end) + [.[$i]] ] | flatten | reverse | implode) else . end;
def flag_emoji: ascii_upcase | explode | map(if . >= 65 and . <= 90 then [127397 + .] | implode else "" end) | join("");
def plural($n; $one; $many): "\($n | commas) " + (if $n == 1 then $one else $many end);
def item: (.scenario // "" | tostring) as $sc | ($sc | scen_label) as $lb
  | ([$sc | match("(?i)cve-[0-9]{4}-[0-9]+")] | .[0].string // "") as $cve
  | (if $cve != "" then ($cve | ascii_upcase) else ($sc | ltrimstr("crowdsecurity/")) end) as $sid
  | if $sid != "" then $lb + " " + $sid else $lb end;
(. // []) as $all
| [ $all[] | select((.kind // "") != "cscli") ] as $det
| [ $det[] | select((.simulated // false) | not) | {ip: ((.source.value // "") | tostring), cn: (.source.cn | cc), as_name: (.source.as_name // ""), n: ([(.events_count // 0), 1] | max), item: item, label: ((.scenario // "") | scen_label)} ] as $a
| ($det | map(select(.simulated // false)) | length) as $simulated
| ($a | map(.n) | add // 0) as $attempts
| ($a | map(.ip) | unique | length) as $addresses
| ($a | group_by(.ip) | map({ip: .[0].ip, cn: .[0].cn, as_name: .[0].as_name, n: (map(.n) | add), top: (group_by(.label) | map({l: .[0].label, n: (map(.n) | add)}) | sort_by(-.n) | .[0].l)}) | sort_by(-.n, .ip) | .[0:5]) as $top_ips
| ($a | group_by(.item) | map({item: .[0].item, n: (map(.n) | add), ips: (map(.ip) | unique | length)}) | sort_by(-.n, .item) | .[0:5]) as $top_items
| [ $all[] | (.decisions // [])[] | select((.simulated // false) | not) | select((.origin // "") != "CAPI" and ((.origin // "") | startswith("lists") | not)) ] as $decs
# counted per address: CrowdSec makes a decision for every alert, so one scanner can carry fifty of them
| ($decs | map(.value // "") | map(select(. != "")) | unique) as $new_vals
| ($bans | map(select((.simulated | not) and .family != "community") | .value) | unique) as $active_vals
| ($new_vals | length) as $new_bans
| ([ $new_vals[] | . as $v | select(($active_vals | index($v)) == null) ] | length) as $ended
| ($active_vals | length) as $in_force
| { attempts: $attempts, addresses: $addresses, alerts: ($a | length), simulated: $simulated, new_bans: $new_bans, ended: $ended, lifted: $lifted, in_force: $in_force, community: $community,
    top_addresses: $top_ips, top_attacks: $top_items } as $sum
| { summary: $sum,
    payload: ({ username: $s.identity.name }
      + (if $s.identity.avatar_url != "" then {avatar_url: $s.identity.avatar_url} else {} end)
      + { allowed_mentions: {parse: []},
          embeds: [ { title: ("📊 Yesterday on " + $server),
                      color: 2282478,
                      description: ((if $attempts == 0 then "A quiet day: nothing was blocked."
                                     else "**" + plural($attempts; "attempt"; "attempts") + "** blocked from **" + plural($addresses; "address"; "addresses") + "**" end)
                                    + (if $simulated > 0 then "\n" + plural($simulated; "more alert"; "more alerts") + " seen in simulation (nothing banned)" else "" end)),
                      fields: ( [ if ($top_ips | length) > 0 then {name: "Top addresses", inline: false,
                                    value: ([ $top_ips[] | "`" + .ip + "`" + (if (.cn | length) == 2 then " " + (.cn | flag_emoji) + " " + .cn else "" end) + " · " + plural(.n; "attempt"; "attempts") + " · " + .top ] | join("\n"))} else empty end,
                                  if ($top_items | length) > 0 then {name: "Top attacks", inline: false,
                                    value: ([ $top_items[] | .item + " · " + plural(.n; "attempt"; "attempts") + (if .ips > 1 then " from " + plural(.ips; "address"; "addresses") else "" end) ] | join("\n"))} else empty end,
                                  {name: "Bans", inline: false,
                                   value: ("**\($new_bans | commas)** " + (if $new_bans == 1 then "address" else "addresses" end) + " banned · **\($ended | commas)** free again · **\($lifted | commas)** lifted by hand · **\($in_force | commas)** banned now"
                                           + (if $community > 0 then "\nCommunity blocklist: " + plural($community; "address"; "addresses") else "" end))} ] | map(.value |= .[0:1024]) ),
                      footer: {text: ("CrowdSec · " + $domain + " · the last 24 hours")},
                      timestamp: ($now | todate) } ] }) }'

# hand-lifted bans in the last 24 hours, from the audit log (DCS's own unbans: one line per unban, "(n)" or "bulk: n of m")
_cs_digest_lifted() {
    local f="${API_AUTH_DIR:-$BASE_DIR/.api-auth}/auth-audit.log" since
    [[ -f "$f" ]] || { printf '0'; return; }
    since=$(date -u -d '24 hours ago' '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null) || { printf '0'; return; }
    awk -F' [|] ' -v s="$since" '$1 >= s && $3 ~ /^CROWDSEC_UNBAN *$/ {
            d = $5; n = 1
            if (match(d, /bulk: [0-9]+ of/)) { n = substr(d, RSTART + 6, RLENGTH - 9) + 0 }
            else if (match(d, /\([0-9]+\)$/)) { n = substr(d, RSTART + 1, RLENGTH - 2) + 0 }
            t += n } END { printf "%d", t + 0 }' "$f" 2>/dev/null || printf '0'
}

# _cs_digest_settings — the message identity and the webhook the summary uses: the Discord alert settings in force
_cs_digest_settings() {
    if [[ -s "$CS_NOTIFY_FILE" ]]; then _cs_notify_saved
    else
        local s="$_CS_NOTIFY_DEFAULTS"
        [[ -z "$(_cs_webhook_resolve global)" && -n "$(_cs_webhook_resolve keep)" ]] && s=$(jq -c '.webhook.mode = "keep"' <<< "$s")
        # without saved settings the alerts are on when the live profiles notify (the page shows the same)
        _cs_live_file "$CS_PROFILES_PATH" | grep -q '^[[:space:]]*-[[:space:]]*http_default' || s=$(jq -c '.enabled = false' <<< "$s")
        printf '%s' "$s"
    fi
}

# _cs_digest_build SETTINGS — the payload and the numbers (JSON {summary, payload}); 1 when CrowdSec did not answer
_cs_digest_build() {
    local s="$1" raw rows domain server
    raw=$(_cs_alerts_raw 24h) || return 1
    rows=$(_cs_decision_rows 2>/dev/null); [[ "$rows" == \[* ]] || rows='[]'
    domain=$(_find_traefik_domain 2>/dev/null); [[ -n "$domain" ]] || domain="${PROXY_DOMAIN:-DCS}"
    server="${SERVER_NAME:-}"; [[ -n "$server" ]] || server=$(hostname 2>/dev/null || echo DCS)
    jq -c --argjson s "$s" --slurpfile bans_f <(printf '%s' "$rows") --argjson lifted "$(_cs_digest_lifted)" --argjson community "$(_cs_community_count 2>/dev/null || echo 0)" \
        --arg domain "${CS_RENDER_DOMAIN:-$domain}" --arg server "${CS_RENDER_SERVER:-$server}" --argjson now "${CS_RENDER_NOW:-$(date +%s)}" \
        "$_CS_JQ_DEFS"' ($bans_f[0] // []) as $bans | '"$_CS_JQ_DIGEST" <<< "$raw"
}

# _cs_digest_record KIND JSON — remember an outcome (kind: scheduled = the day's run, manual = Send now)
_cs_digest_record() {
    local cur; cur=$(_cs_json_file "$CS_DIGEST_STATE" '{}')
    jq -c --arg k "$1" --argjson v "$2" '.[$k] = $v | .last = ($v + {kind: $k})' <<< "$cur" | _cs_json_save "$CS_DIGEST_STATE"
}

# _cs_digest_send KIND — build and post the summary. 0 = posted (delivered or not: CS_RESULT says which), 1 = not posted (CS_ERR_CODE / CS_ERR_BODY)
_cs_digest_send() {
    local kind="$1" s url built payload ok=false msg
    CS_NAME=$(_crowdsec_container) || CS_NAME=""
    [[ -n "$CS_NAME" ]] || { _cs_fail 404 "CrowdSec is not running"; return 1; }
    s=$(_cs_digest_settings)
    url=$(_cs_webhook_resolve "$(jq -r '.webhook.mode' <<< "$s")")
    [[ -n "$url" ]] || { _cs_fail 400 "There is no Discord webhook for CrowdSec: set one on the Discord tab"; return 1; }
    built=$(_cs_digest_build "$s") || { _cs_fail 502 "CrowdSec did not answer: $(_cs_errline)"; return 1; }
    payload=$(jq -c '.payload' <<< "$built")
    if _cs_discord_post "$url" "$payload"; then ok=true; fi
    msg=$(_cs_discord_explain "$CS_HTTP_CODE" "$CS_HTTP_BODY")
    CS_RESULT=$(jq -nc --argjson ok "$ok" --argjson c "${CS_HTTP_CODE:-0}" --arg m "$msg" --argjson at "$(date +%s)" --arg masked "$(_cs_webhook_mask "$url")" --argjson b "$built" \
        '{success: $ok, delivered: $ok, http: $c, message: $m, at: $at, webhook: $masked, summary: $b.summary, payload: $b.payload}')
    _cs_digest_record "$kind" "$(jq -c --arg d "$(date +%F)" '{date: $d, at, ok: .delivered, http, message, attempts: .summary.attempts, addresses: .summary.addresses}' <<< "$CS_RESULT")"
    return 0
}

# The day's run (the minute clock calls it in the background once the hour has come): sends once, tries again twice
# ten minutes apart when Discord did not take it, and notes a day it had nothing to send to
_cs_digest_scheduled() {
    local cur tries s
    cur=$(_cs_json_file "$CS_DIGEST_STATE" '{}')
    tries=$(jq -r --arg d "$(date +%F)" 'if (.scheduled.date // "") == $d then (.scheduled.tries // 0) else 0 end' <<< "$cur")
    # claimed first: the next minute's tick sees a run in progress and waits
    _cs_digest_record scheduled "$(jq -nc --arg d "$(date +%F)" --argjson at "$(date +%s)" --argjson t "$(( tries + 1 ))" '{date: $d, at: $at, ok: false, running: true, tries: $t}')"
    CS_NAME=$(_crowdsec_container) || CS_NAME=""
    s=""; [[ -n "$CS_NAME" ]] && s=$(_cs_digest_settings)
    if [[ -z "$CS_NAME" || "$(jq -r '.enabled' <<< "$s")" != true ]]; then
        _cs_digest_record scheduled "$(jq -nc --arg d "$(date +%F)" --argjson at "$(date +%s)" --arg why "$([[ -z "$CS_NAME" ]] && echo 'CrowdSec is not running' || echo 'the Discord alerts are off')" \
            '{date: $d, at: $at, ok: false, skipped: true, message: ("Not sent: " + $why)}')"
        return 0
    fi
    if _cs_digest_send scheduled; then
        jq -c --argjson t "$(( tries + 1 ))" '.scheduled.tries = $t' <<< "$(_cs_json_file "$CS_DIGEST_STATE" '{}')" | _cs_json_save "$CS_DIGEST_STATE"
    else
        _cs_digest_record scheduled "$(jq -nc --arg d "$(date +%F)" --argjson at "$(date +%s)" --argjson t "$(( tries + 1 ))" --arg m "$(jq -r '.message // "not sent"' <<< "$CS_ERR_BODY" 2>/dev/null)" \
            '{date: $d, at: $at, ok: false, tries: $t, message: $m}')"
    fi
    return 0
}

# The summary as the Discord tab shows it
_cs_digest_view() {
    local hour; hour=$(_cs_digest_hour)
    jq -nc --arg h "$hour" --argjson def "$CS_DIGEST_DEFAULT_HOUR" --argjson st "$(_cs_json_file "$CS_DIGEST_STATE" '{}')" --arg today "$(date +%F)" --argjson nowh "$(( 10#$(date +%H) ))" --arg tz "$(date +%Z)" '
        { enabled: ($h != "off"), hour: (if $h == "off" then null else ($h | tonumber) end), default_hour: $def, timezone: $tz, setting: "CROWDSEC_DIGEST_HOUR",
          sent_today: (($st.scheduled.date // "") == $today and ($st.scheduled.ok // false)),
          next: (if $h == "off" then null elif ($st.scheduled.date // "") == $today then "tomorrow" elif $nowh >= ($h | tonumber) then "soon" else "today" end),
          scheduled: ($st.scheduled // null), last: ($st.last // null),
          note: "One message a day with the last 24 hours, to the webhook of the CrowdSec alerts, while those are on." }'
}

# POST /crowdsec/notifications/digest — Send the daily summary (the last 24 hours) to Discord now, whatever the hour; answers what Discord said and the numbers
handle_crowdsec_digest_send() {
    _api_check_admin || { _api_error 403 "Admin access required"; return; }
    if _cs_digest_send manual; then
        _api_audit_log "${CLIENT_IP:-unknown}" "CROWDSEC_DIGEST" "${AUTH_USERNAME:-}" "sent now: HTTP $CS_HTTP_CODE"
        _api_success "$(jq -c --argjson d "$(_cs_digest_view)" '. + {digest: $d}' <<< "$CS_RESULT")"
    else _api_response "$CS_ERR_CODE" "$CS_ERR_BODY"; fi
}

# PUT /crowdsec/notifications/digest — When the daily summary goes out: {hour: 0-23} or {hour: "off"} (CROWDSEC_DIGEST_HOUR in .env, local time)
handle_crowdsec_digest_set() {
    _api_check_admin || { _api_error 403 "Admin access required"; return; }
    local body="$1" raw h
    [[ "$body" == \{* ]] && jq -e 'type == "object" and has("hour")' >/dev/null 2>&1 <<< "$body" || { _api_error 400 "Send {\"hour\": 8} (0-23) or {\"hour\": \"off\"}"; return; }
    raw=$(jq -r '.hour | if . == null or . == false then "off" else tostring end' <<< "$body")
    h=$(_cs_digest_hour_of "$raw")
    [[ -n "$h" && "$raw" =~ ^([0-9]{1,2}|off|OFF|Off)$ ]] || { _api_error 400 "hour must be a whole number from 0 to 23, or off"; return; }
    _envfile_set "$BASE_DIR/.env" CROWDSEC_DIGEST_HOUR "$h" bash || { _api_error 500 "Could not write .env"; return; }
    export CROWDSEC_DIGEST_HOUR="$h"
    _api_audit_log "${CLIENT_IP:-unknown}" "CROWDSEC_DIGEST" "${AUTH_USERNAME:-}" "hour: $h"
    _api_success "$(jq -c '. + {success: true}' <<< "$(_cs_digest_view)")"
}

# =============================================================================
# The Traefik bouncer plugin's own settings (the middleware file)
#
# DCS wrote crowdsec-bouncer.yml when it registered the bouncer. The page edits a safe subset of the plugin's options in place:
# the mode, how often it asks, how long it remembers, the timeout, the status a banned visitor sees, the log level and the two lists of
# addresses (visitors that are never checked; proxies whose forwarded address is believed). The file keeps the key and everything else it
# had; a marker line names what the page saved, so registering the bouncer again writes the same settings into the fresh file. The write
# is atomic, the old file is kept, and Traefik's file provider picks the change up by itself (.reload is touched as the route writers do).
# =============================================================================

CS_PLUGIN_STATE="$CROWDSEC_STATE_DIR/plugin.json"
CS_PLUGIN_LOCK="$CROWDSEC_STATE_DIR/plugin.lock"
_CS_PLUGIN_DEFAULTS='{"mode":"live","update_interval":60,"default_decision_seconds":10,"http_timeout":10,"remediation_status_code":403,"log_level":"INFO","trust_home":true,"client_trusted_ips":[],"forwarded_headers_trusted_ips":[]}'
# the proxies in front of Traefik that the shipped middleware believes (Cloudflare's published ranges)
_CS_PLUGIN_CDN='["173.245.48.0/20","103.21.244.0/22","103.22.200.0/22","103.31.4.0/22","141.101.64.0/18","108.162.192.0/18","190.93.240.0/20","188.114.96.0/20","197.234.240.0/22","198.41.128.0/17","162.158.0.0/15","104.16.0.0/13","104.24.0.0/14","172.64.0.0/13","131.0.72.0/22","2400:cb00::/32","2606:4700::/32","2803:f800::/32","2405:b500::/32","2405:8100::/32","2a06:98c0::/29","2c0f:f248::/32"]'
_CS_PLUGIN_LIMITS='{"update_interval":[10,3600],"default_decision_seconds":[10,3600],"http_timeout":[1,60],"remediation_status_code":[400,599],"list_max":64,"forwarded_max":128}'

# the LAN Traefik trusts (TRAEFIK_TRUSTED_LAN of the proxy's stack), or the default the template uses
_cs_plugin_lan() {
    local lan="" ef t
    for ef in "$COMPOSE_DIR"/*/.env "$BASE_DIR/.env"; do
        [[ -f "$ef" ]] || continue
        lan=$(grep -m1 '^TRAEFIK_TRUSTED_LAN=' "$ef" 2>/dev/null | cut -d= -f2- | tr -d '"' | tr -d "'"); [[ -n "$lan" ]] && break
    done
    # it is written into the middleware file as a list entry: only an address or a network may go there (a hand-edited .env must not be able to break that file)
    if [[ -n "$lan" ]] && t=$(_cs_norm_target "$lan"); then lan="${t#*$'\t'}"; else lan="192.168.1.0/24"; fi
    printf '%s' "$lan"
}
_cs_plugin_home() {
    local ip=""
    [[ -f "$CROWDSEC_SYNC_STATE" ]] && ip=$(jq -r '.public_ip // ""' "$CROWDSEC_SYNC_STATE" 2>/dev/null)
    _crowdsec_valid_ip "$ip" && printf '%s' "$ip"
    return 0
}

# _cs_plugin_list_ok JSON_ARRAY MAX — every entry an address or a network, none so wide that nothing would be checked (or believed). The normalised array is CS_LIST_OUT; return 1 with CS_CFG_ERR set.
CS_LIST_OUT="[]"
_cs_plugin_list_ok() {
    local in="$1" max="$2" v t bits entries=() n=0
    [[ "$(jq -r 'type' <<< "$in" 2>/dev/null)" == array ]] || { CS_CFG_ERR="must be a list of addresses or networks"; return 1; }
    while IFS= read -r v; do
        [[ -n "$v" ]] || continue
        n=$(( n + 1 )); (( n <= max )) || { CS_CFG_ERR="at most $max entries"; return 1; }
        t=$(_cs_norm_target "$v") || { CS_CFG_ERR="not an IP address or network: ${v:0:60}"; return 1; }
        v="${t#*$'\t'}"
        if [[ "$v" == */* ]]; then
            bits="${v#*/}"
            if { _cs_is_v4 "${v%%/*}" && (( bits < 8 )); } || { ! _cs_is_v4 "${v%%/*}" && (( bits < 16 )); }; then CS_CFG_ERR="$v is far too wide a network"; return 1; fi
        fi
        entries+=("$v")
    done < <(jq -r '.[] | tostring' <<< "$in")
    if (( ${#entries[@]} )); then CS_LIST_OUT=$(printf '%s\n' "${entries[@]}" | awk 'NF && !seen[$0]++' | jq -Rsc 'split("\n") | map(select(length > 0))'); else CS_LIST_OUT="[]"; fi
}

# _cs_plugin_validate SETTINGS_JSON — the merged, normalised settings in CS_PLUGIN_OUT; returns 1 with CS_CFG_ERR set
CS_PLUGIN_OUT="{}"
_cs_plugin_validate() {
    local s="$1" k v lo hi
    jq -e 'type == "object"' >/dev/null 2>&1 <<< "$s" || { CS_CFG_ERR="settings must be an object"; return 1; }
    for k in $(jq -r 'keys[]' <<< "$s"); do
        case "$k" in mode|update_interval|default_decision_seconds|http_timeout|remediation_status_code|log_level|trust_home|client_trusted_ips|forwarded_headers_trusted_ips) ;;
            *) CS_CFG_ERR="unknown setting: ${k:0:40}"; return 1 ;; esac
    done
    v=$(jq -r '.mode | tostring' <<< "$s"); [[ "$v" == live || "$v" == stream ]] || { CS_CFG_ERR="mode must be live or stream"; return 1; }
    v=$(jq -r '.log_level | tostring' <<< "$s"); [[ "$v" =~ ^(DEBUG|INFO|WARN|ERROR)$ ]] || { CS_CFG_ERR="log_level must be DEBUG, INFO, WARN or ERROR"; return 1; }
    jq -e '.trust_home | type == "boolean"' >/dev/null 2>&1 <<< "$s" || { CS_CFG_ERR="trust_home must be true or false"; return 1; }
    for k in update_interval default_decision_seconds http_timeout remediation_status_code; do
        v=$(jq -r --arg k "$k" '.[$k] | if type == "number" and . == floor then tostring else "x" end' <<< "$s")
        [[ "$v" =~ ^[0-9]{1,5}$ ]] || { CS_CFG_ERR="$k must be a whole number"; return 1; }
        lo=$(jq -r --arg k "$k" '.[$k][0]' <<< "$_CS_PLUGIN_LIMITS"); hi=$(jq -r --arg k "$k" '.[$k][1]' <<< "$_CS_PLUGIN_LIMITS")
        (( v >= lo && v <= hi )) || { CS_CFG_ERR="$k must be between $lo and $hi"; return 1; }
    done
    _cs_plugin_list_ok "$(jq -c '.client_trusted_ips' <<< "$s")" 64 || { CS_CFG_ERR="client_trusted_ips: $CS_CFG_ERR"; return 1; }
    s=$(jq -c --argjson l "$CS_LIST_OUT" '.client_trusted_ips = $l' <<< "$s")
    _cs_plugin_list_ok "$(jq -c '.forwarded_headers_trusted_ips' <<< "$s")" 128 || { CS_CFG_ERR="forwarded_headers_trusted_ips: $CS_CFG_ERR"; return 1; }
    CS_PLUGIN_OUT=$(jq -c --argjson l "$CS_LIST_OUT" '.forwarded_headers_trusted_ips = $l' <<< "$s")
}

# _cs_plugin_render FILE SETTINGS_JSON HOME — the middleware file's new text (stdout): the managed keys are written afresh right under the plugin's name, everything else stays.
# SETTINGS holds the lists as the person keeps them; the LAN and, when trust_home is on, the home address are added to the file's client list here.
_cs_plugin_render() {
    local f="$1" s="$2" home="$3" lan cl keys marker
    lan=$(_cs_plugin_lan)
    cl=$(jq -c --arg home "$home" --arg lan "$lan" '(.client_trusted_ips + [$lan] + (if .trust_home and $home != "" then [$home] else [] end)) | map(select(. != "")) | unique' <<< "$s")
    s=$(jq -c --arg lan "$lan" '.forwarded_headers_trusted_ips = ((.forwarded_headers_trusted_ips + [$lan]) | map(select(. != "")) | unique)' <<< "$s")
    keys=$(jq -r --argjson cl "$cl" '
        "          crowdsecMode: \(.mode)",
        "          updateIntervalSeconds: \(.update_interval)",
        "          defaultDecisionSeconds: \(.default_decision_seconds)",
        "          httpTimeoutSeconds: \(.http_timeout)",
        "          remediationStatusCode: \(.remediation_status_code)",
        "          logLevel: \(.log_level)",
        "          forwardedHeadersTrustedIPs:",
        (.forwarded_headers_trusted_ips[] | "            - " + .),
        "          clientTrustedIPs:",
        ($cl[] | "            - " + .)' <<< "$s")
    marker="# dcs-plugin: $(jq -c '{v: 1, settings: .}' <<< "$s")"
    # (the ten-column indent is spelled out: mawk 1.3.4 20240123, Ubuntu 24.04's awk, panics on an interval followed by a
    # group, "^[ \t]{10}(a|b)", and every save of the plugin settings failed there)
    NEWKEYS="$keys" MARKER="$marker" awk '
        BEGIN { skip = 0; placed = 0; inplug = 0; hdr = 0; i10 = "^[ \t][ \t][ \t][ \t][ \t][ \t][ \t][ \t][ \t][ \t]" }
        /^#[ \t]*dcs-plugin:[ \t]/ { next }
        !hdr { print ENVIRON["MARKER"]; hdr = 1 }
        /^[ \t]+plugin:[ \t]*$/ { inplug = 1; print; next }
        inplug && !placed && /^[ \t]{8}[A-Za-z0-9_.-]+:[ \t]*$/ { print; print ENVIRON["NEWKEYS"]; placed = 1; next }
        placed && $0 ~ (i10 "(crowdsecMode|updateIntervalSeconds|defaultDecisionSeconds|httpTimeoutSeconds|remediationStatusCode|logLevel):") { skip = 0; next }
        placed && $0 ~ (i10 "(forwardedHeadersTrustedIPs|clientTrustedIPs):[ \t]*$") { skip = 1; next }
        skip && /^[ \t]{12}-/ { next }
        { skip = 0; print }' "$f"
}

# the settings the page shows: what the file says, with the person's own lists (the LAN and the home address are shown apart, not in them)
_cs_plugin_current() {
    local f="$1" file saved lan home cur
    file=$(_cs_plugin_read_file "$f"); saved=$(_cs_json_file "$CS_PLUGIN_STATE" '{}'); lan=$(_cs_plugin_lan); home=$(_cs_plugin_home)
    jq -nc --argjson file "$file" --argjson saved "$saved" --argjson d "$_CS_PLUGIN_DEFAULTS" --argjson cdn "$_CS_PLUGIN_CDN" --arg lan "$lan" --arg home "$home" '
        ($file.client_trusted_ips // []) as $fc
        | { mode: ($file.mode // $d.mode), update_interval: ($file.update_interval // $d.update_interval), default_decision_seconds: ($file.default_decision_seconds // $d.default_decision_seconds),
            http_timeout: ($file.http_timeout // $d.http_timeout), remediation_status_code: ($file.remediation_status_code // $d.remediation_status_code), log_level: ($file.log_level // $d.log_level),
            trust_home: (if ($saved.settings.trust_home // null) != null then $saved.settings.trust_home else ($home != "" and ($fc | index($home)) != null) end),
            client_trusted_ips: ($fc | map(select(. != $lan and . != $home))),
            forwarded_headers_trusted_ips: (($file.forwarded_headers_trusted_ips // $cdn) | map(select(. != $lan))) }'
}

# the plugin's settings, the defaults and the limits as one JSON object
_cs_plugin_view() {
    local enf f cur lan home
    _cs_probe
    enf=$(_cs_enforcement_json); f=$(jq -r '.middleware_file' <<< "$enf")
    lan=$(_cs_plugin_lan); home=$(_cs_plugin_home)
    if [[ -z "$f" ]]; then
        jq -nc --argjson enf "$enf" '{available: false, reason: (if $enf.routes_dir == "" then "Traefik was not found on this server, so there is no bouncer plugin to set up." else "The Traefik bouncer is not registered yet: register it first." end), plugin: $enf.plugin}'
        return
    fi
    cur=$(_cs_plugin_current "$f")
    jq -nc --argjson enf "$enf" --argjson cur "$cur" --argjson d "$_CS_PLUGIN_DEFAULTS" --argjson cdn "$_CS_PLUGIN_CDN" --argjson lim "$_CS_PLUGIN_LIMITS" --arg lan "$lan" --arg home "$home" --argjson backups "$(_cs_plugin_backups_json)" '
        { available: true, file: $enf.middleware_file, managed: $enf.plugin.managed, plugin: $enf.plugin, settings: $cur,
          defaults: ($d | .forwarded_headers_trusted_ips = $cdn), limits: $lim, lan: $lan, home: $home, backups: $backups,
          help: {
            mode: "live: Traefik asks CrowdSec about a visitor the first time it sees one and remembers the answer for a short while. stream: Traefik downloads the whole ban list every few seconds and decides on its own. Live is simplest; stream saves a round trip per new visitor and keeps working for a while if CrowdSec is down.",
            update_interval: "Stream mode only: how often Traefik downloads the ban list. A new ban reaches the door this many seconds later.",
            default_decision_seconds: "Live mode only: how long a clean verdict is cached. Shorter means a new ban bites faster (and a lifted one is noticed sooner), at the price of one more question to CrowdSec per visitor and window. DCS sets 10 seconds; installs from before keep what they have.",
            http_timeout: "How long Traefik waits for CrowdSec before it gives up on one question.",
            remediation_status_code: "The HTTP status a banned visitor gets. 403 (forbidden) is the usual one; 429 tells well-behaved clients to slow down.",
            log_level: "How much the plugin writes in Traefik'"'"'s log.",
            client_trusted_ips: "Visitors that are never checked at all: your LAN and VPN. The LAN of your Traefik and, when switched on, your home address are always in.",
            forwarded_headers_trusted_ips: "Proxies in front of Traefik (a CDN such as Cloudflare) whose \"forwarded for\" address is believed. Behind none, leave the CDN ranges: a visitor cannot fake them."
          } }'
}

# GET /crowdsec/plugin — The Traefik bouncer plugin's settings (mode, how often it asks, how long it remembers, timeout, the status a banned visitor sees, trusted networks), the defaults and the limits
handle_crowdsec_plugin() { _api_success "$(_cs_plugin_view)"; }

# the kept copies of the middleware file (they hold the bouncer key: private)
_cs_plugin_backups_json() {
    local f n
    [[ -d "$CS_BACKUP_DIR" ]] || { printf '[]'; return; }
    for f in "$CS_BACKUP_DIR"/plugin-*.yml; do
        [[ -f "$f" ]] || continue
        n="${f##*/}"
        jq -nc --arg n "$n" --arg t "${n#plugin-}" --argjson s "$(stat -c %s "$f" 2>/dev/null || echo 0)" '{name: $n, created_at: ($t | sub("\\.yml$"; "") | sub("^(?<d>[0-9]{4})(?<m>[0-9]{2})(?<dd>[0-9]{2})T(?<h>[0-9]{2})(?<mi>[0-9]{2})(?<s>[0-9]{2})Z(-[0-9]+)?$"; "\(.d)-\(.m)-\(.dd)T\(.h):\(.mi):\(.s)Z")), size: $s}'
    done | jq -sc 'sort_by(.created_at) | reverse | .[0:10]'
}

# _cs_plugin_write FILE SETTINGS_JSON — render, write atomically (Traefik'"'"'s file provider watches the directory: the temporary name is not a config), keep the old file, verify by reading back; touches .reload
# Return 0 changed, 4 unchanged, 1 failed (CS_CFG_ERR)
_cs_plugin_write() {
    local f="$1" s="$2" home new tmp bak ts dir
    home=$(_cs_plugin_home)
    new=$(_cs_plugin_render "$f" "$s" "$home") || { CS_CFG_ERR="could not build the new middleware file"; return 1; }
    [[ "$new" == *"crowdsecLapiKey:"* && "$new" == *"plugin:"* ]] || { CS_CFG_ERR="the middleware file does not look like the bouncer's; nothing was changed"; return 1; }
    if [[ "$new"$'\n' == "$(cat "$f")"$'\n' ]]; then return 4; fi
    ts=$(date -u +%Y%m%dT%H%M%SZ); dir="${f%/*}"
    mkdir -p "$CS_BACKUP_DIR" 2>/dev/null; chmod 700 "$CS_BACKUP_DIR" 2>/dev/null
    bak="$CS_BACKUP_DIR/plugin-$ts.yml"
    local n=1; while [[ -e "$bak" ]]; do n=$(( n + 1 )); bak="$CS_BACKUP_DIR/plugin-$ts-$n.yml"; done
    ( umask 077; cp -p "$f" "$bak" ) 2>/dev/null || { CS_CFG_ERR="could not keep a copy of the current file"; return 1; }
    tmp="$f.dcs-new"
    ( umask 077; printf '%s\n' "$new" > "$tmp" ) || { CS_CFG_ERR="could not write the new file"; return 1; }
    chmod 600 "$tmp" 2>/dev/null
    mv -f "$tmp" "$f" || { rm -f "$tmp"; CS_CFG_ERR="could not replace the middleware file"; return 1; }
    # read back: what the file says now is what was asked
    if [[ "$(_cs_plugin_read_file "$f" | jq -c '{mode, update_interval, default_decision_seconds, http_timeout, remediation_status_code, log_level}')" != "$(jq -c '{mode, update_interval, default_decision_seconds, http_timeout, remediation_status_code, log_level}' <<< "$s")" ]]; then
        cp -p "$bak" "$f" 2>/dev/null; rm -f "$bak"; CS_CFG_ERR="the file did not read back as written; the previous file was put back"; return 1
    fi
    touch "$dir/.reload" 2>/dev/null; touch "${dir%/*}/.reload" 2>/dev/null || true
    ls -1t "$CS_BACKUP_DIR"/plugin-*.yml 2>/dev/null | tail -n +11 | while IFS= read -r old; do rm -f "$old"; done
    CS_PLUGIN_BACKUP="${bak##*/}"
    return 0
}

# PUT /crowdsec/plugin — Change the plugin's settings: {settings: {mode, update_interval, default_decision_seconds, http_timeout, remediation_status_code, log_level, trust_home, client_trusted_ips, forwarded_headers_trusted_ips}} (any part); written to Traefik's middleware file atomically, the old one is kept, Traefik reloads by itself
handle_crowdsec_plugin_set() {
    _api_check_admin || { _api_error 403 "Admin access required"; return; }
    local body="$1" enf f cur merged rc msg
    [[ "$body" == \{* ]] && jq -e 'type == "object"' >/dev/null 2>&1 <<< "$body" || { _api_error 400 "Send a JSON body: {\"settings\": {\"mode\": \"stream\"}}"; return; }
    enf=$(_cs_enforcement_json); f=$(jq -r '.middleware_file' <<< "$enf")
    [[ -n "$f" ]] || { _api_error 409 "The Traefik bouncer is not registered yet: register it first, then its settings can be changed."; return; }
    cur=$(_cs_plugin_current "$f")
    merged=$(jq -c --argjson c "$cur" '$c + (.settings // {})' <<< "$body")
    _cs_plugin_validate "$merged" || { _api_response 400 "$(jq -nc --arg m "$CS_CFG_ERR" '{error: true, code: 400, reason: "invalid", message: $m}')"; return; }
    merged="$CS_PLUGIN_OUT"
    mkdir -p "$CROWDSEC_STATE_DIR" 2>/dev/null
    exec 8> "$CS_PLUGIN_LOCK" 2>/dev/null
    flock -w 8 8 || { _api_error 409 "Another change to the bouncer settings is running. Try again in a moment."; return; }
    _cs_plugin_write "$f" "$merged"; rc=$?
    flock -u 8 2>/dev/null; exec 8>&- 2>/dev/null
    if (( rc == 1 )); then _api_response 500 "$(jq -nc --arg m "$CS_CFG_ERR" '{error: true, code: 500, reason: "write_failed", message: $m}')"; return; fi
    if (( rc == 0 )); then
        printf '%s' "$(jq -nc --argjson s "$merged" '{v: 1, settings: $s}')" | _cs_json_save "$CS_PLUGIN_STATE"
        _api_audit_log "${CLIENT_IP:-unknown}" "CROWDSEC_PLUGIN" "${AUTH_USERNAME:-}" "$(jq -c '{mode, update_interval, default_decision_seconds, http_timeout, remediation_status_code, log_level, trust_home}' <<< "$merged")"
        msg="Saved. Traefik reloads the middleware by itself within a few seconds."
    else
        msg="Nothing changed."
    fi
    _cs_cache_clear
    _api_success "$(_cs_plugin_view | jq -c --argjson ch "$([[ $rc == 0 ]] && echo true || echo false)" --arg m "$msg" --arg b "${CS_PLUGIN_BACKUP:-}" '. + {success: true, applied: {changed: $ch, message: $m, backup: (if $b == "" then null else $b end)}}')"
}

# _cs_plugin_apply_saved FILE — registering the bouncer wrote a fresh middleware file from the template: put the settings the page saved back into it (the key stays the new one)
_cs_plugin_apply_saved() {
    local f="$1" saved s new home
    [[ -s "$CS_PLUGIN_STATE" && -f "$f" ]] || return 0
    saved=$(_cs_json_file "$CS_PLUGIN_STATE" '{}'); s=$(jq -c '.settings // empty' <<< "$saved"); [[ -n "$s" ]] || return 0
    _cs_plugin_validate "$(jq -c --argjson d "$_CS_PLUGIN_DEFAULTS" '$d + .' <<< "$s")" || return 0
    s="$CS_PLUGIN_OUT"
    home=$(_cs_plugin_home)
    new=$(_cs_plugin_render "$f" "$s" "$home") || return 0
    [[ "$new" == *"crowdsecLapiKey:"* ]] || return 0
    ( umask 077; printf '%s\n' "$new" > "$f.dcs-new" ) && chmod 600 "$f.dcs-new" && mv -f "$f.dcs-new" "$f"
}

# _cs_plugin_sync_home — the home address changed: the client list of the plugin follows it (when the page manages the settings and trust_home is on)
_cs_plugin_sync_home() {
    local enf f cur
    [[ -s "$CS_PLUGIN_STATE" ]] || return 0
    [[ "$(jq -r '.settings.trust_home // false' "$CS_PLUGIN_STATE" 2>/dev/null)" == true ]] || return 0
    enf=$(_cs_enforcement_json); f=$(jq -r '.middleware_file' <<< "$enf"); [[ -n "$f" ]] || return 0
    cur=$(_cs_json_file "$CS_PLUGIN_STATE" '{}'); cur=$(jq -c --argjson d "$_CS_PLUGIN_DEFAULTS" '$d + .settings' <<< "$cur")
    _cs_plugin_write "$f" "$cur" >/dev/null 2>&1 || true
}
