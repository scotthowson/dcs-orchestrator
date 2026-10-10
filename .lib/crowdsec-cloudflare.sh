#!/bin/bash
# shellcheck shell=bash
# =============================================================================
# Push bans to Cloudflare — CrowdSec's bans refused at Cloudflare's edge
#
# What it does: a bouncer of CrowdSec (dcs-cloudflare-bouncer, registered like
# the Traefik one) whose ban list DCS keeps in ONE Cloudflare IP list per
# account (dcs_crowdsec_bans), and one WAF custom rule per zone that blocks
# every address on it ("ip.src in $dcs_crowdsec_bans", action block, the first
# custom rule of the zone). A scanner CrowdSec banned is then refused by
# Cloudflare before its request is forwarded: it no longer reaches Traefik and
# no longer feeds CrowdSec new detections.
#
# Why not CrowdSec's own Cloudflare bouncers: crowdsecurity/cloudflare-bouncer
# (the IP-list one) is archived and CrowdSec marks it deprecated; it writes
# Cloudflare's Firewall Rules and Filters APIs, which Cloudflare stopped
# supporting on 2025-06-15. Its successor (cloudflare-worker-bouncer) puts a
# Worker in front of every request: on the free plan that is 100,000 requests a
# day (1,000 a minute), its routes are created "fail closed" (a scanner that
# burns the quota takes the sites down with error 1027) and there is no API to
# change that. The list + WAF rule here costs no quota, adds no latency and
# keeps working whatever the traffic. DCS keeps it in sync with the current
# Cloudflare APIs (Lists, Rulesets).
#
# How: every CLOUDFLARE_BOUNCER_INTERVAL seconds (30) the API's background
# loop asks CrowdSec's local API, with the bouncer's own key, for the active
# bans (GET /v1/decisions?type=ban&scopes=ip,range&origins=…: CrowdSec records
# the pull), turns them into the list's items (the newest first, at most
# CLOUDFLARE_BOUNCER_CAPACITY, never a private address or one the ban guard
# protects), and replaces the list's items when, and only when, they changed.
# Every 5 minutes it also reads the list and the rules back from Cloudflare
# and repairs what was changed or deleted there. Nothing is pushed while
# CrowdSec cannot be asked: the list keeps the last bans.
#
# The token (CLOUDFLARE_BOUNCER_TOKEN) is its own setting, never the DNS
# token; it lives in the secrets store (encrypted, 600) and reaches curl on
# its standard input, never on a command line, in a log or an answer.
#
# Loaded on demand (_crowdsec_cf_lib in api-server.sh), after .lib/crowdsec.sh.
# =============================================================================

# shellcheck disable=SC2034  # read by the router (_crowdsec_cf_lib in api-server.sh)
CROWDSEC_CF_LOADED=1
CFB_NAME="dcs-cloudflare-bouncer"
CFB_LIST="dcs_crowdsec_bans"
CFB_REF="dcs_crowdsec_bans"
CFB_PHASE="http_request_firewall_custom"
CFB_SECRET="CLOUDFLARE_BOUNCER_TOKEN"
CFB_STATE="$CROWDSEC_STATE_DIR/cloudflare.json"
CFB_ITEMS="$CROWDSEC_STATE_DIR/cloudflare-items.json"
CFB_KEY_FILE="$CROWDSEC_STATE_DIR/cloudflare-bouncer.key"
# one sync (or one turning on or off) at a time: a directory made atomically, its owner ("PID EPOCH KIND START") inside. Not flock(1):
# a flock stays held while any process keeps the descriptor open (the sync's children inherit it), says nothing about who, and on a
# server the loop found it held on every try and never synced again
CFB_LOCK="$CROWDSEC_STATE_DIR/.cloudflare.lock.d"
CFB_STAMP="$CROWDSEC_STATE_DIR/.cloudflare.stamp"
# how long the lock may be held before the next taker stops its holder (a sync) or takes it over (a request); what the lock and the
# loop say goes to the API's log
CFB_STUCK_AFTER=600
# Cloudflare said "slow down" during this sync (a file: the token checks run in a subshell); the waits after such an answer (2, 5, then
# 15 minutes); the least time between two replacements of the list's items
CFB_RL_MARK="$CROWDSEC_STATE_DIR/.cloudflare.ratelimited"
CFB_BACKOFF=(120 300 900)
CFB_PUSH_GAP=60   # CLOUDFLARE_BOUNCER_PUSH_GAP overrides it (0-600 s)
CFB_LOG="${API_LOG_FILE:-$BASE_DIR/logs/api-server.log}"
# the origins of CrowdSec's own bans (its scenarios, the page, an import, the console) and of the community's
CFB_LOCAL_ORIGINS="crowdsec,cscli,cscli-import,console"
CFB_COMMUNITY_ORIGINS="CAPI,lists"
# how often the list and the rules are read back from Cloudflare, and when a sync that has not succeeded is a problem
CFB_VERIFY_EVERY=300
CFB_STALE_AFTER=600
# what a free plan allows (an account's limits follow its highest plan): custom lists, items over all of them, WAF custom rules per zone
CFB_FREE_LISTS=1
CFB_FREE_ITEMS=10000
CFB_FREE_RULES=5
# the rights the token needs, as Cloudflare's token page names them
CFB_PERMS='[{"group":"Account","item":"Account Filter Lists","level":"Edit","why":"keeps the list of banned addresses"},
{"group":"Zone","item":"Zone WAF","level":"Edit","why":"adds the custom rule that blocks the list"},
{"group":"Zone","item":"Zone","level":"Read","why":"finds the zones of your domains"}]'
CFB_RULE_DESC="DCS Orchestrator: block CrowdSec bans (kept by DCS; turn it off on the CrowdSec page)"

# a sentence the status answer carries once (Sync now within the minute)
CFB_STATUS_MESSAGE=""
# per call: the token, the last Cloudflare answer, the last error
CFB_TOKEN=""; CFB_TOKEN_SOURCE=""; CFB_CODE="000"; CFB_BODY=""; CFB_ERR_CODE=""; CFB_ERR=""

# =============================================================================
# Settings (read from .env on every call: the background loop and the requests see the same thing)
# =============================================================================

_cfb_setting() {
    local v
    v=$(envfile_get "$BASE_DIR/.env" "$1" 2>/dev/null)
    [[ -n "$v" ]] && printf '%s' "$v" || printf '%s' "${2:-}"
}
_cfb_enabled() { [[ "$(_cfb_setting CLOUDFLARE_BOUNCER_ENABLED false)" == true ]]; }
_cfb_capacity() { local c; c=$(_cfb_setting CLOUDFLARE_BOUNCER_CAPACITY "$CFB_FREE_ITEMS"); [[ "$c" =~ ^[0-9]{1,6}$ ]] && (( c >= 1 && c <= 500000 )) || c=$CFB_FREE_ITEMS; printf '%d' "$((10#$c))"; }
_cfb_community() { [[ "$(_cfb_setting CLOUDFLARE_BOUNCER_COMMUNITY false)" == true ]]; }
_cfb_interval() { local i; i=$(_cfb_setting CLOUDFLARE_BOUNCER_INTERVAL 30); [[ "$i" =~ ^[0-9]{1,4}$ ]] && (( i >= 10 && i <= 3600 )) || i=30; printf '%d' "$((10#$i))"; }
_cfb_push_gap() { local g; g=$(_cfb_setting CLOUDFLARE_BOUNCER_PUSH_GAP "$CFB_PUSH_GAP"); [[ "$g" =~ ^[0-9]{1,3}$ ]] && (( 10#$g <= 600 )) || g=$CFB_PUSH_GAP; printf '%d' "$((10#$g))"; }
_cfb_origins() { if _cfb_community; then printf '%s,%s' "$CFB_LOCAL_ORIGINS" "$CFB_COMMUNITY_ORIGINS"; else printf '%s' "$CFB_LOCAL_ORIGINS"; fi; }

# the domains whose zones are protected: CLOUDFLARE_BOUNCER_DOMAINS when set, else every domain of this server (PROXY_DOMAIN and PROXY_DOMAINS_EXTRA)
_cfb_domains() {
    local v d
    v=$(_cfb_setting CLOUDFLARE_BOUNCER_DOMAINS "")
    if [[ -n "$v" ]]; then
        for d in ${v//,/ }; do d="${d,,}"; _domain_valid "$d" && printf '%s\n' "$d"; done | awk '!s[$0]++'
    else
        _domains_all 2>/dev/null
    fi
}

# CFB_TOKEN and CFB_TOKEN_SOURCE (secret | env): the secret first, then CLOUDFLARE_BOUNCER_TOKEN in the root .env (a ${SECRETS_X} reference resolved)
_cfb_token_load() {
    CFB_TOKEN=""; CFB_TOKEN_SOURCE=""
    CFB_TOKEN=$(secrets_get "$CFB_SECRET" 2>/dev/null) || CFB_TOKEN=""
    if [[ -n "$CFB_TOKEN" ]]; then CFB_TOKEN_SOURCE=secret; return 0; fi
    CFB_TOKEN=$(_cf_resolve_value "$(envfile_get "$BASE_DIR/.env" "$CFB_SECRET" 2>/dev/null)")
    [[ -n "$CFB_TOKEN" ]] && CFB_TOKEN_SOURCE="env"
    return 0
}

# A Cloudflare API token: 40 characters today; letters, digits, - and _ (anything else could not travel in curl's config line)
_cfb_token_ok() { local LC_ALL=C; [[ "$1" =~ ^[A-Za-z0-9_-]{30,200}$ ]]; }

# =============================================================================
# Talking to Cloudflare and to CrowdSec's local API
# =============================================================================

# Cloudflare's API (tests point CF_API_BASE at a stand-in on loopback; anything else must be https)
_cfb_api_base() {
    local b="${CF_API_BASE:-https://api.cloudflare.com/client/v4}"
    b="${b%/}"
    if [[ "$b" =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._/-]*)?$ || "$b" =~ ^http://(127\.0\.0\.1|localhost|\[::1\])(:[0-9]{1,5})?(/[A-Za-z0-9._/-]*)?$ ]]; then
        printf '%s' "$b"; return 0
    fi
    return 1
}

# _cfb_cf METHOD PATH [BODY_FILE] — one call with CFB_TOKEN. Sets CFB_CODE (000 when nothing answered) and CFB_BODY.
# The token goes to curl on its standard input (a config line), never on its command line.
_cfb_cf() {
    local m="$1" p="$2" bf="${3:-}" base raw
    CFB_CODE="000"; CFB_BODY=""
    base=$(_cfb_api_base) || { CFB_BODY='{"success":false,"errors":[{"code":0,"message":"CF_API_BASE is not an https:// address"}]}'; return 1; }
    _cfb_token_ok "$CFB_TOKEN" || { CFB_BODY='{"success":false,"errors":[{"code":0,"message":"no usable token"}]}'; return 1; }
    local -a args=(-s --max-time "${CFB_HTTP_TIMEOUT:-30}" -X "$m" -K - -H 'Accept: application/json' -w $'\n%{http_code}')
    [[ -n "$bf" ]] && args+=(-H 'Content-Type: application/json' --data-binary "@$bf")
    raw=$(printf 'header = "Authorization: Bearer %s"\n' "$CFB_TOKEN" | curl "${args[@]}" "$base$p" 2>/dev/null)
    CFB_CODE="${raw##*$'\n'}"
    [[ "$CFB_CODE" =~ ^[0-9]{3}$ ]] || CFB_CODE="000"
    if [[ "$raw" == *$'\n'* ]]; then CFB_BODY="${raw%$'\n'*}"; else CFB_BODY=""; fi
    if _cfb_cf_ratelimited; then date +%s > "$CFB_RL_MARK" 2>/dev/null; fi
    [[ "$CFB_CODE" == 2* ]] && [[ "$(jq -r '.success // false' <<< "$CFB_BODY" 2>/dev/null)" == true ]]
}

# _cfb_cfj METHOD PATH JSON — the same with a JSON body (written to a private temporary file: a list of 10,000 addresses is no argument)
_cfb_cfj() {
    local f rc
    f=$(umask 077; mktemp "${TMPDIR:-/tmp}/dcs-cfb.XXXXXX") || return 1
    printf '%s' "$3" > "$f"
    _cfb_cf "$1" "$2" "$f"; rc=$?
    rm -f "$f"
    return $rc
}

# what Cloudflare said went wrong, in one line
_cfb_cf_msg() {
    local m
    m=$(jq -r '[.errors[]? | (.message // empty) | tostring] | unique | join("; ")' <<< "$CFB_BODY" 2>/dev/null) || m=""
    if [[ -z "$m" ]]; then
        if [[ "$CFB_CODE" == 000 ]]; then m="Cloudflare's API did not answer"; else m="HTTP $CFB_CODE"; fi
    fi
    printf '%s' "${m:0:300}"
}

# Was it refused for lack of a right? (403, or Cloudflare's "Authentication error" / "Unauthorized to access requested resource")
_cfb_cf_denied() {
    [[ "$CFB_CODE" == 403 ]] && return 0
    jq -e '[.errors[]? | ((.code // 0) == 10000 or (.code // 0) == 9109 or ((.message // "") | test("unauthori[sz]ed|authentication error|permission"; "i")))] | any' <<< "$CFB_BODY" >/dev/null 2>&1
}

# CrowdSec's local API, as Docker publishes it for the container (the crowdsec template: 127.0.0.1:PORT_CROWDSEC); CROWDSEC_LAPI_URL overrides it
_cfb_lapi_url() {
    local u="${CROWDSEC_LAPI_URL:-}" c hip hport p
    [[ -n "$u" ]] || u=$(_cfb_setting CROWDSEC_LAPI_URL "")
    if [[ -n "$u" ]]; then
        u="${u%/}"
        [[ "$u" =~ ^https?://[A-Za-z0-9.:\[\]-]+(:[0-9]{1,5})?$ ]] && { printf '%s' "$u"; return 0; }
    fi
    c=$(_crowdsec_container 2>/dev/null) || c=""
    if [[ -n "$c" ]]; then
        IFS=$'\t' read -r hip hport < <(timeout 10 docker inspect "$c" 2>/dev/null </dev/null | jq -r '.[0].NetworkSettings.Ports["8080/tcp"] // [] | map(select((.HostPort // "") != "")) | (map(select((.HostIp // "") | test(":") | not)) + .)[0] // {} | [(.HostIp // ""), (.HostPort // "")] | @tsv' 2>/dev/null)
        if [[ "$hport" =~ ^[0-9]{1,5}$ ]]; then
            case "$hip" in ""|0.0.0.0) hip=127.0.0.1 ;; ::) hip="[::1]" ;; *:*) hip="[$hip]" ;; esac
            printf 'http://%s:%s' "$hip" "$hport"; return 0
        fi
    fi
    p=$(_stack_envs_first PORT_CROWDSEC 2>/dev/null); [[ "$p" =~ ^[0-9]{1,5}$ ]] || p=8070
    printf 'http://127.0.0.1:%s' "$p"
}

# _cfb_lapi PATH_AND_QUERY — a GET with the bouncer's key (from the key file, on curl's standard input). Sets CFB_CODE and CFB_BODY.
_cfb_lapi() {
    local key raw url
    CFB_CODE="000"; CFB_BODY=""
    key=$(cat "$CFB_KEY_FILE" 2>/dev/null) || key=""
    [[ "$key" =~ ^[A-Za-z0-9+/=_-]{16,200}$ ]] || return 1
    url=$(_cfb_lapi_url)
    raw=$(printf 'header = "X-Api-Key: %s"\n' "$key" | curl -s --max-time 30 -K - -H 'User-Agent: dcs-cloudflare-bouncer' -w $'\n%{http_code}' "$url$1" 2>/dev/null)
    CFB_CODE="${raw##*$'\n'}"
    [[ "$CFB_CODE" =~ ^[0-9]{3}$ ]] || CFB_CODE="000"
    if [[ "$raw" == *$'\n'* ]]; then CFB_BODY="${raw%$'\n'*}"; else CFB_BODY=""; fi
    [[ "$CFB_CODE" == 200 ]]
}

# =============================================================================
# State (.data/crowdsec/cloudflare.json, 600)
# =============================================================================

_cfb_state() { local s; s=$(cat "$CFB_STATE" 2>/dev/null); [[ "$s" == \{* ]] && jq -e . >/dev/null 2>&1 <<< "$s" && printf '%s' "$s" || printf '{}'; }

# _cfb_state_set JQ_FILTER [jq args…] — change the state atomically (made when missing)
_cfb_state_set() {
    mkdir -p "$CROWDSEC_STATE_DIR" 2>/dev/null
    [[ -s "$CFB_STATE" ]] && jq -e . "$CFB_STATE" >/dev/null 2>&1 || { (umask 077; printf '{}\n' > "$CFB_STATE"); }
    local filter="$1"; shift
    _api_jq_update_file "$CFB_STATE" "$@" "$filter"
}

# _cfb_fail CODE MESSAGE — remember an error (since: when this run of errors began) and set CFB_ERR_CODE / CFB_ERR
# A Cloudflare failure that came with Cloudflare's "slow down" (HTTP 429, or a message about a rate limit) is no failure of the setup:
# it becomes rate_limited, with a wait before Cloudflare is asked again (CFB_BACKOFF, one step longer each time it happens in a row) and
# never the advice of the failure it looked like (a full list, a missing right).
_cfb_fail() {
    local code="$1" msg="$2" now step delay
    now=$(date +%s)
    if [[ ! "$code" =~ ^(lapi_|token_|internal|rate_limited) && -e "$CFB_RL_MARK" ]]; then
        step=$(_cfb_state | jq -r '(.backoff.step // 0) + 1 | if . > 3 then 3 else . end')
        delay=${CFB_BACKOFF[$((step - 1))]}
        code=rate_limited; msg="Cloudflare asked DCS to slow down; next try in $(( delay / 60 )) min."
        _cfb_state_set '.backoff = {step: $s, until: ($now + $d)}' --argjson s "$step" --argjson d "$delay" --argjson now "$now" >/dev/null 2>&1
    fi
    CFB_ERR_CODE="$code"; CFB_ERR="$msg"
    _cfb_state_set '.error = ({code: $c, message: $m, at: $now, since: (if (.error.since // null) != null then .error.since else $now end)}
            + (if $c == "rate_limited" then {retry_at: (.backoff.until // $now)} else {} end))' \
        --arg c "$code" --arg m "$msg" --argjson now "$now" >/dev/null 2>&1 || true
    return 1
}

# did Cloudflare's last answer ask to slow down? (the status, an error message, a bulk operation's error)
_cfb_cf_ratelimited() {
    [[ "$CFB_CODE" == 429 ]] && return 0
    jq -e '[(.errors // [])[]?.message, (.result.error? // empty)] | map(select(. != null) | tostring) | any(test("rate ?limit|too many"; "i"))' <<< "$CFB_BODY" >/dev/null 2>&1
}

# =============================================================================
# The token's checks: zones, accounts, rights (reads only, nothing is changed)
# =============================================================================

# _cfb_missing_json ITEM… — the CFB_PERMS entries for the given items ("Account Filter Lists", "Zone WAF", "Zone")
_cfb_missing_json() {
    jq -c --args '[.[] | select(.item as $i | $ARGS.positional | index($i))]' "$@" <<< "$CFB_PERMS"
}

# _cfb_check — prints JSON {ok, error: {code, message} | null, missing: [...], token: {kind, status},
# zones: [{domain, name, id, account, account_name, plan, rule: bool, rules}], accounts: [{id, name, list_id, items, lists}], warnings}
_cfb_check() {
    local d cand zres zj zones='[]' accounts='[]' miss=() warnings=() kind="user" status="" err_code="" err_msg="" acc
    if ! _cfb_token_ok "$CFB_TOKEN"; then
        jq -nc '{ok: false, error: {code: "token_invalid", message: "That is not a Cloudflare API token: paste the token itself (about 40 letters, digits, - and _), not the Global API Key or a key id."}, missing: []}'
        return 1
    fi
    # 1. the token itself (a user token; an account-owned token is verified on its account below)
    _cfb_cf GET /user/tokens/verify
    if [[ "$CFB_CODE" == 2* ]]; then
        status=$(jq -r '.result.status // ""' <<< "$CFB_BODY" 2>/dev/null)
        if [[ "$status" != active ]]; then
            jq -nc --arg s "${status:-unknown}" '{ok: false, error: {code: "token_rejected", message: ("Cloudflare says this token is " + $s + ". Make a new one (or activate it) at dash.cloudflare.com → My Profile → API Tokens.")}, missing: []}'
            return 1
        fi
    elif [[ "$CFB_CODE" == 000 ]]; then
        jq -nc --arg m "$(_cfb_cf_msg)" '{ok: false, error: {code: "cloudflare_unreachable", message: ("Cloudflare could not be reached from this server: " + $m)}, missing: []}'
        return 1
    else
        kind="account"; status="unverified"
    fi
    # 2. the zones of the domains (a domain may sit below its zone: lab.example.com is in example.com)
    local -a doms=()
    mapfile -t doms < <(_cfb_domains)
    if (( ${#doms[@]} == 0 )); then
        jq -nc '{ok: false, error: {code: "no_domain", message: "This server has no domain yet (PROXY_DOMAIN): set one on the DNS & Routes page first, or name the domains in CLOUDFLARE_BOUNCER_DOMAINS."}, missing: []}'
        return 1
    fi
    for d in "${doms[@]}"; do
        cand="$d"; zj=""
        while [[ "$cand" == *.* ]]; do
            _cfb_cf GET "/zones?name=$cand"
            if [[ "$CFB_CODE" == 000 ]]; then
                jq -nc --arg m "$(_cfb_cf_msg)" '{ok: false, error: {code: "cloudflare_unreachable", message: ("Cloudflare could not be reached from this server: " + $m)}, missing: []}'
                return 1
            fi
            if [[ "$CFB_CODE" != 2* ]]; then
                if [[ "$kind" == account ]] && ! _cfb_cf_denied; then
                    jq -nc --arg m "$(_cfb_cf_msg)" '{ok: false, error: {code: "token_rejected", message: ("Cloudflare does not accept this token: " + $m + ". Use an API token (dash.cloudflare.com → My Profile → API Tokens), not the Global API Key.")}, missing: []}'
                    return 1
                fi
                if [[ "$kind" == account ]]; then
                    jq -nc --arg m "$(_cfb_cf_msg)" '{ok: false, error: {code: "token_rejected", message: ("Cloudflare does not accept this token (" + $m + "), or it may not read zones. Use an API token with the rights below.")}, missing: []}'
                    return 1
                fi
                miss+=("Zone"); break 2
            fi
            zres=$(jq -c '(.result // [])[0] // empty' <<< "$CFB_BODY" 2>/dev/null)
            if [[ -n "$zres" ]]; then zj="$zres"; break; fi
            cand="${cand#*.}"
        done
        if [[ -z "$zj" ]]; then
            err_code="zone_not_found"; err_msg="No Cloudflare zone for $d can be seen with this token. Add $d (or its parent domain) to Cloudflare, or give the token access to that zone (Zone Resources: include the zone, or all zones)."
            break
        fi
        zones=$(jq -c --arg d "$d" --argjson z "$zj" '. + [{domain: $d, name: $z.name, id: $z.id, account: ($z.account.id // ""), account_name: ($z.account.name // ""), plan: ($z.plan.legacy_id // $z.plan.name // "" | ascii_downcase), status: ($z.status // "")}]' <<< "$zones")
    done
    if (( ${#miss[@]} > 0 )); then
        jq -nc --argjson m "$(_cfb_missing_json "${miss[@]}")" '{ok: false, error: {code: "missing_permissions", message: "The token may not read your zones."}, missing: $m}'
        return 1
    fi
    if [[ -n "$err_code" ]]; then
        jq -nc --arg c "$err_code" --arg m "$err_msg" --argjson z "$zones" '{ok: false, error: {code: $c, message: $m}, missing: [], zones: $z}'
        return 1
    fi
    # several domains in one zone: one zone, the domains joined
    zones=$(jq -c 'group_by(.id) | map(.[0] + {domain: (map(.domain) | join(", ")), domains: map(.domain)})' <<< "$zones")
    if [[ "$(jq '[.[] | select(.account == "")] | length' <<< "$zones")" != 0 ]]; then
        jq -nc --argjson z "$zones" '{ok: false, error: {code: "cloudflare_error", message: "Cloudflare did not say which account a zone belongs to; DCS cannot find the account for the list."}, missing: [], zones: $z}'
        return 1
    fi
    # an account-owned token is verified on its account
    if [[ "$kind" == account ]]; then
        acc=$(jq -r '.[0].account' <<< "$zones")
        _cfb_cf GET "/accounts/$acc/tokens/verify"
        status=$(jq -r '.result.status // ""' <<< "$CFB_BODY" 2>/dev/null)
        if [[ "$CFB_CODE" != 2* || "$status" != active ]]; then
            jq -nc --arg m "$(_cfb_cf_msg)" --arg s "$status" '{ok: false, error: {code: "token_rejected", message: (if $s != "" and $s != "active" then "Cloudflare says this token is " + $s + "." else "Cloudflare does not accept this token: " + $m + "." end)}, missing: []}'
            return 1
        fi
    fi
    # 3. the lists of each account (Account Filter Lists) and 4. the custom rules of each zone (Zone WAF)
    local lists_denied=false waf_denied=false lj nlists ours oitems others
    while IFS=$'\t' read -r acc _; do
        [[ -n "$acc" ]] || continue
        _cfb_cf GET "/accounts/$acc/rules/lists"
        if [[ "$CFB_CODE" != 2* ]]; then
            if _cfb_cf_denied; then lists_denied=true; continue; fi
            jq -nc --arg m "$(_cfb_cf_msg)" '{ok: false, error: {code: "cloudflare_error", message: ("Cloudflare would not list the account'"'"'s lists: " + $m)}, missing: []}'
            return 1
        fi
        lj=$(jq -c '.result // []' <<< "$CFB_BODY")
        nlists=$(jq 'length' <<< "$lj"); ours=$(jq -r --arg n "$CFB_LIST" 'map(select(.name == $n))[0].id // ""' <<< "$lj")
        oitems=$(jq -r --arg n "$CFB_LIST" '[.[] | select(.name != $n) | .num_items // 0] | add // 0' <<< "$lj")
        others=$(jq -r --arg n "$CFB_LIST" '[.[] | select(.name != $n) | .name] | join(", ")' <<< "$lj")
        accounts=$(jq -c --arg id "$acc" --arg name "$(jq -r --arg a "$acc" 'map(select(.account == $a))[0].account_name' <<< "$zones")" --arg lid "$ours" \
            --argjson n "$nlists" --argjson oi "$oitems" --arg others "$others" --argjson items "$(jq -r --arg n "$CFB_LIST" 'map(select(.name == $n))[0].num_items // 0' <<< "$lj")" \
            '. + [{id: $id, name: $name, list_id: $lid, items: $items, lists: $n, other_items: $oi, other_lists: ($others | split(", ") | map(select(length > 0)))}]' <<< "$accounts")
    done < <(jq -r 'map(.account) | unique[] | [., ""] | @tsv' <<< "$zones")
    local zid rules nrules has
    while IFS= read -r zid; do
        [[ -n "$zid" ]] || continue
        _cfb_cf GET "/zones/$zid/rulesets/phases/$CFB_PHASE/entrypoint"
        if [[ "$CFB_CODE" == 404 ]]; then
            zones=$(jq -c --arg z "$zid" 'map(if .id == $z then . + {rule: false, rules: 0} else . end)' <<< "$zones"); continue
        fi
        if [[ "$CFB_CODE" != 2* ]]; then
            if _cfb_cf_denied; then waf_denied=true; continue; fi
            jq -nc --arg m "$(_cfb_cf_msg)" '{ok: false, error: {code: "cloudflare_error", message: ("Cloudflare would not show the zone'"'"'s custom rules: " + $m)}, missing: []}'
            return 1
        fi
        rules=$(jq -c '.result.rules // []' <<< "$CFB_BODY"); nrules=$(jq 'length' <<< "$rules")
        has=$(jq --arg r "$CFB_REF" 'any(.[]; (.ref // "") == $r)' <<< "$rules")
        zones=$(jq -c --arg z "$zid" --argjson h "$has" --argjson n "$nrules" 'map(if .id == $z then . + {rule: $h, rules: $n} else . end)' <<< "$zones")
    done < <(jq -r '.[].id' <<< "$zones")
    [[ "$lists_denied" == true ]] && miss+=("Account Filter Lists")
    [[ "$waf_denied" == true ]] && miss+=("Zone WAF")
    if (( ${#miss[@]} > 0 )); then
        jq -nc --argjson m "$(_cfb_missing_json "${miss[@]}")" --argjson z "$zones" '{ok: false, error: {code: "missing_permissions", message: "The token lacks a right DCS needs."}, missing: $m, zones: $z}'
        return 1
    fi
    # 5. the free plan's limits, before anything is made: one custom list per account, five custom rules per zone
    local all_free
    all_free=$(jq '[.[] | .plan] | all(. == "free" or . == "")' <<< "$zones")
    local full_acc
    full_acc=$(jq -r --argjson free "$all_free" --argjson max "$CFB_FREE_LISTS" '[.[] | select(.list_id == "" and $free and .lists >= $max)] | .[0] // empty | (.name + "\t" + (.other_lists | join(", ")))' <<< "$accounts")
    if [[ -n "$full_acc" ]]; then
        jq -nc --arg a "${full_acc%%$'\t'*}" --arg l "${full_acc#*$'\t'}" --argjson z "$zones" --argjson ac "$accounts" \
            '{ok: false, error: {code: "list_quota", message: ("The free plan allows one custom list per account, and " + (if $a != "" then $a else "the account" end) + " has one already (" + $l + "). Delete it at Cloudflare (Manage Account → Configurations → Lists) if you no longer use it, then try again.")}, missing: [], zones: $z, accounts: $ac}'
        return 1
    fi
    local full_zone
    full_zone=$(jq -r --argjson max "$CFB_FREE_RULES" '[.[] | select((.rule | not) and (.plan == "free") and ((.rules // 0) >= $max))] | .[0].name // empty' <<< "$zones")
    if [[ -n "$full_zone" ]]; then
        jq -nc --arg z "$full_zone" --argjson max "$CFB_FREE_RULES" --argjson zs "$zones" \
            '{ok: false, error: {code: "rule_quota", message: ("The free plan allows " + ($max | tostring) + " custom rules per zone, and " + $z + " has " + ($max | tostring) + " already. Delete or merge one at Cloudflare (Security → WAF → Custom rules), then try again.")}, missing: [], zones: $zs}'
        return 1
    fi
    local cap; cap=$(_cfb_capacity)
    if [[ "$all_free" == true ]] && (( cap > CFB_FREE_ITEMS )); then warnings+=("The free plan holds $CFB_FREE_ITEMS addresses over all lists; a capacity of $cap cannot be reached there."); fi
    jq -nc --arg kind "$kind" --argjson z "$zones" --argjson a "$accounts" --arg w "$(printf '%s\n' "${warnings[@]}")" \
        '{ok: true, error: null, missing: [], token: {kind: $kind, status: "active"}, zones: $z, accounts: $a, warnings: ($w | split("\n") | map(select(length > 0)))}'
}

# =============================================================================
# Making and keeping the list and the rule
# =============================================================================

# _cfb_list_ensure ACCOUNT — CFB_LIST_ID: the id of the list (made when missing; CFB_MADE_LIST=1 then). Not to be called in $( … ):
# what it sets is what the caller reads.
CFB_MADE_LIST=0; CFB_LIST_ID=""
_cfb_list_ensure() {
    local acc="$1" id
    CFB_MADE_LIST=0; CFB_LIST_ID=""
    if ! _cfb_cf GET "/accounts/$acc/rules/lists"; then
        if _cfb_cf_denied; then _cfb_fail missing_permissions "Cloudflare refused to list the account's lists: the token needs Account → Account Filter Lists → Edit."
        else _cfb_fail cloudflare_error "Cloudflare would not list the account's lists: $(_cfb_cf_msg)"; fi
        return 1
    fi
    id=$(jq -r --arg n "$CFB_LIST" '(.result // []) | map(select(.name == $n))[0].id // ""' <<< "$CFB_BODY")
    if [[ -n "$id" ]]; then CFB_LIST_ID="$id"; return 0; fi
    if ! _cfb_cfj POST "/accounts/$acc/rules/lists" "$(jq -nc --arg n "$CFB_LIST" '{name: $n, kind: "ip", description: "CrowdSec bans, kept by DCS Orchestrator (do not edit: DCS replaces the items)"}')"; then
        local m; m=$(_cfb_cf_msg)
        if _cfb_cf_denied; then _cfb_fail missing_permissions "Cloudflare refused to create the list: the token needs Account → Account Filter Lists → Edit."
        elif [[ "$m" =~ [Mm]aximum|[Qq]uota|exceed ]] && ! _cfb_cf_ratelimited; then _cfb_fail list_quota "Cloudflare refused a new list: $m. The free plan allows one custom list per account; delete an unused one at Cloudflare (Manage Account → Configurations → Lists)."
        else _cfb_fail cloudflare_error "Cloudflare refused to create the list: $m"; fi
        return 1
    fi
    id=$(jq -r '.result.id // ""' <<< "$CFB_BODY")
    [[ -n "$id" ]] || { _cfb_fail cloudflare_error "Cloudflare made the list but did not say its id"; return 1; }
    CFB_MADE_LIST=1; CFB_LIST_ID="$id"
}

# the rule DCS keeps in each zone (its ref is how it is found again)
_cfb_rule_json() { jq -nc --arg r "$CFB_REF" --arg l "$CFB_LIST" --arg d "$CFB_RULE_DESC" '{ref: $r, description: $d, expression: ("ip.src in $" + $l), action: "block", enabled: true}'; }

# _cfb_rule_ensure ZONE_ID — the custom rule is there, blocks the list and is on (made, or repaired, when not). Sets CFB_RS_ID and CFB_RULE_ID,
# and CFB_RULE_DID (made | repaired | kept). Not to be called in $( … ).
CFB_RULE_DID=""; CFB_RS_ID=""; CFB_RULE_ID=""
_cfb_rule_ensure() {
    local z="$1" rs rid cur want
    CFB_RULE_DID=""; CFB_RS_ID=""; CFB_RULE_ID=""
    want=$(_cfb_rule_json)
    _cfb_cf GET "/zones/$z/rulesets/phases/$CFB_PHASE/entrypoint"
    if [[ "$CFB_CODE" == 404 ]]; then
        # no custom rule in the zone yet: the phase's entry point is made with this one rule in it
        if ! _cfb_cfj PUT "/zones/$z/rulesets/phases/$CFB_PHASE/entrypoint" "$(jq -nc --argjson r "$want" '{description: "Custom rules", rules: [$r]}')"; then
            _cfb_rule_error "$z"; return 1
        fi
        CFB_RULE_DID=made
    elif [[ "$CFB_CODE" == 2* ]]; then
        rs=$(jq -r '.result.id // ""' <<< "$CFB_BODY")
        cur=$(jq -c --arg r "$CFB_REF" '(.result.rules // []) | map(select((.ref // "") == $r))[0] // empty' <<< "$CFB_BODY")
        if [[ -z "$cur" ]]; then
            if ! _cfb_cfj POST "/zones/$z/rulesets/$rs/rules" "$(jq -c '. + {position: {index: 1}}' <<< "$want")"; then _cfb_rule_error "$z"; return 1; fi
            CFB_RULE_DID=made
        else
            rid=$(jq -r '.id' <<< "$cur")
            # the same rule? (spaces and brackets around the expression aside)
            if jq -e --argjson w "$want" '(.action == $w.action) and (.enabled != false) and (((.expression // "") | gsub("[()\\s]"; "")) == ($w.expression | gsub("[()\\s]"; "")))' <<< "$cur" >/dev/null 2>&1; then
                CFB_RULE_DID=kept; CFB_RS_ID="$rs"; CFB_RULE_ID="$rid"; return 0
            fi
            if ! _cfb_cfj PATCH "/zones/$z/rulesets/$rs/rules/$rid" "$want"; then _cfb_rule_error "$z"; return 1; fi
            CFB_RULE_DID=repaired
        fi
    else
        _cfb_rule_error "$z"; return 1
    fi
    rs=$(jq -r '.result.id // ""' <<< "$CFB_BODY")
    rid=$(jq -r --arg r "$CFB_REF" '(.result.rules // []) | map(select((.ref // "") == $r))[0].id // ""' <<< "$CFB_BODY")
    [[ -n "$rs" && -n "$rid" ]] || { _cfb_fail cloudflare_error "Cloudflare took the custom rule but did not show it back"; return 1; }
    CFB_RS_ID="$rs"; CFB_RULE_ID="$rid"
}
_cfb_rule_error() {
    local m; m=$(_cfb_cf_msg)
    if _cfb_cf_denied; then _cfb_fail missing_permissions "Cloudflare refused the custom rule in zone $1: the token needs Zone → Zone WAF → Edit."
    elif [[ "$m" =~ [Mm]aximum|[Qq]uota|exceed ]] && ! _cfb_cf_ratelimited; then _cfb_fail rule_quota "Cloudflare refused the custom rule in zone $1: $m. The free plan allows $CFB_FREE_RULES custom rules per zone; delete or merge one at Cloudflare (Security → WAF → Custom rules)."
    elif [[ "$m" =~ list|\$ ]]; then _cfb_fail cloudflare_error "Cloudflare refused the custom rule in zone $1: $m (the rule names the list \$$CFB_LIST of the zone's own account)"
    else _cfb_fail cloudflare_error "Cloudflare refused the custom rule in zone $1: $m"; fi
}

# _cfb_push ACCOUNT LIST_ID ITEMS_JSON — replace the list's items (Cloudflare does it as a bulk operation: it is followed to its end, 90 s at most)
_cfb_push() {
    local acc="$1" lid="$2" items="$3" op st i
    if ! _cfb_cfj PUT "/accounts/$acc/rules/lists/$lid/items" "$items"; then
        local m; m=$(_cfb_cf_msg)
        if _cfb_cf_denied; then _cfb_fail missing_permissions "Cloudflare refused to change the list: the token needs Account → Account Filter Lists → Edit."
        elif [[ "$CFB_CODE" == 404 ]]; then _cfb_fail list_gone "The list $CFB_LIST is gone at Cloudflare; DCS makes it again on the next sync."
        elif [[ "$m" =~ [Mm]aximum|[Qq]uota ]]; then _cfb_fail list_full "Cloudflare refused the addresses: $m. Lower the capacity (CLOUDFLARE_BOUNCER_CAPACITY), or free items in your other lists."
        else _cfb_fail cloudflare_error "Cloudflare refused the addresses: $m"; fi
        return 1
    fi
    op=$(jq -r '.result.operation_id // ""' <<< "$CFB_BODY")
    [[ -n "$op" ]] || return 0
    for (( i = 0; i < 90; i++ )); do
        _cfb_cf GET "/accounts/$acc/rules/lists/bulk_operations/$op" || { (( i < 3 )) && { sleep 1; continue; }; _cfb_fail cloudflare_error "Cloudflare did not say how the change of the list went: $(_cfb_cf_msg)"; return 1; }
        st=$(jq -r '.result.status // ""' <<< "$CFB_BODY")
        case "$st" in
            completed) return 0 ;;
            failed)
                local e; e=$(jq -r '.result.error // "no reason given"' <<< "$CFB_BODY")
                if [[ "$e" =~ [Mm]aximum|[Qq]uota ]] && ! _cfb_cf_ratelimited; then _cfb_fail list_full "Cloudflare could not store the addresses: $e. Lower the capacity (CLOUDFLARE_BOUNCER_CAPACITY), or free items in your other lists."
                else _cfb_fail cloudflare_error "Cloudflare could not store the addresses: $e"; fi
                return 1 ;;
        esac
        sleep 1
    done
    _cfb_state_set '.pending_op = {account: $a, id: $o, at: $now}' --arg a "$acc" --arg o "$op" --argjson now "$(date +%s)" >/dev/null 2>&1
    _cfb_fail cloudflare_slow "Cloudflare is still storing the addresses (operation $op); the next sync looks again."
    return 1
}

# =============================================================================
# The bans: CrowdSec's local API → the list's items
# =============================================================================

# _cfb_pull — CFB_ROWS: the active bans as JSON [{value, origin, id}] (one row per address, the newest decision), or 1 with the error recorded
CFB_ROWS="[]"
_cfb_pull() {
    local origins q
    CFB_ROWS="[]"
    origins=$(_cfb_origins)
    q="/v1/decisions?type=ban&scopes=ip,range&origins=$origins"
    if ! _cfb_lapi "$q"; then
        local url; url=$(_cfb_lapi_url)
        if [[ ! -s "$CFB_KEY_FILE" ]]; then _cfb_fail lapi_key "DCS has no key for the bouncer $CFB_NAME: turn Push bans to Cloudflare off and on again."
        elif [[ "$CFB_CODE" == 401 || "$CFB_CODE" == 403 ]]; then _cfb_fail lapi_key "CrowdSec's API refused the bouncer's key (the bouncer $CFB_NAME was deleted, or CrowdSec was reset): turn Push bans to Cloudflare off and on again."
        elif [[ "$CFB_CODE" == 000 || "$CFB_CODE" == 502 || "$CFB_CODE" == 503 || "$CFB_CODE" == 504 ]]; then _cfb_fail lapi_down "CrowdSec's API does not answer at $url: is CrowdSec running? Cloudflare keeps the last bans meanwhile."
        else _cfb_fail lapi_error "CrowdSec's API answered HTTP $CFB_CODE: $(jq -r '.message // empty' <<< "$CFB_BODY" 2>/dev/null | head -c 200)"; fi
        return 1
    fi
    CFB_ROWS=$(jq -c 'if type == "array" then . else [] end
        | map(select((((.type // "") | ascii_downcase) == "ban") and ((((.scope // "") | ascii_downcase) == "ip") or (((.scope // "") | ascii_downcase) == "range")) and ((.value // null) | type == "string")))
        | map({value: .value, origin: (.origin // ""), id: (.id // 0)})
        | group_by(.value) | map(max_by(.id))' <<< "$CFB_BODY" 2>/dev/null) || CFB_ROWS=""
    [[ "$CFB_ROWS" == \[* ]] || { _cfb_fail lapi_error "CrowdSec's API answered something that is not a list of bans"; return 1; }
}

# jq: addresses and networks without a process per row. cfb_net("2001:db8::1/64") → {f: 6, g: [eight 16-bit groups, masked], bits, full}
# (IPv4: f 4, two groups), null when it is neither; cfb_covers(A; B): A's network holds B; cfb_text(N): the canonical text
# (IPv6 with its longest run of zero groups as "::", a single address without its prefix length).
_CFB_JQ_NET='
def _p2: [1,2,4,8,16,32,64,128,256,512,1024,2048,4096,8192,16384,32768,65536];
def _mask($g; $bits): [range($g | length) as $i | ($bits - 16 * $i) as $k
    | if $k >= 16 then $g[$i] elif $k <= 0 then 0 else (($g[$i] / _p2[16 - $k]) | floor) * _p2[16 - $k] end];
def _v4($s): ($s | split(".")) as $p
    | if ($p | length) == 4 and all($p[]; test("^(0|[1-9][0-9]{0,2})$")) and all($p[]; tonumber <= 255)
      then ($p | map(tonumber)) as $o | {f: 4, g: [$o[0] * 256 + $o[1], $o[2] * 256 + $o[3]]} else null end;
def _hexval: explode | reduce .[] as $c (0; . * 16 + (if $c >= 97 then $c - 87 else $c - 48 end));
def _groups($s): if $s == "" then [] else ($s | split(":")) end;
def _v6($s): ($s | ascii_downcase) as $a
    | if ($a | test("^[0-9a-f:.]{2,45}$") | not) or ($a | test(":::")) then null else
        (($a | split(":"))[-1]) as $last
        | (if ($last | test("[.]")) then _v4($last) else {g: []} end) as $tail
        | if $tail == null then null else
            (if ($last | test("[.]")) then $a[0:($a | length) - ($last | length)] + "0:0" else $a end | split("::")) as $h
            | if ($h | length) > 2 then null else
                _groups($h[0]) as $l | (if ($h | length) == 2 then _groups($h[1]) else [] end) as $r
                | if any(($l + $r)[]; test("^[0-9a-f]{1,4}$") | not) then null
                  elif ($h | length) == 2 and (($l | length) + ($r | length)) > 7 then null
                  elif ($h | length) == 1 and ($l | length) != 8 then null
                  else (($l + [range(8 - ($l | length) - ($r | length)) | "0"] + $r) | map(_hexval)) as $g
                    | {f: 6, g: (if ($tail.g | length) == 2 then $g[0:6] + $tail.g else $g end)} end end end end;
def cfb_net($s): ($s | tostring | split("/")) as $x
    | if ($x | length) > 2 then null else
        ($x[0] | if test(":") then _v6(.) else _v4(.) end) as $a
        | if $a == null then null else
            (if $a.f == 4 then 32 else 128 end) as $full
            | (if ($x | length) == 2 then ($x[1] | if test("^[0-9]{1,3}$") then tonumber else null end) else $full end) as $bits
            | if $bits == null or $bits > $full then null else $a + {bits: $bits, full: $full, g: _mask($a.g; $bits)} end end end;
def cfb_covers($a; $b): $a.f == $b.f and $a.bits <= $b.bits and (_mask($b.g; $a.bits) == $a.g);
def _hex: if . == 0 then "0" else [recurse(if . >= 16 then (. / 16 | floor) else empty end)] | map(. % 16) | reverse | map("0123456789abcdef"[.:.+1]) | add end;
def cfb_text($n):
    (if $n.f == 4 then "\($n.g[0] / 256 | floor).\($n.g[0] % 256).\($n.g[1] / 256 | floor).\($n.g[1] % 256)"
     else
        ($n.g | map(_hex)) as $h
        | (reduce range(8) as $i ({bs: -1, bl: 0, cs: -1, cl: 0};
            if $n.g[$i] == 0 then (if .cl == 0 then .cs = $i else . end) | .cl += 1 | (if .cl > .bl then .bs = .cs | .bl = .cl else . end) else .cl = 0 end)) as $r
        | if $r.bl < 2 then ($h | join(":")) else ($h[0:$r.bs] | join(":")) + "::" + ($h[($r.bs + $r.bl):] | join(":")) end
     end) + (if $n.bits == $n.full then "" else "/\($n.bits)" end);
'

# _cfb_items ROWS_JSON — the list's items, in ONE jq pass: local bans before the community's and the newest first, cut to the capacity
# (plus a margin for what the guard takes out) BEFORE anything else, then normalised and guarded: never a private or protected address,
# never a network wider than Cloudflare takes or the ban guard allows (IPv4 /8, IPv6 /16). 100,000 rows take a second or two.
# Prints {items, dropped, skipped}.
_cfb_items() {
    local rows="$1" cap prot priv
    cap=$(_cfb_capacity)
    prot=$(_cs_protected_addresses 2>/dev/null | cut -f2 | jq -R . | jq -sc 'map(select(length > 0))')
    priv=$(printf '%s\n' "${_CS_PRIVATE_NETS[@]}" | jq -R . | jq -sc .)
    jq -c --argjson cap "$cap" --argjson prot "$prot" --argjson priv "$priv" --arg local "$CFB_LOCAL_ORIGINS" "$_CFB_JQ_NET"'
        ($local | split(",")) as $l
        | ([$priv[] | cfb_net(.)] | map(select(. != null))) as $PRIV
        | ([$prot[] | cfb_net(.)] | map(select(. != null))) as $PROT
        | (map(. + {k: (if (.origin as $o | $l | index($o)) != null then 0 else 1 end)}) | sort_by(.k, -(.id // 0))) as $sorted
        | ($sorted | length) as $total
        | [$sorted[0:($cap + ([256, ($cap / 10 | floor)] | max))][]
            | cfb_net(.value) as $n
            | {origin, n: $n, ok: ($n != null
                and (if $n.f == 4 then $n.bits >= 8 else $n.bits >= 16 end)
                and (any($PRIV[]; cfb_covers(.; $n)) | not)
                and (any($PROT[]; cfb_covers(.; $n) or cfb_covers($n; .)) | not))}] as $checked
        | ([$checked[] | select(.ok)] | [.[] | {ip: cfb_text(.n), comment: ("crowdsec: " + (.origin // "ban"))}]
            | reduce .[] as $i ({seen: {}, out: []}; if .seen[$i.ip] then . else .seen[$i.ip] = true | .out += [$i] end) | .out) as $good
        | ([$checked[] | select(.ok | not)] | length) as $skipped
        | {items: $good[0:$cap], skipped: $skipped, dropped: ([$total - $skipped - ([$good | length, $cap] | min), 0] | max)}' <<< "$rows"
}

# =============================================================================
# One sync
# =============================================================================

# _cfb_sync [force] — pull, compare, push when the bans changed; read back and repair every CFB_VERIFY_EVERY s (or when forced).
# Returns 0 when Cloudflare holds what CrowdSec says, 75 when another sync is running.
_cfb_sync() {
    mkdir -p "$CROWDSEC_STATE_DIR" 2>/dev/null
    (
        _cfb_lock_take sync || { _cfb_log "sync skipped: $CFB_LOCK_WHY"; exit 75; }
        trap '_cfb_state_set "del(.running)" >/dev/null 2>&1; _cfb_lock_drop' EXIT
        _cfb_sync_locked "${1:-}"
    )
}

# one line in the API's log
_cfb_log() { mkdir -p "$(dirname "$CFB_LOG")" 2>/dev/null; printf '%s push bans to Cloudflare: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" >> "$CFB_LOG" 2>/dev/null; return 0; }

# _cfb_kill_tree PID — PID and everything it started
_cfb_kill_tree() {
    local c
    for c in $(ps -o pid= --ppid "$1" 2>/dev/null); do _cfb_kill_tree "$c"; done
    kill -TERM "$1" 2>/dev/null
    return 0
}

# when a process started (in clock ticks since boot): a PID with another start time is another process
_cfb_pid_start() { sed 's/^.*) //' "/proc/$1/stat" 2>/dev/null | cut -d' ' -f20; }

# _cfb_lock_take KIND (sync | request) — take the lock for this process ($BASHPID). 1 with CFB_LOCK_WHY when another holds it. A holder
# that is gone (killed, the machine restarted, its PID now another process's) leaves a lock that is simply taken over; one that has held it
# for CFB_STUCK_AFTER seconds is stopped when it is a sync and taken over otherwise (a request). Both are said in the log.
CFB_LOCK_WHY=""
_cfb_lock_take() {
    local kind="${1:-sync}" pid since hkind hstart age now
    CFB_LOCK_WHY=""
    now=$(date +%s)
    if ! mkdir "$CFB_LOCK" 2>/dev/null; then
        read -r pid since hkind hstart < "$CFB_LOCK/owner" 2>/dev/null
        if [[ ! "$pid" =~ ^[0-9]+$ || ! "$since" =~ ^[0-9]+$ ]]; then
            # being made this very moment (the owner file follows the directory), or left half-made long ago
            age=$(( now - $(stat -c %Y "$CFB_LOCK" 2>/dev/null || echo "$now") ))
            if (( age < 10 )); then CFB_LOCK_WHY="another sync is starting"; return 1; fi
            _cfb_log "a lock without an owner (${age} s old) was taken over"
        elif ! kill -0 "$pid" 2>/dev/null || [[ -n "$hstart" && "$(_cfb_pid_start "$pid")" != "$hstart" ]]; then
            _cfb_log "the lock of a ${hkind:-sync} that is gone (pid $pid, $(( (now - since) / 60 )) min) was taken over"
        else
            age=$(( now - since ))
            if (( age <= CFB_STUCK_AFTER )); then CFB_LOCK_WHY="a ${hkind:-sync} (pid $pid) has been running for ${age} s"; return 1; fi
            if [[ "$hkind" == sync ]]; then
                _cfb_log "a sync has held the lock for $(( age / 60 )) min (pid $pid): stopped, the next one starts afresh"
                _cfb_kill_tree "$pid"
            else
                _cfb_log "a ${hkind:-request} has held the lock for $(( age / 60 )) min (pid $pid): taken over"
            fi
            _cfb_state_set '.stuck = {at: $now, minutes: $m, pid: $p, kind: $k}' --argjson now "$now" --argjson m $(( age / 60 )) --arg p "$pid" --arg k "${hkind:-sync}" >/dev/null 2>&1
        fi
        rm -rf "${CFB_LOCK:?}"
        mkdir "$CFB_LOCK" 2>/dev/null || { CFB_LOCK_WHY="another sync took the lock first"; return 1; }
    fi
    printf '%s %s %s %s\n' "$BASHPID" "$now" "$kind" "$(_cfb_pid_start "$BASHPID")" > "$CFB_LOCK/owner"
    return 0
}

# _cfb_lock_wait SECONDS KIND — take the lock, waiting for a running sync up to SECONDS
_cfb_lock_wait() {
    local i
    for (( i = 0; i <= $1; i++ )); do _cfb_lock_take "${2:-request}" && return 0; sleep 1; done
    return 1
}

# give the lock back (only the process that holds it)
_cfb_lock_drop() {
    local pid
    read -r pid _ < "$CFB_LOCK/owner" 2>/dev/null
    [[ "$pid" == "$BASHPID" ]] && rm -rf "${CFB_LOCK:?}"
    return 0
}

_cfb_sync_locked() {
    local force="${1:-}" now st rows raw_hash itemsj items hash last_verify verify=false
    now=$(date +%s)
    _cfb_enabled || return 0
    CFB_ERR_CODE=""; CFB_ERR=""
    rm -f "$CFB_RL_MARK"
    _cfb_state_set '.last_attempt = $now' --argjson now "$now" >/dev/null 2>&1
    _cfb_token_load
    if [[ -z "$CFB_TOKEN" ]]; then _cfb_fail token_missing "The Cloudflare token is gone (the secret $CFB_SECRET was deleted?). Turn the switch off and on again with a token."; return 1; fi
    if ! _cfb_pull; then
        # CrowdSec no longer knows the key (its database was reset, the bouncer deleted by hand): the bouncer is DCS's own, so it is
        # registered again with a fresh key, once, and asked again
        [[ "$CFB_ERR_CODE" == lapi_key ]] && _cfb_bouncer_register && CFB_ERR_CODE="" && _cfb_pull || return 1
        _cfb_state_set '.repaired = {at: $now, what: ["the bouncer, registered again in CrowdSec"]}' --argjson now "$now" >/dev/null 2>&1
    fi
    rows="$CFB_ROWS"
    # CrowdSec answered: an error of the pull (its API, the key, the token) is over, whatever happens at Cloudflare below
    _cfb_state_set 'if ((.error.code // "") | test("^(lapi_|token_)")) then .error = null else . end' >/dev/null 2>&1
    # what the page shows while this runs: "working through N addresses"
    _cfb_state_set '.last_pull = $now | .pulled = $n | .running = {since: $now, rows: $n}' --argjson now "$now" --argjson n "$(jq 'length' <<< "$rows")" >/dev/null 2>&1
    st=$(_cfb_state)
    # the items are worked out again only when the bans or the settings changed. The key is kept IN the items file, so the file is reused
    # only for exactly what it was made from (the key in the state was written only after a push that succeeded: a push that failed left
    # the file of the new settings beside the key of the old ones, and turning the community list off reused its 10,000 items)
    raw_hash=$(printf 'rows=%s|capacity=%s|origins=%s|protected=%s' "$(jq -c 'map([.value, .origin, .id])' <<< "$rows")" "$(_cfb_capacity)" "$(_cfb_origins)" "$(_cs_protected_addresses 2>/dev/null | cut -f2 | sort -u | tr '\n' ' ')" | sha256sum | cut -c1-32)
    if [[ -s "$CFB_ITEMS" ]] && jq -e --arg k "$raw_hash" '.key == $k and (.items | type == "array")' "$CFB_ITEMS" >/dev/null 2>&1; then
        itemsj=$(cat "$CFB_ITEMS")
    else
        itemsj=$(_cfb_items "$rows") || { _cfb_fail internal "Could not work out the list's items"; return 1; }
        itemsj=$(jq -c --arg k "$raw_hash" '. + {key: $k}' <<< "$itemsj")
        (umask 077; printf '%s\n' "$itemsj" > "$CFB_ITEMS.tmp") && mv -f "$CFB_ITEMS.tmp" "$CFB_ITEMS"
    fi
    items=$(jq -c '.items' <<< "$itemsj")
    hash=$(jq -r '[.[].ip] | sort | join(",")' <<< "$items" | sha256sum | cut -c1-32)
    last_verify=$(jq -r '.last_verify // 0' <<< "$st")
    [[ "$force" == force ]] && verify=true
    (( now - last_verify >= CFB_VERIFY_EVERY )) && verify=true
    [[ "$(jq -r '.domains_key // ""' <<< "$st")" != "$(_cfb_domains | paste -sd, -)" ]] && verify=true
    [[ "$(jq -r '.settings_changed // ""' <<< "$st")" != "" ]] && verify=true
    [[ "$(jq -r '.error.code // ""' <<< "$st")" =~ ^(list_gone|missing_permissions|rule_quota|list_quota|cloudflare_error|cloudflare_unreachable|cloudflare_slow|zone_not_found)$ ]] && verify=true
    # in step: the items are those Cloudflare was last given and Cloudflare holds as many. Nothing to send; an old error (a "slow down", a
    # failed push of the same items) no longer applies
    local n_items in_step=false
    n_items=$(jq 'length' <<< "$items")
    [[ "$hash" == "$(jq -r '.hash // ""' <<< "$st")" ]] && [[ "$(jq -r --argjson n "$n_items" '(.cf_items // $n) == $n' <<< "$st")" == true ]] && in_step=true
    if [[ "$in_step" == true && ( "$verify" != true || "$(jq -r '.error.code // ""' <<< "$st")" == rate_limited ) ]]; then
        _cfb_state_set '.last_sync = $now | .error = null | del(.backoff) | del(.settings_changed) | .dropped = $d | .skipped = $s' --argjson now "$now" \
            --argjson d "$(jq '.dropped' <<< "$itemsj")" --argjson s "$(jq '.skipped' <<< "$itemsj")" >/dev/null 2>&1
        return 0
    fi
    # Cloudflare asked to slow down: nothing is asked of it before the wait is over (the error says until when)
    if (( now < $(jq -r '.backoff.until // 0' <<< "$st") )); then return 0; fi
    # the structure: the zones of the domains (looked up again when the domains changed), the list of each account, the rule of each zone
    local zones accounts
    zones=$(jq -c '.zones // []' <<< "$st"); accounts=$(jq -c '.accounts // []' <<< "$st")
    if [[ "$verify" == true ]]; then
        local chk
        chk=$(_cfb_check)
        if [[ "$(jq -r '.ok' <<< "$chk" 2>/dev/null)" != true ]]; then
            _cfb_fail "$(jq -r '.error.code // "cloudflare_error"' <<< "$chk")" "$(jq -r '(.error.message // "The check failed") + (if (.missing // []) | length > 0 then " Missing: " + ((.missing | map(.group + " → " + .item + " → " + .level)) | join(", ")) + "." else "" end)' <<< "$chk")"
            return 1
        fi
        zones=$(jq -c '.zones' <<< "$chk"); accounts=$(jq -c '.accounts' <<< "$chk")
    fi
    local acc lid newz='[]' newa='[]' z repaired=()
    while IFS= read -r acc; do
        [[ -n "$acc" ]] || continue
        lid=$(jq -r --arg a "$acc" 'map(select(.id == $a))[0].list_id // ""' <<< "$accounts")
        if [[ -z "$lid" || "$verify" == true ]]; then
            _cfb_list_ensure "$acc" || return 1
            lid="$CFB_LIST_ID"
            (( CFB_MADE_LIST == 1 )) && repaired+=("the list $CFB_LIST, made again")
        fi
        newa=$(jq -c --arg a "$acc" --arg l "$lid" --argjson acs "$accounts" '. + [($acs | map(select(.id == $a))[0] // {id: $a}) + {list_id: $l}]' <<< "$newa")
    done < <(jq -r 'map(.account) | unique[]' <<< "$zones")
    while IFS= read -r z; do
        [[ -n "$z" ]] || continue
        local rs rid zrow
        zrow=$(jq -c --arg z "$z" 'map(select(.id == $z))[0]' <<< "$zones")
        rs=$(jq -r '.ruleset_id // ""' <<< "$zrow"); rid=$(jq -r '.rule_id // ""' <<< "$zrow")
        if [[ -z "$rid" || "$verify" == true ]]; then
            _cfb_rule_ensure "$z" || return 1
            rs="$CFB_RS_ID"; rid="$CFB_RULE_ID"
            [[ "$CFB_RULE_DID" == made ]] && repaired+=("the custom rule in $(jq -r '.name' <<< "$zrow"), made again")
            [[ "$CFB_RULE_DID" == repaired ]] && repaired+=("the custom rule in $(jq -r '.name' <<< "$zrow"), set back to Block")
        fi
        newz=$(jq -c --argjson r "$zrow" --arg rs "$rs" --arg rid "$rid" '. + [$r + {ruleset_id: $rs, rule_id: $rid}]' <<< "$newz")
    done < <(jq -r '.[].id' <<< "$zones")
    _cfb_state_set '.zones = $z | .accounts = $a | .domains_key = $dk' --argjson z "$newz" --argjson a "$newa" --arg dk "$(_cfb_domains | paste -sd, -)" >/dev/null 2>&1
    # the items: pushed when they changed, or when Cloudflare holds another number of them than DCS pushed (edited there, or a new list)
    local cf_items push=false
    [[ "$hash" != "$(jq -r '.hash // ""' <<< "$st")" ]] && push=true
    (( ${#repaired[@]} > 0 )) && push=true
    if [[ "$verify" == true && "$push" != true ]]; then
        while IFS= read -r acc; do
            cf_items=$(jq -r --arg a "$acc" 'map(select(.id == $a))[0].items // -1' <<< "$newa")
            [[ "$cf_items" == "$(jq 'length' <<< "$items")" ]] || push=true
        done < <(jq -r '.[].id' <<< "$newa")
    fi
    # at most one replacement of the items a minute (a second Settings save, Sync now): the change waits, the next tick sends it
    local last_push; last_push=$(jq -r '.last_push // 0' <<< "$(_cfb_state)")
    local gap; gap=$(_cfb_push_gap)
    if [[ "$push" == true ]] && (( $(date +%s) - last_push < gap )); then
        _cfb_state_set '.push_waiting = {until: ($lp + $g)}' --argjson lp "$last_push" --argjson g "$gap" >/dev/null 2>&1
        return 0
    fi
    if [[ "$push" == true ]]; then
        while IFS=$'\t' read -r acc lid; do
            [[ -n "$acc" ]] || continue
            _cfb_push "$acc" "$lid" "$items" || return 1
        done < <(jq -r '.[] | [.id, .list_id] | @tsv' <<< "$newa")
        _cfb_state_set '.last_push = $now | .accounts = (.accounts | map(.items = $n))' --argjson now "$(date +%s)" --argjson n "$(jq 'length' <<< "$items")" >/dev/null 2>&1
    fi
    _cfb_state_set '.hash = $h | .raw_hash = $rh | .items = $n | .dropped = $d | .skipped = $s | .last_sync = $now | .error = null | del(.pending_op) | del(.backoff) | del(.push_waiting) | del(.settings_changed)
        | (if $v then .last_verify = $now | .cf_items = $n | .cf_checked = $now else . end)
        | (if ($rep | length) > 0 then .repaired = {at: $now, what: $rep} else . end)' \
        --arg h "$hash" --arg rh "$raw_hash" --argjson n "$(jq 'length' <<< "$items")" --argjson d "$(jq '.dropped' <<< "$itemsj")" --argjson s "$(jq '.skipped' <<< "$itemsj")" \
        --argjson now "$(date +%s)" --argjson v "$verify" --argjson rep "$(printf '%s\n' "${repaired[@]}" | jq -R . | jq -sc 'map(select(length > 0))')" >/dev/null 2>&1
    return 0
}

# Called by the API's background loop every few seconds: a sync when the interval has passed since the last attempt
# (the stamp is the time of the last attempt: it moves here, before the sync, so a sync that cannot start is not retried every few seconds)
_cfb_tick() {
    _cfb_enabled || return 0
    local age rc
    age=$(( $(date +%s) - $(stat -c %Y "$CFB_STAMP" 2>/dev/null || echo 0) ))
    (( age >= $(_cfb_interval) )) || return 0
    mkdir -p "$CROWDSEC_STATE_DIR" 2>/dev/null
    touch "$CFB_STAMP" 2>/dev/null || _cfb_log "cannot write $CFB_STAMP: the loop would try every few seconds"
    _cfb_sync; rc=$?
    # a failure is said once, when it begins (the state keeps it for the page)
    if (( rc != 0 && rc != 75 )); then
        _cfb_state | jq -r 'select((.error // null) != null and .error.at == .error.since) | "sync failed: \(.error.code): \(.error.message)"' 2>/dev/null \
            | while IFS= read -r line; do _cfb_log "$line"; done
    fi
    return 0
}

# =============================================================================
# Taking it away: the rule of each zone, the list of each account, the bouncer
# =============================================================================

# _cfb_cleanup — removes DCS's rule from every zone it knows (or finds) and DCS's list from every account. Prints JSON {ok, removed, failed}
_cfb_cleanup() {
    local st zones accounts z acc cleaned=() not_cleaned=() rid rs lid
    st=$(_cfb_state)
    zones=$(jq -c '.zones // []' <<< "$st"); accounts=$(jq -c '[(.accounts // [])[].id]' <<< "$st")
    if [[ "$(jq 'length' <<< "$zones")" == 0 ]]; then
        # nothing remembered (a state file lost): find them the way the check does
        local chk; chk=$(_cfb_check 2>/dev/null)
        zones=$(jq -c '.zones // []' <<< "$chk" 2>/dev/null) || zones='[]'
        accounts=$(jq -c '[(.zones // [])[].account] | unique' <<< "$chk" 2>/dev/null) || accounts='[]'
    fi
    while IFS=$'\t' read -r z name; do
        [[ -n "$z" ]] || continue
        _cfb_cf GET "/zones/$z/rulesets/phases/$CFB_PHASE/entrypoint"
        if [[ "$CFB_CODE" == 404 ]]; then continue; fi
        if [[ "$CFB_CODE" != 2* ]]; then not_cleaned+=("the rule in $name: $(_cfb_cf_msg)"); continue; fi
        rs=$(jq -r '.result.id // ""' <<< "$CFB_BODY")
        rid=$(jq -r --arg r "$CFB_REF" '(.result.rules // []) | map(select((.ref // "") == $r))[0].id // ""' <<< "$CFB_BODY")
        [[ -n "$rid" ]] || continue
        if _cfb_cf DELETE "/zones/$z/rulesets/$rs/rules/$rid"; then cleaned+=("the custom rule in $name"); else not_cleaned+=("the rule in $name: $(_cfb_cf_msg)"); fi
    done < <(jq -r '.[] | [.id, (.name // .id)] | @tsv' <<< "$zones")
    while IFS= read -r acc; do
        [[ -n "$acc" ]] || continue
        _cfb_cf GET "/accounts/$acc/rules/lists" || { not_cleaned+=("the list: $(_cfb_cf_msg)"); continue; }
        lid=$(jq -r --arg n "$CFB_LIST" '(.result // []) | map(select(.name == $n))[0].id // ""' <<< "$CFB_BODY")
        [[ -n "$lid" ]] || continue
        if _cfb_cf DELETE "/accounts/$acc/rules/lists/$lid"; then cleaned+=("the list $CFB_LIST"); else not_cleaned+=("the list $CFB_LIST: $(_cfb_cf_msg)"); fi
    done < <(jq -r '.[]' <<< "$accounts")
    jq -nc --arg r "$(printf '%s\n' "${cleaned[@]}")" --arg f "$(printf '%s\n' "${not_cleaned[@]}")" \
        '{removed: ($r | split("\n") | map(select(length > 0))), failed: ($f | split("\n") | map(select(length > 0)))} | . + {ok: ((.failed | length) == 0)}'
}

# _cfb_bouncer_register — (re)register the bouncer in the running CrowdSec and keep its new key (600). 1 with CFB_ERR when CrowdSec refuses.
_cfb_bouncer_register() {
    local c out key
    CFB_ERR=""
    c=$(_crowdsec_container 2>/dev/null) || c=""
    [[ -n "$c" ]] || { CFB_ERR="CrowdSec is not running"; return 1; }
    CS_NAME="$c"
    _cs_run out bouncers delete "$CFB_NAME" >/dev/null 2>&1 || true
    if ! _cs_run out bouncers add "$CFB_NAME" -o raw; then CFB_ERR="CrowdSec refused to register the bouncer: $(_cs_errline)"; return 1; fi
    key=$(printf '%s\n' "$out" | tail -n 1 | tr -d '\r\n ')
    [[ "$key" =~ ^[A-Za-z0-9+/=_-]{16,200}$ ]] || { CFB_ERR="CrowdSec did not return a key for the bouncer"; return 1; }
    mkdir -p "$CROWDSEC_STATE_DIR" 2>/dev/null
    if ! { (umask 077; printf '%s' "$key" > "$CFB_KEY_FILE.tmp") && mv -f "$CFB_KEY_FILE.tmp" "$CFB_KEY_FILE"; }; then CFB_ERR="Could not keep the bouncer's key"; return 1; fi
    return 0
}

# the bouncer in CrowdSec: delete it (a CrowdSec that is not running keeps it; said in the answer)
_cfb_bouncer_delete() {
    local c out
    c=$(_crowdsec_container 2>/dev/null) || c=""
    [[ -n "$c" ]] || return 1
    CS_NAME="$c"
    _cs_run out bouncers delete "$CFB_NAME" >/dev/null 2>&1 && return 0
    [[ "$CS_ERR" == *"not found"* || "$CS_ERR" == *"does not exist"* ]] && return 0
    return 1
}

# =============================================================================
# What the page shows
# =============================================================================

# health($on; $now; $stale) over the state — off | starting | ok | stale | error (a good sync clears the error, so an error present is the latest word)
_cfb_health_jq='def health($on; $now; $stale):
    if ($on | not) then "off"
    elif (.error // null) != null and .error.code != "rate_limited" then "error"
    elif (.last_sync // 0) == 0 then (if ($now - (.enabled_at // $now)) < $stale then "starting" else "stale" end)
    elif ($now - .last_sync) > $stale then "stale"
    else "ok" end;'

# the few fields /crowdsec/status carries (the dashboard's "Needs your attention" reads them): from local files only, no call to Cloudflare
_cfb_brief() {
    local on=false
    _cfb_enabled && on=true
    _cfb_state | jq -c --argjson on "$on" --argjson now "$(date +%s)" --argjson stale "$CFB_STALE_AFTER" "$_cfb_health_jq"'
        {enabled: $on, health: health($on; $now; $stale), last_sync: (.last_sync // null), last_pull: (.last_pull // null), items: (.items // 0), running: (.running // null),
         error: (if $on then (.error // null) else null end), left_at_cloudflare: (($on | not) and ((.zones // []) | length) > 0 and (.cleaned // false | not))}'
}

# GET /crowdsec/cloudflare — Push bans to Cloudflare: on or off, the token (set or not, never its value), the zones and the list, the last pull and sync, how many addresses Cloudflare holds (read from Cloudflare at most once a minute), the error in plain words, the rights the token needs
handle_crowdsec_cloudflare() {
    local on=false st now cs_running=false bouncer='null' c raw
    now=$(date +%s)
    _cfb_enabled && on=true
    _cfb_token_load
    st=$(_cfb_state)
    # what Cloudflare holds, read back at most once a minute while it is on
    if [[ "$on" == true && -n "$CFB_TOKEN" ]] && (( now - $(jq -r '.cf_checked // 0' <<< "$st") >= 60 )) && [[ "$(jq '(.accounts // []) | length' <<< "$st")" != 0 ]]; then
        local acc n total=0 ok=true
        while IFS= read -r acc; do
            [[ -n "$acc" ]] || continue
            if CFB_HTTP_TIMEOUT=10 _cfb_cf GET "/accounts/$acc/rules/lists"; then
                n=$(jq -r --arg n "$CFB_LIST" '(.result // []) | map(select(.name == $n))[0].num_items // -1' <<< "$CFB_BODY")
                [[ "$n" =~ ^[0-9]+$ ]] && total=$((total + n)) || ok=false
            else ok=false; fi
        done < <(jq -r '.accounts[].id' <<< "$st")
        if [[ "$ok" == true ]]; then
            _cfb_state_set '.cf_items = $n | .cf_checked = $now' --argjson n "$total" --argjson now "$now" >/dev/null 2>&1
        else
            _cfb_state_set '.cf_checked = $now | .cf_items = null' --argjson now "$now" >/dev/null 2>&1
        fi
        st=$(_cfb_state)
    fi
    c=$(_crowdsec_container 2>/dev/null) || c=""
    if [[ -n "$c" ]]; then
        cs_running=true; CS_NAME="$c"
        if raw=$(_cs_json bouncers 8 bouncers list 2>/dev/null); then
            bouncer=$(jq -c --arg n "$CFB_NAME" --argjson now "$now" "$_CS_JQ_DEFS"'fold_bouncers($now) | map(select(.name == $n))[0] // null | if . == null then {registered: false} else {registered: true, name, last_pull: (.last_pull // null), created_at: (.created_at // ""), revoked: (.revoked // false)} end' <<< "$raw" 2>/dev/null) || bouncer='null'
        fi
    fi
    local doms; doms=$(_cfb_domains | jq -R . | jq -sc .)
    _api_success "$(jq -c --argjson on "$on" --argjson now "$now" --argjson stale "$CFB_STALE_AFTER" --arg src "$CFB_TOKEN_SOURCE" --argjson cap "$(_cfb_capacity)" \
        --argjson community "$(_cfb_community && echo true || echo false)" --argjson interval "$(_cfb_interval)" --argjson doms "$doms" \
        --arg domset "$(_cfb_setting CLOUDFLARE_BOUNCER_DOMAINS "")" --argjson perms "$CFB_PERMS" --argjson b "$bouncer" --argjson csr "$cs_running" \
        --arg name "$CFB_NAME" --arg list "$CFB_LIST" --arg ref "$CFB_REF" --arg lorig "$CFB_LOCAL_ORIGINS" --arg corig "$CFB_COMMUNITY_ORIGINS" \
        --arg msg "${CFB_STATUS_MESSAGE:-}" --argjson flists "$CFB_FREE_LISTS" --argjson fitems "$CFB_FREE_ITEMS" --argjson frules "$CFB_FREE_RULES" "$_cfb_health_jq"'
        { enabled: $on, health: health($on; $now; $stale),
          token: {set: ($src != ""), source: (if $src == "" then null else $src end), setting: "CLOUDFLARE_BOUNCER_TOKEN"},
          settings: {capacity: $cap, community: $community, interval: $interval, domains: $doms, domains_from: (if $domset != "" then "CLOUDFLARE_BOUNCER_DOMAINS" else "PROXY_DOMAIN" end),
                     origins: (($lorig | split(",")) + (if $community then ($corig | split(",")) else [] end))},
          bouncer: ({name: $name, crowdsec_running: $csr} + ($b // {})),
          sync: {last_attempt: (.last_attempt // null), last_pull: (.last_pull // null), last_push: (.last_push // null), last_sync: (.last_sync // null), last_verify: (.last_verify // null),
                 pulled: (.pulled // null), items: (.items // 0), dropped: (.dropped // 0), skipped: (.skipped // 0), repaired: (.repaired // null), enabled_at: (.enabled_at // null),
                 running: (.running // null), stuck: (.stuck // null), push_waiting: (.push_waiting // null), backoff: (.backoff // null)},
          cloudflare: {items: (.cf_items // null), checked_at: (.cf_checked // null), list: $list, rule_ref: $ref,
                       accounts: [(.accounts // [])[] | {id, name: (.name // ""), list_id: (.list_id // "")}],
                       zones: [(.zones // [])[] | {name, domains: (.domains // [.domain]), id, plan: (.plan // ""), rule_id: (.rule_id // "")}]},
          error: (if $on then (.error // null) else null end),
          left_at_cloudflare: (($on | not) and ((.zones // []) | length) > 0 and (.cleaned // false | not)),
          permissions: $perms,
          limits: {free: {lists: $flists, items: $fitems, rules: $frules}} }
        + (if $msg != "" then {message: $msg} else {} end)' <<< "$st")"
    CFB_STATUS_MESSAGE=""
}

# _cfb_body_settings BODY — validates and keeps {capacity, community, domains} of a body in the root .env; prints an error and returns 1
_cfb_body_settings() {
    local body="$1" cap com doms d
    cap=$(jq -r 'if has("capacity") then (.capacity | tostring) else "" end' <<< "$body")
    com=$(jq -r 'if has("community") then (.community | tostring) else "" end' <<< "$body")
    doms=$(jq -r 'if has("domains") then (.domains | if type == "array" then join(",") elif type == "string" then . else "\u0000" end) else "\u0001" end' <<< "$body")
    if [[ -n "$cap" ]]; then
        [[ "$cap" =~ ^[0-9]{1,6}$ ]] && (( 10#$cap >= 1 && 10#$cap <= 500000 )) || { printf 'capacity is a number of addresses from 1 to 500000 (the free plan holds 10000)'; return 1; }
    fi
    if [[ -n "$com" && "$com" != true && "$com" != false ]]; then printf 'community is true or false'; return 1; fi
    if [[ "$doms" == $'\x00' ]]; then printf 'domains is a list of domain names'; return 1; fi
    if [[ "$doms" != $'\x01' && -n "$doms" ]]; then
        for d in ${doms//,/ }; do _domain_valid "${d,,}" || { printf '%s is not a domain name' "${d:0:80}"; return 1; }; done
    fi
    [[ -n "$cap" ]] && { _api_env_write CLOUDFLARE_BOUNCER_CAPACITY "$((10#$cap))" || { printf 'could not write .env'; return 1; }; }
    [[ -n "$com" ]] && { _api_env_write CLOUDFLARE_BOUNCER_COMMUNITY "$com" || { printf 'could not write .env'; return 1; }; }
    if [[ "$doms" != $'\x01' ]]; then _api_env_write CLOUDFLARE_BOUNCER_DOMAINS "${doms,,}" || { printf 'could not write .env'; return 1; }; fi
    return 0
}

# the answer for a refused check: 400 with what is missing
_cfb_refuse() {
    local chk="$1" code msg
    code=$(jq -r '.error.code // "cloudflare_error"' <<< "$chk")
    msg=$(jq -r '(.error.message // "The check failed.") + (if (.missing // []) | length > 0 then " Give the token: " + ((.missing | map(.group + " → " + .item + " → " + .level)) | join("; ")) + "." else "" end)' <<< "$chk")
    _api_response 400 "$(jq -c --arg c "$code" --arg m "$msg" '{error: true, code: 400, reason: $c, message: $m, missing: (.missing // []), zones: (.zones // [])}' <<< "$chk")"
}

# POST /crowdsec/cloudflare/verify — Check a Cloudflare token without changing anything: {token?} (else the stored one). Answers the zones it found, the rights that are missing (400) and the free plan's limits it would hit
handle_crowdsec_cloudflare_verify() {
    _api_check_admin || { _api_error 403 "Admin access required"; return; }
    local body="${1:-}" t chk
    [[ -n "$body" ]] || body='{}'
    [[ "$body" == \{* ]] && jq -e . >/dev/null 2>&1 <<< "$body" || { _api_error 400 "Send a JSON body: {\"token\": \"...\"}, or {} to check the stored token"; return; }
    t=$(jq -r '(.token // "") | tostring' <<< "$body")
    if [[ -n "$t" ]]; then CFB_TOKEN="$t"; CFB_TOKEN_SOURCE=body; else _cfb_token_load; fi
    [[ -n "$CFB_TOKEN" ]] || { _api_response 400 "$(jq -nc --arg s "$CFB_SECRET" '{error: true, code: 400, reason: "token_missing", message: ("No Cloudflare token is stored: send {\"token\": \"...\"} (it is kept as the secret " + $s + ").")}')"; return; }
    chk=$(_cfb_check)
    if [[ "$(jq -r '.ok' <<< "$chk" 2>/dev/null)" != true ]]; then _cfb_refuse "$chk"; return; fi
    _api_success "$(jq -c --argjson perms "$CFB_PERMS" '. + {success: true, permissions: $perms, message: ("The token works: " + (.zones | map(.name) | join(", ")) + ".")}' <<< "$chk")"
}

# POST /crowdsec/cloudflare/enable — Turn Push bans to Cloudflare on: {token? (kept as the secret CLOUDFLARE_BOUNCER_TOKEN), capacity?, community?, domains?}. Checks the token's rights first (400 with what is missing, nothing changed), registers the bouncer dcs-cloudflare-bouncer in CrowdSec, makes the list dcs_crowdsec_bans and the blocking custom rule in each zone, and starts the first push in the background (the answer does not wait for it: first_sync "running"; the community blocklist only when the body asks for it)
handle_crowdsec_cloudflare_enable() {
    _api_check_admin || { _api_error 403 "Admin access required"; return; }
    local body="${1:-}" t chk err out c
    [[ -n "$body" ]] || body='{}'
    [[ "$body" == \{* ]] && jq -e . >/dev/null 2>&1 <<< "$body" || { _api_error 400 "Send a JSON body: {\"token\": \"...\", \"capacity\": 10000, \"community\": false}"; return; }
    t=$(jq -r '(.token // "") | tostring' <<< "$body")
    if [[ -n "$t" ]]; then
        _cfb_token_ok "$t" || { _api_response 400 '{"error": true, "code": 400, "reason": "token_invalid", "message": "That is not a Cloudflare API token: paste the token itself (about 40 letters, digits, - and _), not the Global API Key or a key id."}'; return; }
        CFB_TOKEN="$t"; CFB_TOKEN_SOURCE=body
    else
        _cfb_token_load
    fi
    [[ -n "$CFB_TOKEN" ]] || { _api_response 400 "$(jq -nc '{error: true, code: 400, reason: "token_missing", message: "Paste a Cloudflare API token with the rights below: DCS never uses the DNS token for this."}')"; return; }
    # CrowdSec must run: the bouncer is registered in it and the bans come from it
    c=$(_crowdsec_container 2>/dev/null) || c=""
    if [[ -z "$c" ]]; then _cs_target || return; fi
    CS_NAME="$c"
    # the settings in the body first (the check reads the domains and the capacity), put back if the check fails
    local -A before=()
    local k
    for k in CLOUDFLARE_BOUNCER_CAPACITY CLOUDFLARE_BOUNCER_COMMUNITY CLOUDFLARE_BOUNCER_DOMAINS; do before[$k]=$(envfile_get "$BASE_DIR/.env" "$k" 2>/dev/null); done
    # the community blocklist only when the body asks for it (tens of thousands of addresses: a choice, never a default)
    jq -e 'has("community")' >/dev/null 2>&1 <<< "$body" || body=$(jq -c '. + {community: false}' <<< "$body")
    if ! err=$(_cfb_body_settings "$body"); then _api_error 400 "$err"; return; fi
    _cfb_settings_restore() { local k; for k in "${!before[@]}"; do _api_env_write "$k" "${before[$k]}" >/dev/null 2>&1; done; }
    chk=$(_cfb_check)
    if [[ "$(jq -r '.ok' <<< "$chk" 2>/dev/null)" != true ]]; then _cfb_settings_restore; _cfb_refuse "$chk"; return; fi
    # one at a time (a background sync, a second click)
    mkdir -p "$CROWDSEC_STATE_DIR" 2>/dev/null
    _cfb_lock_wait 60 request || { _cfb_settings_restore; _api_error 409 "A sync with Cloudflare is running ($CFB_LOCK_WHY); try again in a minute"; return; }
    # the token is kept before anything is made at Cloudflare (a sync needs it)
    if [[ "$CFB_TOKEN_SOURCE" == body ]]; then
        secrets_set "$CFB_SECRET" "$CFB_TOKEN" 2>/dev/null || { _cfb_lock_drop; _cfb_settings_restore; _api_error 500 "Could not store the token in the secrets store"; return; }
    fi
    # the bouncer: a fresh key (an old registration of the same name goes first)
    if ! _cfb_bouncer_register; then _cfb_lock_drop; _cfb_settings_restore; _api_error 502 "$CFB_ERR"; return; fi
    # the key must open CrowdSec's API before anything is made at Cloudflare
    if ! _cfb_lapi "/v1/decisions?type=ban&scopes=ip,range&origins=$(_cfb_origins)&limit=1"; then
        local why="HTTP $CFB_CODE"; [[ "$CFB_CODE" == 000 ]] && why="no answer at $(_cfb_lapi_url)"
        _cs_run out bouncers delete "$CFB_NAME" >/dev/null 2>&1; rm -f "$CFB_KEY_FILE"
        _cfb_lock_drop; _cfb_settings_restore; _api_error 502 "CrowdSec's API did not accept the new bouncer's key ($why); nothing was made at Cloudflare"; return
    fi
    # the list of each account and the rule of each zone; anything made here is taken away again when a later step fails
    local acc lid made_lists=() made_rules=() newa='[]' newz='[]' z zrow fail="" rs rid
    while IFS= read -r acc; do
        [[ -n "$acc" ]] || continue
        _cfb_list_ensure "$acc" || { fail="$CFB_ERR"; break; }
        lid="$CFB_LIST_ID"
        (( CFB_MADE_LIST == 1 )) && made_lists+=("$acc"$'\t'"$lid")
        newa=$(jq -c --arg a "$acc" --arg l "$lid" --argjson acs "$(jq -c '.accounts' <<< "$chk")" '. + [($acs | map(select(.id == $a))[0] // {id: $a}) + {list_id: $l}]' <<< "$newa")
    done < <(jq -r '.zones | map(.account) | unique[]' <<< "$chk")
    if [[ -z "$fail" ]]; then
        while IFS= read -r z; do
            [[ -n "$z" ]] || continue
            zrow=$(jq -c --arg z "$z" '.zones | map(select(.id == $z))[0]' <<< "$chk")
            _cfb_rule_ensure "$z" || { fail="$CFB_ERR"; break; }
            [[ "$CFB_RULE_DID" == made ]] && made_rules+=("$z"$'\t'"$CFB_RS_ID"$'\t'"$CFB_RULE_ID")
            newz=$(jq -c --argjson r "$zrow" --arg rs "$CFB_RS_ID" --arg rid "$CFB_RULE_ID" '. + [$r + {ruleset_id: $rs, rule_id: $rid}]' <<< "$newz")
        done < <(jq -r '.zones[].id' <<< "$chk")
    fi
    if [[ -n "$fail" ]]; then
        local m
        for m in "${made_rules[@]}"; do IFS=$'\t' read -r z rs rid <<< "$m"; _cfb_cf DELETE "/zones/$z/rulesets/$rs/rules/$rid" >/dev/null 2>&1; done
        for m in "${made_lists[@]}"; do IFS=$'\t' read -r acc lid <<< "$m"; _cfb_cf DELETE "/accounts/$acc/rules/lists/$lid" >/dev/null 2>&1; done
        _cs_run out bouncers delete "$CFB_NAME" >/dev/null 2>&1; rm -f "$CFB_KEY_FILE"
        _cfb_lock_drop; _cfb_settings_restore
        _api_response 400 "$(jq -nc --arg c "${CFB_ERR_CODE:-cloudflare_error}" --arg m "$fail" --argjson perms "$CFB_PERMS" '{error: true, code: 400, reason: $c, message: ($m + " Nothing was left behind at Cloudflare."), missing: (if $c == "missing_permissions" then $perms else [] end)}')"
        return
    fi
    local now; now=$(date +%s)
    (umask 077; jq -nc --argjson z "$newz" --argjson a "$newa" --arg dk "$(_cfb_domains | paste -sd, -)" --argjson now "$now" \
        '{version: 1, zones: $z, accounts: $a, domains_key: $dk, enabled_at: $now, cleaned: false, error: null}' > "$CFB_STATE.tmp") && mv -f "$CFB_STATE.tmp" "$CFB_STATE"
    rm -f "$CFB_ITEMS"
    _api_env_write CLOUDFLARE_BOUNCER_ENABLED true || { _cfb_lock_drop; _api_error 500 "Could not write .env"; return; }
    _cfb_lock_drop
    # the first push runs detached: the answer does not wait for it (the page shows "Turning on" from the status until it is done, and the
    # background loop keeps the list in step from then on)
    ( _cfb_sync force ) </dev/null >/dev/null 2>&1 &
    _cs_cache_clear
    _api_audit_log "${CLIENT_IP:-unknown}" "CROWDSEC_CLOUDFLARE_ON" "${AUTH_USERNAME:-}" "zones: $(jq -r 'map(.name) | join(", ")' <<< "$newz")"
    _api_success "$(jq -nc --argjson z "$newz" --argjson w "$(jq -c '.warnings // []' <<< "$chk")" \
        '{success: true, enabled: true, first_sync: "running", zones: [$z[] | .name], warnings: $w,
          message: ("Turned on: the list and the rule are made in " + ([$z[] | .name] | join(", ")) + ", and DCS is pushing the bans to Cloudflare now.")}')"
}

# POST /crowdsec/cloudflare/disable — Turn Push bans to Cloudflare off: the background sync stops, the bouncer dcs-cloudflare-bouncer is deleted in CrowdSec; {cleanup: true} also deletes the custom rule of each zone and the list at Cloudflare (otherwise they stay, frozen, with the last bans), {forget_token: true} deletes the stored token. Safe to repeat (cleanup after an earlier off)
handle_crowdsec_cloudflare_disable() {
    _api_check_admin || { _api_error 403 "Admin access required"; return; }
    local body="${1:-}" cleanup forget was=false res='null' bdel="kept" note=""
    [[ -n "$body" ]] || body='{}'
    [[ "$body" == \{* ]] && jq -e . >/dev/null 2>&1 <<< "$body" || { _api_error 400 "Send a JSON body: {\"cleanup\": true}"; return; }
    cleanup=$(jq -r '.cleanup == true' <<< "$body"); forget=$(jq -r '.forget_token == true' <<< "$body")
    _cfb_enabled && was=true
    _api_env_write CLOUDFLARE_BOUNCER_ENABLED false || { _api_error 500 "Could not write .env"; return; }
    # a sync that is on its way finishes first (it sees the switch off from then on)
    mkdir -p "$CROWDSEC_STATE_DIR" 2>/dev/null
    _cfb_lock_wait 60 request || _cfb_log "turning off without the lock: $CFB_LOCK_WHY"
    if _cfb_bouncer_delete; then bdel=deleted; else bdel=kept; note="CrowdSec is not running, so the bouncer $CFB_NAME is still registered there (its key file is gone): delete it on the Bouncers tab once CrowdSec runs. "; fi
    rm -f "$CFB_KEY_FILE" "$CFB_ITEMS"
    if [[ "$cleanup" == true ]]; then
        _cfb_token_load
        if [[ -n "$CFB_TOKEN" ]]; then
            res=$(_cfb_cleanup)
        else
            res='{"ok": false, "removed": [], "failed": ["no token is stored, so DCS cannot reach Cloudflare: delete the list dcs_crowdsec_bans and the custom rule by hand"]}'
        fi
        if [[ "$(jq -r '.ok' <<< "$res")" == true ]]; then
            _cfb_state_set '.cleaned = true | .zones = [] | .accounts = [] | .error = null | .hash = null | .raw_hash = null | .disabled_at = $now' --argjson now "$(date +%s)" >/dev/null 2>&1
        else
            _cfb_state_set '.cleaned = false | .disabled_at = $now' --argjson now "$(date +%s)" >/dev/null 2>&1
        fi
    else
        _cfb_state_set '.disabled_at = $now | .error = null' --argjson now "$(date +%s)" >/dev/null 2>&1
    fi
    _cfb_lock_drop
    if [[ "$forget" == true ]]; then
        secrets_delete "$CFB_SECRET" >/dev/null 2>&1 || true
        [[ -n "$(envfile_get "$BASE_DIR/.env" "$CFB_SECRET" 2>/dev/null)" ]] && _api_env_write "$CFB_SECRET" ""
    fi
    _cs_cache_clear
    _api_audit_log "${CLIENT_IP:-unknown}" "CROWDSEC_CLOUDFLARE_OFF" "${AUTH_USERNAME:-}" "cleanup: $cleanup$([[ "$forget" == true ]] && printf ', token forgotten')"
    local left st; st=$(_cfb_state)
    left=$(jq -r '((.zones // []) | length) > 0 and (.cleaned // false | not)' <<< "$st")
    _api_success "$(jq -nc --argjson was "$was" --arg b "$bdel" --argjson res "$res" --argjson left "$left" --arg note "$note" --argjson forget "$forget" --argjson n "$(jq '.items // 0' <<< "$st")" \
        '{success: (if $res == null then true else $res.ok end), enabled: false, was_enabled: $was, bouncer: $b, cleanup: $res, left_at_cloudflare: $left, token_forgotten: $forget,
          message: ($note + (if $res == null then (if $left then "Turned off. The list and the custom rule stay at Cloudflare with the last " + ($n | tostring) + " address(es), which no longer change; clean up to remove them." else "Turned off." end)
                    elif $res.ok then "Turned off, and " + (if ($res.removed | length) > 0 then ($res.removed | join(", ")) + " removed from Cloudflare." else "nothing of DCS was left at Cloudflare." end)
                    else "Turned off, but not everything could be removed from Cloudflare: " + ($res.failed | join("; ")) + "." end))}')"
}

# POST /crowdsec/cloudflare/sync — Sync with Cloudflare now (pull the bans, push them when they changed, read the list and the rules back and repair them) and answer the status; within a minute of the last sync the list is not read back, and a change waits for Cloudflare's one change a minute (message says so: "Already synced N s ago", "The change goes to Cloudflare in N s")
handle_crowdsec_cloudflare_sync() {
    _api_check_admin || { _api_error 403 "Admin access required"; return; }
    _cfb_enabled || { _api_error 409 "Push bans to Cloudflare is off"; return; }
    local rc st ago gap t0 recent=false push_before
    # within a minute of the last sync the bans are still read and compared, but the list and the rules are not read back again
    # (Cloudflare takes one change of the list a minute, and its patience is not spent on a click)
    t0=$(date +%s); st=$(_cfb_state); gap=$(_cfb_push_gap)
    ago=$(( t0 - $(jq -r '.last_sync // 0' <<< "$st") ))
    (( ago < gap )) && [[ "$(jq -r '(.error // null) == null' <<< "$st")" == true ]] && recent=true
    push_before=$(jq -r '.last_push // 0' <<< "$st")
    if [[ "$recent" == true ]]; then _cfb_sync; else _cfb_sync force; fi; rc=$?
    if (( rc == 75 )); then _api_error 409 "A sync with Cloudflare is running already; it finishes in a moment"; return; fi
    st=$(_cfb_state)
    if [[ "$(jq -r '(.push_waiting.until // 0)' <<< "$st")" -gt "$t0" ]]; then
        CFB_STATUS_MESSAGE="The change goes to Cloudflare in $(( $(jq -r '.push_waiting.until' <<< "$st") - t0 )) s: it takes one change of the list a minute."
    elif [[ "$recent" == true && "$(jq -r '.last_push // 0' <<< "$st")" == "$push_before" ]]; then
        CFB_STATUS_MESSAGE="Already synced $ago s ago."
    fi
    _cs_cache_clear
    handle_crowdsec_cloudflare
}

# POST /crowdsec/cloudflare/settings — Change how many addresses go to Cloudflare and which: {capacity? (1-500000; the free plan holds 10000), community? (also the community blocklist, within the capacity), domains? (the domains whose zones are protected; [] = all of this server's)}. Nothing is sent from the request: the next sync (within seconds, when it is on) works the items out afresh and sends one change when they differ
handle_crowdsec_cloudflare_settings() {
    _api_check_admin || { _api_error 403 "Admin access required"; return; }
    local body="${1:-}" err
    [[ "$body" == \{* ]] && jq -e . >/dev/null 2>&1 <<< "$body" || { _api_error 400 "Send a JSON body: {\"capacity\": 10000, \"community\": false}"; return; }
    if ! err=$(_cfb_body_settings "$body"); then _api_error 400 "$err"; return; fi
    _api_audit_log "${CLIENT_IP:-unknown}" "CROWDSEC_CLOUDFLARE_SET" "${AUTH_USERNAME:-}" "$(jq -c '{capacity, community, domains} | with_entries(select(.value != null))' <<< "$body" | head -c 200)"
    # nothing is sent from the request: the items are worked out afresh by the next tick, which comes within seconds (the stamp is
    # put back) and sends one change if, and only if, the items differ from what Cloudflare holds
    rm -f "$CFB_ITEMS"
    if _cfb_enabled; then
        _cfb_state_set '.settings_changed = $now' --argjson now "$(date +%s)" >/dev/null 2>&1
        touch -d '@0' "$CFB_STAMP" 2>/dev/null
        CFB_STATUS_MESSAGE="Saved. The next sync applies it, within a few seconds."
    fi
    _cs_cache_clear
    handle_crowdsec_cloudflare
}
