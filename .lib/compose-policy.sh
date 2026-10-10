#!/bin/bash
# =============================================================================
# compose-policy.sh — what a compose file may ask of the host (SECURITY.md, "Compose policy")
#
# Every path that writes or runs a compose file asks _compose_policy_check. It judges the file the way it will
# run: Docker Compose resolves it (`docker compose config --format json`, with the stack's .env and the server's
# environment filled in, every profile on, include: and extends: followed; the stored secrets are left empty), and the rules in .lib/compose-policy.jq read that
# result, so YAML spelling (a value on the next line, flow style, anchors and merge keys, the long volume syntax, a
# ${VAR} the .env sets to /) changes nothing. Where Compose is not there (a VM before Docker is installed, the tests'
# stand-in docker) .lib/compose-policy.py reads the file itself and the same rules judge it; the answer says which.
#
# Two outcomes per finding: refused (what amounts to root on the host: privileged, SYS_ADMIN, the host's PID
# namespace, a mount of / or /etc, the Docker socket writable, ...) and warned (host networking, NET_ADMIN, the
# Docker socket read-only, a device). .config/compose-policy.json (shipped) and .data/compose-policy.local.json
# (this server's own, PUT /config/compose-policy) allow named rules for an image or a stack, each with its reason:
# an allowed refusal becomes a warning, an allowed warning is listed as allowed.
#
# Verdicts are kept in .data/compose-policy-cache.json by the hash of everything they depend on.
# =============================================================================

COMPOSE_POLICY_VERSION=1
[[ -n "${COMPOSE_POLICY:-}" ]] || COMPOSE_POLICY='{}'
COMPOSE_POLICY_SHIPPED="${COMPOSE_POLICY_SHIPPED:-$BASE_DIR/.config/compose-policy.json}"
COMPOSE_POLICY_LOCAL="${COMPOSE_POLICY_LOCAL:-$BASE_DIR/.data/compose-policy.local.json}"
COMPOSE_POLICY_CACHE="${COMPOSE_POLICY_CACHE:-$BASE_DIR/.data/compose-policy-cache.json}"
COMPOSE_POLICY_CACHE_MAX="${COMPOSE_POLICY_CACHE_MAX:-300}"
_COMPOSE_POLICY_LIB="${BASH_SOURCE[0]%/*}"

# _compose_policy_resolve FILE DIR ENV — sets _CP_OUT ({"config", "raw"}), _CP_ENGINE (compose | python | none) and
# _CP_NOTE (why Compose did not judge it). Compose first; the file read by Python when Compose cannot.
_compose_policy_resolve() {
    local file="$1" dir="$2" env="$3" out="" err="" rc=0 tmpe
    _CP_ENGINE=none; _CP_NOTE=""; _CP_OUT=""
    local -a envarg=()
    [[ -n "$env" && -f "$env" ]] && envarg=(--env-file "$env")
    if [[ "${DCS_POLICY_ENGINE:-}" != python && -n "${DOCKER_COMPOSE_CMD:-}" ]]; then
        tmpe=$(mktemp "${TMPDIR:-/tmp}/dcs-policy-err.XXXXXX" 2>/dev/null) || tmpe=/dev/null
        out=$(
            # the stored secrets are not filled in: their values would end up in the findings (a path, a device name).
            # A ${SECRETS_X} is judged as empty, a ${SECRETS_X:-/} as /.
            if declare -F dcs_stack_appdata_override >/dev/null 2>&1; then _ad=""; _ad=$(dcs_stack_appdata_override "$env") && export APP_DATA_DIR="$_ad"; fi
            # shellcheck disable=SC2086  # DOCKER_COMPOSE_CMD is "docker compose" or "docker-compose"
            $DOCKER_COMPOSE_CMD -f "$file" --project-directory "$dir" ${envarg[@]+"${envarg[@]}"} --profile '*' config --format json 2>"$tmpe" </dev/null
        ) || rc=$?
        if [[ "$tmpe" != /dev/null ]]; then
            err=$(grep -v '^\s*$' "$tmpe" 2>/dev/null | grep -vi 'level=warn' | head -3 | cut -c1-300) || err=""
            rm -f -- "$tmpe"
        fi
        if (( rc == 0 )) && [[ "$out" == \{* ]] && jq -e 'type == "object"' >/dev/null 2>&1 <<< "$out"; then
            if command -v python3 >/dev/null 2>&1; then
                local both
                if both=$(printf '%s' "$out" | env -u PYTHONPATH -u PYTHONHOME python3 -I "$_COMPOSE_POLICY_LIB/compose-policy.py" raw "$file" "$dir" "$env" 2>/dev/null) && [[ "$both" == \{* ]]; then
                    _CP_ENGINE=compose; _CP_OUT="$both"; return 0
                fi
            fi
            # no Python: what Compose printed, and the include: lines found by eye (an include is refused unread)
            _CP_ENGINE=compose
            _CP_OUT=$(jq -c --arg inc "$(grep -qE '^["'"'"']?include["'"'"']?[[:space:]]*:|^[{].*["'"'"'{ ,]include["'"'"']?[[:space:]]*:' "$file" 2>/dev/null && echo yes)" \
                '{config: ., raw: {ok: true, reader: "none", include: (if $inc == "yes" then ["(an include: Python is not installed to read)"] else [] end), extends_files: [], env_files: [], lines: {}, realpath: {}}}' <<< "$out")
            return 0
        fi
        if [[ -z "$out" && -z "$err" ]] || [[ "$err" == *"is not a docker command"* || "$err" == *"unknown shorthand flag"* || "$err" == *"unknown flag"* || "$err" == *"command not found"* || "$err" == *"Cannot connect"* ]]; then
            _CP_NOTE="Docker Compose is not available here"
        else
            _CP_NOTE="Docker Compose could not read the file: ${err:-no answer}"
        fi
    else
        _CP_NOTE="Docker Compose was not asked ($([[ -n "${DCS_POLICY_ENGINE:-}" ]] && printf 'DCS_POLICY_ENGINE=%s' "$DCS_POLICY_ENGINE" || printf 'no compose command'))"
    fi
    if command -v python3 >/dev/null 2>&1; then
        out=$(
            if declare -F dcs_stack_appdata_override >/dev/null 2>&1; then _ad=""; _ad=$(dcs_stack_appdata_override "$env") && export APP_DATA_DIR="$_ad"; fi
            env -u PYTHONPATH -u PYTHONHOME python3 -I "$_COMPOSE_POLICY_LIB/compose-policy.py" resolve "$file" "$dir" "$env" 2>/dev/null
        ) || out=""
        if [[ "$out" == \{* ]]; then
            if [[ "$(jq -r '.raw.ok' <<< "$out" 2>/dev/null)" == true ]]; then
                _CP_ENGINE=python; _CP_OUT="$out"; return 0
            fi
            _CP_NOTE+="; the file could not be read: $(jq -r '.raw.error // "?"' <<< "$out" 2>/dev/null)"
        fi
    else
        _CP_NOTE+="; Python 3 is not installed to read it instead"
    fi
    return 1
}

# _compose_policy_key FILE DIR ENV STACK — the cache key: the file, its .env, the root .env, the policy files, this
# call's extra allowances and where it lives
_compose_policy_key() {
    local file="$1" dir="$2" env="$3" stack="$4"
    {
        printf 'v%s\n%s\n%s\n%s\n%s\n%s\n%s\n' "$COMPOSE_POLICY_VERSION" "$file" "$dir" "$stack" "${COMPOSE_POLICY_EXTRA_ALLOW:-}" "${DCS_POLICY_ENGINE:-}" "${DOCKER_COMPOSE_CMD:-}"
        cat -- "$file" 2>/dev/null || true; printf '\n--env\n'
        [[ -z "$env" ]] || cat -- "$env" 2>/dev/null || true; printf '\n--root\n'
        cat -- "$BASE_DIR/.env" 2>/dev/null || true; printf '\n--policy\n'
        cat -- "$COMPOSE_POLICY_SHIPPED" 2>/dev/null || true
        cat -- "$COMPOSE_POLICY_LOCAL" 2>/dev/null || true
    } | sha256sum | cut -c1-64
}

_compose_policy_cache_get() {
    [[ -s "$COMPOSE_POLICY_CACHE" ]] || return 1
    local v
    v=$(jq -c --arg k "$1" '.[$k].verdict // empty' "$COMPOSE_POLICY_CACHE" 2>/dev/null) || return 1
    [[ "$v" == \{* ]] || return 1
    printf '%s' "$v"
}
_compose_policy_cache_put() {
    local key="$1" verdict="$2" tmp
    mkdir -p "${COMPOSE_POLICY_CACHE%/*}" 2>/dev/null || return 0
    tmp="$COMPOSE_POLICY_CACHE.tmp.$$"
    # bounded: the newest COMPOSE_POLICY_CACHE_MAX verdicts are kept
    { jq -c . "$COMPOSE_POLICY_CACHE" 2>/dev/null || echo '{}'; } | jq -c --arg k "$key" --argjson v "$verdict" --argjson t "$(date +%s)" --argjson max "$COMPOSE_POLICY_CACHE_MAX" '
        (if type == "object" then . else {} end) | .[$k] = {at: $t, verdict: $v}
        | if length > $max then (to_entries | sort_by(.value.at) | .[(length - $max):] | from_entries) else . end' > "$tmp" 2>/dev/null \
        && mv -f "$tmp" "$COMPOSE_POLICY_CACHE" 2>/dev/null || true
    rm -f "$tmp" 2>/dev/null
    return 0
}

# _compose_policy_check FILE [STACK] — judges FILE as it would run in STACK's folder (its .env, its relative paths);
# without STACK, as it would run in FILE's own folder. Sets COMPOSE_POLICY (JSON: {engine, cached, refused, warned,
# allowed, note}) and returns 0 (nothing refused), 1 (something refused) or 2 (no engine could read the file: the
# callers refuse new content and let a start through with a warning).
# Optional: COMPOSE_POLICY_ENV_FILE (the .env to fill ${VAR} from; a .env about to be saved), COMPOSE_POLICY_DIR (the
# folder the file runs in), COMPOSE_POLICY_EXTRA_ALLOW (a JSON list of allow entries for this call only).
_compose_policy_check() {
    local file="$1" stack="${2:-}" dir env key cached verdict resolved rc
    COMPOSE_POLICY='{"engine":"none","cached":false,"refused":[],"warned":[],"allowed":[]}'
    [[ -f "$file" ]] || { COMPOSE_POLICY='{"engine":"none","cached":false,"refused":[],"warned":[],"allowed":[],"note":"no compose file"}'; return 0; }
    if [[ -n "${COMPOSE_POLICY_DIR:-}" ]]; then dir="$COMPOSE_POLICY_DIR"
    elif [[ -n "$stack" ]]; then dir="${COMPOSE_DIR:-$BASE_DIR/Stacks}/$stack"
    else dir=$(dirname -- "$file"); fi
    dir=$(realpath -m -- "$dir" 2>/dev/null || printf '%s' "$dir")
    if [[ -n "${COMPOSE_POLICY_ENV_FILE+x}" ]]; then env="$COMPOSE_POLICY_ENV_FILE"; else env="$dir/.env"; fi
    [[ -n "$env" && -f "$env" ]] || env=""

    key=$(_compose_policy_key "$file" "$dir" "$env" "$stack")
    if cached=$(_compose_policy_cache_get "$key"); then
        COMPOSE_POLICY=$(jq -c '. + {cached: true}' <<< "$cached")
        [[ "$(jq -r '.refused | length' <<< "$COMPOSE_POLICY")" == 0 ]] && return 0 || return 1
    fi

    if ! _compose_policy_resolve "$file" "$dir" "$env"; then
        COMPOSE_POLICY=$(jq -nc --arg n "$_CP_NOTE" '{engine: "none", cached: false, refused: [], warned: [], allowed: [], note: $n}')
        return 2
    fi
    resolved="$_CP_OUT"
    verdict=$(jq -c \
        --argjson ctx "$(jq -nc --arg s "$stack" --arg d "$dir" --arg b "$BASE_DIR" --arg c "${COMPOSE_DIR:-$BASE_DIR/Stacks}" '{stack: $s, stack_dir: $d, base_dir: $b, compose_dir: $c}')" \
        --slurpfile shipped <(jq -c . "$COMPOSE_POLICY_SHIPPED" 2>/dev/null || echo '{}') \
        --slurpfile local <(jq -c . "$COMPOSE_POLICY_LOCAL" 2>/dev/null || echo '{}') \
        --argjson extra "$(jq -c 'if type == "array" then . else [] end' <<< "${COMPOSE_POLICY_EXTRA_ALLOW:-[]}" 2>/dev/null || echo '[]')" \
        -f "$_COMPOSE_POLICY_LIB/compose-policy.jq" <<< "$resolved" 2>/dev/null) || verdict=""
    if [[ "$verdict" != \{* ]]; then
        COMPOSE_POLICY=$(jq -nc --arg n "the policy could not be evaluated" '{engine: "none", cached: false, refused: [], warned: [], allowed: [], note: $n}')
        return 2
    fi
    verdict=$(jq -c --arg e "$_CP_ENGINE" --arg n "$_CP_NOTE" --arg r "$(jq -r '.raw.reader // ""' <<< "$resolved" 2>/dev/null)" \
        '{engine: $e, reader: $r, cached: false} + . + (if $n != "" then {note: $n} else {} end)' <<< "$verdict")
    COMPOSE_POLICY="$verdict"
    rc=0; [[ "$(jq -r '.refused | length' <<< "$verdict")" == 0 ]] || rc=1
    # a file that names other compose files (include:, extends: file) is judged afresh every time: they can change alone
    if [[ "$(jq -r '((.raw.include // []) + (.raw.extends_files // [])) | length' <<< "$resolved" 2>/dev/null)" == 0 ]]; then
        _compose_policy_cache_put "$key" "$verdict"
    fi
    return "$rc"
}

# _compose_policy_check_content CONTENT [STACK] — the same for content not written yet: it is judged from a file next
# to where it will live (so ./ paths, include: and env_file: resolve as they will), removed again
_compose_policy_check_content() {
    local content="$1" stack="${2:-}" dir tmp rc=0
    if [[ -n "${COMPOSE_POLICY_DIR:-}" ]]; then dir="$COMPOSE_POLICY_DIR"
    elif [[ -n "$stack" ]]; then dir="${COMPOSE_DIR:-$BASE_DIR/Stacks}/$stack"
    else dir=""; fi
    if [[ -n "$dir" && -d "$dir" && -w "$dir" ]]; then
        tmp=$(mktemp "$dir/.dcs-policy-XXXXXX.yml" 2>/dev/null) || tmp=""
    fi
    if [[ -z "${tmp:-}" ]]; then
        # no folder of its own (an imported template): a private folder stands in, so every absolute path is outside it
        local tdir; tdir=$(mktemp -d "${TMPDIR:-/tmp}/dcs-policy-XXXXXX") || { COMPOSE_POLICY='{"engine":"none","refused":[],"warned":[],"allowed":[],"note":"no temporary folder"}'; return 2; }
        tmp="$tdir/docker-compose.yml"
        [[ -n "$dir" ]] || dir="$tdir"
        printf '%s\n' "$content" > "$tmp"
        COMPOSE_POLICY_DIR="$dir" _compose_policy_check "$tmp" "$stack" || rc=$?
        rm -rf -- "${tdir:?}"
        return "$rc"
    fi
    printf '%s\n' "$content" > "$tmp"
    COMPOSE_POLICY_DIR="$dir" _compose_policy_check "$tmp" "$stack" || rc=$?
    rm -f -- "$tmp"
    return "$rc"
}

# _compose_policy_text [JSON] — the findings as lines a person reads (the editors point at "line N")
_compose_policy_text() {
    jq -r '
        def where: (if .line then "line \(.line): " else "" end) + (if .service then "services.\(.service): " else "" end);
        ((.refused // [])[] | "refused: " + where + .message + " [" + .rule + "]"),
        ((.warned // [])[] | "warning: " + where + .message + " [" + .rule + "]" + (if .allowed_by then " (allowed: " + .allowed_by + ")" else "" end)),
        (if .engine == "none" then "refused: the file could not be checked: " + (.note // "no engine") else empty end)' <<< "${1:-$COMPOSE_POLICY}" 2>/dev/null
}

# _compose_policy_brief [JSON] — one line: what was refused, or what was warned
_compose_policy_brief() {
    jq -r '
        (.refused // []) as $r | (.warned // []) as $w
        | if ($r | length) > 0 then ($r | map((if .service then .service + ": " else "" end) + .message) | join("; "))
          elif .engine == "none" then "the file could not be checked: " + (.note // "no engine")
          else ($w | map((if .service then .service + ": " else "" end) + .message) | join("; ")) end' <<< "${1:-$COMPOSE_POLICY}" 2>/dev/null
}

# _compose_policy_template_env TEMPLATE_JSON — a .env with every variable of a template at its default (written to a
# temporary file whose name is printed): a template is judged as the gallery would deploy it
_compose_policy_template_env() {
    local tj="$1" f
    f=$(mktemp "${TMPDIR:-/tmp}/dcs-policy-env.XXXXXX") || return 1
    if [[ -f "$tj" ]]; then
        jq -r '.variables[]? | select((.name | type) == "string" and (.name | test("^[A-Za-z_][A-Za-z0-9_]*$")))
               | ((.default // "") | tostring | gsub("\n"; " ")) as $v
               | "\(.name)=" + (if ($v | contains("'"'"'")) then $v else "'"'"'" + $v + "'"'"'" end)' "$tj" > "$f" 2>/dev/null || : > "$f"
    fi
    printf '%s' "$f"
}
