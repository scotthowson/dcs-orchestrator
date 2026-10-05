# A stack's App-Data on another drive — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a stack created on the hub keep its App-Data at an absolute path of its own (another drive), with every DCS
feature following it, and nothing changing for any other stack.

**Architecture:** The setting is `APP_DATA_DIR=<absolute path>` in the stack's own `.env`. A shared helper in
`.lib/secrets.sh` reads it (`dcs_stack_appdata_override`) and `compose_with_secrets` exports it for Compose and refuses
to start the stack when the drive's marker file is missing. In the API, every place that computes a stack's App-Data
gets an override-only branch in front of its existing expression, so a stack without the setting runs exactly the code it
runs today.

**Tech Stack:** Bash (API `.scripts/api-server.sh`, `.lib/secrets.sh`, `.scripts/run.sh`), jq, Docker Compose; the
dashboard in React + TypeScript (repo `../Docker-Compose-Skeleton-UI`, branch `v2.0.0`).

**Spec:** `docs/superpowers/specs/2026-10-04-stack-appdata-location-design.md`

## Global Constraints

- A stack whose `.env` has no absolute `APP_DATA_DIR` behaves byte-for-byte as today: every existing check in
  `tests/smoke.sh` (4924), `tests/fleet-files.sh` (200), `tests/api-workers.sh` (29) passes unchanged.
- The setting is honoured only when absolute (`/…`). A relative stack value keeps today's meaning (relative to the stack).
- Marker file: `<path>/.dcs-appdata`, JSON `{"stack": "<name>", "created": "<ISO-8601 UTC>"}`.
- Refused locations: `/` itself; `/bin`, `/boot`, `/dev`, `/etc`, `/lib`, `/lib32`, `/lib64`, `/libx32`, `/proc`, `/root`,
  `/run`, `/sbin`, `/sys`, `/usr`, `/var` and everything below them; anything inside `$BASE_DIR`; inside or containing
  another stack's App-Data.
- The API runs under `set -euo pipefail`: every `x=$(cmd)` that can fail gets `|| x=""` (CI's Debian container has
  fewer tools and groups than the desktop).
- Smoke runs under mawk on CI and as root in the Debian job: no gawk-only awk, no reliance on a non-root user except in
  checks guarded by `[[ "$(id -u)" -ne 0 ]]`.
- New Tailwind colour classes: run `node scripts/theme-classes.mjs` (dashboard CI checks `npm run check:themes`).
- Commit only the files a task touches (never `git add -A`: `Stacks/*` and `.api-auth/update-history.json` are local).
- Change from the spec: the dashboard uses the existing `GET /disks` (mount, fstype, avail_bytes) for the drive list
  instead of a new `GET /storage/appdata-targets`; the spec is amended in Task 9.

## Review Focus

- A path with spaces (`/mnt/My Drive/appdata/x`): created, written to `.env` quoted, read back intact, passed to Compose.
- A stack `.env` edited later on the Env page that removes or changes `APP_DATA_DIR`: the stack simply follows the new
  value (no marker required for a removed line; a changed absolute path without a marker is guarded).
- `app_data_dir` with a trailing slash or `//` (`/mnt/d//appdata/x/`): normalised, not refused.
- Two stacks pointing into each other (`/mnt/d/a` and `/mnt/d/a/b`): the second is refused.
- The drive mounted but the folder deleted by hand: treated as missing (no marker) — start refused, not recreated empty.

Each line has its check in the task that owns the code (Tasks 1, 3 and 5).

---

### Task 1: Shared helpers, Compose export and the start guard

**Files:**
- Modify: `.lib/secrets.sh` (add two helpers before `compose_with_secrets`, change `compose_with_secrets`)
- Test: `tests/smoke.sh` (new section after the `# --- CrowdSec's parser folder made by its container` block)

**Interfaces:**
- Produces: `dcs_stack_appdata_override ENV_FILE` → prints the absolute `APP_DATA_DIR` of that `.env` (unquoted, no
  trailing slash), returns 1 when there is none or it is relative.
- Produces: `dcs_appdata_marker_ok DIR STACK` → 0 when `DIR/.dcs-appdata` exists and names STACK.
- Produces: `compose_with_secrets` exports `APP_DATA_DIR` = the override (when there is one) and returns **3** with
  `[DCS] <stack> was not started: its App-Data <path> is not there — is the drive mounted?` on stderr when the
  subcommand is `up`, `start`, `restart`, `create` or `run` and the marker is not ok.

- [ ] **Step 1: Write the failing checks** (append to `tests/smoke.sh` after the CrowdSec-folder block)

```bash
# --- a stack's App-Data on another drive: the .env setting, Compose sees it, a missing drive refuses a start
_AD="$WORK/appdata-on-drive"; mkdir -p "$_AD/drive/media" "$_AD/stack" "$_AD/bin"
printf '#!/bin/bash\necho "ADD=${APP_DATA_DIR:-unset} ARGS=$*"\n' > "$_AD/bin/fakecompose"; chmod +x "$_AD/bin/fakecompose"
printf 'services:\n  a:\n    image: alpine:3\n' > "$_AD/stack/docker-compose.yml"
printf 'PUID=1000\nAPP_DATA_DIR="%s"\n' "$_AD/drive/media/" > "$_AD/stack/.env"
check "appdata: the stack's absolute value, unquoted, no trailing slash" "$_AD/drive/media" "$(_lib dcs_stack_appdata_override "$_AD/stack/.env")"
printf 'APP_DATA_DIR=./App-Data\n' > "$_AD/rel.env"; printf 'PUID=1000\n' > "$_AD/none.env"
check "appdata: a relative value is not an override" "1|" "$(_o=$(_lib dcs_stack_appdata_override "$_AD/rel.env"); echo "$?|$_o")"
check "appdata: no line, no override" "1|" "$(_o=$(_lib dcs_stack_appdata_override "$_AD/none.env"); echo "$?|$_o")"
printf 'APP_DATA_DIR="/mnt/My Drive/appdata/x" # on the big disk\n' > "$_AD/space.env"
check "appdata: a path with spaces and a comment" "/mnt/My Drive/appdata/x" "$(_lib dcs_stack_appdata_override "$_AD/space.env")"
printf 'APP_DATA_DIR=/mnt/d//appdata/x/\n' > "$_AD/dbl.env"
check "appdata: doubled and trailing slashes are normalised" "/mnt/d/appdata/x" "$(_lib dcs_stack_appdata_override "$_AD/dbl.env")"
check "appdata: no marker, the start is refused (3) with the reason" "3|yes" "$(_o=$(DOCKER_COMPOSE_CMD="$_AD/bin/fakecompose" _lib compose_with_secrets "$_AD/stack/docker-compose.yml" "$_AD/stack/.env" up -d 2>&1); echo "$?|$(grep -q 'is not there' <<< "$_o" && echo yes)")"
check "appdata: no marker, a stop still runs" "0" "$(DOCKER_COMPOSE_CMD="$_AD/bin/fakecompose" _lib compose_with_secrets "$_AD/stack/docker-compose.yml" "$_AD/stack/.env" stop >/dev/null 2>&1; echo $?)"
printf '{"stack": "stack", "created": "2026-10-04T00:00:00Z"}\n' > "$_AD/drive/media/.dcs-appdata"
check "appdata: with the marker, Compose gets the stack's value" "ADD=$_AD/drive/media ARGS=-f $_AD/stack/docker-compose.yml --env-file $_AD/stack/.env up -d" "$(APP_DATA_DIR=./App-Data DOCKER_COMPOSE_CMD="$_AD/bin/fakecompose" _lib compose_with_secrets "$_AD/stack/docker-compose.yml" "$_AD/stack/.env" up -d 2>/dev/null)"
printf '{"stack": "other", "created": "2026-10-04T00:00:00Z"}\n' > "$_AD/drive/media/.dcs-appdata"
check "appdata: a marker naming another stack is refused" "3" "$(DOCKER_COMPOSE_CMD="$_AD/bin/fakecompose" _lib compose_with_secrets "$_AD/stack/docker-compose.yml" "$_AD/stack/.env" restart >/dev/null 2>&1; echo $?)"
printf '{"stack": "stack", "created": "2026-10-04T00:00:00Z"}\n' > "$_AD/drive/media/.dcs-appdata"
check "appdata: a stack without the setting keeps the caller's environment" "ADD=./App-Data ARGS=-f $_AD/stack/docker-compose.yml --env-file $_AD/none.env up -d" "$(APP_DATA_DIR=./App-Data DOCKER_COMPOSE_CMD="$_AD/bin/fakecompose" _lib compose_with_secrets "$_AD/stack/docker-compose.yml" "$_AD/none.env" up -d 2>/dev/null)"
```

The stack name the guard uses is the basename of the compose file's folder (`stack` here).

- [ ] **Step 2: Run the section, verify it fails**

Run: extract the block into a scratch file and run it with the `_lib`/`check` harness (as in earlier sections), e.g.
`bash -c 'API=$PWD/.scripts/api-server.sh; WORK=$(mktemp -d); PASS=0; FAIL=0; check(){ …; }; _lib(){ …; }; source block.sh'`
Expected: FAIL — `dcs_stack_appdata_override: command not found` (empty outputs).

- [ ] **Step 3: Implement** — in `.lib/secrets.sh`, just above `dcs_ensure_proxy_network`:

```bash
# A stack's App-Data on a drive of its own: the absolute APP_DATA_DIR of its .env (quotes, a trailing comment, doubled and
# trailing slashes dropped); 1 when the stack has none or a relative one (then the usual rule applies: ./App-Data).
dcs_stack_appdata_override() {
    local f="$1" v
    [[ -n "$f" && -f "$f" ]] || return 1
    v=$(sed -nE 's/^[[:space:]]*(export[[:space:]]+)?APP_DATA_DIR=//p' "$f" 2>/dev/null | tail -n 1) || v=""
    v=$(printf '%s' "$v" | sed -E 's/^"([^"]*)".*$/\1/; t; s/^'"'"'([^'"'"']*)'"'"'.*$/\1/; t; s/[[:space:]]+#.*$//; s/[[:space:]]+$//')
    [[ "$v" == /* ]] || return 1
    v=$(printf '%s' "$v" | tr -s '/'); [[ "$v" == / ]] || v="${v%/}"
    printf '%s' "$v"
}
# The drive is really there: the marker DCS wrote when the stack was created names this stack
dcs_appdata_marker_ok() {
    local d="$1" s="$2" m
    [[ -f "$d/.dcs-appdata" ]] || return 1
    m=$(grep -oE '"stack"[[:space:]]*:[[:space:]]*"[^"]*"' "$d/.dcs-appdata" 2>/dev/null | head -n 1 | sed -E 's/.*"([^"]*)"$/\1/') || m=""
    [[ "$m" == "$s" ]]
}
```

and in `compose_with_secrets`, replace the subshell:

```bash
    (
        eval "$(secrets_env_exports "$compose_file" "${env_file:-/dev/null}" "$BASE_DIR/.env")"
        # a stack whose App-Data is on a drive of its own: Compose gets that path (an exported APP_DATA_DIR would otherwise
        # win over the stack's .env), and nothing starts while the drive is not there (Docker would make an empty folder)
        local _ad _st
        if _ad=$(dcs_stack_appdata_override "$env_file"); then
            export APP_DATA_DIR="$_ad"
            _st=$(basename "$(dirname "$compose_file")")
            case " $* " in
                *" up "*|*" start "*|*" restart "*|*" create "*|*" run "*)
                    if ! dcs_appdata_marker_ok "$_ad" "$_st"; then
                        echo "[DCS] $_st was not started: its App-Data $_ad is not there — is the drive mounted?" >&2
                        exit 3
                    fi ;;
            esac
        fi
        ${DOCKER_COMPOSE_CMD:-docker compose} "${args[@]}" "$@"
    )
```

- [ ] **Step 4: Run the section, verify it passes** (11 checks); then `bash -n .lib/secrets.sh` and the whole
  `tests/smoke.sh` — Expected: all previous checks still pass.

- [ ] **Step 5: Commit**

```bash
git add .lib/secrets.sh tests/smoke.sh
git commit -m "feat(appdata): a stack's own APP_DATA_DIR reaches Compose; no start while its drive is missing"
```

### Task 2: The API follows the stack's App-Data

**Files:**
- Modify: `.scripts/api-server.sh` — new `_stack_appdata_dir` next to `_stack_appdata_root` (~line 5703), and the
  override branch at: `_stack_appdata_root`, `handle_maintenance_report` (App-Data size), `_traefik_stack_appdata`,
  `_find_traefik_routes_dir`, `handle_template_deploy` (6 sites: `_check_appdata` ×2, `app_data`, `_pm_ad`,
  `_auth_base`, `_ad`), `handle_template_undeploy` (`_sd_appdata`, `_app_data`), `_authelia_config_file`,
  `_fleet_appdata_status_json`, `_fleet_stack_outside_paths`, `_fleet_stack_cfg_json`, `handle_ui_update_apply`.
- Test: `tests/smoke.sh` (append to the Task 1 section)

**Interfaces:**
- Consumes: `dcs_stack_appdata_override ENV_FILE` (Task 1).
- Produces: `_stack_appdata_override STACK` → `dcs_stack_appdata_override "$COMPOSE_DIR/$STACK/.env"`;
  `_stack_appdata_dir STACK` → the override, else exactly `_stack_appdata_root "$COMPOSE_DIR/$STACK"` as today;
  `_stack_appdata_external STACK` → 0 when the stack has an override.

- [ ] **Step 1: Write the failing checks**

```bash
mkdir -p "$WORK/Stacks/zz-ad/App-Data" "$WORK/Stacks/zz-plain/App-Data"
printf 'services:\n  a:\n    image: alpine:3\n    volumes:\n      - ${APP_DATA_DIR:-./App-Data}/A:/a\n' | tee "$WORK/Stacks/zz-ad/docker-compose.yml" > "$WORK/Stacks/zz-plain/docker-compose.yml"
printf 'APP_DATA_DIR=%s\n' "$_AD/drive/media" > "$WORK/Stacks/zz-ad/.env"; : > "$WORK/Stacks/zz-plain/.env"
check "appdata: a plain stack's App-Data is what it was" "$(APP_DATA_DIR=./App-Data _lib _stack_appdata_root "$WORK/Stacks/zz-plain")" "$(APP_DATA_DIR=./App-Data _lib _stack_appdata_dir zz-plain)"
check "appdata: a plain stack under a global root is what it was" "/srv/ad" "$(APP_DATA_DIR=/srv/ad _lib _stack_appdata_dir zz-plain)"
check "appdata: a stack's own setting wins over the global root" "$_AD/drive/media" "$(APP_DATA_DIR=/srv/ad _lib _stack_appdata_dir zz-ad)"
check "appdata: Nuke & reinstall's root follows it" "$_AD/drive/media" "$(_lib _stack_appdata_root "$WORK/Stacks/zz-ad")"
check "appdata: the resolved compose binds the drive" "$_AD/drive/media/A" "$(APP_DATA_DIR=./App-Data _lib _fleet_stack_cfg_json zz-ad | jq -r '.services.a.volumes[0].source' 2>/dev/null)"
check "appdata: a plain stack's resolved compose is unchanged" "$WORK/Stacks/zz-plain/App-Data/A" "$(APP_DATA_DIR=./App-Data _lib _fleet_stack_cfg_json zz-plain | jq -r '.services.a.volumes[0].source' 2>/dev/null)"
check "appdata: the stack's own drive is not an outside path for a move" "" "$(_lib _fleet_stack_outside_paths zz-ad | grep -F "$_AD/drive/media")"
```

(`_fleet_stack_cfg_json` needs `docker compose`; CI has it. The last two checks are the ones that show today's code
resolving the wrong folder.)

- [ ] **Step 2: Run, verify the new checks fail** (`_stack_appdata_dir: command not found`; the cfg check shows
  `.../zz-ad/App-Data/A`).

- [ ] **Step 3: Implement.** Add above `_stack_appdata_root`:

```bash
# A stack's App-Data on a drive of its own (an absolute APP_DATA_DIR in its .env); 1 when it has none
_stack_appdata_override() { dcs_stack_appdata_override "$COMPOSE_DIR/${1:?}/.env"; }
_stack_appdata_external() { _stack_appdata_override "$1" >/dev/null; }
# Where a stack's App-Data is: its own drive when it has one, else the usual rule (_stack_appdata_root)
_stack_appdata_dir() {
    local ov; ov=$(_stack_appdata_override "$1") && { printf '%s' "$ov"; return 0; }
    _stack_appdata_root "$COMPOSE_DIR/$1"
}
```

In `_stack_appdata_root`, first line of the body:

```bash
    local _ov; _ov=$(dcs_stack_appdata_override "${1%/}/.env") && { printf '%s' "$_ov"; return 0; }
```

At every other listed site, put the override in front of the existing expression, keeping that expression verbatim.
Pattern (example `_traefik_stack_appdata`, line ~13920):

```bash
        _ad=$(_stack_appdata_override "$_s") || _ad="${APP_DATA_DIR:-$COMPOSE_DIR/$_s/App-Data}"
```

Same for: `_find_traefik_routes_dir` (`_ad`), `handle_template_deploy` (`_check_appdata` with `$_check_stack`,
`app_data` / `_pm_ad` / `_auth_base` / `_ad` with the target stack name `$target_stack`), `handle_template_undeploy`
(`_sd_appdata` with `$_sd_stack`, `_app_data` with the target stack), `_authelia_config_file` (`ad` with `$s`),
`_fleet_appdata_status_json` (`ad` with `$name`). `handle_maintenance_report`: when an absolute global root is not set,
sum each stack's `_stack_appdata_dir` instead of `Stacks/*/App-Data` only for stacks with an override (add their `du`
to the existing total).

`_fleet_stack_outside_paths` and `_fleet_stack_cfg_json`: run Compose with the stack's value:

```bash
    local _ov; _ov=$(_stack_appdata_override "$1") || _ov=""
    cfg=$( cd "$dir" 2>/dev/null && { [[ -z "$_ov" ]] || export APP_DATA_DIR="$_ov"; } && timeout 20 $DOCKER_COMPOSE_CMD "${args[@]}" config --format json 2>/dev/null ) || cfg=""
```

and in `_fleet_stack_outside_paths` drop the stack's own override and anything below it from the list
(`[[ -n "$_ov" && ( "$p" == "$_ov" || "$p" == "$_ov"/* ) ]] && continue`).
`handle_ui_update_apply`: prefix the `up` with the same export for the stack that holds DCS-UI.

- [ ] **Step 4: Run, verify pass**; then the whole smoke suite (all previous checks unchanged).

- [ ] **Step 5: Commit** — `git add .scripts/api-server.sh tests/smoke.sh` ·
  `feat(appdata): the API finds a stack's App-Data on its own drive`

### Task 3: Creating a stack with its App-Data on a drive

**Files:**
- Modify: `.scripts/api-server.sh` — `handle_create_stack` (~line 7820); new `_appdata_location_check`
- Test: `tests/smoke.sh`

**Interfaces:**
- Consumes: `_stack_appdata_dir`, `_stack_appdata_override` (Task 2).
- Produces: `POST /stacks {name, app_data_dir?, app_data_adopt?}` → 201-style success JSON gains
  `"app_data": {"path", "external": true}`; refusals are 400 with a sentence; `_appdata_location_check PATH STACK`
  prints the normalised path or `__error=<why>` and returns 1.

- [ ] **Step 1: Failing checks**

```bash
_DRV="$WORK/drive2"; mkdir -p "$_DRV/appdata" "$_DRV/used"; : > "$_DRV/used/keep.txt"
check "create: a stack with its App-Data on a drive" "true|$_DRV/appdata/zz-new" "$(auth_request POST /stacks "{\"name\":\"zz-new\",\"app_data_dir\":\"$_DRV/appdata/zz-new/\"}" | body_of | jq -r '"\(.success)|\(.app_data.path)"')"
check "create: the folder, its marker and the .env line" "yes|zz-new|APP_DATA_DIR=\"$_DRV/appdata/zz-new\"" "$([[ -d "$_DRV/appdata/zz-new" ]] && echo yes)|$(jq -r .stack "$_DRV/appdata/zz-new/.dcs-appdata")|$(grep '^APP_DATA_DIR=' "$WORK/Stacks/zz-new/.env")"
for _bad in / /etc/x /usr/local/x /var/lib/x /proc/x "$WORK/Stacks/zz-x" relative/path "$_DRV/nope/deeper/x"; do
    check "create: refused location $_bad" 400 "$(auth_request POST /stacks "{\"name\":\"zz-bad\",\"app_data_dir\":\"$_bad\"}" | status_of)"
done
check "create: inside another stack's App-Data is refused" 400 "$(auth_request POST /stacks "{\"name\":\"zz-in\",\"app_data_dir\":\"$_DRV/appdata/zz-new/sub\"}" | status_of)"
check "create: a folder that already holds files needs adopt" "400|yes" "$(auth_request POST /stacks "{\"name\":\"zz-old\",\"app_data_dir\":\"$_DRV/used\"}" | status_of)|$(auth_request POST /stacks "{\"name\":\"zz-old\",\"app_data_dir\":\"$_DRV/used\",\"app_data_adopt\":true}" | body_of | jq -r 'if .success then "yes" else .message end')"
check "create: a path with spaces" "true" "$(mkdir -p "$_DRV/My Drive"; auth_request POST /stacks "{\"name\":\"zz-sp\",\"app_data_dir\":\"$_DRV/My Drive/zz-sp\"}" | body_of | jq -r .success)"
check "create: the plain create is unchanged" "true|no" "$(auth_request POST /stacks '{"name":"zz-plain2"}' | body_of | jq -r .success)|$(grep -q '^APP_DATA_DIR=' "$WORK/Stacks/zz-plain2/.env" 2>/dev/null && echo yes || echo no)"
```

- [ ] **Step 2: Run, verify they fail** (the API ignores `app_data_dir`: success without the folder).

- [ ] **Step 3: Implement** `_appdata_location_check` (above `handle_create_stack`):

```bash
# Can a new stack keep its App-Data at PATH: absolute, on a mounted drive (its parent exists), not a system folder, not
# DCS's own folder, not inside or around another stack's App-Data. Prints the normalised path, or `__error=<why>` and 1.
_appdata_location_check() {
    local p="$1" stack="$2" s other
    [[ "$p" == /* ]] || { printf '__error=%s\n' "The App-Data location must be a full path, like /mnt/disk2/appdata/$stack"; return 1; }
    [[ ${#p} -le 4096 && "$p" != *$'\n'* && "$p" != *[[:cntrl:]]* ]] || { printf '__error=%s\n' "That is not a usable path"; return 1; }
    p=$(printf '%s' "$p" | tr -s '/'); [[ "$p" == / ]] || p="${p%/}"
    case "/${p#/}/" in */../*|*/./*) printf '__error=%s\n' "Use a path without . or .."; return 1 ;; esac
    case "$p" in
        /|/bin|/bin/*|/boot|/boot/*|/dev|/dev/*|/etc|/etc/*|/lib|/lib/*|/lib32|/lib32/*|/lib64|/lib64/*|/libx32|/libx32/*|/proc|/proc/*|/root|/root/*|/run|/run/*|/sbin|/sbin/*|/sys|/sys/*|/usr|/usr/*|/var|/var/*)
            printf '__error=%s\n' "$p is a system folder: choose a folder on a data drive (under /mnt, /media, /srv, /opt or /home)"; return 1 ;;
    esac
    [[ "$p" == "$BASE_DIR" || "$p" == "$BASE_DIR"/* ]] && { printf '__error=%s\n' "$p is inside DCS's own folder: leave the location empty to keep it in the stack's folder"; return 1; }
    [[ -d "$(dirname "$p")" ]] || { printf '__error=%s\n' "$(dirname "$p") does not exist: is the drive mounted?"; return 1; }
    for s in "$COMPOSE_DIR"/*/; do
        s="${s%/}"; s="${s##*/}"; [[ "$s" == "$stack" ]] && continue
        other=$(_stack_appdata_override "$s") || continue
        if [[ "$p" == "$other" || "$p" == "$other"/* || "$other" == "$p"/* ]]; then
            printf '__error=%s\n' "$p overlaps the App-Data of $s ($other)"; return 1
        fi
    done
    printf '%s' "$p"
}
```

In `handle_create_stack`, after the name checks and before `mkdir -p "$stack_dir"`:

```bash
    local _adr _ad="" _adopt
    _adr=$(printf '%s' "$body" | jq -r '.app_data_dir // empty | strings' 2>/dev/null) || _adr=""
    _adopt=$(printf '%s' "$body" | jq -r '.app_data_adopt // false' 2>/dev/null) || _adopt=false
    if [[ -n "$_adr" ]]; then
        _ad=$(_appdata_location_check "$_adr" "$name") || { _api_error 400 "${_ad#__error=}"; return; }
        if [[ -d "$_ad" && -n "$(ls -A "$_ad" 2>/dev/null | grep -vx '.dcs-appdata' | head -n 1)" && "$_adopt" != true ]]; then
            _api_error 400 "$_ad already holds files: confirm to use them for $name (app_data_adopt)"; return
        fi
        { mkdir -p -- "$_ad" 2>/dev/null || { sudo -n mkdir -p -- "$_ad" && sudo -n chown "${PUID:-$(id -u)}:${PGID:-$(id -g)}" "$_ad"; }; } 2>/dev/null \
            || { _api_error 400 "$_ad cannot be created by this server's user (and sudo is not available)"; return; }
        chown "${PUID:-$(id -u)}:${PGID:-$(id -g)}" "$_ad" 2>/dev/null || true
        printf '{"stack": "%s", "created": "%s"}\n' "$name" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" > "$_ad/.dcs-appdata" 2>/dev/null \
            || { _api_error 400 "$_ad is not writable by this server's user"; return; }
    fi
```

When writing the stack's `.env` (the existing heredoc), append, when `_ad` is set:

```bash
    [[ -n "$_ad" ]] && printf '\n# This stack keeps its App-Data on a drive of its own (chosen when it was created)\nAPP_DATA_DIR="%s"\n' "$_ad" >> "$stack_dir/.env"
```

and add `\"app_data\": {\"path\": \"$(_api_json_escape "$_ad")\", \"external\": true}` to the success JSON when set.

- [ ] **Step 4: Run, verify pass**; whole smoke suite.
- [ ] **Step 5: Commit** — `feat(appdata): POST /stacks takes app_data_dir (checked, created, marked)`

### Task 4: The stack list, the stack page and deleting a stack

**Files:**
- Modify: `.scripts/api-server.sh` — `handle_stacks` (line ~2761 entry JSON), `handle_stack_detail` (~2840),
  `handle_delete_stack` (~7900)
- Test: `tests/smoke.sh`

**Interfaces:**
- Produces: `GET /stacks` entries and `GET /stacks/{name}` gain
  `"app_data": {"path": "<abs>", "external": bool, "ok": bool, "free_bytes": int|null}`;
  `POST /stacks/{name}/delete` success JSON gains `"app_data_kept": "<abs path>"` for an external one.

- [ ] **Step 1: Failing checks**

```bash
check "list: a stack on its own drive" "true|true|$_DRV/appdata/zz-new" "$(auth_request GET /stacks | body_of | jq -r '.stacks[] | select(.name == "zz-new") | "\(.app_data.external)|\(.app_data.ok)|\(.app_data.path)"')"
check "list: a plain stack" "false|true|$WORK/Stacks/zz-plain2/App-Data" "$(auth_request GET /stacks | body_of | jq -r '.stacks[] | select(.name == "zz-plain2") | "\(.app_data.external)|\(.app_data.ok)|\(.app_data.path)"')"
mv "$_DRV/appdata/zz-new/.dcs-appdata" "$_DRV/appdata/zz-new/.dcs-appdata.off"
check "detail: the drive missing shows" "false" "$(auth_request GET /stacks/zz-new | body_of | jq -r '.app_data.ok')"
mv "$_DRV/appdata/zz-new/.dcs-appdata.off" "$_DRV/appdata/zz-new/.dcs-appdata"
check "delete: the drive's folder is kept and named" "$_DRV/appdata/zz-sp|yes" "$(auth_request POST /stacks/zz-sp/delete | body_of | jq -r '.app_data_kept')|$([[ -d "$_DRV/appdata/zz-sp" || -d "$_DRV/My Drive/zz-sp" ]] && echo yes)"
```

(The `zz-sp` path is `$_DRV/My Drive/zz-sp`; set the expected value to that.)

- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** a helper and use it in the three handlers:

```bash
# {path, external, ok, free_bytes} of a stack's App-Data, for the stack card
_stack_appdata_json() {
    local s="$1" p ext=false ok=true free=null
    if p=$(_stack_appdata_override "$s"); then
        ext=true; dcs_appdata_marker_ok "$p" "$s" || ok=false
    else
        p=$(_stack_appdata_dir "$s") || p=""
    fi
    if [[ "$ok" == true && -d "$p" ]]; then free=$(df -B1 --output=avail -- "$p" 2>/dev/null | tail -n 1 | tr -dc '0-9') || free=""; [[ -n "$free" ]] || free=null; fi
    jq -nc --arg p "$p" --argjson e "$ext" --argjson o "$ok" --argjson f "$free" '{path: $p, external: $e, ok: $o, free_bytes: $f}'
}
```

In `handle_stacks` and `handle_stack_detail` insert `\"app_data\": $(_stack_appdata_json "$stack"),` into the entry
JSON. In `handle_delete_stack`, read the override before the folder is removed and add
`\"app_data_kept\": \"<path>\"` (never remove that folder).

- [ ] **Step 4: Run, verify pass**; whole smoke suite; `./.scripts/api-docs.sh` then `--check`.
- [ ] **Step 5: Commit** — `feat(appdata): the stack list and page say where the App-Data is; deleting keeps it`

### Task 5: A missing drive at boot

**Files:**
- Modify: `.scripts/api-server.sh` — new `_appdata_guard_tick`, called from `_dcs_automation_loop` every minute;
  `.scripts/run.sh` — the failure branch names the reason
- Test: `tests/smoke.sh`

**Interfaces:**
- Consumes: `_stack_appdata_override`, `dcs_appdata_marker_ok`, `_notify_send` (existing: title, message, priority,
  tags, kind, data JSON).
- Produces: `_appdata_guard_tick` — for each hub stack with an override and no valid marker: stops its running
  containers (`compose_with_secrets … stop`), notifies once per missing spell (state `.data/appdata-guard.json`
  `{"<stack>": "missing"}`), notifies again when it is back.

- [ ] **Step 1: Failing checks** (`_notify_send`, `compose_with_secrets` and `_backup_stack_running` stubbed)

```bash
rm -f "$WORK/.data/appdata-guard.json" "$WORK/guard-notes" "$WORK/guard-cmd"
mv "$_DRV/appdata/zz-new/.dcs-appdata" "$_DRV/appdata/zz-new/.off"
_GS='_notify_send() { echo "$1" >> "'"$WORK"'/guard-notes"; }; compose_with_secrets() { echo "$3" > "'"$WORK"'/guard-cmd"; }; _backup_stack_running() { echo c1; }'
_lib eval "$_GS; _appdata_guard_tick; _appdata_guard_tick"
check "guard: a missing drive stops the stack" "stop" "$(cat "$WORK/guard-cmd" 2>/dev/null)"
check "guard: and says so once" "1" "$(grep -c 'not started' "$WORK/guard-notes")"
mv "$_DRV/appdata/zz-new/.off" "$_DRV/appdata/zz-new/.dcs-appdata"
_lib eval "$_GS; _appdata_guard_tick; _appdata_guard_tick"
check "guard: back again is said once" "1" "$(grep -c 'is back' "$WORK/guard-notes")"
check "guard: a plain stack is never touched" "" "$(grep 'zz-plain2' "$WORK/guard-notes")"
```

- [ ] **Step 2: Run, verify fail** (`_appdata_guard_tick: command not found`).
- [ ] **Step 3: Implement** near `_dcs_automation_loop`:

```bash
# A stack whose App-Data is on a drive of its own, with the drive not there (no marker): Docker restarts containers by
# itself at boot and would give them an empty folder on the system disk. They are stopped, and it is said once; and
# once more when the drive is back. State: .data/appdata-guard.json {"<stack>": "missing"}.
_appdata_guard_tick() {
    local sf="$BASE_DIR/.data/appdata-guard.json" st s p was ids
    st=$(jq -c . "$sf" 2>/dev/null) || st='{}'; [[ "$st" == \{* ]] || st='{}'
    for s in "$COMPOSE_DIR"/*/; do
        s="${s%/}"; s="${s##*/}"
        p=$(_stack_appdata_override "$s") || continue
        _fleet_stack_is_hub "$s" 2>/dev/null || [[ ! -f "$COMPOSE_DIR/$s/RUNS-IN-A-VM.txt" ]] || continue
        was=$(jq -r --arg s "$s" '.[$s] // ""' <<< "$st")
        if dcs_appdata_marker_ok "$p" "$s"; then
            if [[ "$was" == missing ]]; then
                _notify_send "💾 $s: its drive is back" "$s: its App-Data $p is back — start the stack from the Stacks page" default "floppy_disk" "appdata" "$(jq -nc --arg s "$s" --arg p "$p" '{stack: $s, path: $p, state: "back"}')" >/dev/null 2>&1 || true
                st=$(jq -c --arg s "$s" 'del(.[$s])' <<< "$st")
            fi
            continue
        fi
        ids=$(_backup_stack_running "$s" 2>/dev/null) || ids=""
        [[ -n "$ids" ]] && { compose_with_secrets "$COMPOSE_DIR/$s/docker-compose.yml" "$COMPOSE_DIR/$s/.env" stop >/dev/null 2>&1 || true; }
        if [[ "$was" != missing ]]; then
            _notify_send "💾 $s was not started" "$s was not started: its App-Data $p is not there — is the drive mounted?" high "warning" "appdata" "$(jq -nc --arg s "$s" --arg p "$p" '{stack: $s, path: $p, state: "missing"}')" >/dev/null 2>&1 || true
            st=$(jq -c --arg s "$s" '. + {($s): "missing"}' <<< "$st")
        fi
    done
    mkdir -p "$(dirname "$sf")" 2>/dev/null; printf '%s\n' "$st" > "$sf.tmp" 2>/dev/null && mv -f "$sf.tmp" "$sf"
    return 0
}
```

  Call it in `_dcs_automation_loop` after `_automation_tick … `: `_appdata_guard_tick >/dev/null 2>&1 || true`.
  In `.scripts/run.sh`'s failure branch, before `log_warning "Failed to start …"`:
  `grep -m1 '\[DCS\] .* is not there' "$compose_output" 2>/dev/null | sed 's/^\[DCS\] //' | while IFS= read -r _r; do log_error "$_r"; done`
  (read `compose_output` before it is removed: move the `rm -f "$compose_output"` below this line).
- [ ] **Step 4: Run, verify pass**; whole smoke suite.
- [ ] **Step 5: Commit** — `feat(appdata): a stack whose drive is missing is stopped and reported, not started empty`

### Task 6: Backups and restores carry the drive's App-Data

**Files:**
- Modify: `.scripts/api-server.sh` — `_backup_part_tar` (new kind `appdata`), `_backup_build` (part after the stack part,
  size measuring), `_backup_restore_run` (restore of `appdata` parts)
- Test: `tests/smoke.sh` (backup section, `FLEET_READER=plain`)

**Interfaces:**
- Produces: manifest part `{kind: "appdata", name: "<stack>", path: "./.dcs-backup/appdata/<stack>.tar",
  appdata_path: "<abs>", files, bytes, sha256}`; restore result `appdata: [<stack>...]`.

- [ ] **Step 1: Failing checks** — back up one stack with an external App-Data holding `a.txt`; the manifest has the
  part; change `a.txt`; restore the stack; `a.txt` is back; the previous copy sits at `<path>.before-restore-<ts>`;
  with the marker removed the restore warns `is not there` and leaves the folder alone; `POST /backups/verify` passes.

```bash
mkdir -p "$_DRV/appdata/zz-new/App"; echo one > "$_DRV/appdata/zz-new/App/a.txt"
_BKF=$(FLEET_READER=plain _lib eval '_backup_build "zz-ad-test.tar.gz" zz-new >/dev/null; echo "$BACKUP_DEST_DIR/zz-ad-test.tar.gz"')
check "backup: the drive's App-Data is a part" "appdata|$_DRV/appdata/zz-new" "$(tar -xzOf "$_BKF" ./.dcs-backup/manifest.json | jq -r '.parts[] | select(.kind == "appdata") | "\(.kind)|\(.appdata_path)"')"
echo two > "$_DRV/appdata/zz-new/App/a.txt"
FLEET_READER=plain _lib eval "_backup_restore_run \"$_BKF\" zz-new >/dev/null"
check "restore: the drive's App-Data comes back" "one|1" "$(cat "$_DRV/appdata/zz-new/App/a.txt")|$(ls -d "$_DRV/appdata/zz-new.before-restore-"* 2>/dev/null | wc -l)"
```

- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement.** `_backup_part_tar`: `appdata) src="$name"; bk_ex=(--exclude=./.trash) ;;`.
  `_backup_build`: `mkdir -p "$stage/.dcs-backup/appdata"`; in the measuring loop add
  `_ov=$(_stack_appdata_override "$s") && { st=$(_backup_du dir "$_ov"); kb=$(( kb + ${st:-0} )); }`; after the stack
  part (still inside the paused section):

```bash
        if _ov=$(_stack_appdata_override "$s"); then
            if dcs_appdata_marker_ok "$_ov" "$s"; then
                f="$stage/.dcs-backup/appdata/$s.tar"; : > "$errf"
                _backup_part_tar appdata "$_ov" > "$f" 2>"$errf"; rc=$?
                _backup_part_note appdata "$s" "$f" "$rc" "./.dcs-backup/appdata/$s.tar" "$(jq -nc --arg p "$_ov" '{appdata_path: $p}')" || true
            else
                bk_warns+=("$s: its App-Data $_ov is not there (drive not mounted?), so it is not in the backup")
            fi
        fi
```

  `_backup_restore_run`: read `bk_ads` (`.parts[] | select(.kind == "appdata" and ($o == "" or .name == $o)) |
  [.name, .appdata_path] | @tsv`), validate each listing with `_backup_listing_check` like the stack parts, add their
  stacks to `bk_want`, and after the stacks loop:

```bash
    for vs in "${bk_ads[@]}"; do
        IFS=$'\t' read -r s v <<< "$vs"
        [[ "$v" == /* ]] || { bk_warns+=("$s: the backup's App-Data path is not absolute, skipped"); continue; }
        if [[ ! -d "$v" ]] || ! dcs_appdata_marker_ok "$v" "$s"; then
            bk_warns+=("$s: its App-Data $v is not there (drive not mounted?), so that part was not restored"); continue
        fi
        _backup_status restoring 82 appdata "Restoring the App-Data of $s..."
        local aside="$v.before-restore-$ts"
        _backup_mv "$v" "$aside" || { bk_warns+=("$s: its App-Data could not be set aside, so it was not restored"); continue; }
        mkdir -p -- "$v"
        tar -xzOf "$archive" --occurrence=1 "./.dcs-backup/appdata/$s.tar" 2>/dev/null | _backup_part_untar "$v" >/dev/null 2>"$pre/$s-appdata.err"
        if [[ "${PIPESTATUS[0]}" != 0 || "${PIPESTATUS[1]}" != 0 ]]; then
            _backup_rm "$v"; _backup_mv "$aside" "$v"
            bk_warns+=("$s: its App-Data could not be written; the folder as it was is back"); continue
        fi
        bk_rads+=("$s")
    done
```

  (`aside` is a sibling on the same drive: no cross-drive copy; it is named in the result as `kept_before_appdata`.)
- [ ] **Step 4: Run, verify pass**; whole smoke suite (all earlier backup checks unchanged).
- [ ] **Step 5: Commit** — `feat(appdata): backups and restores carry a stack's App-Data on its own drive`

### Task 7: Moving such a stack into a VM

**Files:**
- Modify: `.scripts/api-server.sh` — `_fleet_move_data` (copy the external folder into the VM's `App-Data`),
  move-check size (~26859) and `handle_fleet_move_check` folders list, the move's success path (comment the `.env` line)
- Test: `tests/smoke.sh` (move section, with the existing `zz-move` fixtures)

**Interfaces:**
- Consumes: `_stack_appdata_override`, `_fleet_dir_stat`, `_fleet_dir_tar`.
- Produces: `_appdata_unpin STACK` — rewrites `APP_DATA_DIR=` in `Stacks/STACK/.env` to
  `# APP_DATA_DIR=<path>  (on the hub, before the move into a VM; the VM keeps its App-Data in the stack's folder)`.

- [ ] **Step 1: Failing checks** (after the existing `zz-move` move-check checks)

```bash
mkdir -p "$_DRV/appdata/zz-mv/App"; echo hi > "$_DRV/appdata/zz-mv/App/f.txt"
printf '{"stack": "zz-move", "created": "2026-10-04T00:00:00Z"}\n' > "$_DRV/appdata/zz-mv/.dcs-appdata"
cp "$WORK/Stacks/zz-move/.env" "$WORK/zz-move.env.keep" 2>/dev/null || : > "$WORK/zz-move.env.keep"
printf 'APP_DATA_DIR="%s"\n' "$_DRV/appdata/zz-mv" >> "$WORK/Stacks/zz-move/.env"
check "move-check: the drive's App-Data is a folder of the move" "$_DRV/appdata/zz-mv" "$(auth_request GET '/fleet/provision/move-check?stack=zz-move' | body_of | jq -r '.folders[] | select(.path != null) | .path')"
_lib _appdata_unpin zz-move
check "move: the .env line becomes a comment" "1|no" "$(grep -c '^# APP_DATA_DIR=' "$WORK/Stacks/zz-move/.env")|$(_lib dcs_stack_appdata_override "$WORK/Stacks/zz-move/.env" >/dev/null && echo yes || echo no)"
cp "$WORK/zz-move.env.keep" "$WORK/Stacks/zz-move/.env"
```

- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement**:

```bash
# After a stack moved into a VM: its App-Data lives in the VM's stack folder; the hub's .env line becomes a comment
_appdata_unpin() {
    local f="$COMPOSE_DIR/${1:?}/.env" p
    p=$(dcs_stack_appdata_override "$f") || return 0
    sed -i -E "s|^[[:space:]]*(export[[:space:]]+)?APP_DATA_DIR=.*$|# APP_DATA_DIR=\"$p\"  (on the hub, before the move into a VM; the VM keeps its App-Data in the stack's folder)|" "$f"
}
```

  `_fleet_move_data`: after the folder loop, when `_ov=$(_stack_appdata_override "$src")`, the same block as for `$d`
  with `"$_ov"` as the source and `$remote/App-Data` as the destination (free-space check, file count, log lines saying
  "copying App-Data (on <path>)"). `handle_fleet_move_check`: when the stack has an override, add its `_fleet_dir_stat`
  to `kb`/`nfiles` and `{name: "App-Data", path: $_ov, kb, files}` to `dirs`; the move-check size at line ~26859 adds it
  the same way. After the VM has the stack running (where the move logs the success), `_appdata_unpin "$src"`.
- [ ] **Step 4: Run, verify pass**; whole smoke suite and `tests/fleet-files.sh` (200).
- [ ] **Step 5: Commit** — `feat(appdata): a move into a VM takes the drive's App-Data along`

### Task 8: Dashboard — create dialog, stack card, stack page, delete

**Files (repo `../Docker-Compose-Skeleton-UI`):**
- Modify: `src/shared/types.ts` (`StackAppData`, `StackInfo.app_data?`, `StackDetail.app_data?`,
  `StackCreateResponse.app_data?`, `StackDeleteResponse.app_data_kept?`)
- Modify: `src/renderer/api/endpoints.ts` — `createStack(name, opts?: { app_data_dir?: string; app_data_adopt?: boolean })`
- Modify: `src/renderer/components/stacks/CreateStackOverlay.tsx` — the location choice; the saved `.env` keeps the line
- Modify: `src/renderer/components/stacks/StackCard.tsx`, the stack page header (`src/renderer/pages/StackDetail.tsx`)
- Modify: the delete confirmation (where `deleteStack` is called) — names the kept folder
- Modify: `src/renderer/lib/themeClasses.ts` (generated)

**Interfaces:**
- Consumes: `GET /disks` (`{disks: [{mount, fstype, avail_bytes, total_bytes}]}`), `POST /stacks` fields (Task 3),
  `app_data` (Task 4).

- [ ] **Step 1:** Types and `createStack` options.

```ts
/** where a stack's App-Data is (4.0.32): its own drive (external) or the stack's folder */
export interface StackAppData { path: string; external: boolean; ok: boolean; free_bytes: number | null }
```

- [ ] **Step 2:** `CreateStackOverlay`: a segmented choice *In the stack's folder* (default) · *On a drive* · *Custom
  path*. *On a drive* lists `GET /disks` entries (mount, free space via the existing size formatter) and fills
  `<mount>/appdata/<stack name>` (editable, follows the name until edited). On a 400 whose message contains
  `already holds files`, show a confirm ("Use the files already there for <stack>?") and retry with
  `app_data_adopt: true`. Before `saveStackEnv`, when a location is set and the env text has no `APP_DATA_DIR=` line,
  append `APP_DATA_DIR="<path>"` with the same comment the API writes.
- [ ] **Step 3:** `StackCard` and the stack page: under the counts row, a line
  `HardDrive` icon · `App-Data` · path (monospace, truncated with the full path in a tooltip) · free space when external;
  amber `AlertTriangle` + "drive not mounted" when `app_data.ok === false`. Hub stacks only (`placement !== 'vm'`).
- [ ] **Step 4:** Delete confirmation: when the stack's `app_data.external`, add "Its App-Data at <path> is kept."
- [ ] **Step 5:** `npm run -s typecheck`, `node scripts/theme-classes.mjs`, `npm run -s check:themes`,
  `npx vite build` — all pass.
- [ ] **Step 6: Commit** (UI repo) — `feat(stacks): App-Data on another drive — create choice, card label, delete note`

### Task 9: Docs, local end-to-end, release

**Files:**
- Modify: `docs/CONFIGURATION.md` (APP_DATA_DIR per stack), `docs/BACKUP.md` or the backup section (the App-Data part),
  `docs/superpowers/specs/2026-10-04-stack-appdata-location-design.md` (GET /disks instead of the new endpoint),
  `docs/API.md` + catalogue (`./.scripts/api-docs.sh`), `CHANGELOG.md` (4.0.32), `VERSION` (4.0.32)

- [ ] **Step 1:** Docs and changelog; `python3 docs/tools/check-links.py`; `bash docs/tools/gen-templates.sh --check`.
- [ ] **Step 2:** Every CI step locally: lint, shellcheck 0.9 on changed scripts, smoke with mawk, smoke's new sections as
  root in `debian:trixie` with CI's tool list, fleet-files, api-workers, `vm-images/tests/*`, `./setup.sh --dry-run`.
- [ ] **Step 3:** End to end on a throwaway copy (port 9877, `API_AUTH_ENABLED=false`): create `zz-e2e` with App-Data on
  `/mnt/linux_drive/dcs-e2e-appdata/zz-e2e`; deploy the `it-tools` template into it; start; `docker inspect` shows the
  bind under that path; back up the stack, change a file, restore, file back; Nuke & reinstall the container (trash under
  the drive path); move the marker away → start refused with the reason, guard stops it within a minute; marker back →
  starts; delete the stack → folder kept; clean up containers, the stack and the folder.
- [ ] **Step 4:** Dashboard on the dev server against the throwaway API: the create dialog's three choices, the card
  label (plain and external), the missing-drive warning.
- [ ] **Step 5:** Commit, push server (main) and dashboard (branch v2.0.0 + tag v4.0.28), wait for CI on both, tag
  server v4.0.32, confirm the release.
