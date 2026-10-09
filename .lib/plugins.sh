#!/bin/bash
# =============================================================================
# Plugin System v1.0 — what start.sh uses of it: the plugins directory and its scan. The API manages
# plugins itself (install, enable, hooks: _plugin_exec_hook in .scripts/api-server.sh).
# Plugins live in .plugins/ (see .plugins/README.md)
#
# Requires: Bash 4+
# =============================================================================

if [[ -z "${BASE_DIR:-}" ]]; then
    BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi

PLUGINS_DIR="${BASE_DIR}/.plugins"

# =============================================================================
# INITIALIZATION
# =============================================================================

plugins_init() {
    if [[ ! -d "$PLUGINS_DIR" ]]; then
        mkdir -p "$PLUGINS_DIR"
    fi
    if [[ ! -f "$PLUGINS_DIR/.gitignore" ]]; then
        echo '*/' > "$PLUGINS_DIR/.gitignore"
    fi
}

# =============================================================================
# DISCOVERY & LISTING
# =============================================================================

# Scan plugins directory and return JSON array
plugins_scan() {
    plugins_init
    local result="["
    local first=true

    for plugin_dir in "$PLUGINS_DIR"/*/; do
        [[ ! -d "$plugin_dir" ]] && continue
        local manifest="$plugin_dir/plugin.json"
        [[ ! -f "$manifest" ]] && continue

        local name version description author
        name=$(grep -o '"name"[[:space:]]*:[[:space:]]*"[^"]*"' "$manifest" | head -1 | cut -d'"' -f4)
        version=$(grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' "$manifest" | head -1 | cut -d'"' -f4)
        description=$(grep -o '"description"[[:space:]]*:[[:space:]]*"[^"]*"' "$manifest" | head -1 | cut -d'"' -f4)
        author=$(grep -o '"author"[[:space:]]*:[[:space:]]*"[^"]*"' "$manifest" | head -1 | cut -d'"' -f4)

        name="${name:-$(basename "$plugin_dir")}"
        version="${version:-0.0.0}"
        description="${description:-}"
        author="${author:-}"

        # Count templates
        local templates="["
        local tfirst=true
        for tmpl_dir in "$plugin_dir/templates"/*/; do
            [[ ! -d "$tmpl_dir" ]] && continue
            [[ "$tfirst" == "true" ]] && tfirst=false || templates+=","
            templates+="\"$(basename "$tmpl_dir")\""
        done
        templates+="]"

        # Count hooks
        local hooks="["
        local hfirst=true
        for hook_file in "$plugin_dir/hooks"/*; do
            [[ ! -f "$hook_file" ]] && continue
            [[ "$hfirst" == "true" ]] && hfirst=false || hooks+=","
            hooks+="\"$(basename "$hook_file")\""
        done
        hooks+="]"

        # Check enabled state
        local enabled="true"
        [[ -f "$plugin_dir/.disabled" ]] && enabled="false"

        [[ "$first" == "true" ]] && first=false || result+=","
        result+="{\"name\":\"$name\",\"version\":\"$version\",\"description\":\"$description\",\"author\":\"$author\",\"templates\":$templates,\"hooks\":$hooks,\"enabled\":$enabled}"
    done

    result+="]"
    echo "$result"
}
