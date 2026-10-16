#!/bin/bash
# =============================================================================
# stacks-seed.sh — the stack files are the user's, never git's (4.0.58).
#
# Until 4.0.57 git tracked Stacks/<stack>/docker-compose.yml and .env of the ten default stacks. DCS writes those
# files (template deploys, the editors), so on every install they were tracked files with local edits, and one
# "git reset --hard" put the skeleton back over all of them. Now they ship as seeds in .config/stacks-seed/<stack>/
# and git ignores Stacks/.
#
# A seed is the file with "|" in front of every line (docker-compose.yml.seed, .env.seed; stacks_seed_read takes it off).
# A seed with the very content of the file it replaces makes git see a rename, and "git diff --name-only" then names only
# the seed: the 4.0.57 updater would not see that its edited stack files are touched and the update would stop.
#
#   stacks_seed DIR            once per install: what the switch to 4.0.58 took comes back, a fresh checkout is seeded
#   stacks_untrack DIR         stack files left in git's index leave it (the working tree is never touched)
#   stacks_snapshot DIR DEST   every stack's docker-compose.yml and .env copied to DEST/Stacks/, their sha256s in DEST/MANIFEST
#   stacks_guard DIR DEST      every file that differs from that snapshot is put back; prints each path it restored
#   stacks_seed_read SEED      the file a seed stands for, on stdout
# =============================================================================

_STACK_FILES_RE='^Stacks/[^/]+/(docker-compose\.yml|\.env)$'

# git on DIR's own repository: a GIT_DIR left in the environment by a caller must not point it elsewhere
_stacks_git() { local d="$1"; shift; env -u GIT_DIR -u GIT_WORK_TREE -u GIT_INDEX_FILE git -C "$d" "$@"; }
stacks_seed_read() { sed 's/^|//' "$1"; }
_stacks_have_git() { [[ -d "$1/.git" ]] && command -v git >/dev/null 2>&1; }

stacks_untrack() {
    local dir="$1" f
    _stacks_have_git "$dir" || return 0
    local -a stale=()
    while IFS= read -r -d '' f; do
        [[ "$f" =~ $_STACK_FILES_RE ]] || continue
        # HEAD still tracks it (a release before 4.0.58, the minutes of a rollback): that release's updater owns it
        _stacks_git "$dir" cat-file -e "HEAD:$f" 2>/dev/null || stale+=("$f")
    done < <(_stacks_git "$dir" ls-files -z -- Stacks/ 2>/dev/null)
    [[ ${#stale[@]} -eq 0 ]] || _stacks_git "$dir" rm -q --cached -- "${stale[@]}" >/dev/null 2>&1 || true
    return 0
}

stacks_seed() {
    local dir="$1" mark="$1/.data/stack-files-seeded" seed="$1/.config/stacks-seed" f s orig tag
    stacks_untrack "$dir"
    [[ -e "$mark" ]] && return 0
    _stacks_have_git "$dir" || return 0   # a VM of a fleet (code from the hub, no git): its stacks are the hub's to place
    mkdir -p "$dir/.data" "$dir/Stacks" 2>/dev/null || return 0
    # 1. The update from a release that tracked them: git deleted every stack file nobody had edited (the updater put the
    #    edited ones back itself). They come back byte for byte from the commit the updater left (ORIG_HEAD, which is its
    #    backup tag), except a file the owner had deleted (that updater listed it in a backup's .deleted). After a
    #    "git reset --hard" run by hand nothing comes back: an edited file is gone with it, and the skeleton in its place
    #    is what made the stub of 2026-10-16.
    orig=$(_stacks_git "$dir" rev-parse -q --verify 'ORIG_HEAD^{commit}' 2>/dev/null || true)
    tag=$(_stacks_git "$dir" tag -l 'dcs-backup-*' --sort=-refname 2>/dev/null | head -1 || true)
    if [[ -n "$orig" && -n "$tag" && "$(_stacks_git "$dir" rev-parse -q --verify "$tag^{commit}" 2>/dev/null)" == "$orig" ]]; then
        while IFS= read -r -d '' f; do
            [[ "$f" =~ $_STACK_FILES_RE && ! -e "$dir/$f" ]] || continue
            _stacks_git "$dir" cat-file -e "HEAD:$f" 2>/dev/null && continue
            cat "$dir"/.data/update-backups/*/.deleted 2>/dev/null | grep -qxF -- "$f" && continue
            mkdir -p "$dir/${f%/*}" 2>/dev/null || continue
            if _stacks_git "$dir" show "$orig:$f" > "$dir/$f.seed.$$" 2>/dev/null; then
                chmod "$(printf '%o' $(( 0666 & ~8#$(umask) )))" "$dir/$f.seed.$$" 2>/dev/null   # as git checks a file out
                mv -f "$dir/$f.seed.$$" "$dir/$f" && echo "kept $f as it was before the update"
            else
                rm -f "$dir/$f.seed.$$"
            fi
        done < <(_stacks_git "$dir" ls-tree -r -z --name-only "$orig" -- Stacks/ 2>/dev/null)
    fi
    # 2. A fresh checkout (no stack at all): the ten default stacks. A stack deleted later stays deleted (the mark)
    if [[ -d "$seed" ]] && ! compgen -G "$dir/Stacks/*/docker-compose.yml" >/dev/null; then
        for s in "$seed"/*/; do
            s="${s%/}"; s="${s##*/}"
            mkdir -p "$dir/Stacks/$s" || continue
            for f in docker-compose.yml .env; do
                [[ -f "$seed/$s/$f.seed" && ! -e "$dir/Stacks/$s/$f" ]] && stacks_seed_read "$seed/$s/$f.seed" > "$dir/Stacks/$s/$f"
            done
            echo "seeded Stacks/$s"
        done
    fi
    : > "$mark"
}

stacks_snapshot() {
    local dir="$1" dest="$2" f
    mkdir -p "$dest" || return 1
    : > "$dest/MANIFEST"
    for f in "$dir"/Stacks/*/docker-compose.yml "$dir"/Stacks/*/.env; do
        [[ -f "$f" ]] || continue
        f="${f#"$dir"/}"
        mkdir -p "$dest/${f%/*}" && cp -a -- "$dir/$f" "$dest/$f" || return 1
        printf '%s  %s\n' "$(sha256sum < "$dir/$f" | cut -c1-64)" "$f" >> "$dest/MANIFEST"
    done
}

stacks_guard() {
    local dir="$1" dest="$2" sum f
    [[ -s "$dest/MANIFEST" ]] || return 0
    while read -r sum f; do
        [[ -n "$f" && -f "$dest/$f" ]] || continue
        [[ -f "$dir/$f" && "$(sha256sum < "$dir/$f" | cut -c1-64)" == "$sum" ]] && continue
        mkdir -p "$dir/${f%/*}" && cp -a -- "$dest/$f" "$dir/$f" && printf '%s\n' "$f"
    done < "$dest/MANIFEST"
}
