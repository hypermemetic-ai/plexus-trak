#!/usr/bin/env bash
# launch-agent.sh — CLI for trak facets + spawning Claude Code agents
#
# Usage:
#   launch-agent.sh ls                       List root facets
#   launch-agent.sh ls hyperforge            List children (name or ID prefix)
#   launch-agent.sh ls hyperforge/MFORGE     Drill deeper with /
#   launch-agent.sh show <name-or-id>        Show facet detail
#   launch-agent.sh tree <name-or-id>        Show subtree
#   launch-agent.sh search <query>           Full-text search
#   launch-agent.sh blocked                  Show blocked facets
#   launch-agent.sh launch <name-or-id>      Spawn Claude Code agent for facet
#   launch-agent.sh status <name-or-id> <s>  Update status
#
# Names are fuzzy-matched against titles. Short ID prefixes work too.

set -euo pipefail

TRAK_PORT="${TRAK_PORT:-44107}"
SUBSTRATE_PORT="${SUBSTRATE_PORT:-4444}"
MODEL="${CLAUDE_MODEL:-sonnet}"
TOKEN_FILE="${HOME}/.plexus/trak/token"

# ── Token ────────────────────────────────────────────────────────────────────

resolve_token() {
    [[ -n "${TRAK_TOKEN:-}" ]] && { echo "$TRAK_TOKEN"; return; }
    [[ -f "$TOKEN_FILE" ]] && { cat "$TOKEN_FILE"; return; }
    login_interactive
}

login_interactive() {
    echo "No saved trak credential." >&2
    read -rp "Username: " username >/dev/tty
    read -rsp "Password: " password >/dev/tty
    echo "" >&2

    local result token
    result=$(synapse -P "$TRAK_PORT" --json trak identity login \
        --username "$username" --password "$password" 2>&1)
    token=$(echo "$result" | grep -o '"access_token":"[^"]*"' | head -1 | cut -d'"' -f4)

    if [[ -z "$token" ]]; then
        echo "User not found — registering..." >&2
        read -rp "Tenant (optional): " tenant >/dev/tty
        local reg_args="--username $username --password $password"
        [[ -n "$tenant" ]] && reg_args="$reg_args --tenant $tenant"
        synapse -P "$TRAK_PORT" --json trak identity register $reg_args >/dev/null 2>&1
        result=$(synapse -P "$TRAK_PORT" --json trak identity login \
            --username "$username" --password "$password" 2>&1)
        token=$(echo "$result" | grep -o '"access_token":"[^"]*"' | head -1 | cut -d'"' -f4)
    fi

    [[ -z "$token" ]] && { echo "Auth failed." >&2; exit 1; }
    mkdir -p "$(dirname "$TOKEN_FILE")"
    echo "$token" > "$TOKEN_FILE"
    chmod 600 "$TOKEN_FILE"
    echo "Authenticated." >&2
    echo "$token"
}

TOKEN=$(resolve_token)

trak() { synapse -P "$TRAK_PORT" --json -t "$TOKEN" trak "$@" 2>&1; }
substrate() { synapse -P "$SUBSTRATE_PORT" --json substrate "$@" 2>&1; }

# ── Resolve ──────────────────────────────────────────────────────────────────
# Resolve a name, ID prefix, or path (hyperforge/MFORGE/schema) to a UUID.

resolve_id() {
    local input="$1"
    local parent="${2:-}"

    # Already a full UUID
    if [[ "$input" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
        echo "$input"
        return
    fi

    # Path with slashes — resolve each segment
    if [[ "$input" == */* ]]; then
        local first="${input%%/*}"
        local rest="${input#*/}"
        local resolved
        resolved=$(resolve_id "$first" "$parent")
        [[ -z "$resolved" ]] && return
        resolve_id "$rest" "$resolved"
        return
    fi

    # Search in children of parent (or roots)
    local listing
    if [[ -n "$parent" ]]; then
        listing=$(trak facet list --parent-id "$parent" 2>/dev/null)
    else
        listing=$(trak facet list 2>/dev/null)
    fi

    # Try exact title match (case-insensitive)
    local match
    match=$(echo "$listing" | python3 -c "
import sys, json
target = '${input}'.lower()
for line in sys.stdin:
    try:
        obj = json.loads(line)
        c = obj.get('content', {})
        if c.get('type') != 'facet_summary': continue
        title = c.get('title', '').lower()
        fid = c.get('id', '')
        # exact match
        if title == target:
            print(fid); exit()
        # prefix match on title
        if title.startswith(target):
            print(fid); exit()
        # ID prefix match
        if fid.startswith(target):
            print(fid); exit()
        # contains match (fuzzy)
        if target in title:
            print(fid); exit()
    except: pass
" 2>/dev/null)

    echo "$match"
}

# ── Formatters ───────────────────────────────────────────────────────────────

format_list() {
    python3 -c "
import sys, json
for line in sys.stdin:
    try:
        obj = json.loads(line)
        c = obj.get('content', {})
        t = c.get('type', '')
        # Handle both facet_summary and search_result
        if t in ('facet_summary', 'search_result'):
            f = c.get('facet', c)  # search_result wraps in 'facet'
            depth = f.get('depth', c.get('depth', 0))
            indent = '  ' * depth
            children = f.get('child_count', c.get('child_count', 0))
            child_str = f' ({children})' if children > 0 else ''
            fid = f.get('id', c.get('id', '?'))[:8]
            status = f.get('status', c.get('status', '?'))
            title = f.get('title', c.get('title', '?'))
            print(f'{fid}  {indent}{title}  [{status}]{child_str}')
        elif t == 'list_summary':
            print(f'  ({c.get(\"total\", 0)} items)')
        elif t == 'info':
            print(f'  {c.get(\"message\", \"\")}')
        elif t == 'error':
            print(f'ERROR: {c.get(\"message\", \"unknown\")}', file=sys.stderr)
    except: pass
    # Also catch top-level errors
    try:
        obj = json.loads(line)
        if obj.get('type') == 'error':
            print(f'ERROR: {obj.get(\"message\", \"unknown\")}', file=sys.stderr)
    except: pass
"
}

format_detail() {
    python3 -c "
import sys, json
for line in sys.stdin:
    try:
        obj = json.loads(line)
        c = obj.get('content', {})
        if c.get('type') not in ('facet_detail', 'facet_created'): continue
        f = c.get('facet', c)
        print(f'  {f[\"title\"]}')
        print(f'  id:     {f[\"id\"]}')
        print(f'  status: {f.get(\"status\", \"?\")}')
        print(f'  owner:  {f.get(\"owner\", \"?\")}')
        body = f.get('body', '')
        if body:
            print(f'')
            for line in body.split('\n')[:20]:
                print(f'  {line}')
            lines = body.split('\n')
            if len(lines) > 20:
                print(f'  ... ({len(lines) - 20} more lines)')
    except: pass
"
}

format_blocked() {
    python3 -c "
import sys, json
for line in sys.stdin:
    try:
        obj = json.loads(line)
        c = obj.get('content', {})
        if c.get('type') != 'blocked': continue
        f = c.get('facet', {})
        blockers = c.get('blocked_by', [])
        bnames = ', '.join(b.get('title','?')[:30] for b in blockers)
        print(f'{f.get(\"id\",\"\")[:8]}  {f.get(\"title\",\"?\")}')
        print(f'          ← {bnames}')
    except: pass
"
}

# ── Commands ─────────────────────────────────────────────────────────────────

cmd_ls() {
    local target="${1:-}"
    if [[ -z "$target" ]]; then
        trak facet list | format_list
    else
        local id
        id=$(resolve_id "$target")
        if [[ -z "$id" ]]; then
            echo "Not found: $target" >&2
            exit 1
        fi
        trak facet list --parent-id "$id" | format_list
    fi
}

cmd_show() {
    local target="${1:?usage: launch-agent.sh show <name-or-id>}"
    local id
    id=$(resolve_id "$target")
    [[ -z "$id" ]] && { echo "Not found: $target" >&2; exit 1; }
    trak facet get --id "$id" | format_detail
}

cmd_tree() {
    local target="${1:?usage: launch-agent.sh tree <name-or-id>}"
    local id
    id=$(resolve_id "$target")
    [[ -z "$id" ]] && { echo "Not found: $target" >&2; exit 1; }
    trak facet tree --id "$id" | format_list
}

cmd_search() {
    local query="${1:?usage: launch-agent.sh search <query>}"
    trak facet search --query "$query" | format_list
}

cmd_grep() {
    local pattern="${1:?usage: launch-agent.sh grep <regex> [--status <s>] [--in <name-or-id>]}"
    shift
    local status_flag="" parent_flag=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --status) status_flag="--status $2"; shift 2 ;;
            --in)
                local pid
                pid=$(resolve_id "$2")
                [[ -n "$pid" ]] && parent_flag="--parent-id $pid"
                shift 2 ;;
            *) shift ;;
        esac
    done
    trak facet grep --pattern "$pattern" $status_flag $parent_flag | format_list
}

cmd_blocked() {
    trak facet blocked | format_blocked
}

cmd_status() {
    local target="${1:?usage: launch-agent.sh status <name-or-id> <status>}"
    local new_status="${2:?usage: launch-agent.sh status <name-or-id> <status>}"
    local id
    id=$(resolve_id "$target")
    [[ -z "$id" ]] && { echo "Not found: $target" >&2; exit 1; }
    trak facet update --id "$id" --status "$new_status" | format_detail
}

cmd_launch() {
    local target="${1:?usage: launch-agent.sh launch <name-or-id>}"
    local id
    id=$(resolve_id "$target")
    [[ -z "$id" ]] && { echo "Not found: $target" >&2; exit 1; }

    # Load facet
    local detail
    detail=$(trak facet get --id "$id")
    local title body status
    title=$(echo "$detail" | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        c = json.loads(line).get('content',{})
        if 'facet' in c: print(c['facet']['title']); break
    except: pass
")
    body=$(echo "$detail" | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        c = json.loads(line).get('content',{})
        if 'facet' in c: print(c['facet'].get('body','') or ''); break
    except: pass
")
    status=$(echo "$detail" | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        c = json.loads(line).get('content',{})
        if 'facet' in c: print(c['facet'].get('status','')); break
    except: pass
")

    # Load children
    local children
    children=$(trak facet list --parent-id "$id" 2>/dev/null | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        c = json.loads(line).get('content',{})
        if c.get('type') == 'facet_summary':
            print(f'- [{c[\"status\"]}] {c[\"title\"]}')
    except: pass
" 2>/dev/null || echo "")

    # Build prompt
    local prompt="You are working on this task:

# ${title}

${body}

Status: ${status}
Facet ID: ${id}"

    [[ -n "$children" ]] && prompt="${prompt}

## Subtasks
${children}"

    prompt="${prompt}

## Instructions
Work on this task. When you complete subtasks, report back.
Use the codebase at the current working directory.
Be thorough but concise."

    local session_name
    session_name=$(echo "$title" | tr '[:upper:]' '[:lower:]' | tr ' :/' '---' | tr -cd 'a-z0-9-' | head -c 40)

    echo ""
    echo "  Launching: $title"
    echo "  Model: $MODEL"
    echo "  Session: $session_name"
    echo ""

    # Create + chat
    substrate claudecode create --name "$session_name" --model "$MODEL" >/dev/null 2>&1
    substrate claudecode chat --name "$session_name" --prompt "$prompt"

    # Update status
    trak facet update --id "$id" --status "in_progress" >/dev/null 2>&1 || true
    echo ""
    echo "  Session: $session_name"
    echo "  Resume:  synapse substrate claudecode chat --name $session_name --prompt '...'"
}

# ── Main ─────────────────────────────────────────────────────────────────────

cmd="${1:-help}"
shift 2>/dev/null || true

case "$cmd" in
    ls|list)     cmd_ls "$@" ;;
    show)        cmd_show "$@" ;;
    tree)        cmd_tree "$@" ;;
    search|s)    cmd_search "$@" ;;
    grep|g)      cmd_grep "$@" ;;
    blocked)     cmd_blocked ;;
    launch|run)  cmd_launch "$@" ;;
    status)      cmd_status "$@" ;;
    help|-h|--help)
        echo "trak — browse facets, launch agents"
        echo ""
        echo "  ls [name/path]           List facets (roots or children)"
        echo "  show <name-or-id>        Show facet detail"
        echo "  tree <name-or-id>        Show subtree"
        echo "  search <query>           Full-text search (keywords)"
        echo "  grep <regex> [opts]      Regex search across titles + bodies"
        echo "    --status <s>             filter by status"
        echo "    --in <name-or-id>        scope to subtree"
        echo "  blocked                  Show blocked facets"
        echo "  launch <name-or-id>      Spawn Claude Code agent"
        echo "  status <name-or-id> <s>  Update status"
        echo ""
        echo "Names are fuzzy-matched. Paths work: ls hyperforge/MFORGE"
        echo "Short ID prefixes work: show 41110060"
        ;;
    *)
        # Default: treat as ls argument
        cmd_ls "$cmd $*"
        ;;
esac
