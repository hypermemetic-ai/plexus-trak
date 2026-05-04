#!/usr/bin/env bash
# launch-agent.sh — Pick a facet from trak, spawn a Claude Code session
#
# Usage:
#   ./launch-agent.sh                    # interactive: browse tree, pick a facet
#   ./launch-agent.sh <facet-id>         # direct: launch agent for specific facet
#   ./launch-agent.sh --list             # show open facets
#   ./launch-agent.sh --blocked          # show blocked facets
#   ./launch-agent.sh --search "query"   # search facets
#
# Requires:
#   - trak running on port 44107 (or TRAK_PORT env)
#   - substrate running on port 4444 (or SUBSTRATE_PORT env)
#   - TRAK_TOKEN env var or ~/.plexus/trak/token file
#   - synapse CLI

set -euo pipefail

TRAK_PORT="${TRAK_PORT:-44107}"
SUBSTRATE_PORT="${SUBSTRATE_PORT:-4444}"
MODEL="${CLAUDE_MODEL:-sonnet}"

# ── Token ────────────────────────────────────────────────────────────────────

resolve_token() {
    if [[ -n "${TRAK_TOKEN:-}" ]]; then
        echo "$TRAK_TOKEN"
        return
    fi
    if [[ -f ~/.plexus/trak/token ]]; then
        cat ~/.plexus/trak/token
        return
    fi
    echo "ERROR: No trak token. Set TRAK_TOKEN or save to ~/.plexus/trak/token" >&2
    echo "  synapse -P $TRAK_PORT trak identity login --username <user> --password <pass>" >&2
    exit 1
}

TOKEN=$(resolve_token)

# ── Helpers ──────────────────────────────────────────────────────────────────

trak() {
    synapse -P "$TRAK_PORT" --json -t "$TOKEN" trak "$@" 2>&1
}

substrate() {
    synapse -P "$SUBSTRATE_PORT" --json substrate "$@" 2>&1
}

# Extract fields from JSON stream (one event per line)
extract_facets() {
    grep '"type":"facet_summary"' | \
    python3 -c "
import sys, json
for line in sys.stdin:
    try:
        obj = json.loads(line)
        c = obj.get('content', obj)
        depth = c.get('depth', 0)
        indent = '  ' * depth
        children = c.get('child_count', 0)
        child_str = f' ({children})' if children > 0 else ''
        print(f\"{c['id'][:8]}  {indent}{c['title']}  [{c['status']}]{child_str}\")
    except: pass
"
}

extract_detail() {
    grep '"type":"facet_detail"\|"type":"facet_created"' | head -1 | \
    python3 -c "
import sys, json
line = sys.stdin.readline()
if line:
    obj = json.loads(line)
    f = obj.get('content', {}).get('facet', obj.get('content', {}))
    print(f.get('title', 'untitled'))
    print('---')
    print(f.get('body', '') or '(no description)')
    print('---')
    print(f'status: {f.get(\"status\", \"?\")}')
    print(f'owner: {f.get(\"owner\", \"?\")}')
    print(f'id: {f.get(\"id\", \"?\")}')
"
}

# ── Commands ─────────────────────────────────────────────────────────────────

cmd_list() {
    local parent="${1:-}"
    echo "── Open facets ──"
    echo ""
    if [[ -n "$parent" ]]; then
        trak facet list --parent-id "$parent" | extract_facets
    else
        trak facet list | extract_facets
    fi
}

cmd_tree() {
    local id="${1:?usage: launch-agent.sh --tree <facet-id>}"
    echo "── Tree ──"
    echo ""
    trak facet tree --id "$id" | extract_facets
}

cmd_blocked() {
    echo "── Blocked facets ──"
    echo ""
    trak facet blocked | grep '"type":"blocked"' | \
    python3 -c "
import sys, json
for line in sys.stdin:
    try:
        obj = json.loads(line)
        c = obj.get('content', obj)
        f = c.get('facet', {})
        blockers = c.get('blocked_by', [])
        blocker_names = ', '.join(b.get('title','?')[:40] for b in blockers)
        print(f\"{f.get('id','')[:8]}  {f.get('title','?')}  ← blocked by: {blocker_names}\")
    except: pass
"
}

cmd_search() {
    local query="${1:?usage: launch-agent.sh --search <query>}"
    echo "── Search: $query ──"
    echo ""
    trak facet search --query "$query" | extract_facets
}

cmd_show() {
    local id="${1:?usage: launch-agent.sh --show <facet-id>}"
    trak facet get --id "$id" | extract_detail
}

# ── Launch ───────────────────────────────────────────────────────────────────

cmd_launch() {
    local facet_id="${1:?usage: launch-agent.sh <facet-id>}"

    echo "Loading facet context..."
    local detail
    detail=$(trak facet get --id "$facet_id" | grep '"type":"facet_detail"' | head -1)

    if [[ -z "$detail" ]]; then
        echo "ERROR: Facet not found: $facet_id" >&2
        exit 1
    fi

    local title body status facet_uuid
    title=$(echo "$detail" | python3 -c "import sys,json; c=json.loads(sys.stdin.readline())['content']; print(c['facet']['title'])")
    body=$(echo "$detail" | python3 -c "import sys,json; c=json.loads(sys.stdin.readline())['content']; print(c['facet'].get('body','') or '')")
    status=$(echo "$detail" | python3 -c "import sys,json; c=json.loads(sys.stdin.readline())['content']; print(c['facet']['status'])")
    facet_uuid=$(echo "$detail" | python3 -c "import sys,json; c=json.loads(sys.stdin.readline())['content']; print(c['facet']['id'])")

    # Get children (subtasks)
    local children
    children=$(trak facet list --parent-id "$facet_id" 2>/dev/null | grep '"type":"facet_summary"' | \
        python3 -c "
import sys, json
items = []
for line in sys.stdin:
    try:
        c = json.loads(line)['content']
        items.append(f\"- [{c['status']}] {c['title']}\")
    except: pass
print('\n'.join(items))
" 2>/dev/null || echo "")

    # Get blockers
    local blockers
    blockers=$(trak facet links --id "$facet_id" 2>/dev/null | grep '"depends_on"' | \
        python3 -c "
import sys, json
items = []
for line in sys.stdin:
    try:
        c = json.loads(line)['content']
        items.append(f\"- {c.get('target',{}).get('title','?')} [{c.get('target',{}).get('status','?')}]\")
    except: pass
print('\n'.join(items))
" 2>/dev/null || echo "")

    # Build the prompt
    local prompt="You are working on this task:

# ${title}

${body}

Status: ${status}
Facet ID: ${facet_uuid}"

    if [[ -n "$children" ]]; then
        prompt="${prompt}

## Subtasks
${children}"
    fi

    if [[ -n "$blockers" ]]; then
        prompt="${prompt}

## Dependencies
${blockers}"
    fi

    prompt="${prompt}

## Instructions
Work on this task. When you complete subtasks, report back.
Use the codebase at the current working directory.
Be thorough but concise."

    # Create session name from title
    local session_name
    session_name=$(echo "$title" | tr '[:upper:]' '[:lower:]' | tr ' ' '-' | tr -cd 'a-z0-9-' | head -c 40)

    echo ""
    echo "═══════════════════════════════════════════"
    echo "  Launching agent: $title"
    echo "  Model: $MODEL"
    echo "  Session: $session_name"
    echo "═══════════════════════════════════════════"
    echo ""

    # Create claude code session
    substrate claudecode create --name "$session_name" --model "$MODEL" | \
        grep '"type"' | head -3

    echo ""
    echo "Sending prompt..."
    echo ""

    # Chat — streams tokens
    substrate claudecode chat --name "$session_name" --prompt "$prompt"

    # Update facet status to in_progress
    trak facet update --id "$facet_id" --status "in_progress" > /dev/null 2>&1 || true

    echo ""
    echo "═══════════════════════════════════════════"
    echo "  Session: $session_name"
    echo "  Facet status updated to: in_progress"
    echo "  Resume: synapse substrate claudecode chat --name $session_name --prompt '...'"
    echo "═══════════════════════════════════════════"
}

# ── Interactive browse ───────────────────────────────────────────────────────

cmd_browse() {
    local current="${1:-}"

    while true; do
        echo ""
        if [[ -n "$current" ]]; then
            cmd_show "$current"
            echo ""
            cmd_list "$current"
        else
            cmd_list
        fi

        echo ""
        echo "Commands: [id] drill in  [..] go up  [l <id>] launch  [s <query>] search  [q] quit"
        read -rp "> " input

        case "$input" in
            q|quit|exit) break ;;
            ..)  current="" ;;
            s\ *) cmd_search "${input#s }" ;;
            l\ *)
                local launch_id="${input#l }"
                # Expand short ID to full UUID
                local full_id
                full_id=$(trak facet search --query "$launch_id" | \
                    grep '"id"' | head -1 | grep -o '"id":"[^"]*"' | cut -d'"' -f4)
                if [[ -n "$full_id" ]]; then
                    cmd_launch "$full_id"
                else
                    echo "Not found: $launch_id"
                fi
                ;;
            *)
                # Try as facet ID (expand short prefix)
                if [[ ${#input} -eq 8 ]]; then
                    # Short ID — search for it
                    local matches
                    matches=$(trak facet list ${current:+--parent-id "$current"} | \
                        grep "\"$input" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
                    if [[ -n "$matches" ]]; then
                        current="$matches"
                    else
                        echo "Not found: $input"
                    fi
                elif [[ ${#input} -ge 32 ]]; then
                    current="$input"
                else
                    echo "Unknown command: $input"
                fi
                ;;
        esac
    done
}

# ── Main ─────────────────────────────────────────────────────────────────────

case "${1:-}" in
    --list)     cmd_list "${2:-}" ;;
    --tree)     cmd_tree "$2" ;;
    --blocked)  cmd_blocked ;;
    --search)   cmd_search "$2" ;;
    --show)     cmd_show "$2" ;;
    --browse)   cmd_browse "${2:-}" ;;
    --help|-h)
        echo "Usage:"
        echo "  launch-agent.sh <facet-id>         Launch agent for a facet"
        echo "  launch-agent.sh --list [parent-id]  List open facets"
        echo "  launch-agent.sh --tree <facet-id>   Show subtree"
        echo "  launch-agent.sh --blocked           Show blocked facets"
        echo "  launch-agent.sh --search <query>    Search facets"
        echo "  launch-agent.sh --show <facet-id>   Show facet detail"
        echo "  launch-agent.sh --browse            Interactive browser"
        echo ""
        echo "Environment:"
        echo "  TRAK_TOKEN        Auth token (or save to ~/.plexus/trak/token)"
        echo "  TRAK_PORT         Trak port (default: 44107)"
        echo "  SUBSTRATE_PORT    Substrate port (default: 4444)"
        echo "  CLAUDE_MODEL      Model: opus, sonnet, haiku (default: sonnet)"
        ;;
    "")         cmd_browse ;;
    *)          cmd_launch "$1" ;;
esac
