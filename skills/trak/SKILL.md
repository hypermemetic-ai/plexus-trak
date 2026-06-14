---
name: trak
description: The interface layer that realizes the methodology's tracker concepts on trak. Read this whenever you need to DO something on the tracker — create a scope/execution/build/spike, wire a dependency, find what's ready, change a ticket's state, propagate a DAG change, archive superseded work, or query current work for /orient. The methodology skills speak in tracker-agnostic concepts; this is the single place that maps each concept to a concrete trak operation (facets, edges, statuses, synapse invocations, auth). When trak's interface changes, update HERE — not the methodology.
---

# Skill: trak — the tracker interface

The methodology (scope · execution · build · spike · dependency DAG · readiness · states) is written **tracker-agnostic** and names no tool. **trak is the concrete tracker.** This skill is the binding: every methodology concept → the exact trak operation that realizes it. It is the **single source of truth for how to touch the tracker** — the methodology says *what*, this says *how*. Keep all trak mechanics here so the interface lives in one place.

trak is a Plexus backend; there is no `trak` binary. You drive it through the **`synapse` CLI**. One primitive: the **facet** — a recursive node (title, body, status, parent, typed edges). Epic/build/spike/scope are *roles a facet plays*, not types.

## Concept → trak mapping

| Methodology concept | trak realization |
|---|---|
| ticket (any kind) | a **facet** — `facet create`, one UUID id |
| scope · execution · build · spike | facets distinguished by **title prefix** (`Scope:` · `Execution ·` · `B<N> ·` · `S<N> · Spike:`) — not a typed field |
| containment (execution owns its children) | **`parent_id`** tree — `create {parent_id}`, reparent with `move_to` |
| dependency edge (A depends on B) | typed edge **`depends_on`** — `facet link {from_id:A, to_id:B, kind:"depends_on"}` |
| the readiness query ("what's ready / blocked") | **`facet blocked`** — returns facets with a `depends_on` target not yet `done` |
| `## Provides` / `## Consumes` | prose in the facet **`body`**; the edges they imply are the `depends_on` links |
| confidence / severity / framework | **`meta_extra`** keys (`priority` is first-class; arbitrary keys via `meta_extra`) |
| link the landed change (PR/commit) | **`meta_extra`** key (e.g. `change`) or a `discuss comment` — `refs.attach` is a stub, not yet live |
| assignee | a `meta_extra` key or `discuss comment` — `collab.assign` is a stub, not yet live |
| comments / discussion | **`discuss comment` / `discuss list`** (threaded markdown) |

### State model → trak status strings

The methodology's lean states map to free-text `status` strings. **Only `done` is load-bearing** — `facet blocked` treats a dependency as satisfied *iff its status is exactly the string `done`*. Everything else is convention; spell them consistently:

| Concept state | trak `status` | Notes |
|---|---|---|
| **Pending** | `pending` | created, awaiting human ratification. `create` defaults to `open` if status omitted — **pass `status:"pending"` explicitly**; treat a bare `open` as Pending. |
| **Ready** | `ready` | ratified; eligible to start |
| **active** | `active` | in progress (set the moment work starts, so two agents never double-claim a leaf) |
| **in review** | `in-review` | implemented, change open — the agent's finish line |
| **done** | `done` | **exact string required** — the only status the readiness logic reads |
| **archived** | `archived` | superseded/removed — always with a pointer (a `discuss comment` naming the survivor) |

Blocked-ness is **not** a status — it's derived from `depends_on` edges via `facet blocked`. A terminal status spelled anything but `done` will keep dependents looking blocked.

## Auth (do this once per ~hour)

Identity is **plexus-idp (OIDC/RS256)**, not trak. Reads of *public* facets work anonymously; **all writes** and tenant-scoped reads need a token.

1. Get an access token via plexus-idp password grant (audience `plexus:trak`, issuer `127.0.0.1:4461`).
2. Store it where synapse reads natively: `~/.plexus/trak/defaults.json` → `defaults.cookies.access_token`, value prefixed `literal:`. synapse attaches it automatically — **do not pass `-t`**.
3. Tokens last ~1h. Symptom of expiry: reads return empty + writes silently no-op → re-run the grant.

> Do **not** use `trak-cli` or trak's legacy `identity` hub — they mint HS256 tokens the live OIDC daemon rejects.

## Invocation form

```
synapse -P 44107 -j trak <hub> <method> -p '{<json, underscore_keys>}'
```
Flags and `-p` come **before** `trak`. `-P 44107` = the trak port; `-j` = raw JSON. Responses are newline-delimited `{"type":"data",...}` envelopes ending in `{"type":"done"}`; errors are `{"type":"error","code":...}`. Pull a new id with `… | jq -r 'select(.type=="data").content.facet.id'`. **Full UUIDs only** — short/prefix ids error or silently no-op.

## Operations (the methodology, executed)

```bash
# Scope ticket (milestone root) — Pending until the human ratifies
synapse -P 44107 -j trak facet create -p '{"title":"Scope: M9 · audit log","body":"## Language …\n## Interface contract …","status":"pending","tags":["scope"]}'

# Execution ticket — child of nothing (milestone-level) or of a parent program; owns the DAG
synapse -P 44107 -j trak facet create -p '{"title":"Execution · M9 · audit log","body":"## Execution DAG …","status":"active","parent_id":"<MILESTONE_OR_ROOT_UUID>","tags":["execution"]}'

# Build / spike — child of the execution ticket
synapse -P 44107 -j trak facet create -p '{"title":"B0 · AuditEvent type root","body":"## Provides …","status":"pending","parent_id":"<EXEC_UUID>","tags":["build"]}'
synapse -P 44107 -j trak facet create -p '{"title":"S1 · Spike: any bypass writers?","status":"pending","parent_id":"<EXEC_UUID>","tags":["spike"]}'

# Dependency edge: B1 depends_on B0 (derive every edge from ## Consumes → its producing ## Provides)
synapse -P 44107 -j trak facet link -p '{"from_id":"<B1_UUID>","to_id":"<B0_UUID>","kind":"depends_on"}'

# Readiness query — what is actionable (deps all done) under this execution
synapse -P 44107 -j trak facet blocked -p '{"parent_id":"<EXEC_UUID>"}'   # returns the BLOCKED ones

# Ratify (human) / start / finish / land
synapse -P 44107 -j trak facet update -p '{"id":"<UUID>","status":"ready"}'      # Pending → Ready
synapse -P 44107 -j trak facet update -p '{"id":"<UUID>","status":"active"}'     # claim the leaf
synapse -P 44107 -j trak facet update -p '{"id":"<UUID>","status":"in-review","meta_extra":{"change":"<PR-or-commit-url>"}}'
synapse -P 44107 -j trak facet update -p '{"id":"<UUID>","status":"done"}'       # exact string — unblocks dependents

# Propagate a DAG change ONTO the execution ticket in the same unit of work (the parent's body is the DAG's truth)
synapse -P 44107 -j trak facet update -p '{"id":"<EXEC_UUID>","body":"<updated ## Execution DAG + ## The work>"}'

# Archive superseded work — never silent; leave a pointer
synapse -P 44107 -j trak facet update  -p '{"id":"<UUID>","status":"archived"}'
synapse -P 44107 -j trak discuss comment -p '{"facet_id":"<UUID>","body":"Superseded by <SURVIVOR_UUID> — archive tag <tag>, removal commit <sha>."}'

# Inspect / navigate
synapse -P 44107 -j trak facet tree   -p '{"id":"<EXEC_UUID>"}'      # the whole subtree
synapse -P 44107 -j trak facet list   -p '{"parent_id":"<UUID>"}'    # direct children
synapse -P 44107 -j trak facet links  -p '{"id":"<UUID>","direction":"both"}'
synapse -P 44107 -j trak facet search -p '{"query":"audit"}'         # FTS5 over title+body
synapse -P 44107 -j trak facet grep   -p '{"pattern":"(?i)retention"}'
synapse -P 44107 -s trak facet                                       # raw param schema for every method
```

## Current-work query (what `/orient` runs)

To answer "where am I / what's in flight" against trak:
1. **In progress:** facets with `status:"active"` — `facet grep -p '{"pattern":".","status":"active"}'` (optionally scoped by `parent_id`).
2. **Awaiting me:** `status:"in-review"` (handed off, may need a nudge) and `status:"ready"` (ratified, startable).
3. **Blocked vs ready:** `facet blocked` under the live execution ticket(s) — anything NOT returned, and `ready`/`pending`, is actionable.
4. **Each active execution ticket:** `facet tree` it to see leaf states at a glance.
Cross-reference these against git ground truth (branches/worktrees named for their ticket) per the [orient](../../../skills/skills/orient/SKILL.md) methodology rubric: map branch → ticket → state, flag anything unattributable.

## Bulk / at-scale operations

For sweeps (status passes, supersession, audits): filter **server-side** with `facet grep`/`search`/`list` (`status`, `tags`, `parent_id`, `priority`) — never page the whole tree client-side — then `facet update`/`link`/`unlink` per hit. Substantive writes (new tickets, archivals, milestone boundaries) are proposed for human ratification; mechanical sweeps (re-files, status flips across a known set) fan out to subagents.

## Gotchas

- **Full UUIDs only** — prefixes error or silently no-op. Capture ids from create output; never hand-truncate.
- **`done` is the one exact string** the backend reasons about (`facet blocked`). Don't spell terminal states `closed`/`complete`.
- **`parent_id` is set on create / `move_to` only** — never via `update`.
- **`meta_extra` shallow-merges**; a JSON `null` value deletes a key. `tags:[]` clears tags.
- **Writes need an authed tenant**; cross-tenant facets are invisible (`not_found`) on read, `forbidden` on write.
- **Stubs — not yet live:** `refs.attach` (PR/commit link), `collab.assign` (assignee), `access.*`, `audit.*`. Until they land, use `meta_extra` keys or `discuss comment`. Re-check and migrate when implemented — and update this skill.
- **Legacy:** trak's own `identity` hub and `trak-cli` use the dead HS256 path — ignore them; auth via plexus-idp.

## When the interface changes

This file is the contract between the methodology and trak. If trak adds `refs.attach`/`collab.assign`, changes status semantics, or alters the method surface, **edit this skill** (and `/orient` if its queries change) — the methodology skills stay untouched because they never named trak.
