# trak

**A recursive work tracker. Facets within facets.**

trak is a [Plexus RPC](../plexus-protocol/) backend (`plexus-trak`) for tracking work, knowledge, and the relationships between them. Its one universal primitive is the **facet**: a node with a title, body, status, and a parent. Facets nest arbitrarily deep, and any two facets can be joined by a typed edge. There is no hard "epic vs. ticket vs. note" distinction baked into the schema — an epic is just a facet with children, a ticket is just a facet under it, a doc is just a facet with prose in its body. Structure emerges from containment (parent/child) and edges (`depends_on`, `blocks`, …), not from rigid types.

Like every Plexus backend, trak exposes its surface at runtime: define methods in Rust, and the `synapse` CLI discovers them — commands, help text, parameter validation, and output all come from the schema. There is no separate `trak` binary; you talk to it through `synapse`.

## Data model

### Facet

The universal unit of tracked work (`src/types.rs`):

| Field | Type | Notes |
|-------|------|-------|
| `id` | UUID | Server-assigned on create |
| `parent_id` | UUID or absent | Parent facet. Absent = root. Changed only via `move_to`, never `update` |
| `title` | string | Required, non-empty after trimming |
| `body` | string or absent | Optional description / prose / markdown |
| `status` | string | **Free-text, not an enum.** Defaults to `"open"` when omitted on create |
| `owner` | string | Set from the authenticated caller (username, falling back to user id). Not client-settable |
| `meta` | object | Extensible metadata — see below |
| `created_at` | RFC3339 timestamp | |
| `updated_at` | RFC3339 timestamp | Bumped on every `update` call |

There is **no `facet_type` field**. Categorize facets with `tags` and/or `meta_extra` instead.

#### Facet metadata (`meta`)

| Field | Type | Notes |
|-------|------|-------|
| `priority` | string or absent | Free-text (e.g. `low`, `medium`, `high`, `critical`) |
| `tags` | array of strings or absent | Lives at `meta.tags` (the top-level `tags` you send on create/update is folded in here) |
| *(extra)* | arbitrary JSON | Any other keys are flattened into `meta`. The resolved `tenant` is stored here as `meta.tenant` |

> **Reading tags back:** on the wire, tags are nested under `meta.tags`, *not* a top-level `tags` field. `facet get` shows `"tags": null` at the top level even when tags are set — look in `.content.facet.meta.tags`.

### Status values

`status` is a **free-text string**, not a constrained enum — the server stores whatever you send (default `"open"`). The `blocked` query treats a dependency as satisfied when its target status is `"done"`, so `"done"` is the conventional terminal status. Pick a consistent vocabulary (`open` / `in_progress` / `done` / `blocked` …) by convention; the schema does not enforce one.

### Edge kinds

Edges are typed and directional (`from_id` → `to_id`). The kind is a closed enum (`EdgeKind` in `src/types.rs`). The **authoritative, complete set** is exactly four:

| Kind | Meaning |
|------|---------|
| `depends_on` | The source needs the target done first. Drives the `blocked` report |
| `blocks` | The source blocks the target (inverse direction of intent) |
| `relates_to` | Loose, untyped association |
| `duplicates` | The source duplicates the target |

Any other kind string (e.g. `contains`, `parent`, `child`) is **rejected** with `invalid_kind`. Containment is *not* an edge — parent/child is a first-class field (`parent_id`), managed via `create`/`move_to`.

### Ownership & tenancy

trak has no usable anonymous writes (see [Auth](#auth)). On create, `owner` is derived from the caller's auth context and `meta.tenant` from the caller's tenant claim (a forged `meta_extra.tenant` is overwritten with the real one; `update` preserves the existing `meta.tenant` verbatim, defeating tenant-hop attacks). All facet reads and writes pass through a **tenant gate** (`src/tenant_gate.rs`):

| Caller | Public facet (no tenant) | Own-tenant facet | Foreign-tenant facet |
|--------|--------------------------|------------------|----------------------|
| Anonymous | read only | — | invisible |
| Tenant T | read + write | read + write | invisible |

Cross-tenant reads return `not_found` (an existence oracle would leak); cross-tenant writes return `forbidden`. Cross-tenant links, moves, and search/grep leakage are all blocked. Tenant is resolved from the `tenant_id`/`org_id` claim in the validated token; single-user deployments fall back to the user id.

## Running & connecting

trak listens on **WebSocket port 44107** by default (`src/bin/main.rs`). Facet state lives in SQLite at `~/.config/trak/trak.db` (or `$XDG_CONFIG_HOME/trak/trak.db`; macOS bundle builds use `~/Library/Application Support/trak/trak.db`).

```bash
# Build and run the server
cargo run --release            # listens on 44107, OIDC issuer defaults to http://localhost:4461
cargo run --release -- --port 44107 --db /tmp/trak/trak.db \
  --oidc-issuer http://127.0.0.1:4461 --oidc-audience plexus:trak
```

You interact with it through `synapse`, never a `trak` binary. The canonical form (no `-t` — the token is loaded natively, see Auth):

```bash
synapse -P 44107 -j trak <activation> <method> -p '{...}'
```

- `-P 44107` — trak's port
- `-j` — raw JSON stream output (recommended for scripting)
- `-p '{...}'` — params as a JSON object. **Param keys use underscores** (`parent_id`, `from_id`, `to_id`), never hyphens. `-p` is a global option and must come **before** `trak <activation> <method>`

### Auth

> **Auth is OIDC/RS256 (UT-W3 cutover).** As of the UT-W3 cutover (deployed to the live :44107 daemon 2026-06-12), trak validates **RS256 OIDC tokens** against an identity provider's JWKS — there is **no shared secret**, and the old HS256 "mint a token from `jwt_secret`" path is gone. Configure the issuer/audience with `--oidc-issuer` / `TRAK_OIDC_ISSUER` (default `http://localhost:4461`) and `--oidc-audience` / `TRAK_OIDC_AUDIENCE` (default `plexus:trak`).
>
> *Where the validator lives:* the RS256 validator and the tenant gate are **not** trak's own code — they're `plexus_auth_core::oidc::OidcSessionValidator` and `plexus_auth_core::TenantGate` from the shared **plexus-auth-core** crate. trak's `src/auth.rs` / `src/tenant_gate.rs` are thin adapters that *import* them and point the validator at plexus-idp's JWKS. (So: **plexus-idp issues → plexus-auth-core validates → trak adapts + gates**.)
>
> *Source-tree note:* the cutover lives on branch `feature/UT-wave3-oidc-cutover` (the binary running on :44107), currently consuming the validator via a `plexus_auth_core_ut1` shim from plexus-auth-core's UT-1 branch. The default branch still carries the legacy HS256 validator pending the merge; treat OIDC as the operational and intended state.

Identity lives in **plexus-idp** (RPC 4460 / OIDC HTTP 4461), the dedicated provider that this backend's old `identity` hub was extracted into — not in trak itself. To get a token, do an **OIDC password grant** against plexus-idp (audience `plexus:trak`) and store the result where synapse reads it natively — `~/.plexus/trak/defaults.json` under `defaults.cookies.access_token` (prefixed `literal:`). synapse then attaches it automatically; **no `-t` flag needed**. Access tokens are short-lived (~1 h); re-run the grant when calls start returning `Authentication required`. Three layers, three homes: [`plexus-idp`](../skills/skills/plexus-idp/SKILL.md) issues the token, [`synapse-self`](../skills/skills/synapse-self/SKILL.md) stores it, and trak's own auth (token validation + the tenant gate below) is described here and in the [`trak`](../skills/skills/trak/SKILL.md) skill.

`-t <jwt>` / `--token-file <path>` still work as explicit overrides if you want to bypass the stored default. (trak's own `identity` activation is **legacy** — see [identity methods](#identity-methods--legacy-superseded-by-plexus-idp).)

## Usage via synapse

Responses are a streamed JSON envelope; see [Response shape](#response-shape) for how to extract the facet. With native auth configured you can drop `-t` entirely.

**Create a facet** (only `title` is required):

```bash
synapse -P 44107 -j trak facet create \
  -p '{"title":"Ship the widget","body":"End-to-end widget delivery","status":"open","priority":"high","tags":["epic","q3"]}'
```

Create a child by passing the parent's id:

```bash
synapse -P 44107 -j trak facet create \
  -p '{"title":"Wire the backend","parent_id":"<PARENT_UUID>","tags":["ticket"]}'
```

**Get one facet:**

```bash
synapse -P 44107 -j trak facet get -p '{"id":"<UUID>"}'
```

**List children** of a parent (omit `parent_id` for roots); optional `tags` (OR), `tags_all` (AND), `priority` filters:

```bash
synapse -P 44107 -j trak facet list -p '{"parent_id":"<UUID>"}'
synapse -P 44107 -j trak facet list -p '{"tags":["epic"],"priority":["high","critical"]}'
```

**Walk the whole subtree** rooted at a facet (depth-annotated):

```bash
synapse -P 44107 -j trak facet tree -p '{"id":"<ROOT_UUID>"}'
```

**Update** a facet — omit a field to leave it unchanged; `tags:[]` clears tags; `meta_extra` shallow-merges (a `null` value deletes a key); `parent_id` is *not* accepted here (use `move_to`):

```bash
synapse -P 44107 -j trak facet update \
  -p '{"id":"<UUID>","status":"done","meta_extra":{"sprint":"24"}}'
```

**Move** a facet under a new parent (omit `new_parent_id` to make it a root):

```bash
synapse -P 44107 -j trak facet move_to -p '{"id":"<UUID>","new_parent_id":"<NEW_PARENT_UUID>"}'
```

**Link / unlink** two facets with a typed edge (you must be able to write both endpoints):

```bash
synapse -P 44107 -j trak facet link \
  -p '{"from_id":"<A_UUID>","to_id":"<B_UUID>","kind":"depends_on"}'

synapse -P 44107 -j trak facet unlink \
  -p '{"from_id":"<A_UUID>","to_id":"<B_UUID>","kind":"depends_on"}'
```

List a facet's edges (optional `direction`: `outgoing` | `incoming` | `both`; optional `kind` filter):

```bash
synapse -P 44107 -j trak facet links -p '{"id":"<UUID>","direction":"both"}'
```

**Search** (FTS5 full-text across titles + bodies) and **grep** (Rust regex across titles + bodies):

```bash
synapse -P 44107 -j trak facet search -p '{"query":"widget"}'
synapse -P 44107 -j trak facet grep   -p '{"pattern":"(?i)wire.*backend"}'
```

**Find blocked facets** — those with an unsatisfied `depends_on` (target not `done`); scope to a parent's children, or omit for everything visible:

```bash
synapse -P 44107 -j trak facet blocked -p '{"parent_id":"<UUID>"}'
```

**Comment on a facet** (the `discuss` activation — markdown, threaded):

```bash
synapse -P 44107 -j trak discuss comment -p '{"facet_id":"<UUID>","body":"## Evidence\nMerged @ abc123."}'
synapse -P 44107 -j trak discuss list    -p '{"facet_id":"<UUID>"}'
```

### Response shape

trak streams Plexus events. Under `-j` the output is **newline-delimited JSON** (one object per line, not a single array): a sequence of `{"type":"data",...}` envelopes followed by a terminal `{"type":"done"}`. Each data envelope nests the event under `content`, with `type` naming the event kind:

```json
{"content":{"type":"facet_created","facet":{"id":"...","title":"X",...}},"content_type":"facet.created","type":"data"}
{"type":"done"}
```

A `facet create` returns a `facet_created` event carrying the full facet; extract its `id` with:

```bash
synapse -P 44107 -j trak facet create -p '{"title":"X"}' \
  | jq -r 'select(.type=="data") | .content.facet.id'
```

> Encoding note: documented as observed live, where `content` is a JSON **object** (use `.content.facet.id`). Some toolchains/versions surface `content` as a JSON-encoded **string** that must be parsed again (`.content | fromjson | .facet.id`). If `.content.facet.id` yields null, your build is the string-encoded variant.

Errors arrive as an event with `"type":"error"`, a `message`, and often a `code` (e.g. `not_found`, `forbidden`, `invalid_kind`, `unauthenticated`, `invalid_input`).

## Activations

trak registers eight activations (`src/bin/main.rs`); discover them live with `synapse -P 44107 trak`.

| Activation | Status | What it does |
|------------|--------|--------------|
| **facet** | implemented | The core. Facet CRUD, tree traversal, typed links, search/grep, blocked-analysis, and disk checkout/diff/flush + plan import |
| **identity** | **legacy** | Superseded by **plexus-idp** (UT-2). Its token-minting (`register`/`login`/`refresh`/`srp_*`) produces HS256 tokens the OIDC daemon **rejects** — authenticate via plexus-idp instead. API-key methods still run, but API-key callers are anonymous-for-writes on the cutover daemon |
| **discuss** | implemented | Threaded comments on facets (markdown); author-only edit/delete |
| **docs** | implemented | Machine-readable self-documentation — `about`, `guides`, `guide` over a root facet titled "docs" |
| **access** | **stub** | `check` / `grant` — return `not_implemented` |
| **audit** | **stub** | `trail` / `recent` — return `not_implemented` |
| **refs** | **stub** | `attach` / `list` external references — return `not_implemented` |
| **collab** | **stub** | `who` / `assign` collaborators — return `not_implemented` |

### facet methods

| Method | Required params | Optional params | Purpose |
|--------|-----------------|-----------------|---------|
| `create` | `title` | `body`, `parent_id`, `status`, `tags`, `priority`, `meta_extra` | Make a facet (auth required) |
| `get` | `id` | — | Fetch one facet (tenant-scoped) |
| `update` | `id` | `title`, `body`, `status`, `tags`, `priority`, `meta_extra` | Patch fields (omit = unchanged; `tags:[]` clears; no `parent_id`) |
| `delete` | `id` | — | Delete (tenant-scoped) |
| `move_to` | `id` | `new_parent_id` (omit → root) | Reparent (must own both ends) |
| `list` | — | `parent_id`, `tags`, `tags_all`, `priority` | Direct children with filters |
| `tree` | `id` | — | Depth-annotated subtree (anonymous-tolerant) |
| `link` / `unlink` | `from_id`, `to_id`, `kind` | — | Create/remove a typed edge |
| `links` | `id` | `direction`, `kind` | List a facet's edges |
| `blocked` | — | `parent_id` | Facets with an unsatisfied `depends_on` |
| `search` | `query` (FTS5) | `tags`, `tags_all`, `priority` | Full-text over titles + bodies |
| `grep` | `pattern` (regex) | `status`, `parent_id`, `tags`, `tags_all`, `priority` | Regex over titles + bodies |
| `checkout` | `id`, `path` | — | Write a subtree to disk as markdown + `.trak/manifest.json` |
| `diff` | `path` | — | Compare on-disk working copy against the store |
| `flush` | `path` | `force` | Sync on-disk edits back into the store |
| `import_plans` | `path` | `dry_run` | Scan a workspace's `plans/` and materialize facets + `depends_on` edges |

`checkout` / `diff` / `flush` round-trip a facet subtree to disk as markdown for editing; `import_plans` scans a workspace's `plans/` directories and materializes the ticket hierarchy as facets with dependency edges.

### identity methods — LEGACY (superseded by plexus-idp)

This activation is the pre-cutover identity hub. **plexus-idp (UT-2) is now the identity authority** — it was literally extracted from this hub, and the trak daemon validates plexus-idp's RS256 tokens (see [Auth](#auth)). Against the OIDC-cutover daemon:

- `register` / `login` / `refresh` / `srp_*` still execute but mint **HS256** tokens the daemon **does not accept** — they're dead ends. Authenticate through plexus-idp instead (the [`plexus-idp`](../skills/skills/plexus-idp/SKILL.md) skill; store the token via [`synapse-self`](../skills/skills/synapse-self/SKILL.md)).
- `create_api_key` / `revoke_api_key` / `list_api_keys` still work and keys validate locally, **but** API-key callers carry an empty session id → the tenant gate treats them as anonymous (read **public** facets only, no writes). Not a usable path for authenticated work today.

For all real authentication, use plexus-idp. The methods are retained for compatibility and will be removed when the IdentityHub is retired.

### discuss methods

`comment` (`facet_id`, `body`; optional `parent_comment_id` for threaded replies), `list` (`facet_id`; `limit`/`offset`), `get` (`id`), `edit`, `delete` (author-only).

### Inspecting schemas

Parameter schemas are self-describing. Fetch the whole activation's schema (every method's params) with `-s`:

```bash
synapse -P 44107 -s trak facet      # raw schema JSON for all facet methods
synapse -P 44107 trak               # human-readable activation + method list
```

(There is a `schema` *method* in the facet surface, but it is not callable as a CLI subcommand — use `-s` instead.)

## Development

```bash
cargo build
cargo test
cargo run --release            # serve on 44107
```

Source layout (`src/`): `bin/main.rs` (server wiring + OIDC config), `hubs/` (one file per activation), `types.rs` (`Facet`, `FacetMeta`, `Edge`, `EdgeKind`, `NewFacet`, `FacetUpdate`), `events.rs` (the `TrakEvent` wire enum), `store/` (SQLite via sqlx — facets, edges, FTS5, users, api_keys, refresh_tokens, srp_*), `tenant_gate.rs` (tenant isolation), `auth.rs` (session validation — OIDC on the cutover branch, HS256 + API-key on the default branch), `checkout.rs` / `import.rs` (disk sync + plan import).

## References

- **synapse** (the CLI you drive trak through): `../synapse/`
- **plexus-idp** (the identity provider trak validates against): `../plexus-idp/`
- **Plexus RPC protocol**: `../plexus-protocol/`
- **Agent skills:**
  - [`trak`](../skills/skills/trak/SKILL.md) — the day-to-day operator workflow (invocation, gotchas, method reference)
  - [`plexus-idp`](../skills/skills/plexus-idp/SKILL.md) — the identity provider (issue/validate tokens: register/login, password+refresh grants, roles, JWKS) for the whole stack
  - [`synapse-self`](../skills/skills/synapse-self/SKILL.md) — synapse's universal credential store (where the token is kept/resolved for any backend)
  - [`ought-trak`](../skills/skills/ought-trak/SKILL.md) — running the ought methodology on trak
