# AUTHZ-TENANT-GATE-trak-facets — Run Notes

**Branch:** `feature/AUTHZ-TENANT-GATE-trak-facets`
**Status:** Demo + workspace bump + full handler coverage; pentest green.

## What was built

### Round 1 (commit 4df5fe2)

A trak-local tenant-gate (`src/tenant_gate.rs`) wrapping `FacetStore` with
visibility / write predicates derived from the caller's resolved tenant.
Five facet handlers (`create`, `get`, `update`, `delete`, `list`) refactored
to route through the gate. A pentest suite (`tests/tenant_isolation_test.rs`)
of ten attack scenarios — all defeated.

### Round 2 (this commit)

1. **Workspace bump.** plexus-trak's `plexus-core`, `plexus-macros`,
   `plexus-transport` deps switched from crates.io to workspace path-deps
   so `plexus_core::plexus::AuthContext` is now a re-export of
   `plexus_auth_core::AuthContext`. The field-mirroring shim in
   `TenantGate::from_auth` is gone — one type, no clones at the gate
   boundary.

2. **Eleven remaining handlers gated.** `tree`, `search`, `grep`,
   `blocked`, `links`, `link`, `unlink`, `move_to` now route through the
   gate. `checkout`, `diff`, `flush`, `import_plans` are documented as
   deferred (filesystem / bulk-import — see "What was deferred").

3. **Optional auth on read handlers.** Picked up
   AUTHZ-MACRO-OPTIONAL-AUTH-1 from the sibling worktree (the macro now
   emits a pass-through for `Option<&AuthContext>`). `tree`, `search`,
   `grep`, `blocked`, `links` accept optional auth, so anonymous
   readers can access public-tagged subtrees / matches.

4. **Gate API extended.** New methods on `TenantGate`: `subtree`,
   `search`, `collect_all_visible`, `edges`, `blocked_in`, `add_edge`,
   `remove_edge`, `move_to`. All enforce the visibility / write
   predicates established in Round 1.

5. **Eight new pentest tests + one explicit-skip.** Round-1 baseline
   of 10 grows to 18 + 1 ignored deferred test.

### Files touched (Round 2)

| Path | Change |
|---|---|
| `Cargo.toml` | `plexus-core`, `plexus-macros`, `plexus-transport` → path deps. `plexus-macros` points at the AUTHZ-MACRO-OPTIONAL-AUTH-1 worktree (same as plexus-core, to avoid lockfile collisions). `plexus-auth-core` already path. |
| `src/tenant_gate.rs` | Removed `AuthContext` field-mirroring (single-type now). Added new methods: `subtree`, `search`, `collect_all_visible`, `edges`, `blocked_in`, `add_edge`, `remove_edge`, `move_to`. |
| `src/hubs/facet.rs` | All 16 handlers either gated or explicitly deferred. New auth shapes: 5 read handlers (`tree`, `search`, `grep`, `blocked`, `links`) → `Option<&AuthContext>`. 3 write handlers (`link`, `unlink`, `move_to`) → `&AuthContext` (was no-auth). |
| `tests/tenant_isolation_test.rs` | +8 pentest tests + 1 `#[ignore]` deferred-handler test. |
| `plans/AUTHZ/AUTHZ-TENANT-GATE-trak-facets-RUN-NOTES.md` | This file. |

### Files touched (Round 1 — historical)

| Path | Change |
|---|---|
| `Cargo.toml` | Added `plexus-auth-core` as a path dependency. |
| `src/lib.rs` | Declared `pub mod tenant_gate`. |
| `src/tenant_gate.rs` | NEW: `TenantGate`, `GateError`, predicate logic, in-module sanity tests. |
| `src/hubs/facet.rs` | `create` / `get` / `update` / `delete` / `list` routed through the gate. |
| `tests/tenant_isolation_test.rs` | NEW: ten pentest scenarios. |

## What is deferred (Round 2 update)

### Handler-by-handler status

| Handler | Status | Auth shape | Notes |
|---|---|---|---|
| `create` | **Gated** | `&AuthContext` | Overwrites caller-supplied `meta.extra.tenant`. |
| `get` | **Gated** | `&AuthContext` | NotFound on cross-tenant probe. |
| `update` | **Gated** | `&AuthContext` | Tenant preserved (no hopping). |
| `delete` | **Gated** | `&AuthContext` | Forbidden on cross-tenant. |
| `list` | **Gated** | `&AuthContext` | Post-filter foreign-tenant rows. |
| `tree` | **Gated** | `Option<&AuthContext>` | Subtree filtered by visibility; root-invisible → empty. |
| `search` | **Gated** | `Option<&AuthContext>` | FTS5 results post-filtered. |
| `grep` | **Gated** | `Option<&AuthContext>` | Candidate facets visibility-filtered before regex match. |
| `blocked` | **Gated** | `Option<&AuthContext>` | Cross-tenant blockers hidden (no schedule-signal leak). |
| `links` | **Gated** | `Option<&AuthContext>` | Both endpoints must be visible. |
| `link` | **Gated** | `&AuthContext` | Caller must write to both endpoints. |
| `unlink` | **Gated** | `&AuthContext` | Mirror of `link`. |
| `move_to` | **Gated** | `&AuthContext` | Write to source AND new parent required. |
| `checkout` | **Deferred** | `&AuthContext` (unused) | See "Deferred: checkout/diff/flush" below. |
| `diff` | **Deferred** | `&AuthContext` (unused) | Same. |
| `flush` | **Deferred** | `&AuthContext` (owner-only) | Same. |
| `import_plans` | **Partial** | `&AuthContext` | Carries `tenant_from_auth` into bulk insert; does NOT route through the gate (caller-tenant-wins enforcement lives in `gate.create`, which bulk path bypasses). See follow-up. |

### Deferred: `checkout` / `diff` / `flush`

These operate on a filesystem working directory (markdown checkouts of
facet subtrees) rather than the facet DB. Three orthogonal concerns
need a design before gating:

1. **Tenant boundary on the working directory.** Is a checkout
   per-tenant (one tenant per dir) or per-facet (mix-and-match)?
   Today checkout's call signature accepts `auth: &AuthContext` but
   discards it (`let _ = auth;`).

2. **Cross-tenant materialization.** When checkout walks a subtree
   and writes markdown files, foreign-tenant nodes must not be
   written. `crate::checkout::checkout` currently calls
   `store.get_subtree` directly — needs to thread a `TenantGate`
   reference and use `gate.subtree` instead.

3. **Manifest integrity.** `flush` rebuilds facets from on-disk
   markdown. A caller who swaps a UUID in markdown frontmatter could
   trick `flush` into uploading content under a foreign facet ID.
   The on-disk manifest format needs to carry the resolved tenant so
   `flush` can refuse mismatched IDs.

Filed as `AUTHZ-TENANT-CHECKOUT` (not yet written). The current
handlers DO require authentication at the macro boundary (force-auth
posture), so anonymous misuse is denied — what's deferred is the
foreign-tenant case for an *authenticated* caller.

The pentest suite includes a `#[ignore]`-marked placeholder
(`checkout_diff_flush_tenant_isolation_deferred`) that documents this
in-tree for discoverability.

### Deferred: `import_plans` push-down to the gate

The handler reads `tenant_from_auth(auth)` and passes it as a string
into `crate::import::import_into_trak`. This is correct for the
happy path but bypasses the gate's "caller's resolved tenant
overwrites forged meta.extra.tenant" structural property — a future
refactor should call `gate.create(facet)` per imported facet so the
enforcement is uniform. Pin: `import_plans_carries_caller_tenant`
test in the pentest suite.

## Findings

### F1. Macro now supports optional auth (Round 2 update)

The sibling worktree `plexus-macros-AUTHZ-MACRO-OPTIONAL-AUTH-1`
landed the optional-auth codegen — the macro branches on the parsed
shape:

- `auth: &AuthContext` → `let auth_ctx = auth.ok_or_else(...)?;`
- `auth: Option<&AuthContext>` → `let auth_ctx: Option<&AuthContext> = auth;`

plexus-core's `Cargo.toml` now points at that worktree (with a
disambiguating pre-release version `0.5.0-AUTHZ-MACRO-OPTIONAL-AUTH-1`).
plexus-trak picks the same path so cargo sees one `plexus-macros`
package.

**Impact:** Round 2 switched the five read handlers (`tree`, `search`,
`grep`, `blocked`, `links`) from force-auth back to optional-auth,
which is what the gate was designed for from day one.

**Original Round 1 workaround now reverted.** No outstanding force-auth
on read paths.

### F2. Ideally we'd use `Tenanted<S>` from plexus-auth-core (confirmed seal too tight)

`plexus-auth-core::tenant::storage` defines `Tenanted<S>`, `Scoped<'_, S>`,
and `TenantScopedStore`. Inspection:

- `TenantScopedStore` is a sealed trait — third crates cannot impl it.
- `Tenanted::new_sealed` is `pub(crate)` — third crates cannot construct.

The trak-local `TenantGate` is therefore the right shape for *today*; the
"proper" version is `Tenanted<SqliteStore>` once `AUTHZ-DATA-2-MACRO`
(Pending) opens the seal for legitimate downstream wrappers.

### F3. `ClaimTenantResolver` does not check `is_authenticated()`

Reading `plexus-auth-core/src/tenant/resolver.rs` line 140-148:

```rust
async fn resolve(&self, auth: &AuthContext) -> Result<Tenant, TenantError> {
    if let Some(claim) = auth.get_metadata_string(&self.claim_key) {
        return mint_tenant_from_str(claim);
    }
    if self.single_user_fallback && auth.is_authenticated() {
        return mint_tenant_from_str(auth.user_id.clone());
    }
    Err(TenantError::UnresolvedFromAuthContext)
}
```

The `single_user_fallback` branch checks `is_authenticated()`, but the
**claim** branch does NOT. The resolver trusts the AuthContext as
post-SessionValidator. That trust is correct **inside** the framework
dispatch path, where `AuthContext` only enters via `SessionValidator::validate`.
It is **not** safe in a layer (like our gate) where the AuthContext might be
constructed directly (tests, future activations that bypass validation).

**Fix in this ticket:** `TenantGate::from_auth` adds a belt-and-suspenders
`if !ctx.is_authenticated() { return None }` before invoking the resolver.
Pentest 9 (`forged_authcontext_does_not_grant_tenant`) verifies this.

**Should this fix move into `plexus-auth-core`?** Probably yes, as an opt-in
flag on `ClaimTenantResolver`. Filed as an open question.

### F4. Cross-crate `AuthContext` mismatch — fixed in Round 2

plexus-trak's `plexus-core` switched from crates.io 0.5.2 to the
workspace path-dep. The workspace plexus-core re-exports
`AuthContext` from `plexus-auth-core` (AUTHZ-CORE-CRATE-1), so
`plexus_core::plexus::AuthContext` IS `plexus_auth_core::AuthContext`
— same type, no clones, no mirror shim.

Side effect: `plexus-macros` and `plexus-transport` also had to move
to workspace path-deps. The workspace `plexus-transport` is 0.3, the
crates.io version was 0.2 — but `plexus-transport` itself path-deps
plexus-core, so a mixed graph produced two `plexus_core` versions and
`DynamicHub: Activation` failed to satisfy. Aligning everything to
the workspace fixes it.

### F5. Sibling macros worktree path-pinning

Multiple in-flight `plexus-macros-*` worktrees exist for parallel
authz work. Cargo refuses to materialize "two distinct packages with
the same name + version from different paths" in a single dep graph,
so the worktrees disambiguate via pre-release version suffixes
(e.g. `0.5.0-AUTHZ-MACRO-OPTIONAL-AUTH-1`).

plexus-trak's `Cargo.toml` mirrors whatever physical path plexus-core
currently points at (today: `plexus-macros-AUTHZ-MACRO-OPTIONAL-AUTH-1`).
This is fragile — if a sibling agent changes plexus-core's path-pin,
trak needs to follow. Long-term fix: the macros worktrees should
merge to canonical `plexus-macros` so there's exactly one path.

## Pentest results

All 18 attack scenarios defeated, 1 explicitly deferred. From
`cargo test --test tenant_isolation_test`:

### Round 1 (10 tests)

| # | Test | Attack | Defense |
|---|---|---|---|
| 1 | `cross_tenant_read_returns_not_found` | Bob (tenant-B) reads Alice's (tenant-A) facet by UUID | Gate returns `NotFound` (existence-oracle defense) |
| 2 | `cross_tenant_update_returns_forbidden` | Bob updates Alice's facet | Gate returns `Forbidden`; underlying facet unchanged |
| 3 | `cross_tenant_delete_returns_forbidden` | Bob deletes Alice's facet | Gate returns `Forbidden`; facet still present after attack |
| 4 | `cross_tenant_list_excludes_other_tenant_facets` | Both list roots | Each sees only their own |
| 5 | `anonymous_cannot_write` | Anon create / update / delete | `Unauthenticated` for create; `Forbidden` for update/delete |
| 6 | `anonymous_reads_only_public_facets` | Anon reads tenant-A facet vs public facet | NotFound for tenant-A; OK for public |
| 7 | `tenant_cannot_hop_via_update` | Alice updates her facet with `meta.extra.tenant = "tenant-B"` | Tenant preserved at `tenant-A` |
| 8 | `tenant_cannot_hop_via_create_metadata_override` | Alice creates a facet with forged `meta.extra.tenant = "tenant-B"` | Caller's resolved tenant wins |
| 9 | `forged_authcontext_does_not_grant_tenant` | AuthContext with claim but empty `session_id` | Gate's `is_authenticated()` belt rejects |
| 10 | `store_bypass_seed_is_still_isolated` | Legacy direct-write of tenant-B facet | Read predicate still denies cross-tenant |

### Round 2 (8 tests + 1 ignored)

| # | Test | Attack | Defense |
|---|---|---|---|
| 11 | `tree_excludes_other_tenant_subtree` | Bob calls `tree(alice-root)` with leaked UUID | Gate returns empty subtree (no node leaks even if root probe times) |
| 12 | `search_excludes_other_tenant_matches` | Bob runs FTS5 query matching Alice's title | Gate post-filters; Alice's hit absent from Bob's results |
| 13 | `grep_excludes_other_tenant_matches` | Alice and Bob each grep with a shared pattern | `collect_all_visible` returns disjoint pools per caller |
| 14 | `blocked_excludes_other_tenant_dependencies` | Alice's task depends on Bob's blocker (cross-tenant edge) | Blocker is filtered out; Alice's task does not surface in her blocked report |
| 15 | `link_cross_tenant_returns_forbidden` | Alice links her facet to Bob's (and vice versa); anon also tries | All three refused (`Forbidden` / `Forbidden` / `Unauthenticated`); store has no cross-tenant edge |
| 16 | `move_to_cross_tenant_parent_returns_forbidden` | Alice moves under Bob's parent; Bob moves Alice's; anon moves; Alice moves to root (allowed) | First three refused; root-move succeeds and tenant tag preserved |
| 17 | `links_filter_half_visible_edges` | A direct-store edge connects public anchor → bob-secret; Alice asks for edges around public | Alice sees empty (half-visible edge filtered); Bob sees the edge; Alice's direct-probe of bob-secret is NotFound |
| 18 | `import_plans_carries_caller_tenant` | Pin `tenant_from_auth(auth)` contract for the bulk path | Helper returns tenant claim for authed callers, None for anon |
| — | `checkout_diff_flush_tenant_isolation_deferred` | (`#[ignore]`) Filesystem path tenant isolation deferred — see test docstring and "Deferred" section | N/A — placeholder for follow-up `AUTHZ-TENANT-CHECKOUT` ticket |

### What the seal did NOT defeat

Nothing in this round — every attack scenario was defeated. But the
*completeness* claim is bounded by what we tested. The seal does NOT
currently defend against:

- **Tag tampering of foreign-tenant facets via primitives outside the gated
  handlers.** `tree`, `search`, `grep`, `links`, `blocked`, `checkout`,
  `diff`, `flush`, `move_to` still call `FacetStore` directly with no
  tenant filter. A caller hitting `facet.tree` with a foreign-tenant root
  UUID would receive the whole subtree. Tracked as follow-up.
- **Side channels.** A creator's UUID is durable — if Bob obtains Alice's
  facet UUID via a log leak or out-of-band, he can confirm "this facet
  used to exist for this user" by observing a NotFound vs a non-existent
  UUID's NotFound (both identical, so this is actually defended). But he
  could measure **timing** to distinguish "facet exists, denied" from
  "facet does not exist". Not addressed; timing-equalization is a
  framework-level concern.
- **`ClaimTenantResolver`'s direct claim-trust** for AuthContexts that go
  through a SessionValidator (the normal production path). The gate's
  layered `is_authenticated()` check defends test-shape forgeries; it
  does NOT defend "an attacker who has valid credentials and adds a
  `tenant_id` claim to a JWT they sign." That class of attack is the
  SessionValidator's job.

## Regression check

Baseline (Round 1): 142 tests.

After Round 2: 150 tests + 1 ignored. All green.
- 16 lib (unchanged — same 6 in-module tenant_gate predicate tests)
- 23 api (unchanged)
- 16 checkout (unchanged)
- 10 discuss (unchanged)
- 19 facet_hub (unchanged)
- 20 identity (unchanged)
- 28 store (unchanged)
- 18 tenant_isolation (+ 8 new) + 1 `#[ignore]` deferred

Zero regressions. The existing tests work directly against `FacetStore`
(not through the activation), so adding / changing `auth: …` on
handlers did not break any test.

Build status: `cargo build` green. Two warnings carried through from
the path-dep `plexus-core` (`#[deprecated]` flags on
`ChildCapabilities` and the `hub,` macro arg); both pre-exist and are
upstream to fix.

## Open questions for the user

(Round 2 — Round 1 questions about macro support and AuthContext
migration are now resolved.)

1. **Resolver hardening (carried from Round 1).** Should
   `ClaimTenantResolver` gain a `require_authenticated: bool` field
   defaulting to `true`? Today the resolver honors the claim regardless
   of `is_authenticated()`. The gate compensates, but every downstream
   consumer pays the same tax — better to fix once at the source.

2. **Push-down filtering (carried from Round 1).** Should
   `list_children` and the new `subtree` / `search` / `edges` gain a
   tenant-aware SQL path so foreign-tenant rows never leave the store?
   Currently the gate filters post-query, so a 100-tenant deployment
   pays I/O for rows it discards.

3. **`checkout` / `diff` / `flush` design.** Three concrete decisions
   blocking the deferral:
   - Tenant boundary on a working directory — per-tenant or per-facet?
   - Should `checkout::checkout` accept a `&TenantGate` and filter at
     traversal time?
   - Should the on-disk manifest carry the resolved tenant so `flush`
     can refuse a markdown-frontmatter UUID swap?

4. **`import_plans` push-down.** Should bulk import call through
   `gate.create` per facet instead of `import_into_trak` with a tenant
   string? The latter works for the happy path but bypasses the
   structural "caller's tenant wins" property pinned by pentest 8.

5. **Sibling worktree pin fragility.** trak's `Cargo.toml` pins
   `plexus-macros` to whatever physical path plexus-core points at
   today (currently `plexus-macros-AUTHZ-MACRO-OPTIONAL-AUTH-1`).
   When the macros worktrees merge to canonical `plexus-macros`,
   trak's `Cargo.toml` needs a follow-up edit. Recommend a workspace
   `Cargo.toml` so the path lives in one place.
