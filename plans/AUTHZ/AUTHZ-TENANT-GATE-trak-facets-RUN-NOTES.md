# AUTHZ-TENANT-GATE-trak-facets — Run Notes

**Branch:** `feature/AUTHZ-TENANT-GATE-trak-facets`
**Status:** Demo complete; pentest green.

## What was built

A trak-local tenant-gate (`src/tenant_gate.rs`) wrapping `FacetStore` with
visibility / write predicates derived from the caller's resolved tenant.
Five facet handlers (`create`, `get`, `update`, `delete`, `list`) refactored
to route through the gate. A pentest suite (`tests/tenant_isolation_test.rs`)
of ten attack scenarios — all defeated.

### Files touched

| Path | Change |
|---|---|
| `Cargo.toml` | Added `plexus-auth-core` as a path dependency (see "Cross-crate AuthContext" finding). |
| `src/lib.rs` | Declared `pub mod tenant_gate`. |
| `src/tenant_gate.rs` | NEW: `TenantGate`, `GateError`, predicate logic, in-module sanity tests. |
| `src/hubs/facet.rs` | `create` / `get` / `update` / `delete` / `list` routed through the gate. `get`, `update`, `delete`, `list` now require `auth: &AuthContext`. Other 11 handlers untouched. |
| `tests/tenant_isolation_test.rs` | NEW: ten pentest scenarios. |
| `plans/AUTHZ/AUTHZ-TENANT-GATE-trak-facets-RUN-NOTES.md` | This file. |

## What was deferred

### Five handlers gated; eleven left untouched

| Handler | Status | Why left |
|---|---|---|
| `create` | **Gated** | Now overwrites caller-supplied `meta.extra.tenant` with resolved tenant. |
| `get` | **Gated** | Visibility-scoped, NotFound on cross-tenant probe. |
| `update` | **Gated** | Tenant preserved; previously anonymous-writable (!). |
| `delete` | **Gated** | Tenant-scoped; previously anonymous-writable (!). |
| `list` | **Gated** | Post-filter foreign-tenant rows. |
| `tree` | Out of scope | Recursive subtree — needs tenant-scoped traversal; design decision: should foreign-tenant subtrees be opaque or hidden? Defer. |
| `search` | Out of scope | FTS5 results need post-filter. |
| `grep` | Out of scope | Same as search. |
| `link` / `unlink` / `links` | Out of scope | Edge endpoints should respect both endpoints' tenant; needs design. |
| `blocked` | Out of scope | Reads facets via `list_children` + per-row `get_facet`; needs the gate-aware pattern. |
| `checkout` / `diff` / `flush` | Out of scope | Filesystem-touching; bigger refactor. |
| `move_to` | Out of scope | Cross-tenant move semantics undefined. |
| `import_plans` | Out of scope | Bulk import; tenant injection already wired via `tenant_from_auth`. |

## Findings

### F1. Macro doesn't support optional auth (confirmed gap)

`plexus_macros::method` parses `Option<&AuthContext>` (see
`plexus-macros/src/parse.rs` line 1452, `is_auth_context_type`) but the
codegen path (`plexus-macros/src/codegen/activation.rs` line ~908) generates:

```rust
let auth_ctx = auth.ok_or_else(|| PlexusError::Unauthenticated(...))?;
```

…regardless of whether the user declared `auth: &AuthContext` or
`auth: Option<&AuthContext>`. So a handler whose signature expects
`Option<&AuthContext>` would receive a `&AuthContext` from the
macro-generated code → **compile error**.

**Impact:** `get` and `list` could not be made anonymous-readable through the
activation/RPC layer; both are forced-auth at the wire boundary. The gate's
own `from_auth(_, None)` path supports anonymous callers correctly — it's
just unreachable from the macro-generated handler today.

**Workaround in this ticket:** every gated handler takes `auth: &AuthContext`
(forced-auth posture). Tests exercise the gate directly (which DOES support
anonymous), so the "anonymous reads public facets" pentest still verifies
the gate logic end-to-end.

**Follow-up:** filed under "open questions" below.

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

### F4. Cross-crate `AuthContext` mismatch (plexus-core 0.5.2 vs plexus-auth-core)

plexus-trak currently consumes `plexus-core = "0.5"` from crates.io (resolves
to 0.5.2), which predates the AUTHZ-CORE-CRATE-1 migration. The
`AuthContext` that 0.5.2 exposes at `plexus_core::plexus::AuthContext` is
its own type — **not** a re-export of `plexus_auth_core::AuthContext`.

The gate mirrors fields at construction time:

```rust
let mirror = plexus_auth_core::AuthContext::new(
    ctx.user_id.clone(), ctx.session_id.clone(),
    ctx.roles.clone(), ctx.metadata.clone(),
);
```

Tolerable for the demo. The "proper" fix is to bump plexus-trak to a
plexus-core that re-exports `plexus_auth_core::AuthContext`. That's a
workspace-level decision, not in scope.

## Pentest results

All ten attempts defeated. From `cargo test --test tenant_isolation_test`:

| # | Test | Attack | Defense |
|---|---|---|---|
| 1 | `cross_tenant_read_returns_not_found` | Bob (tenant-B) reads Alice's (tenant-A) facet by UUID | Gate returns `NotFound` (existence-oracle defense) |
| 2 | `cross_tenant_update_returns_forbidden` | Bob updates Alice's facet | Gate returns `Forbidden`; underlying facet unchanged |
| 3 | `cross_tenant_delete_returns_forbidden` | Bob deletes Alice's facet | Gate returns `Forbidden`; facet still present after attack |
| 4 | `cross_tenant_list_excludes_other_tenant_facets` | Both list roots | Each sees only their own |
| 5 | `anonymous_cannot_write` | Anon create / update / delete | `Unauthenticated` for create; `Forbidden` for update/delete (see note in test) |
| 6 | `anonymous_reads_only_public_facets` | Anon reads tenant-A facet vs public facet | NotFound for tenant-A; OK for public |
| 7 | `tenant_cannot_hop_via_update` | Alice updates her facet with `meta.extra.tenant = "tenant-B"` | Tenant preserved at `tenant-A`; other fields update normally |
| 8 | `tenant_cannot_hop_via_create_metadata_override` | Alice creates a facet with forged `meta.extra.tenant = "tenant-B"` | Caller's resolved tenant (`tenant-A`) wins |
| 9 | `forged_authcontext_does_not_grant_tenant` | Attacker submits AuthContext with claim but empty `session_id` | Gate's `is_authenticated()` belt rejects; caller treated as anonymous |
| 10 | `store_bypass_seed_is_still_isolated` | Legacy data lands in store with tenant-B tag via direct write | Read predicate still denies cross-tenant access |

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

Baseline test count: 126 (10 lib + 23 api + 16 checkout + 10 discuss + 19
facet_hub + 20 identity + 28 store + 0 from new pentest).

After this ticket: 142 tests, all green.
- 16 lib (+ 6 new in-module tenant_gate predicate tests)
- 23 api (unchanged)
- 16 checkout (unchanged)
- 10 discuss (unchanged)
- 19 facet_hub (unchanged) — the 19 the ticket explicitly called out
- 20 identity (unchanged)
- 28 store (unchanged)
- 10 tenant_isolation (new)

Zero regressions. The existing tests work directly against `FacetStore`
(not through the activation), so adding `auth: &AuthContext` to four
handlers did not break any test.

## Open questions for the user

1. **Macro fix priority.** `Option<&AuthContext>` recognition is half-done.
   Should we file a `plexus-macros` ticket to wire the rest, so anonymous
   reads can flow through the activation? Affects which handlers can be
   "public read, gated write".

2. **Resolver hardening.** Should `ClaimTenantResolver` gain a
   `require_authenticated: bool` field defaulting to `true`? Today the
   resolver honors the claim regardless of `is_authenticated()`. The gate
   compensates, but every downstream consumer pays the same tax — better
   to fix once at the source.

3. **Eleven remaining handlers.** Which subset should be in the next
   ticket? My recommendation: `tree`, `search`, `grep`, `blocked` (all
   read paths that leak tenant data today), then the edge ops
   (`link`/`unlink`/`links`), then `move_to`, then the checkout family.

4. **Push-down filtering.** Should `list_children`, etc. gain a
   tenant-aware SQL path so foreign-tenant rows never leave the store?
   Currently the gate's `list_children` is O(all rows in parent) →
   O(visible). Fine for the demo; bad for a 100-tenant deployment.

5. **`AuthContext` migration timing.** plexus-trak is on `plexus-core 0.5.2`
   from crates.io, which predates the AUTHZ-CORE-CRATE-1 migration. Should
   we bump? The mirror-shim in `TenantGate::from_auth` is two `.clone()`s
   per request — acceptable but inelegant.
