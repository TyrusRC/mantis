# OWASP Testing Guide — Business Logic & Authorization

Deep-reviewer should consult this when a finding involves authorization, identity, or workflow state. Semgrep cannot pattern-match these — they are semantic.

## IDOR / BOLA — Insecure Direct Object Reference / Broken Object-Level Authorization

For each handler that takes an ID (path param, query, body) and looks up an object:

- Is the object scoped to the current user / tenant?
- Does the lookup actually filter by `current_user.id` / `tenant_id` — or only by the supplied id?
- Does the response include any field the user should not see (other tenants' fields, soft-deleted, internal flags)?
- Are there sibling actions on the same object (DELETE / PUT / PATCH / list) that share the auth check?
- Are list endpoints filtered server-side, or does the client filter?

Heuristic flags: `findById($ID)` / `find_by(id=$ID)` / `Model.objects.get(id=$ID)` without a user / tenant predicate, in a code path that derives `$ID` from the request.

## BFLA — Broken Function-Level Authorization

- Are admin endpoints distinguishable from user endpoints by URL only? (path-based gating is insufficient)
- Does the role check happen in middleware, decorator, or handler — and is it consistent across the file?
- Are there hidden HTTP methods (OPTIONS, HEAD, PATCH) that skip the role check?
- Are GraphQL resolvers individually authorized?

## Mass assignment / BOPLA

- Does the create / update path accept the full request body and pass it to the ORM?
- Are there field allow-lists per role? Or is the deny-list trusted to enumerate all dangerous fields?
- Can a user set fields like `is_admin`, `tenant_id`, `owner_id`, `created_at`, balance fields?

## Race conditions / TOCTOU

- Reads of state that are followed by writes without a lock or atomic update.
- "Check then act" idioms: balance check then debit, quota check then increment, idempotency-key check then write.
- Idempotency-key handling: is the key compared with a unique constraint, or only with a SELECT?

## Workflow bypass

- Multi-step flows (signup → email verify → profile complete): can step N be hit directly without N-1?
- State machines: does the server enforce transitions, or does it trust a client-provided "state" field?
- Coupon / discount flows: stacking, replay of expired codes, integer overflow on totals.

## Reporting format

When the deep-reviewer flags a business-logic issue, include in the FINDING block:

```
LOGIC_CLASS: IDOR | BOLA | BFLA | MASS_ASSIGN | RACE | WORKFLOW
WITNESS: <one short paragraph showing the missing check or wrong predicate>
ENTRYPOINT: <route / handler signature>
SCOPING_PRIMITIVE_USED: <e.g. id only, no tenant filter>
SCOPING_PRIMITIVE_NEEDED: <e.g. WHERE tenant_id = current_user.tenant_id>
```
