# Upstream merge — alembic migration review (2026-04-27)

Audit of every change to `lemur/migrations/` introduced by merging `Netflix/lemur main` (2178 commits, merge commit `304fa2ae`) into `wip-apr27`.

## TL;DR

**No new schema migrations were introduced by this merge.** The previous Datadog maintainer kept the migration tree fully sync'd with upstream prior to merging. The Datadog fork carries exactly **one** Datadog-specific migration that is not in upstream, and it remains the head of the chain — unchanged by this merge.

Only two migration files were touched, and both changes are stylistic (no DDL or behavioral change). One change to `env.py` is a behavioral regression to be aware of (drops `compare_type=True` for autogenerate).

## Counts

|                          | Count |
| ------------------------ | ----- |
| Total migrations         | 44    |
| Migrations in upstream   | 43    |
| Datadog-only migrations  | 1     |
| Migrations newly added by this merge | **0** |
| Migration files modified by this merge | 1 |
| Other migration infra modified | 1 (`env.py`) |

## Datadog-only migration (unchanged by merge)

### `44d67c1988a2_.py` — Many-to-many relation between certificates and endpoints

- **Created:** 2022-07-20 (Datadog fork)
- **Revises:** `a9987414cf36`
- **Status:** Head of the migration chain. Not present in `Netflix/lemur main`.

**What it does:**

1. Creates the `endpoints_certificates` join table:
   - `id` (PK), `certificate_id` (FK → `certificates.id` ON DELETE CASCADE), `endpoint_id` (FK → `endpoints.id` ON DELETE CASCADE), `path` (varchar 256), `is_primary` (bool, NOT NULL).
2. Creates a partial unique index `unique_primary_certificate_endpoint_ix` on `(endpoint_id, is_primary) WHERE is_primary` — enforces one primary certificate per endpoint.
3. Backfills the new table by copying every existing `(endpoints.id, endpoints.certificate_id, endpoints.certificate_path)` row in as `is_primary = true`.
4. Drops the FK `endpoints_certificate_id_fkey` and removes the `certificate_id` and `certificate_path` columns from `endpoints`.

**Reversible?** Yes. `downgrade()` recreates the columns/FK on `endpoints` and copies primary rows back.

**Operational note:** This migration has already been applied to all three Datadog environments (sandbox, commercial, government); it does not run again.

## Files modified by this merge

### `lemur/migrations/versions/5770674184de_.py` — cosmetic only

The `pyupgrade --py38-plus` upstream commit (`2c25d6d7`) modernized format strings:

```diff
-        if seen.get("{}-{}".format(x.certificate_id, x.notification_id)):
-            print("Deleting duplicate: {}".format(x))
+        if seen.get(f"{x.certificate_id}-{x.notification_id}"):
+            print(f"Deleting duplicate: {x}")
```

No semantic change. This migration was already applied long ago; the source change is purely cosmetic.

### `lemur/migrations/env.py` — minor + one behavioral change

```diff
-from __future__ import with_statement      # removed (Py3-only now)

-fileConfig(config.config_file_name)
+if config.config_file_name:                # tolerate None
+    fileConfig(config.config_file_name)

-db_url_escaped = current_app.config.get("SQLALCHEMY_DATABASE_URI").replace("%", "%%")
+db_url_escaped = current_app.config.get(
+    "SQLALCHEMY_DATABASE_URI", "postgresql://lemur:lemur@localhost:5432/lemur"
+).replace("%", "%%")

-        **current_app.extensions["migrate"].configure_args,
-        compare_type=True
+        **current_app.extensions["migrate"].configure_args
```

Three of the four hunks are robustness improvements (None-safe `fileConfig`, default URL fallback, dropping a Py2 future import).

**The fourth — `compare_type=True` removal — is a behavioral change worth flagging:**

- `compare_type=True` makes alembic's `--autogenerate` detect column-type changes (e.g., `String(64)` → `String(128)`) when generating new migration scripts.
- Without it, autogenerate will not produce ALTER COLUMN ... TYPE statements when models change column types.
- This **does not affect already-applied migrations** or runtime — only future `lemur db migrate` autogeneration.
- Upstream took this out long ago in commit `cdd24ccf` ("rebase"). Behavior now matches upstream.

If we want to retain the stricter autogenerate behavior, we can re-add `compare_type=True` to `env.py` as a Datadog-specific tweak. Recommendation: leave it as upstream for now and revisit only if a future model change requires explicit type-change tracking.

## Migration tree integrity

Verified the chain has exactly one head (`44d67c1988a2`) and the linkage is consistent:

```
... → a9987414cf36 (last upstream) → 44d67c1988a2 (DD: endpoints_certificates) [HEAD]
```

`alembic heads` should report a single head. No multi-head merge migrations are needed.

## Action items

1. ✅ Merge committed (`304fa2ae`); test fixes committed (`d32e2eb2`).
2. ⏳ Run `lemur db upgrade` against staging to confirm the chain is no-op (it should be — nothing new to apply).
3. ⏳ Decide whether to re-add `compare_type=True` to `env.py`. Default: leave as upstream.
