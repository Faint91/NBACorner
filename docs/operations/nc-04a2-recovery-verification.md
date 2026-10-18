# NC-04A recovery verification — mechanism PASS

**Overall NC-04A: BLOCKED — PRODUCTION REMEDIATION/DECISION REQUIRED.**

Backup completed UTC: 2026-10-18T21:34:44.853887+00:00. Restore/cleanup verified UTC: 2026-10-18T21:37:28.192262+00:00.

Private retained directory: `C:\NBA-Corner-Private-Backups\20261018T212752Z`. It is outside all repositories and restricted to the current Windows user and SYSTEM. No backup files or credential values are copied into this audit.

## Method and retained files

Supabase CLI2.120.0 supplied provider-filtered roles/schema/COPY data exports. A complete PostgreSQL17.6 custom archive includes managed schemas as well;complete password-free global role metadata supplements the provider-filtered roles export. The restore proof used complete roles plus the full archive in a fresh template0 database on a compatible Supabase PostgreSQL17.6 image.

| File | Bytes | SHA-256 |
|---|---:|---|
| roles.sql | 358 | 4350a72b5ec109888e740c17f3eb4da2fcd95ab73af26499538ed0bf615db543 |
| schema.sql | 50146 | 6f185af1df9115a0a59d7e340b616c6749d75cd87f4b6d6e53ef7950a5cd8dfd |
| data.sql | 251409 | 985f5f3ff2f7006fcf690a81a85ab8917b8be25bda8e2b95779f2dc60a61dbf7 |
| database.dump | 487323 | 43463d57b98b4813af9d60e6ecd89a0d97b5bf4bdef03ec1053e2d11286bb4d6 |
| roles-complete.sql | 5641 | 6dd307a6d66b5beedc50244d4b137d1012352c47573e7f78f41490bc7129155c |

Production sessions were read-only. Schema/data/archive used one exported repeatable-read snapshot. Role metadata is cluster-wide and separately exported without role password verifiers,as in provider guidance. No DB password/connection string appeared in command arguments;password was supplied privately via process environment or in-memory client parameters.

## Restore proof

- A new container had network disabled,no published ports and tmpfs database storage. Canonical synthetic test data was not used for the restore.
- Restore was transactional/fail-fast. An initially missing platform role was supplied from complete role metadata in the disposable cluster only;original backup files were retained unchanged.
- All51 table counts match,including all13 public application tables. Application counts:users57,brackets21,matches441,leagues1,memberships1,scores14,standings30,history headers7/history rows140.
- All13 structural/aggregate check groups pass:server version/read-only mode,table counts,columns,constraints,indexes,relation ownership/ACL/RLS,policies,functions,triggers,extensions,master structure and orphan aggregates.
- Policy expressions match exactly when session visibility/search_path is aligned;no expressions/policies were edited or stripped.
- Active master remains admin-owned and active,21 matches/22 derived edges;both existing pure master/complete validators pass. Bracket/match/history orphan counts0.
- Foreign keys inspected:20;unvalidated:0. Constraint definitions and validation state match.
- Vault secret rows0;no project root-key transfer was needed for this database proof. This is a logical database backup,not a backup of external storage objects,hosting settings or deployed edge functions.
- Disposable restore/container,tmpfs database and temporary backup clients removed. Backup hashes rechecked;private backup remains available.

## Acceptance and remaining gates

Recovery gate:PASS. This proves the backup/restore mechanism;NC04B still requires a fresh completed/verified backup after confirmed write quiescence immediately before migrations. Never substitute this earlier point-in-time artifact.

Overall NC04A remains blocked by the separately observed diagnostic-debug FAIL,rate-limit-bypass FAIL and unresolved deterministic write-fence/deployment/resume procedure. No config fix was attempted.

Production DB writes0;no migration,canonical designation,deploy,email,job,standings or rollover operation. Initial pooler auth failure resolved after user confirmed the reset;the agent did not reset the password. No unexpected production dependency found.

Provider references: https://supabase.com/docs/guides/platform/migrating-within-supabase/backup-restore and https://supabase.com/docs/guides/self-hosting/restore-from-platform .

STOP. NC04B not started.

Docker Desktop was returned to its initial stopped state after all temporary clients and the restore were removed.
