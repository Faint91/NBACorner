# NC-04A5 — Free-tier maintenance fence (future execution only)

WRITE-FENCE DESIGN = PASS / pending NC-04B execution. NC-03 remains PASS;
NC-04A remains BLOCKED. No deployment/configuration/DB mutation authorized here.
This branch-only supplement supersedes the paid-maintenance/suspension proposal in
older NC-04B planning; historical records remain unchanged.

## Baselines and isolation

Backend main: ff341dfa556a08ae396aacf33b74cb6c56a0ab71.
Frontend main: 4fa0e9fc11d49354e3da137ee43e9d1ddbc87357. Both started clean.
Temporary branch: nc04-maintenance, based on the backend target, not merged to main.
Its exact SHA is obtained with `git rev-parse nc04-maintenance` and reported at
completion. Keep that immutable SHA in the future execution record; never use latest.
No branch was pushed here. Before future deployment, push only this branch to the
already-linked GitHub repository under the execution authorization and verify the
remote ref equals the recorded maintenance SHA. No plan upgrade is needed.

Only maintenance_app.py is launched. The original app.py stays byte-identical to
main and is never imported. The maintenance branch requirements.txt contains only
a comment: no dependencies, install scripts, local editable packages or migration
hooks. The existing build command therefore has no application packages to install.
The implementation uses only os, socketserver and wsgiref.simple_server (stdlib).
The only environment value read is PORT. No dotenv or application secret is read.

## Current Render read-only observation

Service srv-d4239u6uk2gs73b8fts0, NBACorner, Python, Free, linked main branch in
https://github.com/Faint91/NBACorner, root directory empty (repository root).
Build: `pip install -r requirements.txt`.
Start: `gunicorn app:app`.
Pre-deploy: absent. No Procfile/render.yaml/setup.py/pyproject.toml startup/build
hook exists in this checkout. Current dependency file has ordinary PyPI entries,
no project setup execution; the maintenance branch removes those dependencies.
Live deploy dep-dbajssc9v7es738q8nu0 at5bcb0b43ae0c232381ae857cd40c3fd7b1e23422.
Auto-deploy OFF, deployment queue idle, HTTP healthCheckPath empty: TCP probing.
No provider configuration was modified.

## Response/start contract

Future dedicated maintenance start command: `python -B maintenance_app.py`.
It binds0.0.0.0 to the provider's PORT. It never starts gunicorn app:app.
All normal paths, including /health, auth, diagnostics, write routes and unknown
paths, return503 with a fixed generic message, no-store and Retry-After300.
GET/HEAD /__maintenance_health alone returns fixed200 OK; writes to it return503.
No reflected query/body/header, software-version header, request logging or CORS
permission is added. HEAD has no response body. Request threads only service HTTP;
no scheduler/background application job starts. No file or database persistence.

Keep Render's existing empty healthCheckPath/TCP mode. TCP probes succeed because
the process listens; HTTP503 on /health does not mark TCP health failed. The narrow
200 endpoint provides an explicit dependency-free manual smoke check. If the
provider's health setting differs at execution time, stop and review it; do not
silently deploy with a normal HTTP /health check that would reject maintenance.

## Exact future deployment/config mechanism (not executed)

Render supports manually deploying a full SHA from the linked repository rather
than its linked branch HEAD. A commit reachable on the pushed temporary branch
can be supplied from that same repo; no linked-branch switch is planned.
Use POST /v1/services/srv-d4239u6uk2gs73b8fts0/deploys with body
`{"commitId":"<exact maintenance SHA>"}`. No omitted commit, deploy_only, latest,
clear cache, rollback-to-old-app or target deployment during fence establishment.
A pinned-SHA API deploy does not disable auto-deploy itself: verify it remains OFF.
If the provider cannot resolve the pushed temporary-branch SHA, STOP, do not
switch the service branch or substitute a commit without authorization.

Before that call, separately authorize/save startCommand
`python -B maintenance_app.py` using the service PATCH API (only this field).
The documented service PATCH stages config and does not itself deploy. Verify no
unexpected deployment, then invoke the exact SHA. Do not use a dashboard save
that could deploy an unintended commit. Preserve existing build command, root,
runtime, plan, pre-deploy absence, health mode and all other settings.

## Future NC-04B fence acceptance — hard gates

1. Reconfirm exact service, auto-deploy OFF, queue idle, no mutation hooks and the
   immutable maintenance/backend/frontend SHAs. Verify maintenance branch is remote.
2. Hold every independent writer: disabled standings workflow, any provider/manual
   job, scheduler, privileged client and relevant operator. Inventory must still
   show no unheld independent writer; public Supabase access must remain contained.
3. Save maintenance-only startCommand; deploy the exact maintenance SHA.
4. Require deploy live, correct SHA, generic503 on / and a representative write
   route,200 on maintenance health, and no normal app response through any public
   API hostname. Client/cached frontend routes may remain visible but cannot write.
5. Render overlaps old and new instances: routing changes are not full quiescence.
   Wait for retirement of all old app instances and in-flight requests. Docs describe
   SIGTERM after60seconds, followed by configured shutdown delay; read the actual
   delay/instance state at execution. Do not infer completion from elapsed time alone.
6. Independently verify no remaining app instance/worker/transaction/DB writer,
   including old connection pools. Use separately authorized restricted operational
   metadata/DB checks; no blanket DB-session termination or credential rotation.
   If termination/writer quiescence cannot be verified, remain fenced and STOP.
7. Create and verify a fresh private logical roles/schema/data backup after
   quiescence immediately before migrations, with sizes/checksums and recovery proof.
   The earlier verified backup proves the mechanism, not deployment-day freshness.
8. Only then begin authorized migrations. No DB work was performed in NC-04A5.

## Schema-independent migration/config stage

Maintenance never reads DB schema, so it serves unchanged through all stages:
0001,0002; designate approved2025-26 season994f58bc-bdbc-422e-9786-bb5c8559ea0f;
verify exactly one canonical singleton/intended existing season; then0003–0011;
run required schema/security checks. No new season or rollover is implied.

While maintenance remains live, stage exactly ENABLE_DEBUG_LOGS=0 and
DISABLE_RATE_LIMITS=0 through individual-variable PUT endpoints, privately compare
all keys/values before and after each update, and verify no extra deploy/race.
Do not replace the full variable list and do not redeploy the old application to
activate flags. Maintenance ignores both; the next pinned target deployment loads
corrected values on startup. Preserve JWT/origin/email credentials and every other
variable. Verify the final saved safe values before target activation.

## Target, reopening and returning to maintenance

After migrations/verifiers/config are correct, stage the original target start
command `gunicorn app:app` with no automatic deploy. Keep TCP health mode unchanged.
Manually deploy exact audited target ff341dfa556a08ae396aacf33b74cb6c56a0ab71
(or a separately approved replacement SHA). Before invocation, recheck all state.
Render continues routing to maintenance while building/starting the target. If
build/start/readiness fails before traffic cutover, maintenance remains live.
TCP readiness is NOT database correctness: schema verification must precede this
step, and immediate post-cutover auth/read/security smoke checks remain mandatory.
Target success opens traffic; it does not provide a hidden post-live test interval.

Never use the old backend SHA as a rollback against migrated schema. To restore
the fence after a failed target smoke: stage `python -B maintenance_app.py` again,
deploy the exact retained maintenance SHA, wait for live503 and re-verify old target
workers/transactions drained. This is a new pinned deployment, not a rollback API
that could restore an inappropriate command/environment snapshot. Keep artifact
availability and repo access verified. Restoration requires deploy time; it is not
instantaneous or atomic, and target writes may occur before fencing completes.
Pause all further DB recovery actions until the fence is re-established.

After target backend/schema/security/safe flags are confirmed, deploy exact known
frontend target. Old/cached clients must still be subject to backend guards. Finish
frontend compatibility and smoke checks; only then permit standings workflow resume.
No separate paid/static frontend maintenance page is needed; temporary API/network
errors during downtime are accepted. If frontend deploy fails, do not label rollout
complete; retain target only if proven compatible/safe, otherwise restore the fence.

## Failure/recovery matrix

| Failure | Required action |
|---|---|
| Maintenance build/start fails | Abort before backup/migration; old app remains live; fence NOT established. |
| Writer drain cannot be proven | Remain maintenance; no fresh migration sequence. |
| Fresh backup fails | Remain maintenance; no migrations. |
| Migration/designation/verifier fails | Remain maintenance; approved recovery/repair only; never reopen old app. |
| Target build/start/readiness fails | Verify maintenance remains live; no old-app rollback. |
| Target becomes live but smoke fails | Stage maintenance command, deploy exact maintenance SHA, verify503 and drain again. |
| Frontend deploy/compatibility fails | Keep rollout incomplete; retain safe target or return to maintenance as above. |
| Maintenance restore build fails | Escalate; no claim of fence, no further migration/recovery until verified. |

Retain the maintenance commit/branch until NC-04B stabilization and rollback
confidence; delete the temporary branch only under later cleanup instruction.

## Local validation

Six tests run the actual main entrypoint in a separate Python process with only
PORT and platform process essentials supplied. An import blocker rejects app,
Flask, DB/provider/email/job modules. Audit hooks reject outbound connects/DNS,
child processes and file mutations. Real loopback GET/HEAD/write/unknown requests
all pass, logs stay empty and the subprocess is terminated after testing.
Static AST import/environment proof, compilation, Black, dependency/build check,
changed-file secret scan and whitespace checks pass. Main app.py and main ref remain
unchanged. No full app suite rerun: no shared application implementation changed.

## Sources

- https://render.com/docs/deploys (exact SHA, old/new instance overlap, failed-deploy behavior)
- https://render.com/docs/health-checks (TCP default and HTTP health semantics)
- https://render.com/docs/web-services#port-binding (0.0.0.0/PORT)
- https://api-docs.render.com/reference/create-deploy (commitId)
- https://api-docs.render.com/reference/update-service (staged service changes)

Provider behavior is documented and metadata-compatible, not production-tested in
this phase. Actual instance drain, backup freshness and deployment gates must be
proved during an explicitly authorized NC-04B execution. NC-04A is not fully PASS:
production unsafe flags and all deployment-day gates remain pending.
