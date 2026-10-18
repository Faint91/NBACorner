# NC-03R4 — Rate-limit bucket integrity repair

**NC04A-CODE-002 = REPAIRED LOCALLY / pending final production deployment.**
NC-03 remains PASS. NC-04A remains BLOCKED. No production contact.

## Checkpoint and scope

Backend main started clean at `1d0dcea7b109edc593728e0f431788cbcf3b52be`.
Frontend main remains clean at `4fa0e9fc11d49354e3da137ee43e9d1ddbc87357`.
Only the missing centralized bucket, focused offline acceptance/inventory coverage,
and this repair/evidence record changed. No deployment, configuration, database,
authentication, email-business-logic or frontend change occurred.

## Before repair and approved policy

The actual admin test-email route called `is_rate_limited("test_email_ip", ip)`,
but the map omitted that key. The KeyError branch returned False before recording
an attempt. An isolated execution of the actual helper allowed 100 synthetic
attempts with bypass disabled, recorded zero attempts and throttled none.
The first R4 attempt reviewed all 126 historical app.py versions and found no
numeric policy. It correctly stopped without choosing a threshold.

The user then explicitly approved **5 requests per IP per 15-minute rolling
window**. The repair adds `test_email_ip: (5, 900)` to RATE_LIMITS. The existing
helper admits the first five requests, rejects the sixth, and removes events whose
age reaches 900 seconds. Rejected requests do not extend the window.

## Architecture and complete runtime inventory

The helper uses process-local lists keyed by (bucket, key), guarded by the existing
thread lock. IP extraction and proxy behavior remain unchanged. No shared-store
or cross-worker guarantee is introduced.

| Bucket | Limit | Window seconds | Caller |
|---|---:|---:|---|
| login_ip | 10 | 60 | login |
| login_identifier | 5 | 60 | login |
| forgot_ip | 5 | 300 | forgot-password |
| forgot_identifier | 3 | 300 | forgot-password |
| register_ip | 3 | 3600 | register |
| health_ip | 30 | 60 | health without valid health token |
| test_email_ip | 5 | 900 | authenticated, database-confirmed admin test email |

AST inventory across tracked runtime Python now has seven referenced and seven
defined buckets, no undefined or dynamic references, no unused bucket, no duplicate
keys and one map definition. Reset completion and the admin master diagnostic have
no existing rate-limit-helper caller; this repair does not introduce one.

## Acceptance and regressions

The test fixture extracts the actual functions into isolated Flask test clients.
It never imports app.py or starts its season/bootstrap hook. All database objects
are mocks; email delivery is a mock; socket connections are blocked.

- First four requests: 200; fifth: 200; sixth: existing JSON error and HTTP429.
  Only five mock delivery calls occur, preserving the supplied synthetic recipient.
- Staggered events prove rolling expiry immediately before and exactly at 900
  seconds; later events remain counted and denials are not recorded.
- Different IPs have independent counters; login and health buckets are independent.
- DISABLE_RATE_LIMITS=1 retains the intentional bypass without recording attempts;
  switching the isolated fixture back to False enforces five then429.
- Anonymous401, nonadmin403 and token-admin/database-nonadmin403 remain unchanged;
  none reaches mail or consumes test-email throttle events.
- All six preexisting bucket boundaries/windows pass; actual login/register return
  429 when saturated; throttled forgot-password retains its generic200 without
  account lookup; health retains HTTP429 and its valid-token exemption.
- All 11 R4 tests and all 370 offline tests pass, including auth/password reset,
  environment safety and R1/R2/R3 tests. Separate R1/R2/R3 proof functions also pass;
  R2 covers46 diagnostic scenarios. No existing guarded database tests were needed:
  this change adds no DB code and all requested throttle acceptance is synthetic.
- Black checks the new test file; application imports and all function/class ASTs
  are identical to the starting HEAD; compilation, whitespace and changed-file
  secret/privacy checks pass. Existing app.py formatting is preserved.

Historical NC-01A characterization records remain historical; their old missing-
bucket assertion is superseded by this approved-policy R4 acceptance/inventory test.
No historical evidence was rewritten to imply that the bucket previously existed.

## Separate advisory: NC-03R4-ADV-001

Unknown-bucket lookup still fails open. That is unsafe for a programmer/configuration
error, but generic fail-closed behavior is explicitly outside this repair. The
focused negative control removes the new bucket only in isolated memory and proves
the original fail-open behavior. A separate hardening decision should choose how
unknown buckets fail without broadening R4. No new bypass was added. The existing
valid HEALTHCHECK_TOKEN exemption remains unchanged.

## Cleanup and reproduction

No local database was accessed, restored or created; no seed/reset was needed.
Canonical fixture source files remain byte-identical to HEAD. Database fixture
checksum was not re-queried because no database was used. Flask port55410 is stopped,
the capture mailbox is empty, and no jobs or mutation admission were enabled.
All rate-limit state belongs to short-lived isolated test processes.

```text
python -B -m unittest discover -s tests/offline -p test_rate_limit_integrity.py -v
python -B -m unittest discover -s tests/offline -q
python -B -m black --check tests/offline/test_rate_limit_integrity.py
git diff --check
```

Machine evidence: `db/records/nc_03r4_rate_limit_bucket_integrity.json`.
Production code remains unrepaired until a separately authorized final deployment.
Production unsafe flags, old diagnostic route, and NC-04B operational write-fence
remain outside this local repair. No Render/API/production read or write occurred.
