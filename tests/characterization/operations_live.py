"""Live operational admission/refusal only; jobs remain disabled."""

import unittest
from integration_harness import GuardedHarness, CANONICAL_CHECKSUM

CONFIG = None
OPT_IN = False
RESULTS = []


def behavior(group, current):
    def wrap(fn):
        fn.metadata = dict(
            scenario=fn.__name__,
            group=group,
            current_behavior=current,
            approved_requirement=None,
            classification="REQUIREMENT NOT YET REVIEWED",
            future_business_question="Operational job semantics require offline/static evidence while guard is preserved.",
            evidence_source="LIVE guarded local refusal/read; reset per sequence",
        )
        return fn

    return wrap


class CurrentLiveOperations(unittest.TestCase):
    def setUp(self):
        self.c = GuardedHarness(
            CONFIG, allow_local_mutations=OPT_IN, characterization_scope="NC-01E"
        )
        self.c.__enter__()

    def tearDown(self):
        self.c.__exit__(None, None, None)
        self.assertEqual(self.c.cleanup_proof["fixture_checksum"], CANONICAL_CHECKSUM)
        r = dict(getattr(self, self._testMethodName).metadata)
        r.update(evidence=self.c.summary, cleanup_checksum=CANONICAL_CHECKSUM)
        RESULTS.append(r)

    def call(self, method, path, status, role=None):
        actual, body = self.c.operational_request(method, path, role=role)
        self.assertEqual(actual, status)
        return body

    @behavior(
        "authorization",
        "JWT routes reject anonymous 401; ordinary/admin operational jobs return existing job-guard 500 before operational authorization. No live maintenance write.",
    )
    def current_behavior__admin_ops__refusals(self):
        for role in ["user-a", "admin"]:
            self.c.login(role)
        for path in [
            "/admin/standings/refresh",
            "/admin/insert_test_teams",
            "/admin/season/rollover",
            "/admin/leaderboard/snapshot",
        ]:
            self.call("POST", path, 401)
            for role in ["user-a", "admin"]:
                self.call("POST", path, 500, role)
        for path in ["/internal/standings/refresh", "/internal/standings/overwrite"]:
            self.call("POST", path, 500)

    @behavior(
        "admin operations",
        "Health read works; env diagnostic anonymous401/ordinary403/admin200 with only masked presence metadata; season flags readable.",
    )
    def current_behavior__admin_ops__diagnostics(self):
        self.c.login("user-a")
        self.c.login("admin")
        self.call("GET", "/health", 200)
        self.call("GET", "/admin/env-check", 401)
        self.call("GET", "/admin/env-check", 403, "user-a")
        self.call("GET", "/admin/env-check", 200, "admin")
        self.call("GET", "/brackets/me", 200, "user-a")
