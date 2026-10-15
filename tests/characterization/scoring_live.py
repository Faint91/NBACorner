"""Persisted scoring/history surfaces via guarded local environment."""

import unittest
from integration_harness import GuardedHarness, CANONICAL_CHECKSUM

CONFIG = None
OPT_IN = False
RESULTS = []


def behavior(
    group,
    current,
    classification="REQUIREMENT NOT YET REVIEWED",
    requirement=None,
    question=None,
):
    def wrap(fn):
        fn.metadata = dict(
            scenario=fn.__name__,
            group=group,
            current_behavior=current,
            approved_requirement=requirement,
            classification=classification,
            future_business_question=question,
            evidence_source="LIVE guarded local fixture reads/job refusal; canonical reset per case",
        )
        return fn

    return wrap


class CurrentLiveScoring(unittest.TestCase):
    def setUp(self):
        self.c = GuardedHarness(
            CONFIG, allow_local_mutations=OPT_IN, characterization_scope="NC-01D"
        )
        self.c.__enter__()
        self.facts = {}

    def tearDown(self):
        self.c.__exit__(None, None, None)
        self.assertEqual(self.c.cleanup_proof["fixture_checksum"], CANONICAL_CHECKSUM)
        r = dict(getattr(self, self._testMethodName).metadata)
        r.update(
            evidence=self.c.summary,
            facts=self.facts,
            cleanup_checksum=CANONICAL_CHECKSUM,
        )
        RESULTS.append(r)

    def call(self, method, path, status, role=None):
        actual, body = self.c.scoring_request(method, path, role=role)
        self.assertEqual(actual, status)
        return body

    @behavior(
        "global leaderboard",
        "Anonymous leaderboard reads stored current score rows; no rank field/pagination; malformed unrelated query ignored.",
        question="Approve accessibility/pagination and score presentation?",
    )
    def current_behavior__scoring__global(self):
        self.c.install_scoring_read_state()
        b = self.call("GET", "/leaderboard", 200)
        self.assertEqual(len(b["rows"]), 2)
        self.assertTrue(all("rank" not in r for r in b["rows"]))
        self.assertEqual(b, self.call("GET", "/leaderboard?malformed=synthetic", 200))
        self.facts = {"row_fields": sorted(b["rows"][0]), "rows": 2}

    @behavior(
        "tie ordering",
        "Exact equal score/full-hit tie ranks earlier saved_at first on global backend.",
        "MATCHES REQUIREMENT",
        "Exact leaderboard ties are ranked by earlier bracket saved_at.",
    )
    def current_behavior__scoring__tie(self):
        ids = self.c.install_scoring_read_state("tie")
        b = self.call("GET", "/leaderboard", 200)
        self.assertEqual([r["bracket_id"] for r in b["rows"]], [ids["b"], ids["a"]])

    @behavior(
        "ranking/sorting",
        "Equal points with unequal full_hits rank more full hits ahead of saved time; full equality has no explicit further tiebreak.",
        question="Approve full-hit priority and equal-time tie policy?",
    )
    def current_behavior__scoring__hits_priority(self):
        ids = self.c.install_scoring_read_state("unequal_hits")
        b = self.call("GET", "/leaderboard", 200)
        self.assertEqual(b["rows"][0]["bracket_id"], ids["a"])

    @behavior(
        "eligibility",
        "Stored unsaved score row appears in anonymous leaderboard; same draft-score surface established in NC-01C.",
        "KNOWN GAP",
        "Another user's bracket may be visible only if saved.",
    )
    def current_behavior__scoring__draft(self):
        ids = self.c.install_scoring_read_state("draft")
        b = self.call("GET", "/leaderboard", 200)
        self.assertFalse(any(r["bracket_id"] == ids["a"] for r in b["rows"]))
        self.facts = {"prior_reference": "NC-01C draft_scored_leaderboard"}

    @behavior(
        "eligibility",
        "Soft-deleted current bracket omitted despite retained stored score; historical snapshot rows remain readable.",
        question="Approve deleted-object retention/visibility?",
    )
    def current_behavior__scoring__deleted(self):
        ids = self.c.install_scoring_read_state("deleted")
        b = self.call("GET", "/leaderboard", 200)
        self.assertFalse(any(r["bracket_id"] == ids["a"] for r in b["rows"]))
        self.c.login("user-a")
        self.assertEqual(
            len(
                self.call("GET", "/leaderboard/history/2024-25", 200, "user-a")["rows"]
            ),
            2,
        )

    @behavior(
        "historical reads",
        "History index/detail require JWT; read structured snapshots/rows, retain ranks/display/numeric points, omit email/security/bracket-user IDs.",
        "MATCHES REQUIREMENT",
        "Email addresses must never be exposed.",
    )
    def current_behavior__history__reads(self):
        self.c.install_scoring_read_state()
        self.call("GET", "/leaderboard/history", 401)
        self.c.login("user-a")
        b = self.call("GET", "/leaderboard/history/2024-25", 200, "user-a")
        self.assertTrue(
            all(
                not ({"email", "user_id", "bracket_id", "password", "token"} & set(r))
                for r in b["rows"]
            )
        )
        self.assertEqual(
            len(self.call("GET", "/leaderboard/history", 200, "user-a")["seasons"]), 1
        )
        self.call("GET", "/leaderboard/history/invalid", 404, "user-a")
        self.call("GET", "/leaderboard/history/2025-26", 404, "user-a")
        self.facts = {
            "row_fields": sorted(b["rows"][0]),
            "rows": 2,
            "anonymous_denied": True,
        }

    @behavior(
        "recomputation",
        "Existing test job guard refuses recompute/snapshot HTTP execution (500) even admin; score/history records remain unchanged. Preserved characterization limitation.",
        question="A separately approved scoped-job extension would be needed for live maintenance execution.",
    )
    def current_behavior__scoring__job_refusal(self):
        ids = self.c.install_scoring_read_state()
        self.c.login("admin")
        before = self.call("GET", "/leaderboard", 200)
        self.call(
            "POST", f"/admin/score/master/{ids['master']}/recompute", 500, "admin"
        )
        self.call("POST", "/admin/leaderboard/snapshot", 500, "admin")
        self.assertEqual(before, self.call("GET", "/leaderboard", 200))

    @behavior(
        "edge behavior",
        "No stored scores returns empty rows/master map; historical missing snapshots return 404 authenticated.",
        question="Approve empty/missing response contract?",
    )
    def current_behavior__scoring__empty(self):
        self.assertEqual(self.call("GET", "/leaderboard", 200)["rows"], [])
        self.c.login("user-a")
        self.call("GET", "/leaderboard/history/2024-25", 404, "user-a")


from scripts.nc02a2_acceptance_metadata import mark_acceptance as mark_nc02a2_acceptance

mark_nc02a2_acceptance(CurrentLiveScoring)
