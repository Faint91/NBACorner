"""Static operational schedule, season, freeze and UI source mapping."""

import ast, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
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
            evidence_source="STATIC application/script/workflow/schema/frontend",
        )
        return fn

    return wrap


class CurrentStaticOperations(unittest.TestCase):
    def setUp(self):
        self.source = (ROOT / "app.py").read_text(encoding="utf-8")
        self.tree = ast.parse(self.source)
        self.script = (ROOT / "scripts/update_standings.py").read_text(encoding="utf-8")
        self.workflow = (ROOT / ".github/workflows/standings-cron.yml").read_text()

    def tearDown(self):
        RESULTS.append(dict(getattr(self, self._testMethodName).metadata))

    def fn(self, name):
        return ast.get_source_segment(
            self.source,
            next(
                n
                for n in self.tree.body
                if isinstance(n, ast.FunctionDef) and n.name == name
            ),
        )

    @behavior(
        "automation/schedule",
        "Workflow schedules every day 09:00 UTC including weekends, invokes ESPN script and allows manual dispatch. No seasonal scheduler condition.",
        "MATCHES REQUIREMENT",
        "Standings refresh daily during the regular season.",
    )
    def current_behavior__standings__schedule(self):
        self.assertIn('cron: "0 9 * * *"', self.workflow)
        self.assertIn("python scripts/update_standings.py", self.workflow)

    @behavior(
        "freeze",
        "Scheduled script and active admin/cron refresh helper lack regular-season-end/bracket-opening freeze checks; overwrite also lacks freeze.",
        "KNOWN GAP",
        "Standings freeze when the regular season ends / bracket-creation period opens.",
    )
    def current_behavior__standings__freeze(self):
        self.assertNotIn("REGULAR_SEASON_END_UTC", self.script)
        for name in [
            "fetch_and_sync_standings_from_nba",
            "admin_refresh_standings",
            "internal_cron_refresh_standings",
            "internal_overwrite_standings",
        ]:
            self.assertNotIn("playoffs_locked", self.fn(name))
            self.assertNotIn("REGULAR_SEASON_END_UTC", self.fn(name))

    @behavior(
        "season source",
        "App CURRENT_SEASON_CODE selects DB dates/id; script override/calendar independent; workflow NBA_SEASON_YEAR not consumed. NC-ENV-04B mismatch persists.",
        "KNOWN GAP",
        "Future season selection must derive from canonical application season configuration, not conflicting independent environment variables.",
    )
    def current_behavior__standings__season_sources(self):
        self.assertIn("NBA_SEASON_YEAR", self.workflow)
        self.assertNotIn("NBA_SEASON_YEAR", self.script)
        self.assertNotIn('os.getenv("NBA_STANDINGS_SEASON")', self.script)
        self.assertIn("return current_season()", self.fn("_resolve_season_globals"))

    @behavior(
        "cron operations",
        "Internal refresh/overwrite share STANDINGS_CRON_TOKEN header/query equality; admin refresh uses JWT+DB admin; job guard runs first. Token values not inspected.",
        question="Approve cron replay/token transport/diagnostic contract?",
    )
    def current_behavior__admin_ops__cron(self):
        for name in ["internal_cron_refresh_standings", "internal_overwrite_standings"]:
            self.assertIn("token_supplied != STANDINGS_CRON_TOKEN", self.fn(name))
            self.assertIn('request.args.get("token")', self.fn(name))

    @behavior(
        "team maintenance",
        "Admin route attempts 20 team upserts (synthetic IDs plus LAL), omitting required code; optional standings fallback. STATIC only, live job guard unchanged.",
        question="Approve team maintenance/idempotence/schema prerequisite policy?",
    )
    def current_behavior__admin_ops__teams(self):
        self.assertIn(".upsert(", self.fn("admin_insert_test_teams"))
        self.assertIn("seed_standings", self.fn("admin_insert_test_teams"))

    @behavior(
        "season lifecycle",
        "Seasons have unique code/dates/master pointer, no current flag; rollover inserts next row without changing app globals/config, does not initialize standings/teams/master.",
        question="Approve creation/default/current-season transition policy?",
    )
    def current_behavior__rollover__season_model(self):
        f = self.fn("_rollover_current_season")
        self.assertIn("env_next_actions", f)
        self.assertNotIn("os.environ[", f)
        schema = (ROOT / "db/baseline/000_current_schema.sql").read_text()
        self.assertIn('"seasons_code_key"', schema)

    @behavior(
        "admin operations",
        "No shared playoff guard blocks maintenance/rollover/snapshot/team helpers; ordinary creation gate has admin bypass (NC-01B).",
        "MATCHES REQUIREMENT",
        "Playoff start is not a universal block on unrelated actions.",
    )
    def current_behavior__admin_ops__lock(self):
        for name in [
            "_rollover_current_season",
            "admin_insert_test_teams",
            "admin_snapshot_leaderboard",
        ]:
            self.assertNotIn("playoffs_locked", self.fn(name))

    @behavior(
        "edges",
        "Internal overwrite expects standings.season_id though current table lacks it; delete+insert not atomic. No product/schema correction.",
        question="Approve overwrite schema and failure contract?",
    )
    def current_behavior__standings__overwrite(self):
        schema = (ROOT / "db/baseline/000_current_schema.sql").read_text()
        start = schema.index('CREATE TABLE "public"."standings"')
        end = schema.index('ALTER TABLE "public"."standings"', start)
        self.assertNotIn("season_id", schema[start:end])
        self.assertRegex(
            self.fn("internal_overwrite_standings"),
            r'.eq\(\s*"season_id",\s*current_season\(\)\.id\s*\)',
        )

    @behavior(
        "frontend",
        "AdminPage cached admin gate, snapshot/rollover confirmation and error/result/env-next-action display; UI completeness gates can differ from helper preconditions.",
        question="Approve UI/backend operational preconditions?",
    )
    def current_behavior__admin_ops__frontend(self):
        s = (ROOT.parent / "frontend/src/pages/AdminPage.tsx").read_text(
            encoding="utf-8"
        )
        for x in [
            "/admin/season/rollover",
            "/admin/leaderboard/snapshot",
            "rolloverDisabledReason",
            "snapshotDisabledReason",
            "new_season_code",
        ]:
            self.assertIn(x, s)

    @behavior(
        "admin operations",
        "Admin bracket creation bypasses ordinary early/locked window checks; prior NC-01B result retained, source gate unchanged.",
        "MATCHES REQUIREMENT",
        "Admin bracket creation may bypass the ordinary creation window.",
    )
    def current_behavior__admin_ops__creation_bypass(self):
        f = self.fn("create_bracket_for_user")
        self.assertIn("if not is_admin:", f)
        self.assertIn("current_season().bracket_creation_opens_at", f)
        self.assertIn("playoffs_locked()", f)
