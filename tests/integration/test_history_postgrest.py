"""Real PostgREST regression. Load history_links_fixture.sql into an empty test DB,
serve it on loopback with db-anon-role=fixture_reader, set HISTORY_FIXTURE_POSTGREST_PORT,
and run python -m unittest discover -s tests/integration. Only GET requests are made.
"""
import os
import unittest
from types import SimpleNamespace
from uuid import UUID

import requests
from postgrest import SyncPostgrestClient

from history_service import historical_bracket_links


class HistoryRelationshipTest(unittest.TestCase):
    def test_resolves_archived_bracket_season_with_two_foreign_keys(self):
        port = int(os.environ["HISTORY_FIXTURE_POSTGREST_PORT"])
        origin = f"http://127.0.0.1:{port}"
        # Prove this fixture reproduces the original ambiguity.
        response = requests.get(
            f"{origin}/brackets",
            params={"select": "id,seasons!inner(code)", "limit": "0"},
            timeout=5,
            allow_redirects=False,
        )
        self.assertEqual(response.status_code, 300)
        self.assertEqual(response.json()["code"], "PGRST201")
        snapshot = {"season_id": 1, "season_code": "2025-26"}
        rows = [{"id": 100 + i} for i in range(1, 14)]
        with SyncPostgrestClient(origin) as client:
            links = historical_bracket_links(
                client, snapshot, rows, SimpleNamespace(id=2, code="2026-27")
            )
        self.assertEqual(links, {100 + i: str(UUID(int=i)) for i in range(1, 14)})
