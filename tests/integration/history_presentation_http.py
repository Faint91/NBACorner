"""Verify frozen matchup presentation through Flask, PostgREST and PostgreSQL.

Optional: pass the built frontend directory and its browser script to exercise
the same data in Edge. Build with VITE_API_URL=http://127.0.0.1:51892.
"""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from threading import Thread

from werkzeug.serving import make_server
from werkzeug.middleware.shared_data import SharedDataMiddleware

import master_lifecycle as fixture

# Public column definitions verified independently of the application mapping.
EXPECTED = json.loads(r'''[
  [
    "2017-18", "7812e982-1e70-4cb4-a775-c2321cf2a3a5",
    [
      ["tor_was","TOR - WAS",1],
      ["cle_ind","CLE - IND",1],
      ["phi_mia","PHI - MIA",1],
      ["bos_mil","BOS - MIL",1],
      ["hou_min","HOU - MIN",1],
      ["uta_okc","UTA - OKC",1],
      ["por_nop","POR - NOP",1],
      ["gsw_sas","GSW - SAS",1],
      ["tor_cle","TOR - CLE",2],
      ["bos_phi","BOS - PHI",2],
      ["hou_uta","HOU - UTA",2],
      ["gsw_nop","GSW - NOP",2],
      ["bos_cle","BOS - CLE",3],
      ["hou_gsw","HOU - GSW",3],
      ["cle_gsw","CLE - GSW",4]
    ],
    {}
  ],
  [
    "2018-19", "a06cad70-f2d1-4ff9-8a13-3e836d0fb26c",
    [
      ["gsw_lac","GSW - LAC",1],
      ["hou_uta","HOU - UTA",1],
      ["por_okc","POR - OKC",1],
      ["den_sas","DEN - SAS",1],
      ["mil_det","MIL - DET",1],
      ["tor_orl","TOR - ORL",1],
      ["phi_bkn","PHI - BKN",1],
      ["bos_ind","BOS - IND",1],
      ["gsw_hou","GSW - HOU",2],
      ["por_den","POR - DEN",2],
      ["mil_bos","MIL - BOS",2],
      ["tor_phi","TOR - PHI",2],
      ["gsw_por","GSW - POR",3],
      ["mil_tor","MIL - TOR",3],
      ["gsw_tor","GSW - TOR",4]
    ],
    {}
  ],
  [
    "2019-20", "8fe9031f-c5d2-4517-9dd7-38bc4ff09a5f",
    [
      ["lal_por","LAL - POR",1],
      ["okc_hou","OKC - HOU",1],
      ["den_uta","DEN - UTA",1],
      ["lac_dal","LAC - DAL",1],
      ["mil_orl","MIL - ORL",1],
      ["mia_ind","MIA - IND",1],
      ["bos_phi","BOS - PHI",1],
      ["tor_bkn","TOR - BKN",1],
      ["lal_hou","LAL - HOU",2],
      ["den_lac","DEN - LAC",2],
      ["mil_mia","MIL - MIA",2],
      ["bos_tor","BOS - TOR",2],
      ["lal_den","LAL - DEN",3],
      ["bos_mia","BOS - MIA",3],
      ["lal_mia","LAL - MIA",4]
    ],
    {}
  ],
  [
    "2020-21", "2666b16a-48e6-4ddd-9e64-7d03d81895cc",
    [
      ["uta_mem","UTA - MEM",1],
      ["lac_dal","LAC - DAL",1],
      ["den_por","DEN - POR",1],
      ["phx_lal","PHX - LAL",1],
      ["phi_was","PHI - WAS",1],
      ["nyk_atl","NYK - ATL",1],
      ["mil_mia","MIL - MIA",1],
      ["bkn_bos","BKN - BOS",1],
      ["phi_atl","PHI - ATL",2],
      ["mil_bkn","MIL - BKN",2],
      ["den_phx","DEN - PHX",2],
      ["lac_uta","LAC - UTA",2],
      ["phx_lac","PHX - LAC",3],
      ["atl_mil","ATL - MIL",3],
      ["phx_mil","PHX - MIL",4]
    ],
    {}
  ],
  [
    "2021-22", "76de48b4-7de5-4b99-9329-88d99410cbb9",
    [
      ["mia_atl","MIA - ATL",1],
      ["phi_tor","PHI - TOR",1],
      ["mil_chi","MIL - CHI",1],
      ["bos_bkn","BOS - BKN",1],
      ["phx_nop","PHX - NOP",1],
      ["dal_uta","DAL - UTA",1],
      ["gsw_den","GSW - DEN",1],
      ["mem_min","MEM - MIN",1],
      ["mia_phi","MIA - PHI",2],
      ["mil_bos","MIL - BOS",2],
      ["phx_dal","PHX - DAL",2],
      ["gsw_mem","GSW - MEM",2],
      ["mia_bos","MIA - BOS",3],
      ["gsw_dal","GSW - DAL",3],
      ["bos_gsw","BOS - GSW",4]
    ],
    {}
  ],
  [
    "2022-23", "15c1d0a2-0cd3-4456-b723-df83fdb5aaaf",
    [
      ["den_min","DEN - MIN",1],
      ["phx_lac","PHX - LAC",1],
      ["sac_gsw","SAC - GSW",1],
      ["mem_lal","MEM - LAL",1],
      ["mil_mia","MIL - MIA",1],
      ["cle_nyk","CLE - NYK",1],
      ["phi_bkn","PHI - BKN",1],
      ["bos_atl","BOS - ATL",1],
      ["den_phx","DEN - PHX",2],
      ["gsw_lal","GSW - LAL",2],
      ["mia_nyk","MIA - NYK",2],
      ["phi_bos","PHI - BOS",2],
      ["den_lal","DEN - LAL",3],
      ["bos_mia","BOS - MIA",3],
      ["den_mia","DEN - MIA",4]
    ],
    {}
  ],
  [
    "2024-25", "ef9daf28-7294-49fc-9a67-ee074c8ad242",
    [
      ["okc_mem","OKC - MEM",1],
      ["den_lac","DEN - LAC",1],
      ["lal_min","LAL - MIN",1],
      ["hou_gsw","HOU - GSW",1],
      ["cle_mia","CLE - MIA",1],
      ["ind_mil","IND - MIL",1],
      ["nyk_det","NYK - DET",1],
      ["bos_orl","BOS - ORL",1],
      ["okc_den","OKC - DEN",2],
      ["min_gsw","MIN - GSW",2],
      ["cle_ind","CLE - IND",2],
      ["bos_nyk","BOS - NYK",2],
      ["okc_min","OKC - MIN",3],
      ["nyk_ind","NYK - IND",3],
      ["okc_ind","OKC - IND",4]
    ],
    {}
  ],
  [
    "2025-26", "1df7e788-9e5a-4b5e-9cd5-1d65eae9916b",
    [
      ["east-0-1","east-0-1",0],
      ["east-0-2","east-0-2",0],
      ["east-0-3","east-0-3",0],
      ["west-0-1","west-0-1",0],
      ["west-0-2","west-0-2",0],
      ["west-0-3","west-0-3",0],
      ["east-1-4","east-1-4",1],
      ["east-1-5","east-1-5",1],
      ["east-1-6","east-1-6",1],
      ["east-1-7","east-1-7",1],
      ["west-1-4","west-1-4",1],
      ["west-1-5","west-1-5",1],
      ["west-1-6","west-1-6",1],
      ["west-1-7","west-1-7",1],
      ["east-2-8","east-2-8",2],
      ["east-2-9","east-2-9",2],
      ["west-2-8","west-2-8",2],
      ["west-2-9","west-2-9",2],
      ["east-3-10","east-3-10",3],
      ["west-3-10","west-3-10",3],
      ["nba-4-11","nba-4-11",4]
    ],
    {
      "east-0-1": [["Charlotte Hornets","CHA"],["Miami Heat","MIA"]],
      "east-0-2": [["Philadelphia 76ers","PHI"],["Orlando Magic","ORL"]],
      "east-0-3": [["Charlotte Hornets","CHA"],["Orlando Magic","ORL"]],
      "west-0-1": [["Los Angeles Clippers","LAC"],["Golden State Warriors","GSW"]],
      "west-0-2": [["Phoenix Suns","PHX"],["Portland Trail Blazers","POR"]],
      "west-0-3": [["Golden State Warriors","GSW"],["Phoenix Suns","PHX"]],
      "east-1-4": [["Detroit Pistons","DET"],["Orlando Magic","ORL"]],
      "east-1-5": [["Boston Celtics","BOS"],["Philadelphia 76ers","PHI"]],
      "east-1-6": [["New York Knicks","NYK"],["Atlanta Hawks","ATL"]],
      "east-1-7": [["Cleveland Cavaliers","CLE"],["Toronto Raptors","TOR"]],
      "west-1-4": [["Oklahoma City Thunder","OKC"],["Phoenix Suns","PHX"]],
      "west-1-5": [["San Antonio Spurs","SAS"],["Portland Trail Blazers","POR"]],
      "west-1-6": [["Denver Nuggets","DEN"],["Minnesota Timberwolves","MIN"]],
      "west-1-7": [["Los Angeles Lakers","LAL"],["Houston Rockets","HOU"]],
      "east-2-8": [["New York Knicks","NYK"],["Philadelphia 76ers","PHI"]],
      "east-2-9": [["Detroit Pistons","DET"],["Cleveland Cavaliers","CLE"]],
      "west-2-8": [["Minnesota Timberwolves","MIN"],["San Antonio Spurs","SAS"]],
      "west-2-9": [["Oklahoma City Thunder","OKC"],["Los Angeles Lakers","LAL"]],
      "east-3-10": [["Cleveland Cavaliers","CLE"],["New York Knicks","NYK"]],
      "west-3-10": [["Oklahoma City Thunder","OKC"],["San Antonio Spurs","SAS"]],
      "nba-4-11": [["New York Knicks","NYK"],["San Antonio Spurs","SAS"]]
    }
  ]
]''')
EXPECTED_ROWS = {
    "2017-18": 22,
    "2018-19": 22,
    "2019-20": 28,
    "2020-21": 14,
    "2021-22": 17,
    "2022-23": 15,
    "2024-25": 22,
    "2025-26": 13,
}
HOST_ENV = {
    key: value for key, value in os.environ.items()
    if key.upper() in {
        "APPDATA", "COMSPEC", "HOMEDRIVE", "HOMEPATH", "LOCALAPPDATA", "PATH",
        "PLAYWRIGHT_DEPENDENCIES", "PROGRAMFILES", "PROGRAMFILES(X86)", "SYSTEMROOT",
        "TEMP", "TMP", "USERPROFILE", "WINDIR",
    }
}
NODE_EXECUTABLE = shutil.which("node")
SUMMARY = (
    ("bonus_finalists", "Finalists", "bonus"),
    ("bonus_champion", "Champion", "bonus"),
    ("full_hits", "Full hits", "summary"),
    ("partial_hits", "Partial hits", "summary"),
    ("misses", "Misses", "summary"),
)


def insert(sql, table, rows):
    fields = ",".join(rows[0])
    sql(f"""INSERT INTO {table}({fields})
            SELECT {fields} FROM jsonb_populate_recordset(NULL::{table}, $fixture$
            {json.dumps(rows)} $fixture$::jsonb);""")


def snapshot(sql, code, snap_id, definitions, labels, season_id, template):
    count = EXPECTED_ROWS[code]
    columns = [
        dict(key=key, label=label, round=round_number, type="matchup", internal="private")
        for key, label, round_number in definitions
    ]
    columns.extend(dict(key=key, label=label, type=kind) for key, label, kind in SUMMARY)
    columns.append(dict(key="private_matchup", label="Do not expose", type="matchup"))
    keys = [key for key, _, _ in definitions]
    # Include a real legacy key from a different snapshot, as well as an unknown key.
    foreign_key = "cle_gsw" if "cle_gsw" not in keys else "gsw_lac"
    columns.append(dict(key=foreign_key, label="Wrong snapshot", type="matchup"))
    stored_rows, brackets, references, mappings, matches, users = [], [], [], [], [], []
    for i in range(count):
        row_id = fixture.identity(f"walkthrough-row-{snap_id}-{i}")
        scores = {key: (i + j) % 7 for j, key in enumerate(keys)}
        stored_rows.append(dict(
            id=row_id, snapshot_id=snap_id, rank=1 if i < 2 else i + 1,
            display_name=f"{code} entrant {i:02}", total_points=100 - max(1, i),
            bonus_finalists=4, bonus_champion=3, full_hits=2, partial_hits=1, misses=5,
            per_match_points={**scores, "private_matchup": 999, foreign_key: 998},
            points_by_round={"1": 10, "private_matchup": 999, foreign_key: 998}, display_order=i + 1,
        ))
        if labels:
            user_id = fixture.identity(f"walkthrough-user-{i}")
            bracket_id = fixture.identity(f"walkthrough-bracket-{i}")
            users.append(dict(id=user_id, username=f"fixture_{i}", email=f"fixture_{i}@example.invalid"))
            brackets.append(dict(id=bracket_id, season_id=season_id, user_id=user_id, is_done=True,
                                 saved_at="2026-07-01T00:00:00Z", name=stored_rows[-1]["display_name"]))
            references.append(dict(season_id=season_id, season_code=code, rank=stored_rows[-1]["rank"],
                                   bracket_name=brackets[-1]["name"], username=users[-1]["username"],
                                   total_points=stored_rows[-1]["total_points"], full_hits=2, partial_hits=1,
                                   misses=5, bonus_finalists=4, bonus_champion=3,
                                   bracket_id=bracket_id, user_id=user_id))
            mappings.append(dict(snapshot_row_id=row_id, user_id=user_id))
            match_ids = {match["id"]: fixture.identity(f'{i}-{match["id"]}') for match in template}
            matches.extend(dict(match, id=match_ids[match["id"]], bracket_id=bracket_id,
                                next_match_id=match_ids.get(match["next_match_id"])) for match in template)
    if brackets:
        insert(sql, "users", users)
        insert(sql, "brackets", brackets)
        insert(sql, "leaderboard_history", references)
        fields = ",".join(matches[0])
        sql(f"""BEGIN; SET CONSTRAINTS ALL DEFERRED;
                INSERT INTO matches({fields})
                SELECT {fields} FROM jsonb_populate_recordset(NULL::matches,$fixture$
                {json.dumps(matches)} $fixture$::jsonb);
                COMMIT;""")
    insert(sql, "leaderboard_history_snapshots", [dict(
        id=snap_id, season_id=season_id, season_code=code, columns=columns,
        is_final=False if labels else None, expected_rows=count,
        master_bracket_id=brackets[0]["id"] if labels else None,
    )])
    insert(sql, "leaderboard_history_rows", stored_rows)
    if mappings:
        insert(sql, "leaderboard_history_competitors", mappings)
        sql(f"UPDATE leaderboard_history_snapshots SET is_final=true WHERE id='{snap_id}'")
    return stored_rows, brackets


def check_snapshot(body, stored, brackets, definitions, labels):
    columns = body["columns"]
    assert [col["key"] for col in columns] == [col[0] for col in definitions] + [col[0] for col in SUMMARY]
    for column, (key, label, round_number) in zip(columns, definitions):
        expected = dict(key=key, label=label, round=round_number, type="matchup")
        if labels:
            (name_a, code_a), (name_b, code_b) = labels[key]
            expected.update(team_label=f"{name_a} vs. {name_b}", short_label=f"{code_a} \u2013 {code_b}")
        assert column == expected, column
    assert len(body["rows"]) == len(stored)
    for index, (actual, row) in enumerate(zip(body["rows"], stored)):
        for field in ("id", "rank", "display_name", "total_points", "bonus_finalists",
                      "bonus_champion", "full_hits", "partial_hits", "misses"):
            assert actual[field] == row[field], (field, actual)
        assert actual["per_match_points"] == {key: row["per_match_points"][key] for key, _, _ in definitions}
        assert not {"user_id", "snapshot_id", "competitor_id"} & actual.keys()
        assert actual["points_by_round"] == {"1": 10}
        assert actual["historical_bracket_id"] == (brackets[index]["id"] if brackets else None)


def exercise(module, sql):
    historic = fixture.identity("historical")
    current = fixture.identity("current")
    sql(f"UPDATE seasons SET code='2026-27' WHERE id='{current}'; UPDATE seasons SET code='2025-26' WHERE id='{historic}';")
    client = module.app.test_client()
    current_board = client.get("/leaderboard")
    assert current_board.status_code == 200
    template = fixture.bracket_scenario("historical")["matches"]
    cases = []
    for code, snap_id, definitions, labels in EXPECTED:
        season_id = historic if labels else fixture.identity(f"walkthrough-season-{code}")
        if not labels:
            insert(sql, "seasons", [dict(id=season_id, code=code)])
        cases.append((code, definitions, labels, *snapshot(sql, code, snap_id, definitions, labels, season_id, template)))

    def assert_read_only(request):
        assert request.url.host == "127.0.0.1"
        assert request.method == "GET" or (
            request.method == "POST" and request.url.path == "/rpc/read_current_score_snapshot"
        ), (request.method, request.url.path)

    module.supabase.session.event_hooks["request"].append(assert_read_only)
    for code, definitions, labels, stored, brackets in cases:
        response = client.get("/leaderboard/history/" + code)
        assert response.status_code == 200, response.status_code
        body = response.get_json()
        assert body["season_code"] == code
        check_snapshot(body, stored, brackets, definitions, labels)
        for bracket in brackets:
            detail = client.get("/history/bracket/" + bracket["id"])
            assert detail.status_code == 200
            payload = detail.get_json()
            assert payload["bracket"]["id"] == bracket["id"] and payload["bracket"]["read_only"]
            assert sum(len(group) for rounds in payload["matches"].values() for group in rounds.values()) == 21
    assert client.get("/leaderboard").get_json() == current_board.get_json()
    assert len(cases) == 8
    assert sum(len(definitions) for _, definitions, _, _, _ in cases) == 126
    assert sum(len(definitions) * len(rows) for _, definitions, _, rows, _ in cases) == 2373
    print("PASS real HTTP/PostgREST: 8 seasons, 126 matchup columns, 2373 point cells, totals, ranks, 13 read-only links and unchanged current leaderboard", flush=True)

    if len(sys.argv) == 5:
        bundle, browser_script = map(Path, sys.argv[3:])
        # Unknown frontend routes serve the SPA shell. API reads remain real HTTP.
        static_app = SharedDataMiddleware(module.app, {"/": str(bundle.resolve())})

        def site(environ, start_response):
            if environ["PATH_INFO"] in ("/past-seasons", "/"):
                environ["PATH_INFO"] = "/index.html"
            return static_app(environ, start_response)

        serve = make_server("127.0.0.1", 51892, site)
        worker = Thread(target=serve.serve_forever, daemon=True)
        worker.start()
        try:
            assert NODE_EXECUTABLE, "Node is required for the browser regression"
            subprocess.run([NODE_EXECUTABLE, "--test", str(browser_script.resolve())], check=True, env=HOST_ENV)
        finally:
            serve.shutdown()
            worker.join()

    # A newer, unapproved snapshot of the exact same season must not inherit the keys.
    code, _, definitions, _ = EXPECTED[0]
    season_id = fixture.identity(f"walkthrough-season-{code}")
    snapshot(sql, code, fixture.identity("unapproved-snapshot"), definitions, {}, season_id, template)
    unapproved = client.get("/leaderboard/history/" + code).get_json()
    assert all(column["type"] != "matchup" for column in unapproved["columns"])
    assert all(row["per_match_points"] == {} for row in unapproved["rows"])
    print("PASS same-season snapshot scope and private field filtering", flush=True)


if __name__ == "__main__":
    fixture.exercise = exercise
    fixture.main(Path(sys.argv[1]), Path(sys.argv[2]))
