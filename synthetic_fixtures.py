"""Pure synthetic states, not approved feature requirements. No transport or writer."""

import json
import uuid
from pathlib import Path

VERSION = "nc-fixtures-v1"
STAMP = "2025-08-01T00:00:00+00:00"
NAMESPACE = uuid.UUID("946e5050-c000-4000-8000-000000000001")
TABLES = (
    "users",
    "seasons",
    "teams",
    "standings",
    "brackets",
    "matches",
    "bracket_scores",
    "leagues",
    "league_members",
    "password_resets",
    "leaderboard_history",
    "leaderboard_history_snapshots",
    "leaderboard_history_rows",
)
SEQUENCES = ("standings_id_seq", "password_resets_id_seq", "leaderboard_history_id_seq")
EAST = "ATL BOS BKN CHA CHI CLE DET IND MIA MIL NYK ORL PHI TOR WAS".split()
WEST = "DAL DEN GSW HOU LAC LAL MEM MIN NOP OKC PHX POR SAC SAS UTA".split()


def identity(label):
    return str(uuid.uuid5(NAMESPACE, label))


def hashes():
    return json.loads(
        (
            Path(__file__).parent / "tests/fixtures/application/synthetic-bcrypt.json"
        ).read_text(encoding="utf-8")
    )


def empty_state():
    return {table: [] for table in TABLES}


def foundation():
    data = empty_state()
    for role in ("user-a", "user-b", "admin", "owner"):
        data["users"].append(
            dict(
                id=identity(role),
                username="fixture-" + role,
                email=role + "@nba-corner.example",
                created_at=STAMP,
                password=hashes()[role],
                is_admin=role == "admin",
                reset_token=None,
                reset_token_expires=None,
            )
        )
    for kind, code, end, start in (
        (
            "current",
            "2025-26",
            "2026-04-12T07:00:00+00:00",
            "2026-04-18T07:00:00+00:00",
        ),
        (
            "historical",
            "2024-25",
            "2025-04-12T07:00:00+00:00",
            "2025-04-19T07:00:00+00:00",
        ),
    ):
        data["seasons"].append(
            dict(
                id=identity(kind),
                code=code,
                regular_season_end_utc=end,
                playoffs_start_utc=start,
                created_at=STAMP,
                master_bracket_id=None,
            )
        )
    for conference, codes in (("east", EAST), ("west", WEST)):
        for seed, code in enumerate(codes, 1):
            data["teams"].append(
                dict(
                    id=code,
                    code=code,
                    name="Fixture " + code,
                    conference=conference,
                    logo_url=None,
                    primary_color=None,
                    secondary_color=None,
                )
            )
            wins = 61 - seed * 2
            losses = 82 - wins
            data["standings"].append(
                dict(
                    id=len(data["standings"]) + 1,
                    code=code,
                    name="Fixture " + code,
                    wins=wins,
                    losses=losses,
                    conference=conference,
                    seed=seed,
                    updated_at="2025-08-01T00:00:00",
                    win_pct=wins / 82,
                )
            )
    return data


def bracket_scenario(kind):
    if kind not in {"draft", "saved", "master", "deleted", "historical"}:
        raise ValueError("Unknown synthetic bracket scenario")
    data = foundation()
    bid = identity("bracket-" + kind)
    season = identity("historical" if kind == "historical" else "current")
    user = identity("admin" if kind == "master" else "user-a")
    data["brackets"].append(
        dict(
            id=bid,
            user_id=user,
            created_at=STAMP,
            updated_at=STAMP,
            is_done=kind in {"saved", "master", "historical"},
            saved_at=STAMP if kind in {"saved", "master", "historical"} else None,
            deleted_at=STAMP if kind == "deleted" else None,
            deleted_by_user_id=identity("admin") if kind == "deleted" else None,
            name="Fixture " + kind,
            is_master=kind == "master",
            season_id=season,
        )
    )
    if kind == "master":
        next(row for row in data["seasons"] if row["id"] == season)[
            "master_bracket_id"
        ] = bid
    # Separate bundles avoid the existing global active-user uniqueness constraint.
    for conf, codes in (("east", EAST), ("west", WEST)):
        for slot, rnd in (
            (1, 0),
            (2, 0),
            (3, 0),
            (4, 1),
            (5, 1),
            (6, 1),
            (7, 1),
            (8, 2),
            (9, 2),
            (10, 3),
        ):
            teams = {
                1: (codes[8], codes[9]),
                2: (codes[6], codes[7]),
                4: (codes[0], None),
                5: (codes[1], None),
                6: (codes[2], codes[5]),
                7: (codes[3], codes[4]),
            }.get(slot, (None, None))
            data["matches"].append(match_row(bid, season, conf, rnd, slot, *teams))
    data["matches"].append(match_row(bid, season, "nba", 4, 11, None, None))
    links = {
        1: (3, "a"),
        2: (5, "b"),
        3: (4, "b"),
        4: (9, "a"),
        5: (8, "b"),
        6: (8, "a"),
        7: (9, "b"),
        8: (10, "b"),
        9: (10, "a"),
        10: (11, "a"),
    }
    for row in data["matches"]:
        if row["conference"] == "nba":
            continue
        slot, nslot = links[row["slot"]]
        conf = "nba" if slot == 11 else row["conference"]
        row.update(
            next_match_id=identity(f"{bid}-{conf}-{slot}"),
            next_slot="b" if slot == 11 and row["conference"] == "west" else nslot,
        )
    if kind in {"saved", "master", "historical"}:
        row = data["matches"][0]
        row.update(predicted_winner=row["team_a"], predicted_winner_games=1)
        child = next(x for x in data["matches"] if x["id"] == row["next_match_id"])
        child["team_a"] = row["predicted_winner"]
    return data


def match_row(bid, season, conf, rnd, slot, a, b):
    return dict(
        id=identity(f"{bid}-{conf}-{slot}"),
        bracket_id=bid,
        round=rnd,
        slot=slot,
        team_a=a,
        team_b=b,
        team_a_locked=a is not None,
        team_b_locked=b is not None,
        predicted_winner=None,
        predicted_winner_games=None,
        next_match_id=None,
        next_slot=None,
        created_at=STAMP,
        updated_at=STAMP,
        conference=conf,
        season_id=season,
    )


def league_scenario():
    data = foundation()
    for kind in ("public", "private"):
        lid = identity("league-" + kind)
        data["leagues"].append(
            dict(
                id=lid,
                name="Fixture " + kind,
                password_hash=hashes()["private-league"] if kind == "private" else None,
                owner_user_id=identity("owner"),
                is_global=False,
                created_at=STAMP,
                updated_at=STAMP,
            )
        )
        for role in ("owner", "user-a"):
            data["league_members"].append(
                dict(
                    id=identity(kind + "-" + role),
                    league_id=lid,
                    user_id=identity(role),
                    joined_at=STAMP,
                )
            )
    return data


def score_history_scenario():
    data = bracket_scenario("master")
    master = data["brackets"][0]["id"]
    for role in ("user-a", "user-b"):
        bid = identity("score-" + role)
        data["brackets"].append(
            dict(
                id=bid,
                user_id=identity(role),
                created_at=STAMP,
                updated_at=STAMP,
                is_done=True,
                saved_at=STAMP,
                deleted_at=None,
                deleted_by_user_id=None,
                name="Fixture score " + role,
                is_master=False,
                season_id=identity("current"),
            )
        )
        data["bracket_scores"].append(
            dict(
                bracket_id=bid,
                master_bracket_id=master,
                total_points=3,
                full_hits=1,
                partial_hits=0,
                misses=0,
                bonus_finalists=0,
                bonus_champion=0,
                points_by_round={"1": 3},
                points_by_match={},
                updated_at=STAMP,
                season_id=identity("current"),
            )
        )
    sid = identity("snapshot")
    data["leaderboard_history_snapshots"].append(
        dict(
            id=sid,
            season_id=identity("historical"),
            season_code="2024-25",
            snapshot_at=STAMP,
            columns=[],
            note="Synthetic raw history state",
            created_by=identity("admin"),
            created_at=STAMP,
        )
    )
    for rank, role in enumerate(("user-a", "user-b"), 1):
        bid = identity("history-" + role)
        data["brackets"].append(
            dict(
                id=bid,
                user_id=identity(role),
                created_at=STAMP,
                updated_at=STAMP,
                is_done=True,
                saved_at=STAMP,
                deleted_at=STAMP,
                deleted_by_user_id=identity("admin"),
                name="Fixture historical " + role,
                is_master=False,
                season_id=identity("historical"),
            )
        )
        data["leaderboard_history"].append(
            dict(
                id=rank,
                season_id=identity("historical"),
                season_code="2024-25",
                snapshot_at=STAMP,
                rank=rank,
                bracket_name="Fixture historical " + role,
                username="fixture-" + role,
                total_points=3,
                full_hits=1,
                partial_hits=0,
                misses=0,
                bonus_finalists=0,
                bonus_champion=0,
                points_by_match={},
                bracket_id=bid,
                user_id=identity(role),
            )
        )
        data["leaderboard_history_rows"].append(
            dict(
                id=identity("history-row-" + role),
                snapshot_id=sid,
                rank=rank,
                display_name="fixture-" + role,
                total_points=3,
                bonus_finalists=0,
                bonus_champion=0,
                full_hits=1,
                partial_hits=0,
                misses=0,
                per_match_points={},
                created_at=STAMP,
            )
        )
    return data


def reset_scenario(*, used=False):
    data = foundation()
    data["password_resets"].append(
        dict(
            id=1,
            token="fixture-only-reset-user-a",
            expires_at="2026-04-01T00:00:00",
            used=used,
            created_at="2026-03-31T00:00:00",
            user_id=identity("user-a"),
        )
    )
    return data


def validate_state(data):
    """Structural integrity only; no assertion about approved product semantics."""
    manifest = json.loads(
        (Path(__file__).parent / "tests/fixtures/application/manifest.json").read_text(
            encoding="utf-8"
        )
    )
    if set(data) != set(TABLES) or manifest["fixture_version"] != VERSION:
        raise ValueError("Fixture inventory/version mismatch")
    for table, rows in data.items():
        if not isinstance(rows, list) or any(
            set(row) != set(manifest["columns"][table]) for row in rows
        ):
            raise ValueError("Fixture columns mismatch")
        key = "bracket_id" if table == "bracket_scores" else "id"
        if len({row[key] for row in rows}) != len(rows):
            raise ValueError("Duplicate fixture identity")
    users = {r["id"]: r for r in data["users"]}
    seasons = {r["id"]: r for r in data["seasons"]}
    teams = {r["id"]: r for r in data["teams"]}
    brackets = {r["id"]: r for r in data["brackets"]}
    if len(teams) != 30 or {r["code"] for r in teams.values()} != set(EAST + WEST):
        raise ValueError("Team reference mismatch")
    if len(seasons) != 2 or {r["code"] for r in seasons.values()} != {
        "2025-26",
        "2024-25",
    }:
        raise ValueError("Season mismatch")
    if len(users) != 4 or sum(r["is_admin"] for r in users.values()) != 1:
        raise ValueError("Synthetic roles mismatch")
    if any(
        not r["email"].endswith("@nba-corner.example") or r["reset_token"] is not None
        for r in users.values()
    ):
        raise ValueError("Synthetic account isolation mismatch")
    if (
        len(data["standings"]) != 30
        or len({r["code"] for r in data["standings"]}) != 30
    ):
        raise ValueError("Standings identity mismatch")
    for conf, codes in (("east", EAST), ("west", WEST)):
        rows = sorted(
            (r for r in data["standings"] if r["conference"] == conf),
            key=lambda r: r["seed"],
        )
        if [r["seed"] for r in rows] != list(range(1, 16)) or {
            r["code"] for r in rows
        } != set(codes):
            raise ValueError("Standings rank mismatch")
    active = [r for r in brackets.values() if r["deleted_at"] is None]
    if len({r["user_id"] for r in active}) != len(active):
        raise ValueError("Preserved active bracket uniqueness limitation")
    masters = [r for r in brackets.values() if r["is_master"]]
    if len({r["season_id"] for r in masters}) != len(masters):
        raise ValueError("Master uniqueness limitation")
    for row in brackets.values():
        if row["user_id"] not in users or row["season_id"] not in seasons:
            raise ValueError("Bracket relation mismatch")
    for row in seasons.values():
        bid = row["master_bracket_id"]
        if bid and (
            bid not in brackets
            or brackets[bid]["season_id"] != row["id"]
            or not brackets[bid]["is_master"]
        ):
            raise ValueError("Master pointer mismatch")
    matches = {r["id"]: r for r in data["matches"]}
    for row in matches.values():
        if (
            row["bracket_id"] not in brackets
            or row["season_id"] != brackets[row["bracket_id"]]["season_id"]
        ):
            raise ValueError("Match season mismatch")
        if any(
            row[k] is not None and row[k] not in teams
            for k in ("team_a", "team_b", "predicted_winner")
        ):
            raise ValueError("Match team mismatch")
        visited = {row["id"]}
        nxt = row["next_match_id"]
        while nxt:
            if (
                nxt not in matches
                or nxt in visited
                or matches[nxt]["bracket_id"] != row["bracket_id"]
            ):
                raise ValueError("Match graph mismatch")
            visited.add(nxt)
            nxt = matches[nxt]["next_match_id"]
    leagues = {r["id"]: r for r in data["leagues"]}
    for row in leagues.values():
        if row["owner_user_id"] not in users:
            raise ValueError("League owner mismatch")
    for row in data["league_members"]:
        if row["league_id"] not in leagues or row["user_id"] not in users:
            raise ValueError("Membership mismatch")
    for row in data["bracket_scores"]:
        if (
            any(row[k] not in brackets for k in ("bracket_id", "master_bracket_id"))
            or brackets[row["bracket_id"]]["season_id"] != row["season_id"]
        ):
            raise ValueError("Score relation mismatch")
    snapshots = {r["id"]: r for r in data["leaderboard_history_snapshots"]}
    for row in list(snapshots.values()) + data["leaderboard_history"]:
        if (
            row["season_id"] not in seasons
            or seasons[row["season_id"]]["code"] != row["season_code"]
        ):
            raise ValueError("History season mismatch")
    for row in data["leaderboard_history_rows"]:
        if row["snapshot_id"] not in snapshots:
            raise ValueError("History snapshot mismatch")
    for row in data["password_resets"]:
        if row["user_id"] not in users or not row["token"].startswith(
            "fixture-only-reset-"
        ):
            raise ValueError("Reset isolation mismatch")
    return True
