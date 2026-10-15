"""Pure B6-B9 rules for the existing NBA bracket, without IO or authorization."""

from collections import Counter, deque
from copy import deepcopy


def game_count_error(match, value, *, allow_missing=False, count_edit=False):
    if match.get("round") == 0:
        if count_edit:
            return "Play-in game counts cannot be edited."
        if type(value) is int and value == 1:
            return None
        return "Play-in game count must be 1."
    if value is None and allow_missing:
        return None
    if type(value) is not int or value not in (4, 5, 6, 7):
        return "Series game count must be an integer from 4 through 7."
    return None


def dependency_edges(matches):
    rows = {m["id"]: m for m in matches}
    if len(rows) != len(matches):
        raise ValueError("Duplicate match identity.")
    edges = {mid: [] for mid in rows}
    for m in matches:
        dest = m.get("next_match_id")
        if dest:
            if dest not in rows or m.get("next_slot") not in ("a", "b"):
                raise ValueError("Invalid bracket dependency.")
            edges[m["id"]].append((dest, m["next_slot"], "winner"))
    # The schema stores only one winner edge. Derive the existing 7/8 loser
    # feed from the other root play-in's edge into the deciding play-in.
    for m in matches:
        if m.get("round") != 0 or not m.get("next_match_id"):
            continue
        if rows[m["next_match_id"]].get("round") != 1:
            continue
        feeders = [
            p
            for p in matches
            if p.get("round") == 0
            and p.get("conference") == m.get("conference")
            and p.get("next_match_id") in rows
            and rows[p["next_match_id"]].get("round") == 0
        ]
        if len(feeders) != 1:
            raise ValueError("Invalid play-in dependencies.")
        feeder = feeders[0]
        final = rows[feeder["next_match_id"]]
        if final["id"] != m["id"]:
            edges[m["id"]].append(
                (final["id"], "b" if feeder["next_slot"] == "a" else "a", "loser")
            )
    # Refuse cyclic graphs before any caller writes anything.
    incoming = Counter(dest for values in edges.values() for dest, _, _ in values)
    queue = deque(mid for mid in rows if not incoming[mid])
    visited = 0
    while queue:
        mid = queue.popleft()
        visited += 1
        for dest, _, _ in edges[mid]:
            incoming[dest] -= 1
            if incoming[dest] == 0:
                queue.append(dest)
    if visited != len(rows):
        raise ValueError("Cyclic bracket dependencies.")
    return edges


def output_team(match, kind):
    winner = match.get("predicted_winner")
    if not winner:
        return None
    if kind == "winner":
        return winner
    return match.get("team_b") if winner == match.get("team_a") else match.get("team_a")


def apply_prediction(matches, match_id, winner, games):
    """Replace changed outputs recursively, clearing only dependent predictions."""
    rows = {m["id"]: deepcopy(m) for m in matches}
    edges = dependency_edges(matches)
    source = rows[match_id]
    source["predicted_winner"] = winner
    source["predicted_winner_games"] = games
    touched = {match_id}
    queue = deque([match_id])
    while queue:
        mid = queue.popleft()
        for dest_id, slot, kind in edges[mid]:
            dest = rows[dest_id]
            value = output_team(rows[mid], kind)
            field = "team_" + slot
            if dest.get(field) == value:
                continue
            dest[field] = value
            dest["predicted_winner"] = None
            dest["predicted_winner_games"] = None
            touched.add(dest_id)
            queue.append(dest_id)
    return [rows[mid] for mid in sorted(touched)]


def submission_error(matches, *, master=False):
    """Full ordinary graph validity; incomplete master results are persistable."""
    try:
        edges = dependency_edges(matches)
    except (ValueError, KeyError, TypeError):
        return "Bracket dependencies are invalid."
    rows = {m["id"]: m for m in matches}
    if not master:
        expected = {
            (conf, rnd): count
            for conf in ("east", "west")
            for rnd, count in ((0, 3), (1, 4), (2, 2), (3, 1))
        }
        expected[("nba", 4)] = 1
        if Counter((m.get("conference"), m.get("round")) for m in matches) != expected:
            return "Bracket is missing required matchups or contains invalid matchups."
        if len(
            {(m.get("conference"), m.get("round"), m.get("slot")) for m in matches}
        ) != len(matches):
            return "Bracket contains duplicate matchups."
    incoming = {mid: {} for mid in rows}
    for mid, values in edges.items():
        src = rows[mid]
        for dest_id, slot, kind in values:
            dest = rows[dest_id]
            if slot in incoming[dest_id]:
                return "Bracket has conflicting dependency slots."
            incoming[dest_id][slot] = (mid, kind)
            if not master:
                same_conf = src.get("conference") == dest.get("conference")
                permitted = (
                    src.get("round") == 0
                    and dest.get("round") in (0, 1)
                    and same_conf
                    or src.get("round") in (1, 2)
                    and dest.get("round") == src["round"] + 1
                    and same_conf
                    or src.get("round") == 3
                    and dest.get("round") == 4
                    and dest.get("conference") == "nba"
                )
                if not permitted:
                    return "Bracket has an invalid round dependency."
            if dest.get("team_" + slot) != output_team(src, kind):
                return "Bracket participants do not match their upstream results."
    for m in matches:
        winner, games = m.get("predicted_winner"), m.get("predicted_winner_games")
        if not master:
            rnd = m.get("round")
            feeds = len(incoming[m["id"]])
            if (
                rnd in (2, 3, 4)
                and feeds != 2
                or rnd == 0
                and feeds not in (0, 2)
                or rnd == 1
                and feeds not in (0, 1)
            ):
                return "Bracket is missing required dependencies."
            if (
                rnd != 4
                and not m.get("next_match_id")
                or rnd == 4
                and m.get("next_match_id")
            ):
                return "Bracket is missing required dependencies."
            if not m.get("team_a") or not m.get("team_b") or not winner:
                return "Bracket is not fully predicted."
        if winner is not None:
            if (
                not m.get("team_a")
                or not m.get("team_b")
                or m["team_a"] == m["team_b"]
                or winner not in (m["team_a"], m["team_b"])
            ):
                return "Winner requires two distinct populated participants."
            error = game_count_error(m, games, allow_missing=master)
            if error:
                return error
        elif games is not None:
            error = game_count_error(m, games)
            if error:
                return error
    return None
