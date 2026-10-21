"""Explicit bracket creation needs unique slots, not a manufactured tie order."""

from standings_service import CONFERENCES


class AmbiguousPlayoffSeeding(ValueError):
    pass


def required_playoff_teams(standings, team_by_code):
    """The 21-match builder consumes seeds 1..10 in each conference only.

    Ties/gaps wholly below qualification (11..15) do not affect those slots.
    Every required seed must identify exactly one distinct canonical NBA team.
    No retrieval order, alphabetical order or secondary tiebreaker is consulted.
    """
    slots = {"east": {}, "west": {}}
    seen = set()
    for row in standings:
        code, seed = row.get("code"), row.get("seed")
        if (
            not isinstance(code, str)
            or code not in CONFERENCES
            or code in seen
            or type(seed) is not int
            or not 1 <= seed <= 15
        ):
            raise AmbiguousPlayoffSeeding()
        seen.add(code)
        team = team_by_code.get(code)
        if not team or str(team.get("conference", "")).lower() != CONFERENCES[code]:
            raise AmbiguousPlayoffSeeding()
        if seed > 10:
            continue
        conference = CONFERENCES[code]
        if seed in slots[conference]:
            raise AmbiguousPlayoffSeeding()
        slots[conference][seed] = team
    if any(set(values) != set(range(1, 11)) for values in slots.values()):
        raise AmbiguousPlayoffSeeding()
    selected = [
        [slots[conf][seed] for seed in range(1, 11)] for conf in ("east", "west")
    ]
    if len({team["id"] for teams in selected for team in teams}) != 20:
        raise AmbiguousPlayoffSeeding()
    return tuple(selected)
