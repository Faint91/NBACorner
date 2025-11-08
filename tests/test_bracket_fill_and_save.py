import os
import uuid
import requests
from typing import Dict, Any, List

BASE_URL = os.getenv("NBACORNER_BASE_URL", "https://nbacorner.onrender.com")


def _post(path: str, json: Dict[str, Any], headers: Dict[str, str] = None) -> requests.Response:
    url = f"{BASE_URL}{path}"
    return requests.post(url, json=json, headers=headers or {}, timeout=15)


def _get(path: str, headers: Dict[str, str] = None) -> requests.Response:
    url = f"{BASE_URL}{path}"
    return requests.get(url, headers=headers or {}, timeout=15)


def _patch(path: str, json: Dict[str, Any], headers: Dict[str, str] = None) -> requests.Response:
    url = f"{BASE_URL}{path}"
    return requests.patch(url, json=json, headers=headers or {}, timeout=15)


def register_and_login() -> Dict[str, Any]:
    """
    Registers a fresh test user, then logs in and returns { token, user }.
    """
    email = f"test_{uuid.uuid4().hex[:8]}@example.com"
    username = f"testuser_{uuid.uuid4().hex[:8]}"
    password = "Password001!!"

    # 1) Register
    reg_resp = _post(
        "/auth/register",
        json={"email": email, "username": username, "password": password},
    )
    assert reg_resp.status_code == 201, f"Register failed: {reg_resp.status_code} {reg_resp.text}"
    reg_data = reg_resp.json()
    assert reg_data["user"]["email"] == email
    assert reg_data["user"]["username"] == username

    # 2) Login (using email)
    login_resp = _post(
        "/auth/login",
        json={"email": email, "password": password},
    )
    assert login_resp.status_code == 200, f"Login failed: {login_resp.status_code} {login_resp.text}"

    login_data = login_resp.json()
    token = login_data["token"]
    user = login_data["user"]

    return {"token": token, "user": user}


def create_bracket(token: str) -> str:
    """
    Creates a new bracket for the logged-in user and returns bracket_id.
    """
    headers = {"Authorization": f"Bearer {token}"}
    resp = _post("/bracket/create", json={}, headers=headers)
    assert resp.status_code in (200, 201), f"Create bracket failed: {resp.status_code} {resp.text}"
    data = resp.json()
    bracket_id = data["bracket"]["id"]
    return bracket_id


def get_bracket(token: str, bracket_id: str) -> Dict[str, Any]:
    """
    Fetches the full bracket view: { bracket: {...}, matches: {...} }.
    """
    headers = {"Authorization": f"Bearer {token}"}
    resp = _get(f"/bracket/{bracket_id}", headers=headers)
    assert resp.status_code == 200, f"Get bracket failed: {resp.status_code} {resp.text}"
    return resp.json()


def flatten_matches(matches_grouped: Dict[str, Dict[str, List[Dict[str, Any]]]]) -> List[Dict[str, Any]]:
    """
    Flatten the grouped matches structure:
      { conference: { round_key: [match, ...], ...}, ... } -> [match, match, ...]
    """
    result: List[Dict[str, Any]] = []
    for conf, rounds_dict in matches_grouped.items():
        for round_key, arr in rounds_dict.items():
            for m in arr:
                result.append(m)
    return result


def set_winner_for_match(token: str, bracket_id: str, match: Dict[str, Any]) -> None:
    """
    Calls PATCH /bracket/<bracket_id>/match/<match_id> with action='set_winner',
    choosing team_a as the winner (purely for testing).
    """
    match_id = match["id"]
    team_a = match["team_a"]
    team_b = match["team_b"]

    # Sanity: we only call this when both teams are present
    assert team_a is not None and team_b is not None, f"Match {match_id} does not have both teams yet"

    # Round 0 = play-in (forced to best-of-one by your backend)
    round_num = match["round"]
    games = 1 if round_num == 0 else 4

    payload = {
        "action": "set_winner",
        "team": team_a,  # choose team_a as deterministic winner
        "games": games,
    }

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    resp = _patch(f"/bracket/{bracket_id}/match/{match_id}", json=payload, headers=headers)
    assert resp.status_code == 200, f"set_winner failed for match {match_id}: {resp.status_code} {resp.text}"
    data = resp.json()
    assert "message" in data, f"Unexpected response for set_winner: {data}"


def fill_entire_bracket(token: str, bracket_id: str) -> None:
    """
    Repeatedly:
      - Fetch the bracket
      - Find all matches where team_a and team_b are set, but predicted_winner is null
      - For each such match, set team_a as the winner

    Stop when there are no more such matches.
    """
    # To avoid infinite loops if something goes wrong, we cap iterations
    max_iterations = 50
    iterations = 0

    while True:
        iterations += 1
        assert iterations <= max_iterations, "Too many iterations while filling bracket (possible infinite loop)"

        bracket_view = get_bracket(token, bracket_id)
        matches_grouped = bracket_view["matches"]
        flat = flatten_matches(matches_grouped)

        # Matches ready to be decided: both teams present, but no predicted_winner yet
        pending = [
            m for m in flat
            if m.get("team_a") is not None
            and m.get("team_b") is not None
            and m.get("predicted_winner") is None
        ]

        if not pending:
            # No more matches can be filled -> bracket is fully decided
            break

        # Fill all currently decidable matches in this iteration
        for match in pending:
            set_winner_for_match(token, bracket_id, match)


def save_bracket(token: str, bracket_id: str) -> Dict[str, Any]:
    """
    Calls PATCH /bracket/<bracket_id>/save and returns its JSON.
    """
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    resp = _patch(f"/bracket/{bracket_id}/save", json={}, headers=headers)
    assert resp.status_code in (200, 201), f"Save bracket failed: {resp.status_code} {resp.text}"
    data = resp.json()
    assert data.get("bracket_id") == bracket_id
    assert data.get("saved_at") is not None
    return data


def test_fill_and_save_full_bracket_flow():
    """
    End-to-end test for the core bracket logic:

      1. Register + login
      2. Create bracket
      3. Automatically fill ALL matches (play-in, rounds, finals)
      4. Save bracket
      5. Re-fetch and validate state

    This is the "core" test ensuring the bracket engine is consistent.
    """
    # 1) Auth
    auth = register_and_login()
    token = auth["token"]

    # 2) Create bracket
    bracket_id = create_bracket(token)

    # 3) Fill entire bracket by repeatedly setting winners where possible
    fill_entire_bracket(token, bracket_id)

    # 4) Save the bracket
    save_info = save_bracket(token, bracket_id)
    print("Bracket saved at:", save_info["saved_at"])

    # 5) Re-fetch and validate
    final_view = get_bracket(token, bracket_id)
    bracket = final_view["bracket"]
    matches_grouped = final_view["matches"]
    flat_matches = flatten_matches(matches_grouped)

    # Bracket should be marked as done and have a saved_at timestamp
    assert bracket.get("is_done") is True
    assert bracket.get("saved_at") is not None

    # Every match that has both teams should have a predicted winner
    for m in flat_matches:
        if m.get("team_a") is not None and m.get("team_b") is not None:
            assert m.get("predicted_winner") is not None, f"Match {m['id']} is missing predicted_winner"

    # There should be exactly one NBA finals match with a predicted winner
    finals = [
        m for m in flat_matches
        if m.get("conference") == "nba" and m.get("round") == 4
    ]
    # Depending on structure you expect 1 finals match
    assert len(finals) == 1, f"Expected 1 NBA finals match, got {len(finals)}"
    assert finals[0].get("predicted_winner") is not None, "NBA finals match does not have a predicted winner"
