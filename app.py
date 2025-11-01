# app.py
from datetime import datetime
from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
from supabase import create_client
from dotenv import load_dotenv
import os
import bcrypt
import uuid

# load .env
load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("SUPABASE_URL and SUPABASE_KEY must be set in .env")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

app = Flask(__name__)
CORS(app)

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")
    username = data.get("username")  # ✅ add this line

    if not email or not password or not username:
        return jsonify({"error": "email, password, and username are required"}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    try:
        supabase.table("users").insert({
            "email": email,
            "password": hashed_password,
            "username": username
        }).execute()
        return jsonify({"message": "User registered successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    username = data.get("username")
    password = data.get("password")

    # Must include password AND either email or username
    if not password or (not email and not username):
        return jsonify({"error": "You must provide either email or username and password"}), 400

    # Look up user by email or username
    if email:
        response = supabase.table("users").select("*").eq("email", email).execute()
    else:
        response = supabase.table("users").select("*").eq("username", username).execute()

    if not response.data:
        return jsonify({"error": "User not found"}), 404

    user = response.data[0]
    stored_password = user.get("password")

    # Verify hashed password
    if not bcrypt.checkpw(password.encode("utf-8"), stored_password.encode("utf-8")):
        return jsonify({"error": "Invalid password"}), 401

    return jsonify({
        "message": "Login successful",
        "user": {
            "id": user["id"],
            "email": user["email"],
            "username": user["username"]
        }
    }), 200

# ------------------------------------------------------------------
# ----------------- End registration/login unchanged ----------------
# ------------------------------------------------------------------

# -----------------------
# Helpers for auth (dev)
# -----------------------
def get_current_user_id():
    """
    Development helper: read X-User-Id header to identify the user.
    When testing with Postman: after /login grab the returned user.id
    and set header X-User-Id: <user-id> in subsequent calls.
    """
    uid = request.headers.get("X-User-Id")
    if not uid:
        # also support Authorization: Bearer <user-id> for convenience
        auth = request.headers.get("Authorization")
        if auth and auth.lower().startswith("bearer "):
            uid = auth.split()[1]
    return uid

# -----------------------
# Bracket endpoints
# -----------------------

@app.route("/admin/insert_test_teams", methods=["POST"])
def admin_insert_test_teams():
    """
    Admin helper to re-insert the 10 test teams for both conferences.
    (This is idempotent: uses upsert behavior.)
    """
    # these match the SQL test teams inserted earlier; safe to re-run
    east = [
        {"id":"T1E","name":"TestEast1","conference":"east"},
        {"id":"T2E","name":"TestEast2","conference":"east"},
        {"id":"T3E","name":"TestEast3","conference":"east"},
        {"id":"T4E","name":"TestEast4","conference":"east"},
        {"id":"T5E","name":"TestEast5","conference":"east"},
        {"id":"T6E","name":"TestEast6","conference":"east"},
        {"id":"T7E","name":"TestEast7","conference":"east"},
        {"id":"T8E","name":"TestEast8","conference":"east"},
        {"id":"T9E","name":"TestEast9","conference":"east"},
        {"id":"T10E","name":"TestEast10","conference":"east"}
    ]
    west = [
        {"id":"T1W","name":"TestWest1","conference":"west"},
        {"id":"T2W","name":"TestWest2","conference":"west"},
        {"id":"T3W","name":"TestWest3","conference":"west"},
        {"id":"T4W","name":"TestWest4","conference":"west"},
        {"id":"T5W","name":"TestWest5","conference":"west"},
        {"id":"T6W","name":"TestWest6","conference":"west"},
        {"id":"T7W","name":"TestWest7","conference":"west"},
        {"id":"T8W","name":"TestWest8","conference":"west"},
        {"id":"T9W","name":"TestWest9","conference":"west"},
        {"id":"T10W","name":"TestWest10","conference":"west"}
    ]
    # Upsert: supabase-py doesn't have upsert convenience; we'll try insert and ignore conflicts
    for t in east + west:
        supabase.table("teams").upsert(t).execute()

    return jsonify({"message":"test teams inserted/updated"}), 200


# ---------------- BRACKET CREATION ----------------

@app.route("/bracket/create", methods=["POST"])
def create_bracket_for_user():
    user_id = request.headers.get("x-user-id")
    if not user_id:
        return jsonify({"error": "Missing x-user-id header"}), 400

    # ✅ Check if the user already has a bracket before inserting
    existing = supabase.table("brackets").select("id").eq("user_id", user_id).execute().data
    if existing:
        return jsonify({"error": "User already has a bracket"}), 400

    # ✅ Handle duplicate bracket creation gracefully (redundant safety)
    try:
        bracket = supabase.table("brackets").insert({"user_id": user_id}).execute().data[0]
    except Exception as e:
        if hasattr(e, "args") and e.args and "duplicate key value" in str(e.args[0]):
            return jsonify({"error": "User already has a bracket"}), 400
        return jsonify({"error": "Unexpected error creating bracket", "details": str(e)}), 500

    # Fetch teams
    teams = supabase.table("teams").select("id, name, conference").execute().data
    east_teams = [t for t in teams if t["conference"].lower() == "east"]
    west_teams = [t for t in teams if t["conference"].lower() == "west"]

    if len(east_teams) < 10 or len(west_teams) < 10:
        return jsonify({"error": "Not enough teams in database"}), 400

    def create_conference_matches(conference, teams):
        matches = []

        # ---- PLAY-IN ROUND ----
        m1 = {"round": 0, "slot": 1, "conference": conference, "team_a": teams[8]["id"], "team_b": teams[9]["id"]}
        m2 = {"round": 0, "slot": 2, "conference": conference, "team_a": teams[6]["id"], "team_b": teams[7]["id"]}
        m3 = {"round": 0, "slot": 3, "conference": conference}
        matches.extend([m1, m2, m3])

        # ---- ROUND 1 ----
        r1 = [
            {"round": 1, "slot": 4, "conference": conference, "team_a": teams[0]["id"]},
            {"round": 1, "slot": 5, "conference": conference, "team_a": teams[1]["id"]},
            {"round": 1, "slot": 6, "conference": conference, "team_a": teams[2]["id"], "team_b": teams[5]["id"]},
            {"round": 1, "slot": 7, "conference": conference, "team_a": teams[3]["id"], "team_b": teams[4]["id"]},
        ]
        matches.extend(r1)

        # ---- SEMIFINALS ----
        matches.append({"round": 2, "slot": 8, "conference": conference})
        matches.append({"round": 2, "slot": 9, "conference": conference})

        # ---- CONFERENCE FINALS ----
        matches.append({"round": 3, "slot": 10, "conference": conference})

        return matches

    # 1️⃣ Create all match entries
    all_matches = []
    all_matches.extend(create_conference_matches("east", east_teams))
    all_matches.extend(create_conference_matches("west", west_teams))
    all_matches.append({
        "round": 4, "slot": 11, "conference": "nba"
    })  # NBA Finals

    for m in all_matches:
        m["bracket_id"] = bracket["id"]

    # 2️⃣ Insert matches
    supabase.table("matches").insert(all_matches).execute()

    # 3️⃣ Retrieve IDs for linking
    inserted = supabase.table("matches").select("id, round, slot, conference").eq("bracket_id", bracket["id"]).execute().data

    # 4️⃣ Link matches
    def link(conference, from_slot, to_slot, next_slot):
        src = next((m for m in inserted if m["conference"] == conference and m["slot"] == from_slot), None)
        dest = next((m for m in inserted if m["conference"] == conference and m["slot"] == to_slot), None)
        if src and dest:
            supabase.table("matches").update({
                "next_match_id": dest["id"],
                "next_slot": next_slot
            }).eq("id", src["id"]).execute()

    # 🏀 PLAY-IN ROUND
    link("east", 1, 3, "a")
    link("west", 1, 3, "a")
    link("east", 2, 3, "b")
    link("west", 2, 3, "b")
    link("east", 2, 5, "b")
    link("west", 2, 5, "b")
    link("east", 3, 4, "b")
    link("west", 3, 4, "b")

    # ---- Round 1 → Semifinals ----
    link("east", 4, 9, "a")
    link("east", 7, 9, "b")
    link("east", 5, 8, "a")
    link("east", 6, 8, "b")
    link("west", 4, 9, "a")
    link("west", 7, 9, "b")
    link("west", 5, 8, "a")
    link("west", 6, 8, "b")

    # ---- Semifinals → Conference Finals ----
    link("east", 8, 10, "a")
    link("east", 9, 10, "b")
    link("west", 8, 10, "a")
    link("west", 9, 10, "b")

    # ----- Conference Finals → NBA Finals -----
    nba_final = next((m for m in inserted if m["conference"] == "nba" and m["slot"] == 11), None)
    if nba_final:
        east_final = next((m for m in inserted if m["conference"] == "east" and m["slot"] == 10), None)
        west_final = next((m for m in inserted if m["conference"] == "west" and m["slot"] == 10), None)
        if east_final:
            supabase.table("matches").update({
                "next_match_id": nba_final["id"],
                "next_slot": "a"
            }).eq("id", east_final["id"]).execute()
        if west_final:
            supabase.table("matches").update({
                "next_match_id": nba_final["id"],
                "next_slot": "b"
            }).eq("id", west_final["id"]).execute()

    return jsonify({"message": "Bracket created successfully", "bracket": bracket})


@app.route("/bracket/<bracket_id>/save", methods=["PATCH"])
def save_bracket(bracket_id):
    user_id = request.headers.get("x-user-id")
    if not user_id:
        return jsonify({"error": "Missing x-user-id header"}), 400

    # ✅ Fetch the requesting user's admin status
    user_res = supabase.table("users").select("id, is_admin").eq("id", user_id).execute().data
    if not user_res:
        return jsonify({"error": "User not found"}), 404
    is_admin = user_res[0].get("is_admin", False)

    # ✅ Retrieve target bracket by ID
    bracket_data = supabase.table("brackets").select("id, user_id, is_done").eq("id", bracket_id).execute().data
    if not bracket_data:
        return jsonify({"error": "Bracket not found"}), 404
    bracket = bracket_data[0]

    # 🔒 Ownership or admin check
    if str(bracket["user_id"]) != str(user_id) and not is_admin:
        return jsonify({"error": "Unauthorized: Only the owner or an admin can save this bracket"}), 403

    # Prevent re-saving an already done bracket
    if bracket.get("is_done"):
        return jsonify({"error": "Bracket already saved"}), 400

    # ✅ Mark as done and add timestamp
    saved_at = datetime.utcnow().isoformat()
    supabase.table("brackets").update({
        "is_done": True,
        "saved_at": saved_at
    }).eq("id", bracket_id).execute()

    return jsonify({
        "message": "Bracket successfully saved!",
        "bracket_id": bracket_id,
        "saved_at": saved_at
    }), 200


@app.route("/bracket/<bracket_id>", methods=["GET"])
def get_bracket_by_id(bracket_id):
    """
    Allows any user to view a specific bracket by ID (read-only).
    Rules:
      - Owner and admins can view their bracket even if it's not finished.
      - Other users can only view if is_done = True.
    """
    viewer_id = request.headers.get("x-user-id")

    # ✅ Fetch viewer info (to check admin rights)
    viewer_data = (
        supabase.table("users")
        .select("id, is_admin")
        .eq("id", viewer_id)
        .execute()
        .data
    )
    is_admin = viewer_data[0]["is_admin"] if viewer_data else False

    # ✅ Fetch the bracket (no is_done filter yet)
    bracket_data = (
        supabase.table("brackets")
        .select("*")
        .eq("id", bracket_id)
        .execute()
        .data
    )
    if not bracket_data:
        return jsonify({"error": "Bracket not found"}), 404

    bracket = bracket_data[0]

    # ✅ Access control:
    #   - Owner or admin → allowed even if not done
    #   - Other users → allowed only if is_done = True
    is_owner = str(viewer_id) == str(bracket["user_id"])
    if not is_owner and not is_admin and not bracket.get("is_done", False):
        return jsonify({"error": "Bracket not yet saved or not accessible"}), 403

    # ✅ Retrieve matches
    matches = (
        supabase.table("matches")
        .select("*")
        .eq("bracket_id", bracket["id"])
        .order("round", desc=False)
        .execute()
        .data
    )

    # ✅ Group matches by conference + round
    grouped = {}
    for match in matches:
        conf = match["conference"].lower() if match["conference"] else "unknown"
        rnd = match["round"]
        if conf not in grouped:
            grouped[conf] = {}
        if rnd not in grouped[conf]:
            grouped[conf][rnd] = []
        grouped[conf][rnd].append(match)

    # ✅ Fetch bracket owner info
    owner_data = (
        supabase.table("users")
        .select("id, username, email")
        .eq("id", bracket["user_id"])
        .execute()
        .data
    )
    owner = owner_data[0] if owner_data else {}

    return jsonify({
        "bracket": {
            **bracket,
            "owner": {
                "id": owner.get("id"),
                "username": owner.get("username"),
                "email": owner.get("email")
            },
            "is_owner": is_owner
        },
        "matches": grouped
    })



@app.route("/brackets", methods=["GET"])
def list_all_brackets():
    """
    Returns a list of all brackets that are marked as is_done = True,
    along with the user who created each one.
    Only basic info: bracket_id, saved_at, and user info.
    """
    try:
        # ✅ Fetch only saved brackets (is_done = True)
        brackets_res = (
            supabase.table("brackets")
            .select("id, user_id, saved_at, created_at")
            .eq("is_done", True)
            .order("saved_at", desc=True)
            .execute()
        )
        brackets = brackets_res.data

        if not brackets:
            return jsonify([]), 200

        # Collect unique user_ids
        user_ids = list({b["user_id"] for b in brackets if b.get("user_id")})

        # Fetch user info
        users_res = (
            supabase.table("users")
            .select("id, username, email")
            .in_("id", user_ids)
            .execute()
        )
        users = {u["id"]: u for u in users_res.data}

        # Merge user info into output
        output = []
        for b in brackets:
            user_info = users.get(b["user_id"], {})
            output.append({
                "bracket_id": b["id"],
                "saved_at": b.get("saved_at"),
                "created_at": b.get("created_at"),
                "user": {
                    "id": b["user_id"],
                    "username": user_info.get("username"),
                    "email": user_info.get("email")
                }
            })

        return jsonify(output), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------- DELETE BRACKET ----------------

@app.route("/bracket/<bracket_id>", methods=["DELETE"])
def delete_bracket(bracket_id):
    user_id = request.headers.get("x-user-id")
    if not user_id:
        return jsonify({"error": "Missing x-user-id header"}), 400

    # ✅ Fetch user and admin status
    user_res = supabase.table("users").select("id, is_admin").eq("id", user_id).execute().data
    if not user_res:
        return jsonify({"error": "User not found"}), 404
    is_admin = user_res[0].get("is_admin", False)

    # ✅ Fetch target bracket
    bracket_res = supabase.table("brackets").select("id, user_id").eq("id", bracket_id).execute().data
    if not bracket_res:
        return jsonify({"error": "Bracket not found"}), 404
    bracket = bracket_res[0]

    # ✅ Check permissions
    if bracket["user_id"] != user_id and not is_admin:
        return jsonify({"error": "Unauthorized: Only the owner or an admin can delete this bracket"}), 403

    # ✅ Perform deletion (cascade deletes matches)
    supabase.table("brackets").delete().eq("id", bracket_id).execute()

    return jsonify({"message": "Bracket deleted successfully"})


# ---------------- UPDATE PREDICTION ----------------

@app.route("/bracket/<bracket_id>/match/<match_id>", methods=["PATCH"])
def update_match(bracket_id, match_id):
    user_id = request.headers.get("x-user-id")
    if not user_id:
        return jsonify({"error": "Missing x-user-id header"}), 400

    data = request.get_json() or {}
    action = data.get("action")

    # Load the match we’re updating
    res = supabase.table("matches").select(
        "id, bracket_id, conference, round, slot, team_a, team_b, "
        "predicted_winner, predicted_winner_games, next_match_id, next_slot"
    ).eq("id", match_id).execute().data
    if not res:
        return jsonify({"error": "Match not found"}), 404
    match = res[0]

    # ✅ Verify match belongs to this bracket
    if str(match["bracket_id"]) != str(bracket_id):
        return jsonify({"error": "Match does not belong to the specified bracket"}), 400

    # ✅ Ownership and admin check
    user_res = supabase.table("users").select("id, is_admin").eq("id", user_id).execute().data
    if not user_res:
        return jsonify({"error": "User not found"}), 404
    is_admin = user_res[0].get("is_admin", False)

    bracket_check = supabase.table("brackets").select("user_id").eq("id", bracket_id).execute().data
    if not bracket_check:
        return jsonify({"error": "Bracket not found"}), 404
    bracket_owner_id = bracket_check[0]["user_id"]

    if bracket_owner_id != user_id and not is_admin:
        return jsonify({"error": "Unauthorized: You are not allowed to modify this bracket"}), 403


    # --- helper functions (unchanged) ---
    def clear_dest(dest_id):
        if not dest_id: return
        supabase.table("matches").update({
            "predicted_winner": None,
            "predicted_winner_games": None,
            "updated_at": datetime.utcnow().isoformat()
        }).eq("id", dest_id).execute()

    def set_in_dest(dest_id, slot_letter, team_id):
        if not dest_id or not slot_letter: return
        supabase.table("matches").update({
            f"team_{slot_letter}": team_id,
            "predicted_winner": None,
            "predicted_winner_games": None,
            "updated_at": datetime.utcnow().isoformat()
        }).eq("id", dest_id).execute()

    def clear_in_dest_slot(dest_id, slot_letter, team_id=None):
        if not dest_id or not slot_letter: return
        dest = supabase.table("matches").select("id, team_a, team_b").eq("id", dest_id).execute().data
        if not dest: return
        dest = dest[0]
        field = f"team_{slot_letter}"
        current_val = dest.get(field)
        if team_id is None or current_val == team_id:
            supabase.table("matches").update({
                field: None,
                "predicted_winner": None,
                "predicted_winner_games": None,
                "updated_at": datetime.utcnow().isoformat()
            }).eq("id", dest_id).execute()

    def get_match(conference, round_num, slot_num):
        rows = (supabase.table("matches")
                .select("id, team_a, team_b, predicted_winner, predicted_winner_games")
                .eq("bracket_id", match["bracket_id"])
                .eq("conference", conference)
                .eq("round", round_num)
                .eq("slot", slot_num)
                .execute().data)
        return rows[0] if rows else None

    def cleanup_future_matches(losing_team_id):
        if not match.get("next_match_id"): return
        to_check = [match["next_match_id"]]
        visited = set()
        while to_check:
            current_id = to_check.pop()
            if current_id in visited: continue
            visited.add(current_id)
            res = supabase.table("matches").select("id, team_a, team_b, next_match_id").eq("id", current_id).execute().data
            if not res: continue
            next_match = res[0]
            updated_fields = {}
            if next_match["team_a"] == losing_team_id: updated_fields["team_a"] = None
            if next_match["team_b"] == losing_team_id: updated_fields["team_b"] = None
            if updated_fields:
                updated_fields["predicted_winner"] = None
                updated_fields["predicted_winner_games"] = None
                updated_fields["updated_at"] = datetime.utcnow().isoformat()
                supabase.table("matches").update(updated_fields).eq("id", next_match["id"]).execute()
            if next_match.get("next_match_id"):
                to_check.append(next_match["next_match_id"])

    # ------------------ ACTIONS ------------------
    if action == "set_winner":
        team = data.get("team")
        games = data.get("games")
        if not team:
            return jsonify({"error": "Missing team"}), 400

        # ✅ NEW: force best-of-one for play-in round
        if match["round"] == 0:
            games = 1

        if team not in (match["team_a"], match["team_b"]):
            return jsonify({"error": "Winner must be team_a or team_b for this match"}), 400

        old_winner = match.get("predicted_winner")
        old_games = match.get("predicted_winner_games")
        loser = match["team_b"] if match["team_a"] == team else match["team_a"]

        if old_winner and old_winner != team:
            if match.get("next_match_id") and match.get("next_slot"):
                clear_in_dest_slot(match["next_match_id"], match["next_slot"], old_winner)
                clear_dest(match["next_match_id"])
            cleanup_future_matches(old_winner)
            if match["round"] == 0 and match["slot"] == 2:
                m3 = get_match(match["conference"], 0, 3)
                if m3:
                    supabase.table("matches").update({
                        "team_b": None,
                        "predicted_winner": None,
                        "predicted_winner_games": None,
                        "updated_at": datetime.utcnow().isoformat()
                    }).eq("id", m3["id"]).execute()

        if old_winner == team:
            if games != old_games:
                supabase.table("matches").update({
                    "predicted_winner_games": games,
                    "updated_at": datetime.utcnow().isoformat()
                }).eq("id", match_id).execute()
            if match["round"] == 0 and match["slot"] == 2:
                m3 = get_match(match["conference"], 0, 3)
                if m3 and m3.get("team_b") != loser:
                    set_in_dest(m3["id"], "b", loser)
            # ✅ Mark bracket as not saved
            supabase.table("brackets").update({
                "is_done": False,
                "saved_at": None
            }).eq("id", match["bracket_id"]).execute()
            return jsonify({"message": "Winner updated"}), 200

        supabase.table("matches").update({
            "predicted_winner": team,
            "predicted_winner_games": games,
            "updated_at": datetime.utcnow().isoformat()
        }).eq("id", match_id).execute()

        if match.get("next_match_id") and match.get("next_slot"):
            set_in_dest(match["next_match_id"], match["next_slot"], team)

        if match["round"] == 0 and match["slot"] == 2:
            m3 = get_match(match["conference"], 0, 3)
            if m3:
                set_in_dest(m3["id"], "b", loser)

        # ✅ Mark bracket as not saved
        supabase.table("brackets").update({
            "is_done": False,
            "saved_at": None
        }).eq("id", match["bracket_id"]).execute()

        return jsonify({"message": "Winner set"}), 200

    elif action == "undo":
        old_winner = match.get("predicted_winner")
        supabase.table("matches").update({
            "predicted_winner": None,
            "predicted_winner_games": None,
            "updated_at": datetime.utcnow().isoformat()
        }).eq("id", match_id).execute()

        if old_winner and match.get("next_match_id") and match.get("next_slot"):
            clear_in_dest_slot(match["next_match_id"], match["next_slot"], old_winner)
            clear_dest(match["next_match_id"])
            cleanup_future_matches(old_winner)

        if match["round"] == 0 and match["slot"] == 2:
            m3 = get_match(match["conference"], 0, 3)
            if m3:
                supabase.table("matches").update({
                    "team_b": None,
                    "predicted_winner": None,
                    "predicted_winner_games": None,
                    "updated_at": datetime.utcnow().isoformat()
                }).eq("id", m3["id"]).execute()

        # ✅ Mark bracket as not saved
        supabase.table("brackets").update({
            "is_done": False,
            "saved_at": None
        }).eq("id", match["bracket_id"]).execute()

        return jsonify({"message": "Prediction undone"}), 200

    else:
        return jsonify({"error": "Invalid or unsupported action"}), 400



# Lightweight endpoint: set only predicted_winner_games for a match (already covered by set_games above)
# but keep for convenience
@app.route("/bracket/match/<match_id>/games", methods=["PATCH"])
def set_match_games(match_id):
    body = request.get_json() or {}
    games = body.get("games")
    if games is None:
        return jsonify({"error":"games required"}), 400
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"error":"X-User-Id header required"}), 401
    # check ownership
    m_resp = supabase.table("matches").select("*").eq("id", match_id).execute()
    if not m_resp.data:
        return jsonify({"error":"match not found"}), 404
    match = m_resp.data[0]
    br = supabase.table("brackets").select("*").eq("id", match["bracket_id"]).execute().data
    if not br or br[0]["user_id"] != user_id:
        return jsonify({"error":"forbidden"}), 403

    supabase.table("matches").update({"predicted_winner_games": games, "updated_at": "now()"}).eq("id", match_id).execute()
    return jsonify({"ok": True}), 200


# small health endpoint
@app.route("/", methods=["GET"])
def home():
    return jsonify({"message":"NBACorner backend running"}), 200


@app.route("/health", methods=["GET", "HEAD"])
def health():
    resp = make_response("OK", 200)
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    return resp


if __name__ == "__main__":
    app.run(debug=True)
