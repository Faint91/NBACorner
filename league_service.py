"""Live league policy; Flask authenticates, trusted RPCs fence concurrent mutations."""

import base64
import hashlib
import bcrypt

NAME_MAX = 80
PASSWORD_MAX = 128
LONG_PASSWORD_PREFIX = "bcrypt-sha256:"
FIELDS = "id,name,owner_user_id,password_hash,is_global,created_at,updated_at"


class LeagueError(RuntimeError):
    def __init__(self, message, status=400):
        self.status = status
        super().__init__(message)


def normalize_name(value):
    if not isinstance(value, str):
        raise LeagueError("League name must be a string")
    value = value.strip()
    if not value or len(value) > NAME_MAX or "\x00" in value:
        raise LeagueError("League name must contain 1 through 80 characters")
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise LeagueError("League name must contain valid text") from None
    return value


def password_text(value, *, required=True):
    if not isinstance(value, str):
        raise LeagueError("League password must be a string")
    value = value.strip()
    if len(value) > PASSWORD_MAX or (required and not value) or "\x00" in value:
        raise LeagueError("League password must contain 1 through 128 characters")
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise LeagueError("League password must contain valid text") from None
    return value


def hash_password(value, rounds):
    raw = password_text(value).encode("utf-8")
    prefix = ""
    if len(raw) > 72:
        # bcrypt's byte limit must not truncate distinct long passwords.
        raw = base64.b64encode(hashlib.sha256(raw).digest())
        prefix = LONG_PASSWORD_PREFIX
    return prefix + bcrypt.hashpw(raw, bcrypt.gensalt(rounds=rounds)).decode("ascii")


def verify_password(value, stored):
    raw = password_text(value).encode("utf-8")
    try:
        if stored.startswith(LONG_PASSWORD_PREFIX):
            raw = base64.b64encode(hashlib.sha256(raw).digest())
            stored = stored[len(LONG_PASSWORD_PREFIX) :]
        else:
            # Legacy raw bcrypt may have used its historical 72-byte truncation.
            # New long passwords always use the marked prehash scheme above.
            raw = raw[:72]
        return bcrypt.checkpw(raw, stored.encode("ascii"))
    except (ValueError, TypeError, UnicodeError):
        return False


def rpc(client, name, params):
    result = client.rpc(name, params).execute().data
    if not isinstance(result, dict) or type(result.get("ok")) is not bool:
        raise LeagueError("League operation unavailable", 503)
    if not result["ok"]:
        raise LeagueError(
            result.get("error", "League action refused"), result.get("status", 400)
        )
    return result


def load_league(client, lid):
    rows = client.table("leagues").select(FIELDS).eq("id", lid).limit(1).execute().data
    if not isinstance(rows, list):
        raise LeagueError("League operation unavailable", 503)
    if not rows:
        raise LeagueError("League not found", 404)
    return rows[0]


def require_league_member(client, lid, uid):
    rows = (
        client.table("league_members")
        .select("id,joined_at")
        .eq("league_id", lid)
        .eq("user_id", uid)
        .limit(1)
        .execute()
        .data
    )
    if not isinstance(rows, list):
        raise LeagueError("League operation unavailable", 503)
    return rows[0] if rows else None


def require_league_owner(client, lid, uid):
    league = load_league(client, lid)
    if league["owner_user_id"] != uid:
        raise LeagueError("Only the current league owner may perform this action", 403)
    if not require_league_member(client, lid, uid):
        raise LeagueError("League ownership requires consistency review", 409)
    return league


def checked_name(client, value, except_id=None):
    display = normalize_name(value)
    # PostgreSQL owns lower()/collation semantics; avoid a divergent Python key.
    result = (
        client.rpc("inspect_league_name", dict(p_name=display, p_except=except_id))
        .execute()
        .data
    )
    if (
        not isinstance(result, dict)
        or result.get("name") != display
        or not isinstance(result.get("key"), str)
    ):
        raise LeagueError("League name validation unavailable", 503)
    if result.get("available") is not True:
        raise LeagueError("League name is already in use", 409)
    return display


def mutate(client, action, uid, *, lid=None, target=None, body=None, rounds=12):
    if not isinstance(body, dict):
        raise LeagueError("Request body must be an object")
    if action == "create":
        name = checked_name(client, body.get("name"))
        password = password_text(body.get("password", ""), required=False)
        private = body.get("is_private", bool(password))
        if type(private) is not bool:
            raise LeagueError("is_private must be a boolean")
        if not private and password:
            raise LeagueError("Public leagues do not use a password")
        hashed = hash_password(password, rounds) if private else None
        return rpc(
            client,
            "create_league_with_owner",
            dict(p_actor=uid, p_name=name, p_hash=hashed),
        )
    if action == "join":
        league = load_league(client, lid)
        member = require_league_member(client, lid, uid)
        if not member and league.get("password_hash"):
            if not verify_password(body.get("password", ""), league["password_hash"]):
                raise LeagueError("Invalid league password", 400)
        return rpc(
            client,
            "join_league_member",
            dict(
                p_actor=uid, p_league=lid, p_expected_hash=league.get("password_hash")
            ),
        )
    if action in {"settings", "transfer", "remove", "delete"}:
        league = require_league_owner(client, lid, uid)
    if action == "settings":
        if not body or set(body) - {"name", "is_private", "password"}:
            raise LeagueError("Provide only league name or privacy/password settings")
        name = checked_name(client, body["name"], lid) if "name" in body else None
        private = body.get("is_private")
        if "is_private" in body and type(private) is not bool:
            raise LeagueError("is_private must be a boolean")
        hashed = None
        if "password" in body and private is None:
            if not league.get("password_hash"):
                raise LeagueError("Set is_private=true when making a league private")
            private = True
        if private is True:
            hashed = hash_password(body.get("password", ""), rounds)
        if (
            private is False
            and "password" in body
            and password_text(body["password"], required=False)
        ):
            raise LeagueError("Public leagues do not use a password")
        return rpc(
            client,
            "update_league_settings",
            dict(
                p_actor=uid,
                p_league=lid,
                p_name=name,
                p_private=private,
                p_hash=hashed,
                p_expected_hash=league.get("password_hash"),
            ),
        )
    if action == "transfer":
        return rpc(
            client,
            "transfer_league_ownership",
            dict(p_actor=uid, p_league=lid, p_target=target),
        )
    if action in {"leave", "remove"}:
        return rpc(
            client,
            "remove_league_membership",
            dict(
                p_actor=uid,
                p_league=lid,
                p_target=target if action == "remove" else None,
            ),
        )
    if action == "delete":
        if body.get("confirm_delete") is not True:
            raise LeagueError("Explicit confirm_delete=true is required")
        return rpc(
            client,
            "delete_league_confirmed",
            dict(p_actor=uid, p_league=lid, p_confirm=True),
        )
    raise LeagueError("Unsupported league action")
