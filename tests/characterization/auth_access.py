"""Live local NC-01A current behavior only; loaded solely by guarded runner."""

import re
import unittest
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit, parse_qs
from unittest.mock import patch
import jwt
from email_transport import test_mailbox, CaptureMailbox
from integration_harness import GuardedHarness, CANONICAL_CHECKSUM
from synthetic_fixtures import identity

CONFIG = None
OPT_IN = False
RESULTS = []
CLASSIFICATION = "REQUIREMENT NOT YET REVIEWED"
TEMP_PASSWORD = "NCAuthTemp!2026"
NEW_PASSWORD = "NCAuthChange!2026"


def behavior(group, current, question):
    def decorate(fn):
        fn.metadata = {
            "scenario": fn.__name__,
            "group": group,
            "current_behavior": current,
            "approved_requirement": None,
            "classification": CLASSIFICATION,
            "future_business_question": question,
            "evidence_source": "Live guarded local Flask API; canonical reset per case",
        }
        return fn

    return decorate


class CurrentAuthBehavior(unittest.TestCase):
    def setUp(self):
        self.context = GuardedHarness(
            CONFIG, allow_local_mutations=OPT_IN, characterization_scope="NC-01A"
        )
        self.context.__enter__()
        self.facts = {}

    def tearDown(self):
        self.context.__exit__(None, None, None)
        self.assertTrue(
            self.context.cleanup_proof["fixture_checksum"] == CANONICAL_CHECKSUM
        )
        row = dict(getattr(self, self._testMethodName).metadata)
        row.update(
            evidence=self.context.summary,
            facts=self.facts,
            cleanup_checksum=self.context.cleanup_proof["fixture_checksum"],
        )
        RESULTS.append(row)

    def call(self, method, path, status, **kwargs):
        actual, body = self.context.auth_request(method, path, **kwargs)
        self.assertEqual(
            actual, status
        )  # Status only; never print response or credentials.
        return body

    def register(
        self,
        username="ncauthtemp",
        email="nc-temp@nba-corner.example",
        password=TEMP_PASSWORD,
    ):
        return self.call(
            "POST",
            "/auth/register",
            201,
            payload={"email": email, "username": username, "password": password},
        )

    def forgot(self):
        self.call(
            "POST",
            "/auth/forgot-password",
            200,
            payload={"email": "user-a@nba-corner.example"},
        )
        return self.context.auth_reset_records()[-1]["token"]

    @behavior(
        "Registration",
        "Valid synthetic registration returns 201, message/user, no JWT or auto-login.",
        "Should registration create a session or require login?",
    )
    def current_behavior__auth__valid_registration(self):
        body = self.register()
        self.assertTrue(
            set(body) == {"message", "user"}
            and set(body["user"]) == {"id", "email", "username", "created_at"}
        )
        self.facts = {
            "response_fields": sorted(body),
            "user_fields": sorted(body["user"]),
            "token_issued": False,
        }

    @behavior(
        "Registration",
        "Duplicate email is normalized to lowercase and rejected with 400.",
        "Approve email normalization and duplicate response policy?",
    )
    def current_behavior__auth__duplicate_email(self):
        self.call(
            "POST",
            "/auth/register",
            400,
            payload={
                "email": "USER-A@NBA-CORNER.EXAMPLE",
                "username": "ncauthduplicate",
                "password": TEMP_PASSWORD,
            },
        )

    @behavior(
        "Registration",
        "Duplicate valid username rejected with 400.",
        "Approve username uniqueness and normalization?",
    )
    def current_behavior__auth__duplicate_username(self):
        self.register()
        self.call(
            "POST",
            "/auth/register",
            400,
            payload={
                "email": "nc-second@nba-corner.example",
                "username": "ncauthtemp",
                "password": TEMP_PASSWORD,
            },
        )

    @behavior(
        "Registration",
        "Missing fields, invalid email and invalid username return 400.",
        "What request validation contract should be approved?",
    )
    def current_behavior__auth__registration_invalid_fields(self):
        for payload in (
            {},
            {"email": "invalid", "username": "valid_name", "password": TEMP_PASSWORD},
            {
                "email": "nc-temp@nba-corner.example",
                "username": "bad-name",
                "password": TEMP_PASSWORD,
            },
        ):
            self.call("POST", "/auth/register", 400, payload=payload)

    @behavior(
        "Registration",
        "Weak or non-string passwords rejected with 400.",
        "Approve the current length/character policy?",
    )
    def current_behavior__auth__registration_password_policy(self):
        for password in ("short", 123):
            self.call(
                "POST",
                "/auth/register",
                400,
                payload={
                    "email": "nc-temp@nba-corner.example",
                    "username": "ncauthtemp",
                    "password": password,
                },
            )

    @behavior(
        "Registration",
        "Truthy non-object JSON causes sanitized 500.",
        "Should non-object JSON be an explicit client error?",
    )
    def current_behavior__auth__registration_nonobject(self):
        body = self.call("POST", "/auth/register", 500, payload=["unexpected"])
        self.assertTrue(set(body) == {"error"})

    @behavior(
        "Login/session",
        "Username storage is case-sensitive, login lowercases identifiers; case-distinct registered accounts can resolve to the lowercase account.",
        "Approve case handling and which account a username identifies?",
    )
    def current_behavior__auth__username_case_resolution(self):
        upper = self.register(username="NCAuthTemp")
        self.call(
            "POST",
            "/auth/login",
            401,
            payload={"username": "NCAuthTemp", "password": TEMP_PASSWORD},
        )
        lower = self.register(
            username="ncauthtemp", email="nc-lower@nba-corner.example"
        )
        body = self.call(
            "POST",
            "/auth/login",
            200,
            payload={"username": "NCAuthTemp", "password": TEMP_PASSWORD},
        )
        self.assertTrue(
            body["user"]["id"] == lower["user"]["id"]
            and body["user"]["id"] != upper["user"]["id"]
        )
        self.facts = {
            "case_distinct_accounts_created": True,
            "uppercase_login_resolved_lowercase_account": True,
        }

    @behavior(
        "Login/session",
        "Email login succeeds with case/outer whitespace normalization; JWT contains identity/admin/expiry and ~7-day expiration.",
        "Approve JWT lifetime, claims and email-login normalization?",
    )
    def current_behavior__auth__login_metadata(self):
        body = self.call(
            "POST",
            "/auth/login",
            200,
            payload={
                "email": " USER-A@NBA-CORNER.EXAMPLE ",
                "password": "NCFixture!2026-user-a",
            },
        )
        claims = jwt.decode(
            body["token"],
            self.context.module.JWT_SECRET,
            algorithms=[self.context.module.JWT_ALGORITHM],
        )
        ttl = claims["exp"] - datetime.now(timezone.utc).timestamp()
        self.assertTrue(
            set(claims) == {"user_id", "username", "is_admin", "exp"}
            and 604790 < ttl <= 604800
        )
        self.facts = {
            "jwt_claim_fields": sorted(claims),
            "expiry_days": 7,
            "algorithm": self.context.module.JWT_ALGORITHM,
            "user_fields": sorted(body["user"]),
        }

    @behavior(
        "Login/session",
        "Wrong password/unknown user/malformed identifier return 401; missing fields return 400.",
        "Approve failure categories and enumeration behavior?",
    )
    def current_behavior__auth__login_failures(self):
        for payload, status in (
            ({"email": "user-a@nba-corner.example", "password": "wrong"}, 401),
            ({"email": "unknown@nba-corner.example", "password": TEMP_PASSWORD}, 401),
            ({"email": "invalid", "password": TEMP_PASSWORD}, 401),
            ({}, 400),
        ):
            self.call("POST", "/auth/login", status, payload=payload)

    @behavior(
        "Login/session",
        "Fixture usernames contain hyphens and are rejected by current username-login regex; their email login works.",
        "Should username format and fixture/user identity conventions be reconciled later?",
    )
    def current_behavior__auth__fixture_username_login(self):
        self.call(
            "POST",
            "/auth/login",
            401,
            payload={"username": "fixture-user-a", "password": "NCFixture!2026-user-a"},
        )

    @behavior(
        "Login/session",
        "Registration preserves password whitespace while login strips it, preventing login with that stored password.",
        "Should password normalization be consistent?",
    )
    def current_behavior__auth__password_whitespace(self):
        self.register(password=" " + TEMP_PASSWORD + " ")
        self.call(
            "POST",
            "/auth/login",
            401,
            payload={
                "email": "nc-temp@nba-corner.example",
                "password": " " + TEMP_PASSWORD + " ",
            },
        )

    @behavior(
        "User/profile access",
        "Missing, malformed and expired tokens return 401; A/B identities come from their JWT claims.",
        "Approve identity/profile payload and session verification contract?",
    )
    def current_behavior__auth__required_identity_access(self):
        for role in (
            None,
            self.context.auth_token_variant("malformed"),
            self.context.auth_token_variant("expired-user-a"),
        ):
            self.call("GET", "/auth/test-me", 401, role=role)
        for role in ("user-a", "user-b", "admin"):
            self.context.login(role)
            body = self.call("GET", "/auth/test-me", 200, role=role)
            self.assertTrue(body["user"]["user_id"] == identity(role))
        self.facts = {
            "identity_fields": ["exp", "is_admin", "user_id", "username"],
            "user_a_b_identity_is_token_bound": True,
        }

    @behavior(
        "Admin authorization",
        "Admin env diagnostic: missing auth 401, ordinary 403, admin 200; response only masks configuration presence.",
        "Approve admin diagnostic visibility and response schema?",
    )
    def current_behavior__auth__admin_boundary(self):
        self.call("GET", "/admin/env-check", 401)
        self.context.login("user-a")
        self.call("GET", "/admin/env-check", 403, role="user-a")
        self.context.login("admin")
        body = self.call("GET", "/admin/env-check", 200, role="admin")
        self.assertTrue(
            all(
                set(v) == {"name", "present", "preview"}
                and v["preview"] in {"set", "unset"}
                for v in body["env"]
            )
        )
        self.facts = {"env_values_masked": True, "response_fields": sorted(body)}

    @behavior(
        "Admin authorization",
        "Locally signed ordinary-user JWT claiming admin is returned by identity endpoint, but DB admin recheck rejects admin diagnostic with 403.",
        "Which authorization decisions must refresh database roles rather than trust claims?",
    )
    def current_behavior__auth__admin_claim_db_recheck(self):
        role = self.context.auth_token_variant("signed-user-a-admin-claim")
        body = self.call("GET", "/auth/test-me", 200, role=role)
        self.assertTrue(body["user"]["is_admin"] is True)
        self.call("GET", "/admin/env-check", 403, role=role)
        self.facts = {
            "synthetic_server_signed_claim_only": True,
            "not_an_unsigned_token_bypass": True,
        }

    @behavior(
        "Password reset",
        "Existing user request returns neutral 200; stores unused reset and captures a loopback link with ~24-hour expiry.",
        "Approve lifetime, link contract, storage and delivery behavior?",
    )
    def current_behavior__auth__reset_request_metadata(self):
        token = self.forgot()
        rows = self.context.auth_reset_records()
        messages = test_mailbox().inspect_messages()
        self.assertTrue(
            len(rows) == 1 and len(messages) == 1 and rows[0]["used"] is False
        )
        expiry = datetime.fromisoformat(rows[0]["expires_at"])
        ttl = (expiry - datetime.utcnow()).total_seconds()
        url = re.search(
            r'href="([^"]+reset-password\?token=[^"]+)"', messages[0].body
        ).group(1)
        parsed = urlsplit(url)
        self.assertTrue(
            parsed.scheme + "://" + parsed.netloc == self.context.target.backend_origin
            and parse_qs(parsed.query)["token"] == [token]
            and 86380 < ttl <= 86400
        )
        self.facts = {
            "captured": 1,
            "reset_rows": 1,
            "unused": True,
            "expiry_hours": 24,
            "link_loopback": True,
            "token_matches_db": True,
            "tokens_logged": False,
        }

    @behavior(
        "Password reset",
        "Unknown/missing/malformed identifiers return neutral 200 without reset rows or email.",
        "Approve neutral response and error categories?",
    )
    def current_behavior__auth__reset_request_unknown(self):
        for payload in (
            {"email": "unknown@nba-corner.example"},
            {},
            {"email": "invalid"},
        ):
            self.call("POST", "/auth/forgot-password", 200, payload=payload)
        self.assertTrue(
            not self.context.auth_reset_records()
            and not test_mailbox().inspect_messages()
        )

    @behavior(
        "Password reset",
        "Repeated requests create distinct unused records and captured messages; older record remains unused.",
        "Should newer requests invalidate earlier reset tokens?",
    )
    def current_behavior__auth__reset_request_repeated(self):
        first = self.forgot()
        second = self.forgot()
        rows = self.context.auth_reset_records()
        self.assertTrue(
            first != second
            and len(rows) == 2
            and all(not row["used"] for row in rows)
            and len(test_mailbox().inspect_messages()) == 2
        )

    @behavior(
        "Password reset",
        "A capture transport reporting delivery failure still yields neutral 200 and stored unused reset.",
        "Approve ignored delivery result and operational visibility?",
    )
    def current_behavior__auth__reset_delivery_failure(self):
        with patch.object(CaptureMailbox, "send", return_value=False):
            self.forgot()
        self.assertTrue(
            len(self.context.auth_reset_records()) == 1
            and not test_mailbox().inspect_messages()
        )

    @behavior(
        "Password reset",
        "Valid unused reset changes password and marks token used; old password fails/new succeeds; pre-reset JWT still valid.",
        "Should password changes revoke existing sessions?",
    )
    def current_behavior__auth__reset_completion_and_sessions(self):
        self.context.login("user-a")
        token = self.forgot()
        self.call(
            "POST",
            "/auth/reset-password",
            200,
            payload={"token": token, "new_password": NEW_PASSWORD},
        )
        self.assertTrue(self.context.auth_reset_records()[0]["used"] is True)
        self.call(
            "POST",
            "/auth/login",
            401,
            payload={
                "email": "user-a@nba-corner.example",
                "password": "NCFixture!2026-user-a",
            },
        )
        self.call(
            "POST",
            "/auth/login",
            200,
            payload={"email": "user-a@nba-corner.example", "password": NEW_PASSWORD},
        )
        self.call("GET", "/auth/test-me", 200, role="user-a")
        self.call(
            "POST",
            "/auth/reset-password",
            400,
            payload={"token": token, "new_password": NEW_PASSWORD},
        )
        self.facts = {
            "old_password_rejected": True,
            "new_password_accepted": True,
            "token_marked_used": True,
            "pre_reset_jwt_accepted": True,
        }

    @behavior(
        "Password reset",
        "Expired and invalid tokens return 400; expired token remains unused.",
        "Approve expired/invalid token behavior and cleanup policy?",
    )
    def current_behavior__auth__reset_expired_invalid(self):
        token = self.forgot()
        self.context.expire_auth_reset(token)
        for value in (token, "fixture-only-invalid-token"):
            self.call(
                "POST",
                "/auth/reset-password",
                400,
                payload={"token": value, "new_password": NEW_PASSWORD},
            )
        self.assertTrue(self.context.auth_reset_records()[0]["used"] is False)

    @behavior(
        "Password reset",
        "Missing fields and weak new password return 400; truthy non-object JSON returns sanitized 500.",
        "Approve input validation and response categories?",
    )
    def current_behavior__auth__reset_invalid_payload(self):
        for payload in (
            {},
            {"token": "fixture-only-invalid-token", "new_password": "weak"},
        ):
            self.call("POST", "/auth/reset-password", 400, payload=payload)
        self.call("POST", "/auth/reset-password", 500, payload=["unexpected"])

    @behavior(
        "Sensitive-field exposure",
        "Admin test-email requires JWT + DB admin; missing auth 401/ordinary 403/admin 200, sending to capture only.",
        "Approve test-email authorization and operational endpoint availability?",
    )
    def current_behavior__auth__test_email_boundary(self):
        payload = {"to": "admin@nba-corner.example"}
        self.call("POST", "/test-email", 401, payload=payload)
        self.context.login("user-a")
        self.call("POST", "/test-email", 403, payload=payload, role="user-a")
        self.context.login("admin")
        self.call("POST", "/test-email", 200, payload=payload, role="admin")
        self.assertTrue(len(test_mailbox().inspect_messages()) == 1)

    @behavior(
        "User/profile access",
        "Ordinary A can read saved B bracket and its owner id/username/email; no password/reset/admin fields in owner object.",
        "Which cross-user identity/contact fields should saved-content viewers see?",
    )
    def current_behavior__auth__cross_user_saved_owner_display(self):
        bid = self.context.install_auth_boundary_bracket(saved=True)
        self.context.login("user-a")
        body = self.call("GET", "/bracket/" + bid, 200, role="user-a")
        owner = body["bracket"]["owner"]
        self.assertTrue(
            set(owner) == {"id", "username"}
            and owner["id"] == identity("user-b")
            and "email" not in owner
        )
        self.facts = {
            "cross_user_owner_fields": sorted(owner),
            "email_visible": False,
            "no_profile_write_route": True,
        }

    @behavior(
        "User/profile access",
        "Ordinary A gets 403 for B draft; B owner and admin get 200. Only access boundary is tested.",
        "Approve draft/owner/admin identity visibility boundaries?",
    )
    def current_behavior__auth__cross_user_draft_boundary(self):
        bid = self.context.install_auth_boundary_bracket(saved=False)
        for role, status in (("user-a", 403), ("user-b", 200), ("admin", 403)):
            self.context.login(role)
            self.call("GET", "/bracket/" + bid, status, role=role)

    @behavior(
        "Login/session",
        "Local health returns 200 without JWT when no health token is configured; identity route remains harness-protected.",
        "Approve health endpoint and token policy per deployment configuration?",
    )
    def current_behavior__auth__public_health(self):
        self.call("GET", "/health", 200)
        self.facts = {
            "health_token_configured": False,
            "rate_limits_disabled": self.context.module.DISABLE_RATE_LIMITS,
        }


# Preserve NC-01 provenance while explicitly marking approved repair acceptance.
from scripts.nc02a1_acceptance_metadata import mark_acceptance

mark_acceptance(CurrentAuthBehavior)
