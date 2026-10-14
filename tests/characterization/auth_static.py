"""Static frontend/auth findings only. No browser/API/production contact."""

import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FRONT = Path("C:/NBACorner/frontend/src")
RESULTS = []


def behavior(group, current, question, source):
    def decorate(fn):
        fn.metadata = {
            "scenario": fn.__name__,
            "group": group,
            "current_behavior": current,
            "approved_requirement": None,
            "classification": "REQUIREMENT NOT YET REVIEWED",
            "future_business_question": question,
            "evidence_source": "Static source inspection: " + source,
        }
        return fn

    return decorate


class CurrentStaticAuthBehavior(unittest.TestCase):
    def tearDown(self):
        RESULTS.append(dict(getattr(self, self._testMethodName).metadata))

    def front(self, path):
        return (FRONT / path).read_text(encoding="utf-8")

    def backend(self):
        return (ROOT / "app.py").read_text(encoding="utf-8")

    @behavior(
        "Frontend auth behavior",
        "AuthContext stores/restores auth_token/auth_user in localStorage; logout clears client state only; ProtectedRoute checks token presence, not validity.",
        "Approve storage, logout/revocation and expired-session handling?",
        "AuthContext.tsx; main.tsx",
    )
    def current_behavior__auth__frontend_storage_logout_guard(self):
        source = self.front("auth/AuthContext.tsx")
        main = self.front("main.tsx")
        self.assertTrue(
            all(
                text in source
                for text in (
                    'localStorage.getItem("auth_token")',
                    'localStorage.setItem("auth_user"',
                    'localStorage.removeItem("auth_token")',
                    'localStorage.removeItem("auth_user")',
                )
            )
            and "if (!token)" in main
        )

    @behavior(
        "Frontend auth behavior",
        "Login caches returned session and navigates dashboard; registration navigates login with registered/email state; callers use VITE_API_URL.",
        "Approve login/register navigation and API environment contract?",
        "LoginPage.tsx; RegisterPage.tsx; api/client.ts",
    )
    def current_behavior__auth__frontend_login_register_flow(self):
        login = self.front("pages/LoginPage.tsx")
        reg = self.front("pages/RegisterPage.tsx")
        self.assertTrue(
            "login({ token: data.token, user: data.user })" in login
            and 'navigate("/dashboard")' in login
            and "registered: true, email" in reg
            and "useLocation" in login
            and "import.meta.env.VITE_API_URL" in self.front("api/client.ts")
        )

    @behavior(
        "Frontend auth behavior",
        "ResetPasswordPage requests forgot-password only; no token-query/new-password completion UI or reset-password POST is present. AccountPage also requests reset email.",
        "What complete browser reset flow should be approved?",
        "ResetPasswordPage.tsx; AccountPage.tsx; main.tsx",
    )
    def current_behavior__auth__frontend_reset_request_only(self):
        source = self.front("pages/ResetPasswordPage.tsx")
        self.assertTrue(
            '"/auth/forgot-password"' in source
            and "new_password" not in source
            and "useSearchParams" not in source
            and '"/auth/reset-password"' not in source
        )
        self.assertTrue(
            '"/auth/forgot-password"' in self.front("pages/AccountPage.tsx")
        )

    @behavior(
        "Frontend auth behavior",
        "Admin UI is driven by cached user.is_admin checks; tested server admin diagnostic independently verifies JWT claim and DB role.",
        "Approve cached role refresh and server enforcement coverage?",
        "AdminPage.tsx; AuthContext.tsx; admin_env_check",
    )
    def current_behavior__auth__frontend_admin_display(self):
        self.assertTrue(
            "user?.is_admin" in self.front("pages/AdminPage.tsx")
            and "is_admin_db" in self.backend()
        )

    @behavior(
        "User/profile access",
        "No dedicated account/profile read/write or server logout route; auth/test-me returns JWT claims, and AccountPage uses cached user fields.",
        "Which profile/account mutation and session-revocation features are required?",
        "Flask route inventory; AccountPage.tsx; test_me",
    )
    def current_behavior__auth__account_route_absence(self):
        routes = []
        for node in ast.walk(ast.parse(self.backend())):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "route"
                and node.args
                and isinstance(node.args[0], ast.Constant)
            ):
                routes.append(node.args[0].value)
        self.assertTrue(
            not any(
                path.startswith(("/users", "/profile", "/account"))
                or path == "/auth/logout"
                for path in routes
            )
        )

    @behavior(
        "Login/session",
        "Custom PyJWT uses user_id/username/is_admin/exp, seven-day tokens, configurable algorithm/key with a hardcoded development fallback; bcrypt defaults to cost 12. Supabase Auth is not the app identity model.",
        "Approve key configuration, lifetime, claim freshness and hashing policy?",
        "generate_token; decode_token; environment globals",
    )
    def current_behavior__auth__implementation_defaults(self):
        source = self.backend()
        tree = ast.parse(source)
        key = next(
            node
            for node in tree.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(t, ast.Name) and t.id == "JWT_SECRET" for t in node.targets
            )
        )
        self.assertTrue(
            len(key.value.args) == 2
            and isinstance(key.value.args[1], ast.Constant)
            and bool(key.value.args[1].value)
        )
        self.assertTrue(
            "timedelta(days=7)" in source
            and "bcrypt.gensalt(rounds=BCRYPT_ROUNDS)" in source
            and 'os.getenv("BCRYPT_ROUNDS", "12")' in source
        )

    @behavior(
        "Login/session",
        "In-memory rate limits: login 10/IP/60s and 5/identifier/60s; forgot 5/IP/300s and 3/identifier/300s; register 3/IP/hour. X-Forwarded-For is honored; unknown buckets fail open. test_email_ip is missing from the configured map.",
        "Approve proxy trust, thresholds and unknown-bucket behavior?",
        "RATE_LIMITS; get_client_ip; is_rate_limited",
    )
    def current_behavior__auth__rate_limit_static(self):
        tree = ast.parse(self.backend())
        node = next(
            n
            for n in tree.body
            if isinstance(n, ast.Assign)
            and any(
                isinstance(t, ast.Name) and t.id == "RATE_LIMITS" for t in n.targets
            )
        )
        rates = ast.literal_eval(node.value)
        self.assertTrue(
            rates["login_ip"] == (10, 60)
            and rates["forgot_identifier"] == (3, 300)
            and rates["register_ip"] == (3, 3600)
            and "test_email_ip" not in rates
        )

    @behavior(
        "Sensitive-field exposure",
        "Existing bracket owner/list and league-member display sources include id/username/email; league access semantics are deferred. Auth payloads omit password/reset hashes; admin env response masks values.",
        "Which contact/security fields may be visible across users and features?",
        "get_bracket_by_id; list_all_brackets; get_league_members; auth responses",
    )
    def current_behavior__auth__display_fields_static(self):
        source = self.backend()
        self.assertTrue(
            '.select("id, username, email")' in source
            and '"email": u.get("email")' in source
            and '"preview": "set" if os.getenv(name) else "unset"' in source
        )
