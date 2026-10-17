"""R3 pure routing/config/capture checks. No application startup or network."""

import contextlib
import io
import os
import re
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import email_transport as email
from environment_safety import SafetyError
from password_reset_service import issue_reset

ROOT = Path(__file__).resolve().parents[2]
INVALID = [
    None,
    "",
    " ",
    " /relative",
    "/reset-password",
    "//frontend.example.invalid",
    "https://",
    "http://frontend.example.invalid",
    "ftp://frontend.example.invalid",
    "https:///missing",
    "https://frontend.example.invalid/reset-password",
    "https://frontend.example.invalid//",
    "https://frontend.example.invalid?query=x",
    "https://frontend.example.invalid#fragment",
    "https://frontend.example.invalid?",
    "https://frontend.example.invalid#",
    "https://user:private@frontend.example.invalid",
    "https://frontend.example.invalid:bad",
    "https://frontend.example.invalid:",
    "https://frontend.example.invalid:0",
    "https://frontend.example.invalid:70000",
    "https://front end.example.invalid",
    "https://frontend.example.invalid\\bad",
    "https://frontend.example.invalid\n",
    "https://bad<host.invalid",
    'https://bad"host.invalid',
    "https://.",
    "https://-bad.invalid",
]


class ResetLinkR3Tests(unittest.TestCase):
    def test_configuration_negative_cases_are_fixed_and_private(self):
        for value in INVALID:
            with self.subTest(case=INVALID.index(value)):
                try:
                    email.reset_link_for_settings(
                        "non-issued-synthetic-marker",
                        {"NBA_CORNER_ENV": "production", "FRONTEND_ORIGIN": value},
                    )
                    self.fail("Unsafe configuration accepted")
                except SafetyError as error:
                    self.assertTrue(
                        str(error) == "Frontend reset origin is unavailable or invalid."
                    )

    def test_missing_configuration_has_no_api_or_source_fallback(self):
        for settings in [
            {},
            {"NBA_CORNER_ENV": "production"},
            {"BACKEND_BASE_URL": "https://api.example.invalid"},
            {"SUPABASE_URL": "https://database.example.invalid"},
        ]:
            with self.assertRaises(SafetyError):
                email.reset_link_for_settings("non-issued-synthetic-marker", settings)

    def test_explicit_frontend_trailing_slash_and_token_encoding(self):
        for origin in [
            "https://frontend.example.invalid",
            "https://frontend.example.invalid/",
            "https://frontend.example.invalid:8443/",
        ]:
            marker = "non-issued synthetic/+&=? marker"
            url = urlsplit(
                email.reset_link_for_settings(
                    marker,
                    {
                        "FRONTEND_ORIGIN": origin,
                        "BACKEND_BASE_URL": "https://api.example.invalid",
                    },
                )
            )
            self.assertTrue(url.hostname == "frontend.example.invalid")
            self.assertTrue(url.path == "/reset-password")
            self.assertTrue(parse_qs(url.query) == {"token": [marker]})
            self.assertFalse(url.fragment)

    def test_runtime_reads_only_explicit_frontend_setting(self):
        with patch.dict(
            os.environ,
            {
                "NBA_CORNER_ENV": "production",
                "FRONTEND_ORIGIN": "https://frontend.example.invalid",
                "BACKEND_BASE_URL": "https://api.example.invalid",
            },
            clear=True,
        ):
            self.assertTrue(
                urlsplit(email.build_reset_link("non-issued-synthetic-marker")).hostname
                == "frontend.example.invalid"
            )
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(SafetyError):
            email.build_reset_link("non-issued-synthetic-marker")

    def test_invalid_destination_never_sends_and_cancels_without_leak(self):
        for value in INVALID:
            calls = []
            messages = []
            logs = []

            def rpc(name, args):
                calls.append((name, args))
                return SimpleNamespace(execute=lambda: SimpleNamespace(data=True))

            def send(*args):
                messages.append(args)
                return True

            with contextlib.redirect_stdout(
                io.StringIO()
            ) as output, contextlib.redirect_stderr(io.StringIO()) as errors:
                issue_reset(
                    {"id": "synthetic-id", "email": "synthetic@example.invalid"},
                    SimpleNamespace(rpc=rpc),
                    send,
                    lambda raw: email.reset_link_for_settings(
                        raw, {"FRONTEND_ORIGIN": value}
                    ),
                    logs.append,
                )
            self.assertFalse(messages)
            self.assertTrue(
                [name for name, _ in calls]
                == ["issue_password_reset", "cancel_password_reset"]
            )
            self.assertTrue(calls[0][1]["p_digest"] == calls[1][1]["p_digest"])
            self.assertTrue(
                all(
                    x
                    in {
                        "Password reset delivery unavailable",
                        "Password reset delivery failed; cancelling issued verifier",
                    }
                    for x in logs
                )
            )
            self.assertFalse(output.getvalue() or errors.getvalue())

    def test_actual_issue_helper_captures_frontend_link_only_in_memory(self):
        mailbox = email.CaptureMailbox()
        calls = []

        def rpc(name, args):
            calls.append((name, args))
            return SimpleNamespace(execute=lambda: SimpleNamespace(data=True))

        issue_reset(
            {"id": "synthetic-id", "email": "synthetic@example.invalid"},
            SimpleNamespace(rpc=rpc),
            mailbox.send,
            lambda raw: email.reset_link_for_settings(
                raw, {"FRONTEND_ORIGIN": "https://frontend.example.invalid"}
            ),
            lambda _: None,
        )
        message = mailbox.inspect_messages()[0]
        link = urlsplit(re.search(r'href="([^\"]+)"', message.body)[1])
        raw = parse_qs(link.query)["token"][0]
        self.assertTrue(
            link.hostname == "frontend.example.invalid"
            and link.path == "/reset-password"
        )
        self.assertTrue(len(raw) == 43 and set(parse_qs(link.query)) == {"token"})
        self.assertTrue([name for name, _ in calls] == ["issue_password_reset"])
        self.assertFalse(raw in repr(message) or raw in str(calls))
        mailbox.clear()
        self.assertFalse(mailbox.inspect_messages())

    def test_frontend_route_and_api_contract_unchanged(self):
        frontend = ROOT.parent / "frontend"
        self.assertTrue(
            'path="/reset-password"'
            in (frontend / "src/main.tsx").read_text(encoding="utf-8")
        )
        self.assertTrue(
            '"/auth/reset-password"'
            in (frontend / "src/pages/ResetPasswordPage.tsx").read_text(
                encoding="utf-8"
            )
        )
        bootstrap = (frontend / "index.html").read_text(encoding="utf-8")
        self.assertTrue(
            bootstrap.index("searchParams.getAll('token')")
            < bootstrap.index("googletagmanager")
        )


class PreflightRoutingTests(unittest.TestCase):
    def test_read_only_config_interface(self):
        from scripts.verify_nc03r3_reset_routing import inspect_config

        valid = inspect_config(
            {"FRONTEND_ORIGIN": "https://frontend.example.invalid/"},
            "https://api.example.invalid",
        )
        self.assertTrue(valid["routing_contract_valid"])
        self.assertFalse("https://" in str(valid))
        self.assertFalse(
            inspect_config({}, "https://api.example.invalid")["routing_contract_valid"]
        )
        self.assertFalse(
            inspect_config(
                {"FRONTEND_ORIGIN": "https://api.example.invalid:443/"},
                "https://api.example.invalid",
            )["routing_contract_valid"]
        )

    def test_current_route_proof_and_historical_finding_preservation(self):
        from scripts.verify_nc03r3_reset_routing import run

        self.assertTrue(run()["frontend_route_unchanged"])
        record = __import__("json").loads(
            (ROOT / "db/records/nc_04a_reset_route_finding.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertTrue(
            record["classification"] == "CONFIRMED LOCAL RELEASE DEFECT / STOP"
        )


if __name__ == "__main__":
    unittest.main()
