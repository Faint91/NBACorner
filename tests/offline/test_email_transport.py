"""Synthetic in-memory email checks. No app import, DB workflow or real network."""

import ast
import contextlib
import io
import logging
import os
import socket
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import email_transport as email
import environment_safety as safety

TARGET = safety.TestTarget(
    "local-email-offline",
    "local:nba-corner-local-test",
    "http://127.0.0.1:55421",
    "http://127.0.0.1:55410",
    "nba-corner-local-test",
    "1",
)


def settings():
    return {
        "NBA_CORNER_ENV": "test",
        "NBA_CORNER_ALLOW_MUTATING_TESTS": "0",
        "NBA_CORNER_TEST_TARGET": TARGET.name,
        "NBA_CORNER_EXPECTED_PROJECT_REF": TARGET.project_ref,
        "SUPABASE_URL": TARGET.supabase_origin,
        "NBACORNER_BASE_URL": TARGET.backend_origin,
        "NBA_CORNER_EMAIL_MODE": "capture",
        "NBA_CORNER_RESET_LINK_ORIGIN": TARGET.backend_origin,
    }


class EmailTests(unittest.TestCase):
    def setUp(self):
        for name in ["create_connection"]:
            guard = patch.object(
                socket, name, side_effect=AssertionError("Network forbidden")
            )
            guard.start()
            self.addCleanup(guard.stop)
        for name in ["connect", "connect_ex"]:
            guard = patch.object(
                socket.socket, name, side_effect=AssertionError("Network forbidden")
            )
            guard.start()
            self.addCleanup(guard.stop)
        self.mailbox = email.CaptureMailbox()
        self.provider = Mock(
            side_effect=AssertionError("Provider forbidden in capture")
        )

    def choose(self, config=None, ambient=None):
        return email.select_email_transport(
            settings() if config is None else config,
            self.provider,
            self.mailbox,
            (TARGET,),
            ambient={} if ambient is None else ambient,
        )

    def test_existing_production_provider_request_and_errors(self):
        # Extract only the original provider function; never import/start Flask.
        root = Path(__file__).resolve().parents[2]
        tree = ast.parse((root / "app.py").read_text(encoding="utf-8"))
        function = next(
            n
            for n in tree.body
            if isinstance(n, ast.FunctionDef)
            and n.name == "_send_email_via_brevo_production"
        )
        post = Mock()
        logger = Mock()
        namespace = {
            "requests": SimpleNamespace(post=post),
            "BREVO_API_KEY": "offline-provider-fixture",
            "os": os,
            "ENABLE_DEBUG_LOGS": False,
            "safe_print": logger,
        }
        exec(
            compile(
                ast.Module(body=[function], type_ignores=[]),
                "offline_brevo_function",
                "exec",
            ),
            namespace,
        )
        sender = namespace[function.name]
        with patch.dict(
            os.environ, {"BREVO_SENDER_EMAIL": "sender@example.invalid"}, clear=True
        ):
            for status in [200, 201, 400, 500]:
                post.return_value = SimpleNamespace(status_code=status)
                self.assertEqual(
                    sender(
                        "alice@example.invalid", "Synthetic subject", "Synthetic body"
                    ),
                    status in [200, 201],
                )
                self.assertEqual(
                    post.call_args.args, ("https://api.brevo.com/v3/smtp/email",)
                )
                self.assertEqual(post.call_args.kwargs["timeout"], 20)
                self.assertEqual(
                    post.call_args.kwargs["json"],
                    {
                        "sender": {
                            "name": "NBA Corner",
                            "email": "sender@example.invalid",
                        },
                        "to": [{"email": "alice@example.invalid"}],
                        "subject": "Synthetic subject",
                        "htmlContent": "Synthetic body",
                    },
                )
                self.assertEqual(
                    post.call_args.kwargs["headers"],
                    {
                        "accept": "application/json",
                        "api-key": "offline-provider-fixture",
                        "content-type": "application/json",
                    },
                )
            post.side_effect = OSError("offline-sensitive-message")
            namespace["ENABLE_DEBUG_LOGS"] = True
            logger.reset_mock()
            self.assertFalse(sender("alice@example.invalid", "subject", "body"))
            self.assertNotIn("offline-sensitive-message", str(logger.call_args_list))
            self.assertNotIn("offline-provider-fixture", str(logger.call_args_list))

    def test_test_mode_cannot_inject_a_live_transport(self):
        with self.assertRaises(safety.SafetyError):
            email.select_email_transport(
                settings(),
                self.provider,
                email.BrevoTransport(self.provider),
                (TARGET,),
                ambient={},
            )
        self.provider.assert_not_called()

    def test_capture_selected_without_provider(self):
        transport = self.choose()
        self.assertIs(transport, self.mailbox)
        self.assertTrue(
            transport.send(
                "alice@example.invalid", "Synthetic subject", "Synthetic body"
            )
        )
        self.provider.assert_not_called()

    def test_production_delegates_exactly_and_preserves_result(self):
        provider = Mock(return_value=False)
        for config in [{}, {"NBA_CORNER_ENV": "production"}]:
            transport = email.select_email_transport(config, provider)
            self.assertIsInstance(transport, email.BrevoTransport)
            self.assertFalse(transport.send("alice@example.invalid", "subject", "body"))
        self.assertEqual(provider.call_count, 2)
        provider.assert_called_with("alice@example.invalid", "subject", "body")

    def test_missing_capture_mode_refuses(self):
        config = settings()
        config.pop("NBA_CORNER_EMAIL_MODE")
        with self.assertRaises(safety.SafetyError):
            self.choose(config)

    def test_live_and_unknown_modes_refuse(self):
        for mode in ["brevo", "live", "smtp", "", None]:
            with self.subTest(mode=mode), self.assertRaises(safety.SafetyError):
                self.choose(dict(settings(), NBA_CORNER_EMAIL_MODE=mode))

    def test_unknown_environment_refuses(self):
        with self.assertRaises(safety.SafetyError):
            self.choose({"NBA_CORNER_ENV": "staging"})

    def test_brevo_credentials_in_settings_or_ambient_refuse(self):
        for name in ["BREVO_API_KEY", "BREVO_SENDER_EMAIL", "SENDINBLUE_API_KEY"]:
            with self.subTest(name=name), self.assertRaises(safety.SafetyError):
                self.choose(dict(settings(), **{name: "offline-provider-fixture"}))
            with self.assertRaises(safety.SafetyError):
                self.choose(ambient={name: "offline-provider-fixture"})
        self.provider.assert_not_called()

    def test_controlled_config_rejects_brevo_field(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env.test.local"
            path.write_text(
                "NBA_CORNER_ENV=test\nBREVO_API_KEY=offline-provider-fixture\n"
            )
            with self.assertRaises(safety.SafetyError):
                safety.load_test_config(str(path))

    def test_local_origin_is_explicit_and_enrolled(self):
        origin = safety.validate_test_email_settings(settings(), TARGET, ambient={})
        self.assertEqual(origin, TARGET.backend_origin)
        for value in [None, "", "http://127.0.0.1:55411", "http://localhost:55410"]:
            with self.subTest(value=value), self.assertRaises(safety.SafetyError):
                self.choose(dict(settings(), NBA_CORNER_RESET_LINK_ORIGIN=value))

    def test_production_and_malformed_origins_refuse(self):
        for value in [
            "https://nbacorner.onrender.com",
            "https://rpwesmvzmgoctrokrbhy.supabase.co",
            "https://nbacorner.com",
            "http://127.0.0.1:55410/reset",
            "http://user:fixture@127.0.0.1:55410",
            "http://127.0.0.1:bad",
            "ftp://127.0.0.1",
            "http://127.0.0.1:55410?token=fixture",
        ]:
            with self.subTest(value=value), self.assertRaises(safety.SafetyError):
                self.choose(dict(settings(), NBA_CORNER_RESET_LINK_ORIGIN=value))

    def test_capture_fields_and_safe_metadata(self):
        self.choose().send(
            "alice@example.invalid", "Synthetic subject", "<p>Synthetic body</p>"
        )
        message = self.mailbox.inspect_messages()[0]
        self.assertEqual(message.recipient, "alice@example.invalid")
        self.assertEqual(message.subject, "Synthetic subject")
        self.assertTrue(message.body == "<p>Synthetic body</p>")
        self.assertEqual(message.metadata, {"transport": "capture", "sequence": 1})

    def test_capture_order_clear_and_private_repr(self):
        transport = self.choose()
        transport.send("alice@example.invalid", "subject", "body")
        transport.send("bob@example.invalid", "subject", "body")
        self.assertEqual([m.sequence for m in self.mailbox.inspect_messages()], [1, 2])
        self.mailbox.clear()
        self.assertEqual(self.mailbox.inspect_messages(), ())
        transport.send("alice@example.invalid", "subject", "body")
        self.assertEqual(self.mailbox.inspect_messages()[0].sequence, 1)
        self.assertNotIn("alice", repr(self.mailbox.inspect_messages()))

    def test_reset_link_deliberate_memory_inspection_no_logs(self):
        token = "synthetic-reset-token"
        link = email.reset_link_for_settings(token, settings(), (TARGET,), ambient={})
        output = io.StringIO()
        log = io.StringIO()
        handler = logging.StreamHandler(log)
        logging.getLogger().addHandler(handler)
        self.addCleanup(logging.getLogger().removeHandler, handler)
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            self.choose().send(
                "alice@example.invalid", "Reset", '<a href="' + link + '">Reset</a>'
            )
        message = self.mailbox.inspect_messages()[0]
        self.assertTrue(token in message.body)
        self.assertTrue(link.startswith(TARGET.backend_origin + "/reset-password?"))
        self.assertNotIn(token, repr(message))
        self.assertNotIn(token, repr(self.mailbox.inspect_messages()))
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(log.getvalue(), "")

    def test_production_reset_effective_url_unchanged(self):
        self.assertTrue(
            email.reset_link_for_settings("synthetic-reset-token", {})
            == "https://nbacorner.onrender.com/reset-password?token=synthetic-reset-token"
        )

    def test_test_runtime_requires_controlled_config(self):
        with patch.dict(
            os.environ, {"NBA_CORNER_ENV": "test"}, clear=True
        ), self.assertRaises(safety.SafetyError):
            email.runtime_email_settings()

    def test_production_test_config_mix_refuses(self):
        with patch.dict(
            os.environ,
            {"NBA_CORNER_ENV": "production", "NBA_CORNER_TEST_CONFIG": "fixture"},
            clear=True,
        ), self.assertRaises(safety.SafetyError):
            email.runtime_email_settings()

    def test_runtime_capture_uses_controlled_fields_only(self):
        with patch.dict(
            os.environ,
            {"NBA_CORNER_ENV": "test", "NBA_CORNER_TEST_CONFIG": "fixture"},
            clear=True,
        ), patch.object(
            email, "load_test_config", return_value=settings()
        ), patch.object(
            email, "load_enrollments", return_value=(TARGET,)
        ):
            email.test_mailbox().clear()
            self.assertTrue(
                email.deliver_email(
                    self.provider, "alice@example.invalid", "subject", "body"
                )
            )
            self.assertEqual(len(email.test_mailbox().inspect_messages()), 1)
            email.test_mailbox().clear()
        self.provider.assert_not_called()

    def test_readiness_checks_email_before_live_identity_and_no_mutation_permit(self):
        with patch.object(
            safety, "load_enrollments", return_value=(TARGET,)
        ), patch.object(
            safety,
            "verify_live_local_identity",
            return_value={"identity_verified": True},
        ) as live, patch.dict(
            os.environ, {}, clear=True
        ):
            result = safety.verify_test_email_readiness(settings())
            self.assertTrue(result["email_gate_passed"])
            self.assertFalse(result["mutation_permitted"])
            live.reset_mock()
            with self.assertRaises(safety.SafetyError):
                safety.verify_test_email_readiness(
                    dict(settings(), NBA_CORNER_EMAIL_MODE="brevo")
                )
            live.assert_not_called()

    def test_startup_still_refuses_after_email_gate(self):
        config = dict(settings(), NBA_CORNER_ALLOW_MUTATING_TESTS="1")
        with patch.dict(
            os.environ,
            {"NBA_CORNER_ENV": "test", "NBA_CORNER_TEST_CONFIG": "fixture"},
            clear=True,
        ), patch.object(safety, "load_test_config", return_value=config), patch.object(
            safety, "load_enrollments", return_value=(TARGET,)
        ), patch.object(
            safety,
            "require_live_identity",
            side_effect=safety.SafetyError("Remaining gates closed"),
        ) as remaining, self.assertRaises(
            safety.SafetyError
        ):
            safety.prepare_runtime_environment(
                Mock(side_effect=AssertionError("Production dotenv forbidden"))
            )
        remaining.assert_called_once_with(TARGET)


if __name__ == "__main__":
    unittest.main()
