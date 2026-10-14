"""Canonical local smoke context. No production route or global mutation switch."""

import contextlib
import hmac
import http.client
import importlib
import json
import logging
import os
import re
import secrets
import socket
import sys
import threading
from urllib.parse import urlsplit
from unittest.mock import patch
import environment_safety as safety
from scripts.reset_local_fixtures import (
    LocalFixtureLease,
    run_reset,
    verify_fixture_readiness,
)
from synthetic_fixtures import VERSION, identity

CANONICAL_CHECKSUM = "a96f2c44f571e830624cef17e91ba02ae883d8a5768a81730d29d6a42adad1b0"
_ACTIVE = None


class QuietSink:
    def write(self, text):
        return len(text)

    def flush(self):
        pass


def validate_harness_settings(settings, explicit_invocation):
    if explicit_invocation is not True:
        raise safety.SafetyError("Explicit harness mutation invocation required.")
    target = safety.validate_test_target(settings, safety.load_enrollments())
    safety.validate_test_email_settings(settings, target)
    safety.validate_test_provider_settings(settings, target)
    safety.validate_test_job_settings(settings)
    return target


def validate_harness_identity(target, marker):
    safety.validate_local_marker(target, marker)
    if (
        marker["fixture_state"] != "SEEDED"
        or marker["fixture_version"] != VERSION
        or marker["fixture_checksum"] != CANONICAL_CHECKSUM
    ):
        raise safety.SafetyError("Canonical seeded identity is required.")


def startup_settings(settings):
    permit = _ACTIVE
    if permit is None:
        return settings
    permit._require_lease()
    if (
        not permit._starting
        or threading.get_ident() != permit._owner
        or settings != permit.original_settings
    ):
        raise safety.SafetyError("Verified harness startup context required.")
    # CLI opt-in is scoped to this verified context; ignored config remains opt-in=0.
    return dict(permit.settings)


def require_harness_startup(target):
    permit = _ACTIVE
    if permit is None or not permit._starting:
        return safety.require_live_identity(target)
    permit._require_lease()
    if target != permit.target or threading.get_ident() != permit._owner:
        raise safety.SafetyError("Harness startup identity mismatch.")
    marker = safety.verify_live_local_identity(permit.settings)["marker"]
    validate_harness_identity(target, marker)
    verify_fixture_readiness(permit.original_settings)


def validate_backend_identity(target, response):
    expected = {
        "environment": "test",
        "project_ref": target.project_ref,
        "marker_id": target.marker_id,
        "marker_version": "2",
        "baseline_version": "nc-env-02-current-secured-v1",
        "fixture_state": "SEEDED",
        "fixture_version": VERSION,
        "fixture_checksum": CANONICAL_CHECKSUM,
        "backend_origin": target.backend_origin,
        "email_mode": "capture",
        "provider_mode": "fixtures",
        "jobs_enabled": False,
    }
    if not isinstance(response, dict) or any(
        response.get(k) != v for k, v in expected.items()
    ):
        raise safety.SafetyError(
            "Backend identity disagrees with verified environment."
        )


class GuardedHarness:
    def __init__(self, config, *, allow_local_mutations=False):
        self.config = config
        self.original_settings = safety.load_test_config(config)
        self.settings = dict(self.original_settings)
        if allow_local_mutations is True:
            self.settings["NBA_CORNER_ALLOW_MUTATING_TESTS"] = "1"
        self.target = validate_harness_settings(self.settings, allow_local_mutations)
        self.settings["CURRENT_SEASON_CODE"] = "2025-26"
        self._owner = threading.get_ident()
        self._starting = False
        self._ready = False
        self._closed = False
        self._admission = secrets.token_urlsafe(32)
        self._tokens = {}
        self._brackets = set()
        self._matches = set()
        self._owns_app = False
        self.lease = None
        self.server = None
        self.thread = None
        self.stack = contextlib.ExitStack()
        self.summary = []
        self.cleanup_proof = None

    def _require_lease(self):
        if (
            self._closed
            or _ACTIVE is not self
            or type(self.lease) is not LocalFixtureLease
            or not self.lease.active
            or self.lease.process.poll() is not None
        ):
            raise safety.SafetyError(
                "Active exclusive verified harness lease required."
            )

    def __enter__(self):
        global _ACTIVE
        if _ACTIVE is not None:
            raise safety.SafetyError("Another harness context is active.")
        marker = safety.verify_live_local_identity(self.settings)["marker"]
        validate_harness_identity(self.target, marker)
        verify_fixture_readiness(self.original_settings)
        try:
            self.lease = LocalFixtureLease(
                self.original_settings, allow_local_reset=True
            ).__enter__()
            _ACTIVE = self
            run_reset(self.original_settings, True, lease=self.lease)
            verify_fixture_readiness(self.original_settings)
            env = safety.controlled_child_environment(self.settings, self.config)
            self.stack.enter_context(patch.dict(os.environ, env, clear=True))
            # Retain no raw app/request/SDK logs; only explicit response summaries.
            self.stack.enter_context(contextlib.redirect_stdout(QuietSink()))
            self.stack.enter_context(contextlib.redirect_stderr(QuietSink()))
            previous_logging_disable = logging.root.manager.disable
            logging.disable(logging.CRITICAL)
            self.stack.callback(logging.disable, previous_logging_disable)
            self._install_egress_guards()
            if "app" in sys.modules:
                raise safety.SafetyError(
                    "Existing application import is not a harness startup."
                )
            self._starting = True
            module = importlib.import_module("app")
            self._starting = False
            self.module = module
            self._owns_app = True
            if (
                safety.normalize_origin(module.SUPABASE_URL)
                != self.target.supabase_origin
                or safety.normalize_origin(str(module.supabase.supabase_url))
                != self.target.supabase_origin
            ):
                raise safety.SafetyError("Actual backend database identity mismatch.")
            module.JWT_SECRET = secrets.token_urlsafe(
                48
            )  # In-memory test-only signing key.
            module.ENABLE_DEBUG_LOGS = False
            app = module.app
            self.stack.enter_context(patch.object(app.logger, "disabled", True))
            self.stack.enter_context(
                patch.object(logging.getLogger("werkzeug"), "disabled", True)
            )
            from flask import request, jsonify

            def admission_guard():
                if not self._ready and request.path != "/__test__/identity":
                    return jsonify({"error": "Backend admission not ready"}), 403
                try:
                    self._require_lease()
                except safety.SafetyError:
                    return jsonify({"error": "Verified lease unavailable"}), 403
                if not self.lease.active or not hmac.compare_digest(
                    request.headers.get("X-NBA-Test-Context", ""), self._admission
                ):
                    return jsonify({"error": "Guarded harness admission required"}), 403
                try:
                    self._check_path(
                        request.method, request.path, identity_bootstrap=True
                    )
                except safety.SafetyError:
                    return jsonify({"error": "Route outside approved smoke scope"}), 403
                marker = safety.verify_live_local_identity(self.settings)["marker"]
                validate_harness_identity(self.target, marker)

            app.before_request_funcs.setdefault(None, []).insert(0, admission_guard)

            def backend_identity():
                marker = safety.verify_live_local_identity(self.settings)["marker"]
                return jsonify(
                    dict(
                        marker,
                        backend_origin=self.target.backend_origin,
                        email_mode="capture",
                        provider_mode="fixtures",
                        jobs_enabled=False,
                    )
                )

            app.add_url_rule(
                "/__test__/identity",
                "harness_identity",
                backend_identity,
                methods=["GET"],
            )
            from werkzeug.serving import make_server

            origin = urlsplit(self.target.backend_origin)
            self.server = make_server("127.0.0.1", origin.port, app, threaded=False)
            self.thread = threading.Thread(
                target=self.server.serve_forever, daemon=True
            )
            self.thread.start()
            status, body = self._exchange("GET", "/__test__/identity")
            if status != 200:
                raise safety.SafetyError("Backend identity request failed.")
            validate_backend_identity(self.target, body)
            self._ready = True
            return self
        except BaseException:
            self._cleanup()
            raise safety.SafetyError(
                "Harness startup failed; cleanup attempted; sensitive logs withheld."
            ) from None

    def _install_egress_guards(self):
        import httpx, requests

        target = self.target
        original_connect = socket.socket.connect
        ports = {
            urlsplit(target.supabase_origin).port,
            urlsplit(target.backend_origin).port,
        }

        def connect(sock, address):
            if (
                not isinstance(address, tuple)
                or address[0] != "127.0.0.1"
                or address[1] not in ports
            ):
                raise safety.SafetyError("Non-enrolled socket destination refused.")
            return original_connect(sock, address)

        self.stack.enter_context(patch.object(socket.socket, "connect", connect))
        self.stack.enter_context(
            patch.object(
                socket.socket,
                "connect_ex",
                lambda *a: (_ for _ in ()).throw(
                    safety.SafetyError("Raw alternate connection refused.")
                ),
            )
        )
        send = httpx.Client.send

        def httpx_send(client, request, **kwargs):
            safety.validate_test_destination(target, str(request.url))
            kwargs["follow_redirects"] = False
            response = send(client, request, **kwargs)
            if 300 <= response.status_code < 400:
                raise safety.SafetyError("Test redirect refused.")
            return response

        self.stack.enter_context(patch.object(httpx.Client, "send", httpx_send))
        self.stack.enter_context(
            patch.object(
                httpx.AsyncClient,
                "send",
                side_effect=safety.SafetyError("Unreviewed async transport refused."),
            )
        )
        send_requests = requests.Session.send

        def requests_send(session, request, **kwargs):
            safety.validate_test_destination(target, request.url)
            kwargs["allow_redirects"] = False
            response = send_requests(session, request, **kwargs)
            if 300 <= response.status_code < 400:
                raise safety.SafetyError("Test redirect refused.")
            return response

        self.stack.enter_context(patch.object(requests.Session, "send", requests_send))

    def _check_path(self, method, path, *, identity_bootstrap=False):
        if not isinstance(path, str) or "?" in path or "%" in path or "\\" in path:
            raise safety.SafetyError("Unexpected guarded HTTP path.")
        reads = {
            "/",
            "/health",
            "/auth/test-me",
            "/brackets/me",
            "/brackets",
            "/leagues",
            "/leagues/me",
            "/leaderboard",
            "/leaderboard/history",
        }
        if method == "GET" and (
            path in reads or path == "/__test__/identity" and identity_bootstrap
        ):
            return
        if method == "POST" and path in {"/auth/login", "/bracket/create"}:
            return
        if method == "GET" and path in {"/bracket/" + bid for bid in self._brackets}:
            return
        if method == "PATCH" and path in {
            f"/bracket/{bid}/match/{mid}" for bid, mid in self._matches
        }:
            return
        raise safety.SafetyError("Request outside approved smoke route allowlist.")

    def _exchange(self, method, path, payload=None, role=None):
        self._require_lease()
        self._check_path(method, path, identity_bootstrap=not self._ready)
        headers = {
            "X-NBA-Test-Context": self._admission,
            "Content-Type": "application/json",
        }
        if role is not None:
            if role not in self._tokens:
                raise safety.SafetyError("Synthetic login session required.")
            headers["Authorization"] = "Bearer " + self._tokens[role]
        origin = urlsplit(self.target.backend_origin)
        connection = http.client.HTTPConnection("127.0.0.1", origin.port, timeout=15)
        try:
            connection.request(
                method,
                path,
                body=json.dumps(payload) if payload is not None else None,
                headers=headers,
            )
            response = connection.getresponse()
            raw = response.read(1048577)
            if len(raw) > 1048576 or 300 <= response.status < 400:
                raise safety.SafetyError("Unexpected smoke HTTP response.")
            body = (
                json.loads(raw)
                if response.getheader("Content-Type", "").startswith("application/json")
                else None
            )
            return response.status, body
        except (OSError, ValueError, http.client.HTTPException):
            raise safety.SafetyError(
                "Guarded HTTP request failed; response details withheld."
            ) from None
        finally:
            connection.close()

    def request(self, method, path, *, payload=None, role=None):
        self._require_lease()
        if not self._ready or threading.get_ident() != self._owner:
            raise safety.SafetyError(
                "Verified backend/context required before application HTTP."
            )
        # Only synthetic session requests and the two explicitly selected write kinds.
        if path == "/auth/login":
            raise safety.SafetyError("Use synthetic login method.")
        if method == "POST" and (
            path != "/bracket/create" or payload != {} or role != "admin"
        ):
            raise safety.SafetyError("Unapproved application write.")
        if method == "PATCH" and (
            role != "admin"
            or not isinstance(payload, dict)
            or set(payload) != {"action", "team", "games"}
            or payload["action"] != "set_winner"
            or payload["games"] != 1
            or payload["team"] not in {"MIA", "MIL"}
        ):
            raise safety.SafetyError("Unapproved prediction write.")
        status, body = self._exchange(method, path, payload, role)
        self.summary.append(
            {
                "method": method,
                "path": re.sub(r"[0-9a-f]{8}-[0-9a-f-]{27}", "<id>", path),
                "status": status,
                "shape": (
                    sorted(body)
                    if isinstance(body, dict)
                    else "list" if isinstance(body, list) else "text"
                ),
            }
        )
        if method == "POST" and status in {200, 201}:
            self._brackets.add(body["bracket"]["id"])
        if method == "GET" and path.startswith("/bracket/") and status == 200:
            for rounds in body["matches"].values():
                for matches in rounds.values():
                    for match in matches:
                        self._matches.add((path.split("/")[-1], match["id"]))
        return status, body

    def verify_admission_denial(self):
        self._require_lease()
        origin = urlsplit(self.target.backend_origin)
        connection = http.client.HTTPConnection("127.0.0.1", origin.port, timeout=5)
        try:
            connection.request(
                "POST",
                "/bracket/create",
                body="{}",
                headers={"Content-Type": "application/json"},
            )
            response = connection.getresponse()
            response.read(1024)
            if response.status != 403:
                raise safety.SafetyError("Unscoped backend request was not refused.")
            self.summary.append(
                {
                    "method": "POST",
                    "path": "/bracket/create",
                    "status": 403,
                    "admission": "missing-context-refused",
                }
            )
        finally:
            connection.close()

    def login(self, role):
        self._require_lease()
        if not self._ready or role not in {"user-a", "user-b", "admin"}:
            raise safety.SafetyError("Seeded smoke login required.")
        status, body = self._exchange(
            "POST",
            "/auth/login",
            {
                "email": role + "@nba-corner.example",
                "password": "NCFixture!2026-" + role,
            },
        )
        if status != 200 or body.get("user", {}).get("id") != identity(role):
            raise safety.SafetyError("Synthetic login smoke failed.")
        self._tokens[role] = body["token"]
        self.summary.append(
            {
                "method": "POST",
                "path": "/auth/login",
                "status": status,
                "role": role,
                "shape": ["message", "token", "user"],
            }
        )

    def _cleanup(self):
        global _ACTIVE
        self._ready = False
        self._starting = False
        try:
            if self.server is not None:
                if self.thread is not None and self.thread.is_alive():
                    self.server.shutdown()
                    self.thread.join(timeout=10)
                self.server.server_close()
            if self.lease is not None and self.lease.active:
                try:
                    self.cleanup_proof = run_reset(
                        self.original_settings, True, lease=self.lease
                    )
                except safety.SafetyError:
                    self.lease.close()
                    self.cleanup_proof = run_reset(self.original_settings, True)
                verify_fixture_readiness(self.original_settings)
        finally:
            if self.lease is not None:
                self.lease.close()
            self._tokens.clear()
            self._admission = ""
            self._closed = True
            from email_transport import test_mailbox

            test_mailbox().clear()
            self.stack.close()
            _ACTIVE = None
            if self._owns_app:
                sys.modules.pop("app", None)

    def __exit__(self, *args):
        self._cleanup()


def readiness_report(settings):
    """Read-only availability report. Never creates an execution context/permit."""
    target = safety.validate_test_target(
        settings, safety.load_enrollments(), identity_only=True
    )
    validate_harness_identity(
        target, safety.verify_live_local_identity(settings)["marker"]
    )
    result = safety.verify_provider_job_readiness(settings)
    result.update(
        integration_harness="PASS",
        harness_state="AVAILABLE_GUARDED",
        harness_scoped_mutation_permitted=False,
        mutation_permitted=False,
    )
    return result
