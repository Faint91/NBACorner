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
    def __init__(
        self, config, *, allow_local_mutations=False, characterization_scope=None
    ):
        if characterization_scope not in {
            None,
            "NC-01A",
            "NC-01B",
            "NC-01C",
            "NC-01D",
            "NC-01E",
            "NC-02A2",
            "NC-02B1",
            "NC-02B2",
            "NC-02B3",
            "NC-02C1",
            "NC-02C2",
            "NC-02C3",
            "NC-02D1",
            "NC-02D2",
            "NC-02F1",
        }:
            raise safety.SafetyError("Unreviewed characterization scope.")
        self.characterization_scope = characterization_scope
        self._auth_subjects = {
            identity(role) for role in ("user-a", "user-b", "admin", "owner")
        }
        self.config = config
        self.original_settings = safety.load_test_config(config)
        self.settings = dict(self.original_settings)
        if allow_local_mutations is True:
            self.settings["NBA_CORNER_ALLOW_MUTATING_TESTS"] = "1"
        self.target = validate_harness_settings(self.settings, allow_local_mutations)
        # Canonical season is designated by guarded fixture reset, never environment.
        self._owner = threading.get_ident()
        self._starting = False
        self._ready = False
        self._closed = False
        self._admission = secrets.token_urlsafe(32)
        self._tokens = {}
        self._scoring_active = False
        self._snapshot_active = False
        self._transition_active = False
        self._standings_jobs = frozenset()
        self._standings_token_mode = "missing"
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
                        request.method,
                        (
                            request.full_path.removesuffix("?")
                            if self.characterization_scope
                            in {
                                "NC-01C",
                                "NC-02A2",
                                "NC-02B1",
                                "NC-02B2",
                                "NC-02B3",
                                "NC-02C1",
                                "NC-02C2",
                                "NC-02C3",
                                "NC-02D1",
                                "NC-02D2",
                                "NC-02F1",
                            }
                            else request.path
                        ),
                        identity_bootstrap=True,
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
        if getattr(self, "characterization_scope", None) == "NC-02F1":
            lids = getattr(self, "_leagues", set()) | {
                identity("missing-league"),
                "invalid",
            }
            if method == "GET" and path in {"/leagues", "/leagues/me", "/health"}:
                return
            if method == "POST" and (
                path == "/leagues"
                or path
                in {
                    f"/leagues/{lid}/{suffix}"
                    for lid in lids
                    for suffix in ("join", "ownership")
                }
            ):
                return
            if method == "PATCH" and path in {f"/leagues/{lid}" for lid in lids}:
                return
            if method == "DELETE" and (
                path
                in {
                    f"/leagues/{lid}{suffix}"
                    for lid in lids
                    for suffix in ("", "/membership")
                }
                or path
                in {
                    f"/leagues/{lid}/members/{uid}"
                    for lid in lids
                    for uid in self._auth_subjects | {identity("missing-user")}
                }
            ):
                return
        if (
            getattr(self, "characterization_scope", None) == "NC-02D2"
            and method == "POST"
            and path == "/admin/leaderboard/snapshot"
        ):
            return
        if (
            getattr(self, "characterization_scope", None)
            in {"NC-02D1", "NC-02D2", "NC-02F1"}
            and method == "POST"
            and (
                path == "/admin/score/recompute"
                or path
                in {
                    "/admin/score/master/" + bid + "/recompute"
                    for bid in self._brackets
                }
            )
        ):
            return
        if getattr(self, "characterization_scope", None) in {
            "NC-02C3",
            "NC-02D2",
            "NC-02F1",
        }:
            if method == "POST" and path in {
                "/admin/season/rollover",
                "/admin/standings/refresh",
                "/internal/standings/refresh",
            }:
                return
            if method == "GET" and path in {
                "/admin/env-check",
                "/leaderboard/history/2025-26",
            }:
                return

        if (
            getattr(self, "characterization_scope", None) == "NC-02C2"
            and method == "POST"
            and path
            in {
                "/admin/standings/refresh",
                "/internal/standings/refresh",
                "/internal/standings/overwrite",
                "/admin/insert_test_teams",
            }
        ):
            return
        if getattr(self, "characterization_scope", None) in {
            "NC-02A2",
            "NC-02B1",
            "NC-02B2",
            "NC-02B3",
            "NC-02C1",
            "NC-02C2",
            "NC-02C3",
            "NC-02D1",
            "NC-02D2",
            "NC-02F1",
        }:
            lids = getattr(self, "_leagues", set())
            reads = {
                "/season",
                "/leaderboard",
                "/brackets",
                "/brackets/me",
                "/stats/champion-picks",
                "/leaderboard/history",
                "/leaderboard/history/2024-25",
            }
            reads |= {f"/leagues/{lid}/members" for lid in lids}
            reads |= {
                f"/{route}?league_id={lid}"
                for route in ("brackets", "leaderboard", "stats/champion-picks")
                for lid in lids
            }
            reads |= {"/bracket/" + bid for bid in self._brackets}
            if self.characterization_scope in {"NC-02B3", "NC-02D2", "NC-02F1"}:
                # E reuses the D2 lease for post-rollover B15 read-only proof.
                reads |= {"/history/bracket/" + bid for bid in self._brackets}
            if self.characterization_scope == "NC-02B3":
                if method == "DELETE" and path in {
                    "/bracket/" + bid for bid in self._brackets
                }:
                    return
            if method == "GET" and (
                path in reads or path == "/__test__/identity" and identity_bootstrap
            ):
                return
            if method == "POST" and path == "/auth/login":
                return
            if (
                self.characterization_scope
                in {
                    "NC-02B1",
                    "NC-02B2",
                    "NC-02B3",
                    "NC-02C1",
                    "NC-02C2",
                    "NC-02C3",
                    "NC-02D1",
                    "NC-02D2",
                    "NC-02F1",
                }
                and method == "POST"
                and path == "/bracket/create"
            ):
                return
            edits = {f"/bracket/{bid}/save" for bid in self._brackets}
            edits |= {f"/bracket/{bid}/match/{mid}" for bid, mid in self._matches}
            edits |= {f"/bracket/match/{mid}/games" for _, mid in self._matches}
            if method == "PATCH" and path in edits:
                return
            raise safety.SafetyError("Outside NC-02A2 competition acceptance scope.")
        if getattr(self, "characterization_scope", None) == "NC-01E":
            if method == "GET" and path in {
                "/health",
                "/admin/env-check",
                "/brackets/me",
            }:
                return
            if method == "GET" and path == "/__test__/identity" and identity_bootstrap:
                return
            if method == "POST" and path in {
                "/auth/login",
                "/admin/standings/refresh",
                "/internal/standings/refresh",
                "/internal/standings/overwrite",
                "/admin/insert_test_teams",
                "/admin/season/rollover",
                "/admin/leaderboard/snapshot",
            }:
                return  # Job guard unchanged; permitted requests characterize refusals only.
            raise safety.SafetyError("Outside NC-01E scope.")
        if getattr(self, "characterization_scope", None) == "NC-01D":
            if method == "GET" and path in {
                "/leaderboard",
                "/leaderboard?malformed=synthetic",
                "/leaderboard/history",
                "/leaderboard/history/2024-25",
                "/leaderboard/history/2025-26",
                "/leaderboard/history/invalid",
            }:
                return
            if method == "GET" and path == "/__test__/identity" and identity_bootstrap:
                return
            if method == "POST" and path == "/auth/login":
                return
            if method == "POST" and (
                path == "/admin/leaderboard/snapshot"
                or path
                in {f"/admin/score/master/{bid}/recompute" for bid in self._brackets}
            ):
                return  # Existing job guard is deliberately retained and must refuse writes.
            raise safety.SafetyError("Outside NC-01D route scope.")
        if getattr(self, "characterization_scope", None) == "NC-01C":
            lids = getattr(self, "_leagues", set()) | {
                identity("missing-league"),
                "invalid",
            }
            reads = {"/leagues", "/leagues/me", "/leaderboard", "/brackets/me"}
            reads |= {f"/leagues/{lid}/members" for lid in lids}
            reads |= {
                f"/{route}?league_id={lid}"
                for route in ("brackets", "stats/champion-picks", "leaderboard")
                for lid in lids
            }
            reads |= {
                f"/stats/champion-picks?league_id={lid}&season_code=2024-25"
                for lid in lids
            }
            reads |= {"/bracket/" + bid for bid in self._brackets}
            if method == "GET" and (
                path in reads or path == "/__test__/identity" and identity_bootstrap
            ):
                return
            if method == "POST" and (
                path in {"/auth/login", "/leagues"}
                or path in {f"/leagues/{lid}/join" for lid in lids}
            ):
                return
            if method == "DELETE" and path in {
                f"/leagues/{lid}{suffix}"
                for lid in lids
                for suffix in ("", "/membership")
            }:
                return
            raise safety.SafetyError("Outside NC-01C route scope.")
        if not isinstance(path, str) or "?" in path or "%" in path or "\\" in path:
            raise safety.SafetyError("Unexpected guarded HTTP path.")
        if getattr(self, "characterization_scope", None) == "NC-01B":
            if (method, path) in {
                ("POST", "/auth/login"),
                ("POST", "/bracket/create"),
                ("GET", "/brackets/me"),
                ("GET", "/brackets"),
                ("GET", "/auth/test-me"),
                ("GET", "/health"),
                ("GET", "/leaderboard/history"),
                ("GET", "/leaderboard/history/2024-25"),
            } or (
                method == "GET" and path == "/__test__/identity" and identity_bootstrap
            ):
                return
            bids = self._brackets | {identity("missing-bracket"), "invalid"}
            mids = {mid for _, mid in self._matches} | {
                identity("missing-match"),
                "invalid",
            }
            if (
                method in {"GET", "DELETE"}
                and path in {f"/bracket/{b}" for b in bids}
                or method == "PATCH"
                and path in {f"/bracket/{b}/save" for b in bids}
                or method == "PATCH"
                and path in {f"/bracket/{b}/match/{m}" for b in bids for m in mids}
                or method == "PATCH"
                and path in {f"/bracket/match/{m}/games" for m in mids}
            ):
                return
            raise safety.SafetyError("Outside NC-01B route scope.")
        if getattr(self, "characterization_scope", None) == "NC-01A":
            if method == "POST" and path in {
                "/auth/register",
                "/auth/login",
                "/auth/forgot-password",
                "/auth/reset-password",
                "/test-email",
            }:
                return
            if method == "GET" and (
                path in {"/admin/env-check", "/auth/test-me", "/health"}
                or path == "/__test__/identity"
                and identity_bootstrap
                or path in {"/bracket/" + bid for bid in self._brackets}
            ):
                return
            raise safety.SafetyError("Outside NC-01A route scope.")
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
        if self.characterization_scope in {
            "NC-02C2",
            "NC-02C3",
            "NC-02D1",
            "NC-02D2",
            "NC-02F1",
        } and path in {
            "/internal/standings/refresh",
            "/internal/standings/overwrite",
        }:
            if self._standings_token_mode == "valid":
                headers["X-Cron-Token"] = self.module.STANDINGS_CRON_TOKEN
            elif self._standings_token_mode == "invalid":
                headers["X-Cron-Token"] = "invalid-synthetic-only"
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

    def _require_bracket_scope(self):
        self._require_lease()
        if (
            not self._ready
            or self.characterization_scope
            not in {
                "NC-01B",
                "NC-01C",
                "NC-02A2",
                "NC-02B1",
                "NC-02B2",
                "NC-02B3",
                "NC-02C1",
                "NC-02C2",
                "NC-02C3",
                "NC-02D1",
                "NC-02D2",
                "NC-02F1",
            }
            or threading.get_ident() != self._owner
        ):
            raise safety.SafetyError("Explicit verified NC-01B context required.")

    def bracket_request(self, method, path, *, payload=None, role=None):
        self._require_bracket_scope()
        if path == "/auth/login":
            raise safety.SafetyError("Use synthetic login method.")
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
        if method == "POST" and path == "/bracket/create" and status == 200:
            self._brackets.add(body["bracket"]["id"])
            self.bracket_snapshot()
        return status, body

    def standings_request(self, kind, *, role=None, token="valid", payload=None):
        self._require_bracket_scope()
        if (
            self.characterization_scope
            not in {"NC-02C2", "NC-02C3", "NC-02D1", "NC-02D2", "NC-02F1"}
            or kind not in {"scheduled", "admin", "cron", "overwrite", "seed"}
            or token not in {"valid", "invalid", "missing"}
        ):
            raise safety.SafetyError("Fixed C2 standings request required")
        if self.characterization_scope in {
            "NC-02C3",
            "NC-02D2",
            "NC-02F1",
        } and kind not in {
            "scheduled",
            "admin",
            "cron",
        }:
            raise safety.SafetyError("C3 admits refresh only")
        if kind == "seed" and payload != {"seed_standings": True}:
            raise safety.SafetyError("Only fixed seed-refusal proof is admitted")
        jobs = (
            {"standings-refresh"}
            if kind in {"admin", "cron", "scheduled"}
            else {"standings-overwrite"} if kind == "overwrite" else {"team-insert"}
        )
        if kind == "scheduled":
            jobs.add("standings-script")
        self._standings_jobs = frozenset(jobs)
        self._standings_token_mode = token
        if not self.module.STANDINGS_CRON_TOKEN:
            self.module.STANDINGS_CRON_TOKEN = secrets.token_urlsafe(32)
        try:
            if kind == "scheduled":
                import ast
                from pathlib import Path

                source = Path(__file__).parent / "scripts/update_standings.py"
                node = next(
                    n
                    for n in ast.parse(source.read_text(encoding="utf-8")).body
                    if isinstance(n, ast.FunctionDef)
                    and n.name == "update_standings_from_json"
                )
                import standings_service

                ns = {
                    "supabase": self.module.supabase,
                    "guard_runtime_job": __import__("job_safety").guard_runtime_job,
                    "refresh_current_standings": standings_service.refresh_current_standings,
                    "StandingsRefreshError": standings_service.StandingsRefreshError,
                    "log_result": standings_service.log_result,
                }
                exec(
                    compile(
                        ast.Module(body=[node], type_ignores=[]), str(source), "exec"
                    ),
                    ns,
                )
                return 200, ns["update_standings_from_json"]()
            route = {
                "admin": "/admin/standings/refresh",
                "cron": "/internal/standings/refresh",
                "overwrite": "/internal/standings/overwrite",
                "seed": "/admin/insert_test_teams",
            }[kind]
            return self._exchange("POST", route, payload or {}, role)
        finally:
            self._standings_jobs = frozenset()
            self._standings_token_mode = "missing"

    def recompute_request(self, *, master_id=None, role="admin"):
        self._require_bracket_scope()
        if self.characterization_scope not in {"NC-02D1", "NC-02D2", "NC-02F1"} or (
            master_id is not None and master_id not in self._brackets
        ):
            raise safety.SafetyError("Registered D1 scoring request required")
        self._scoring_active = True
        try:
            path = (
                "/admin/score/recompute"
                if master_id is None
                else "/admin/score/master/" + master_id + "/recompute"
            )
            return self._exchange("POST", path, {}, role)
        finally:
            self._scoring_active = False

    def snapshot_request(self, *, role="admin"):
        self._require_bracket_scope()
        if self.characterization_scope != "NC-02D2":
            raise safety.SafetyError("Registered D2 snapshot context required")
        self._snapshot_active = True
        try:
            return self._exchange("POST", "/admin/leaderboard/snapshot", {}, role)
        finally:
            self._snapshot_active = False

    def prepare_transition_competition(self):
        """Fixed C3 prerequisite graph; align the explicit synthetic history IDs."""
        self._require_bracket_scope()
        if self.characterization_scope not in {"NC-02C3", "NC-02D2", "NC-02F1"}:
            raise safety.SafetyError("Fixed C3 prerequisite context required")
        ids = self.install_competitive_scenario()
        # The existing scenario inserts history IDs 1/2 explicitly; nextval must
        # start after them for a real snapshot, without changing canonical seed.
        proof = self.lease._exchange(
            b"DO $$ BEGIN PERFORM setval('public.leaderboard_history_id_seq',(SELECT max(id) FROM public.leaderboard_history),true); END $$; SELECT jsonb_build_object('history_sequence_aligned',true);\n"
        )
        if proof != {"history_sequence_aligned": True}:
            raise safety.SafetyError("Synthetic history sequence setup failed")
        return ids

    def transition_request(self, *, payload, role="admin"):
        """Only the fixed next synthetic target through the real authorized route."""
        self._require_bracket_scope()
        if (
            self.characterization_scope not in {"NC-02C3", "NC-02D2", "NC-02F1"}
            or not isinstance(payload, dict)
            or payload.get("new_season_code") != "2026-27"
            or set(payload)
            - {"new_season_code", "regular_season_end_utc", "playoffs_start_utc"}
        ):
            raise safety.SafetyError("Fixed C3 transition request required")
        self._transition_active = True
        try:
            return self._exchange("POST", "/admin/season/rollover", payload, role)
        finally:
            self._transition_active = False

    def canonical_fixture_season(self, mode):
        self._require_bracket_scope()
        if self.characterization_scope != "NC-02C1" or mode not in {
            "current",
            "historical",
            "missing",
        }:
            raise safety.SafetyError(
                "Fixed NC-02C1 canonical fixture scenario required"
            )
        table = self.module.supabase.table("application_season")
        if mode == "missing":
            table.delete().eq("singleton", True).execute()
        else:
            table.upsert({"singleton": True, "season_id": identity(mode)}).execute()

    def bracket_timing(self, mode):
        self._require_bracket_scope()
        from datetime import datetime, timezone, timedelta

        if mode not in {"early", "open", "locked", "boundary"}:
            raise safety.SafetyError("Unreviewed local season-date scenario.")
        now = datetime.now(timezone.utc)
        end = now + timedelta(days=2 if mode == "early" else -2)
        start = now + timedelta(days=-1 if mode in {"locked", "boundary"} else 2)
        self.module.supabase.table("seasons").update(
            {
                "regular_season_end_utc": end.isoformat(),
                "playoffs_start_utc": start.isoformat(),
            }
        ).eq("id", identity("current")).execute()
        self.module._resolve_season_globals()
        return {
            "locked": self.module.playoffs_locked(),
            "creation_open": self.module.bracket_creation_open(),
        }

    def bracket_deadline_boundary(self, relative):
        """Lease-scoped deterministic clock around the existing configured deadline."""
        self._require_bracket_scope()
        from datetime import timedelta

        if self.characterization_scope not in {
            "NC-02B1",
            "NC-02B2",
            "NC-02B3",
            "NC-02C1",
            "NC-02C2",
            "NC-02C3",
            "NC-02D1",
            "NC-02D2",
            "NC-02F1",
        } or relative not in {
            "before",
            "at",
            "after",
        }:
            raise safety.SafetyError("Unreviewed deadline boundary context.")
        instant = self.module.current_season().playoff_lock_at + timedelta(
            microseconds={"before": -1, "at": 0, "after": 1}[relative]
        )
        self.stack.enter_context(patch.object(self.module, "now_utc", lambda: instant))
        return {
            "locked": self.module.playoffs_locked(),
            "creation_open": self.module.bracket_creation_open(),
        }

    def install_lifecycle_history(self, kind):
        self._require_bracket_scope()
        if self.characterization_scope != "NC-02B3" or kind not in {
            "submitted",
            "draft",
            "master",
        }:
            raise safety.SafetyError("Fixed NC-02B3 historical fixture required.")
        bid = self.install_bracket_scenario(
            "historical", role="admin" if kind == "master" else "user-a"
        )
        if kind == "draft":
            self.module.supabase.table("brackets").update(
                {"is_done": False, "saved_at": None}
            ).eq("id", bid).execute()
        elif kind == "master":
            self.module.supabase.table("brackets").update({"is_master": True}).eq(
                "id", bid
            ).execute()
            self.module.supabase.table("seasons").update({"master_bracket_id": bid}).eq(
                "id", identity("historical")
            ).execute()
        return bid

    def master_failure_rollback_proof(self):
        self._require_bracket_scope()
        if self.characterization_scope != "NC-02B3":
            raise safety.SafetyError("Explicit NC-02B3 scope required.")
        before = self.bracket_snapshot()
        from synthetic_fixtures import bracket_scenario

        rows = bracket_scenario("draft")["matches"]
        # Deliberately fail only after the transaction has retired the old master.
        for row in rows:
            row["id"] = identity("b3-rollback-" + row["id"])
        for row in rows:
            if row["next_match_id"]:
                row["next_match_id"] = identity("b3-rollback-" + row["next_match_id"])
        rows[0]["team_a"] = "INVALID_SYNTHETIC_TEAM"
        try:
            self.module.supabase.rpc(
                "create_master_bracket_atomic",
                {
                    "p_user_id": identity("admin"),
                    "p_season_id": identity("current"),
                    "p_replace": True,
                    "p_matches": rows,
                },
            ).execute()
        except Exception as error:
            if getattr(error, "code", None) != "23503":
                raise safety.SafetyError(
                    "Unexpected synthetic rollback result."
                ) from None
        else:
            raise safety.SafetyError("Synthetic invalid graph was accepted.")
        if self.bracket_snapshot() != before:
            raise safety.SafetyError(
                "Master replacement rollback did not preserve state."
            )
        return True

    @contextlib.contextmanager
    def bracket_validity_fault(self, kind):
        """Fixed synthetic Finals faults only, restored before leaving this context."""
        self._require_bracket_scope()
        if self.characterization_scope != "NC-02B2":
            raise safety.SafetyError("Explicit verified NC-02B2 scope required.")
        faults = {
            "missing_winner",
            "missing_count",
            "count_3",
            "count_8",
            "count_negative",
            "count_zero",
            "one_sided",
            "wrong_winner",
            "stale_participant",
        }
        if kind not in faults:
            raise safety.SafetyError("Unreviewed bracket validity fault.")
        snapshot = self.bracket_snapshot()
        bid = identity("bracket-draft")
        candidates = [
            m for m in snapshot["matches"] if m["bracket_id"] == bid and m["round"] == 4
        ]
        if len(candidates) != 1:
            raise safety.SafetyError("Fixed synthetic draft required.")
        row = candidates[0]
        other = next(
            m["team_a"]
            for m in snapshot["matches"]
            if m.get("team_a") and m["team_a"] not in (row["team_a"], row["team_b"])
        )
        changes = {
            "missing_winner": {"predicted_winner": None},
            "missing_count": {"predicted_winner_games": None},
            "count_3": {"predicted_winner_games": 3},
            "count_8": {"predicted_winner_games": 8},
            "count_negative": {"predicted_winner_games": -1},
            "count_zero": {"predicted_winner_games": 0},
            "one_sided": {"team_a": None},
            "wrong_winner": {"predicted_winner": other},
            "stale_participant": {"team_a": other},
        }[kind]
        try:
            self.module.supabase.table("matches").update(changes).eq(
                "id", row["id"]
            ).execute()
            yield
        finally:
            self.module.supabase.table("matches").update(
                {key: row[key] for key in changes}
            ).eq("id", row["id"]).execute()

    def install_bracket_scenario(self, kind, *, role="user-a"):
        self._require_bracket_scope()
        from synthetic_fixtures import bracket_scenario

        if kind not in {
            "draft",
            "saved",
            "master",
            "deleted",
            "historical",
        } or role not in (
            {"user-a", "user-b", "admin", "owner"}
            if self.characterization_scope
            in {
                "NC-01C",
                "NC-02A2",
                "NC-02B1",
                "NC-02B2",
                "NC-02B3",
                "NC-02C1",
                "NC-02C2",
                "NC-02C3",
                "NC-02D1",
                "NC-02D2",
                "NC-02F1",
            }
            else {"user-a", "user-b", "admin"}
        ):
            raise safety.SafetyError("Unreviewed synthetic bracket scenario.")
        data = bracket_scenario(kind)
        row = data["brackets"][0]
        row["user_id"] = identity(role)
        if row["id"] in self._brackets:
            raise safety.SafetyError("Synthetic bracket already installed.")
        self.module.supabase.table("brackets").insert(row).execute()
        self._brackets.add(row["id"])
        matches = data["matches"]
        self.module.supabase.table("matches").insert(
            [dict(m, next_match_id=None, next_slot=None) for m in matches]
        ).execute()
        for m in matches:
            if m["next_match_id"]:
                self.module.supabase.table("matches").update(
                    {"next_match_id": m["next_match_id"], "next_slot": m["next_slot"]}
                ).eq("id", m["id"]).execute()
            self._matches.add((row["id"], m["id"]))
        if kind == "master":
            self.module.supabase.table("seasons").update(
                {"master_bracket_id": row["id"]}
            ).eq("id", row["season_id"]).execute()
        return row["id"]

    def bracket_snapshot(self):
        self._require_bracket_scope()
        brackets = (
            self.module.supabase.table("brackets").select("*").execute().data or []
        )
        if any(r["user_id"] not in self._auth_subjects for r in brackets):
            raise safety.SafetyError("Unexpected bracket subject.")
        matches = self.module.supabase.table("matches").select("*").execute().data or []
        for r in brackets:
            self._brackets.add(r["id"])
        if any(m["bracket_id"] not in self._brackets for m in matches):
            raise safety.SafetyError("Unexpected match subject.")
        self._matches.update((m["bracket_id"], m["id"]) for m in matches)
        seasons = (
            self.module.supabase.table("seasons")
            .select("id,master_bracket_id")
            .execute()
            .data
        )
        return {"brackets": brackets, "matches": matches, "seasons": seasons}

    def _require_league_scope(self):
        self._require_lease()
        if (
            not self._ready
            or self.characterization_scope
            not in {
                "NC-01C",
                "NC-02A2",
                "NC-02B1",
                "NC-02B2",
                "NC-02B3",
                "NC-02C1",
                "NC-02C2",
                "NC-02C3",
                "NC-02D1",
                "NC-02D2",
                "NC-02F1",
            }
            or threading.get_ident() != self._owner
        ):
            raise safety.SafetyError("Explicit verified NC-01C context required.")

    def league_request(self, method, path, *, payload=None, role=None):
        self._require_league_scope()
        if path == "/auth/login":
            raise safety.SafetyError("Use synthetic login method.")
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
        if method == "POST" and path == "/leagues" and status == 201:
            self._leagues = getattr(self, "_leagues", set()) | {body["league"]["id"]}
        return status, body

    def install_league_scenario(self, *, empty=False, global_public=False):
        self._require_league_scope()
        if (
            type(empty) is not bool
            or type(global_public) is not bool
            or getattr(self, "_leagues", set())
        ):
            raise safety.SafetyError("Single reviewed league fixture only.")
        from synthetic_fixtures import league_scenario

        data = league_scenario()
        if global_public:
            data["leagues"][0]["is_global"] = True
        # F1 owner membership must exist at commit; "empty" means owner-only.
        if empty:
            data["league_members"] = [
                m for m in data["league_members"] if m["user_id"] == identity("owner")
            ]
        sql = "BEGIN;\n"
        for table in ("leagues", "league_members"):
            columns = ",".join('"' + c + '"' for c in data[table][0])
            payload = json.dumps(data[table]).replace("'", "''")
            sql += f"INSERT INTO public.{table}({columns}) SELECT {columns} FROM jsonb_populate_recordset(NULL::public.{table},'{payload}'::jsonb);\n"
        result = self.lease._exchange(
            (sql + "COMMIT; SELECT '{\"installed\":true}'::jsonb;\n").encode()
        )
        if result != {"installed": True}:
            raise safety.SafetyError("Atomic synthetic league installation failed")
        self._leagues = {r["id"] for r in data["leagues"]}
        return {kind: identity("league-" + kind) for kind in ("public", "private")}

    def league_snapshot(self):
        self._require_league_scope()
        leagues = self.module.supabase.table("leagues").select("*").execute().data or []
        members = (
            self.module.supabase.table("league_members").select("*").execute().data
            or []
        )
        allowed = getattr(self, "_leagues", set())
        if any(
            l["id"] not in allowed or l["owner_user_id"] not in self._auth_subjects
            for l in leagues
        ) or any(
            m["league_id"] not in allowed or m["user_id"] not in self._auth_subjects
            for m in members
        ):
            raise safety.SafetyError("Unexpected league subjects.")
        return {
            "leagues": leagues,
            "members": members,
        }  # In-memory only: never serialize hashes.

    def install_league_score_surface(self, *, draft_member=False):
        self._require_league_scope()
        if type(draft_member) is not bool or self._brackets:
            raise safety.SafetyError("Single reviewed score-display fixture only.")
        from synthetic_fixtures import score_history_scenario

        data = score_history_scenario()
        if draft_member:
            for row in data["brackets"]:
                if row["id"] == identity("score-user-a"):
                    row.update(is_done=False, saved_at=None)
        self.module.supabase.table("brackets").insert(data["brackets"]).execute()
        matches = data["matches"]
        self.module.supabase.table("matches").insert(
            [dict(m, next_match_id=None, next_slot=None) for m in matches]
        ).execute()
        for m in matches:
            if m["next_match_id"]:
                self.module.supabase.table("matches").update(
                    {"next_match_id": m["next_match_id"], "next_slot": m["next_slot"]}
                ).eq("id", m["id"]).execute()
        self.module.supabase.table("bracket_scores").insert(
            data["bracket_scores"]
        ).execute()
        self.module.supabase.table("seasons").update(
            {"master_bracket_id": identity("bracket-master")}
        ).eq("id", identity("current")).execute()
        self._brackets.update(b["id"] for b in data["brackets"])
        self._matches.update((m["bracket_id"], m["id"]) for m in matches)
        return {role: identity("score-" + role) for role in ("user-a", "user-b")}

    def install_competitive_scenario(self):
        """Fixed NC-02A2 graph + stored scores/history; existing lease/reset gates apply."""
        self._require_league_scope()
        if (
            self.characterization_scope
            not in {
                "NC-02A2",
                "NC-02B1",
                "NC-02B2",
                "NC-02B3",
                "NC-02C1",
                "NC-02C2",
                "NC-02C3",
                "NC-02D1",
                "NC-02D2",
                "NC-02F1",
            }
            or self._brackets
        ):
            raise safety.SafetyError("Fresh verified NC-02A2 context required.")
        from synthetic_fixtures import (
            score_history_scenario,
            bracket_scenario,
            match_row,
        )

        data = score_history_scenario()
        bid = identity("score-user-a")
        for row in data["brackets"]:
            if row["id"] == bid:
                row.update(is_done=False, saved_at=None)
        graph = bracket_scenario("draft")["matches"]
        mapping = {m["id"]: identity("nc02a2-" + m["id"]) for m in graph}
        for m in graph:
            m.update(
                id=mapping[m["id"]],
                bracket_id=bid,
                next_match_id=mapping.get(m["next_match_id"]),
            )
        data["matches"].extend(graph)
        other = match_row(
            identity("score-user-b"), identity("current"), "nba", 4, 11, "BOS", "LAL"
        )
        other.update(predicted_winner="LAL", predicted_winner_games=4)
        data["matches"].append(other)
        data["bracket_scores"][0]["points_by_match"] = {
            "east-1-6": {
                "points": 3,
                "status": "full",
                "conference": "east",
                "round": 1,
                "slot": 6,
            }
        }
        self.module.supabase.table("brackets").insert(data["brackets"]).execute()
        self.module.supabase.table("matches").insert(
            [dict(m, next_match_id=None, next_slot=None) for m in data["matches"]]
        ).execute()
        for m in data["matches"]:
            if m["next_match_id"]:
                self.module.supabase.table("matches").update(
                    {"next_match_id": m["next_match_id"], "next_slot": m["next_slot"]}
                ).eq("id", m["id"]).execute()
        for table in (
            "bracket_scores",
            "leaderboard_history_snapshots",
            "leaderboard_history_rows",
            "leaderboard_history",
        ):
            self.module.supabase.table(table).insert(data[table]).execute()
        self.module.supabase.table("seasons").update(
            {"master_bracket_id": identity("bracket-master")}
        ).eq("id", identity("current")).execute()
        self._brackets.update(b["id"] for b in data["brackets"])
        self._matches.update((m["bracket_id"], m["id"]) for m in data["matches"])
        return {
            "a": bid,
            "b": identity("score-user-b"),
            "master": identity("bracket-master"),
        }

    def competitive_snapshot(self):
        self._require_league_scope()
        if self.characterization_scope not in {
            "NC-02A2",
            "NC-02B1",
            "NC-02B2",
            "NC-02B3",
            "NC-02C1",
            "NC-02C2",
            "NC-02C3",
            "NC-02D1",
            "NC-02D2",
            "NC-02F1",
        }:
            raise safety.SafetyError("Verified NC-02A2 context required.")
        result = self.bracket_snapshot()
        for table in (
            "bracket_scores",
            "leaderboard_history_snapshots",
            "leaderboard_history_rows",
            "leaderboard_history",
        ):
            result[table] = (
                self.module.supabase.table(table).select("*").execute().data or []
            )
        if any(r["bracket_id"] not in self._brackets for r in result["bracket_scores"]):
            raise safety.SafetyError("Unexpected score subject.")
        return result

    def _require_scoring_scope(self):
        self._require_lease()
        if (
            not self._ready
            or self.characterization_scope != "NC-01D"
            or threading.get_ident() != self._owner
        ):
            raise safety.SafetyError("Explicit verified NC-01D context required.")

    def scoring_request(self, method, path, *, role=None):
        self._require_scoring_scope()
        if path == "/auth/login":
            raise safety.SafetyError("Use synthetic login method.")
        status, body = self._exchange(
            method, path, {} if method == "POST" else None, role
        )
        self.summary.append(
            {
                "method": method,
                "path": re.sub(r"[0-9a-f]{8}-[0-9a-f-]{27}", "<id>", path),
                "status": status,
                "shape": sorted(body) if isinstance(body, dict) else "list",
            }
        )
        return status, body

    def install_scoring_read_state(self, mode="saved"):
        self._require_scoring_scope()
        if self._brackets or mode not in {
            "saved",
            "draft",
            "deleted",
            "tie",
            "unequal_hits",
        }:
            raise safety.SafetyError("Single reviewed scoring read-state only.")
        from synthetic_fixtures import score_history_scenario

        data = score_history_scenario()
        for row in data["brackets"]:
            if row["id"] == identity("score-user-a"):
                if mode == "draft":
                    row.update(is_done=False, saved_at=None)
                if mode == "deleted":
                    row["deleted_at"] = "2026-01-01T00:00:00+00:00"
                if mode in {"tie", "unequal_hits"}:
                    row["saved_at"] = "2026-01-02T00:00:00+00:00"
            if row["id"] == identity("score-user-b") and mode in {
                "tie",
                "unequal_hits",
            }:
                row["saved_at"] = "2026-01-01T00:00:00+00:00"
        if mode == "unequal_hits":
            data["bracket_scores"][0]["full_hits"] = 2
        self.module.supabase.table("brackets").insert(data["brackets"]).execute()
        self.module.supabase.table("bracket_scores").insert(
            data["bracket_scores"]
        ).execute()
        for table in (
            "leaderboard_history_snapshots",
            "leaderboard_history_rows",
            "leaderboard_history",
        ):
            self.module.supabase.table(table).insert(data[table]).execute()
        self.module.supabase.table("seasons").update(
            {"master_bracket_id": identity("bracket-master")}
        ).eq("id", identity("current")).execute()
        self._brackets.update(b["id"] for b in data["brackets"])
        return {
            "master": identity("bracket-master"),
            "a": identity("score-user-a"),
            "b": identity("score-user-b"),
        }

    def operational_request(self, method, path, *, role=None):
        self._require_lease()
        if (
            not self._ready
            or self.characterization_scope != "NC-01E"
            or threading.get_ident() != self._owner
        ):
            raise safety.SafetyError("Explicit verified NC-01E context required.")
        if path == "/auth/login":
            raise safety.SafetyError("Use synthetic login method.")
        status, body = self._exchange(
            method, path, {} if method == "POST" else None, role
        )
        self.summary.append(
            {
                "method": method,
                "path": path,
                "status": status,
                "shape": sorted(body) if isinstance(body, dict) else "text",
            }
        )
        return status, body

    def _require_auth_scope(self):
        self._require_lease()
        if (
            not self._ready
            or self.characterization_scope != "NC-01A"
            or threading.get_ident() != self._owner
        ):
            raise safety.SafetyError("Explicit verified NC-01A context required.")

    def auth_request(self, method, path, *, payload=None, role=None):
        self._require_auth_scope()
        allowed = {
            ("POST", "/auth/register"),
            ("POST", "/auth/login"),
            ("POST", "/auth/forgot-password"),
            ("POST", "/auth/reset-password"),
            ("POST", "/test-email"),
            ("GET", "/auth/test-me"),
            ("GET", "/admin/env-check"),
            ("GET", "/health"),
        }
        if method == "GET" and path in {"/bracket/" + bid for bid in self._brackets}:
            allowed.add((method, path))
        if (method, path) not in allowed:
            raise safety.SafetyError("Outside auth characterization scope.")
        if isinstance(payload, dict):
            for key in ("email", "to"):
                value = payload.get(key)
                if (
                    isinstance(value, str)
                    and "@" in value
                    and not value.strip().lower().endswith(".example")
                ):
                    raise safety.SafetyError("Only reserved synthetic auth addresses.")
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
        if path == "/auth/register" and status == 201:
            self._auth_subjects.add(body["user"]["id"])
        return status, body

    def auth_token_variant(self, variant):
        self._require_auth_scope()
        if variant == "malformed":
            self._tokens[variant] = "invalid.synthetic.token"
        elif variant in {"expired-user-a", "signed-user-a-admin-claim"}:
            import jwt
            from datetime import datetime, timezone, timedelta

            payload = {
                "user_id": identity("user-a"),
                "username": "fixture-user-a",
                "is_admin": variant == "signed-user-a-admin-claim",
                "exp": datetime.now(timezone.utc)
                + timedelta(seconds=-60 if variant == "expired-user-a" else 60),
            }
            self._tokens[variant] = jwt.encode(
                payload, self.module.JWT_SECRET, algorithm=self.module.JWT_ALGORITHM
            )
        else:
            raise safety.SafetyError("Unreviewed synthetic token variant.")
        return variant

    def install_auth_boundary_bracket(self, *, saved):
        self._require_auth_scope()
        if type(saved) is not bool or self._brackets:
            raise safety.SafetyError("Single reviewed auth boundary fixture only.")
        from synthetic_fixtures import bracket_scenario

        row = bracket_scenario("saved" if saved else "draft")["brackets"][0]
        row["user_id"] = identity("user-b")
        # No match/progression setup: only owner and is_done access boundary.
        self.module.supabase.table("brackets").insert(row).execute()
        self._brackets.add(row["id"])
        return row["id"]

    def auth_reset_records(self):
        self._require_auth_scope()
        rows = (
            self.module.supabase.table("password_resets")
            .select("id,user_id,token,expires_at,used,created_at")
            .execute()
            .data
            or []
        )
        if any(row["user_id"] not in self._auth_subjects for row in rows):
            raise safety.SafetyError("Unexpected reset subject.")
        return rows  # Deliberate in-memory inspection only; never serialize in reports.

    def expire_auth_reset(self, token):
        self._require_auth_scope()
        if token not in {row["token"] for row in self.auth_reset_records()}:
            raise safety.SafetyError("Only existing synthetic reset may be expired.")
        self.module.supabase.table("password_resets").update(
            {"expires_at": "2000-01-01T00:00:00"}
        ).eq("token", token).execute()

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
        if not self._ready or role not in (
            {"user-a", "user-b", "admin", "owner"}
            if self.characterization_scope
            in {
                "NC-01C",
                "NC-02A2",
                "NC-02B1",
                "NC-02B2",
                "NC-02B3",
                "NC-02C1",
                "NC-02C2",
                "NC-02C3",
                "NC-02D1",
                "NC-02D2",
                "NC-02F1",
            }
            else {"user-a", "user-b", "admin"}
        ):
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


def authorize_standings_test_job(job):
    permit = _ACTIVE
    if (
        type(permit) is not GuardedHarness
        or permit.characterization_scope
        not in {"NC-02C2", "NC-02C3", "NC-02D1", "NC-02D2", "NC-02F1"}
        or not permit._ready
        or job not in permit._standings_jobs
    ):
        return False
    permit._require_lease()
    from flask import has_request_context, request

    if has_request_context():
        if job == "team-insert" and request.get_json(silent=True) != {
            "seed_standings": True
        }:
            return False
        return (
            request.method == "POST"
            and request.path
            in {
                "/admin/standings/refresh",
                "/internal/standings/refresh",
                "/internal/standings/overwrite",
                "/admin/insert_test_teams",
            }
            and hmac.compare_digest(
                request.headers.get("X-NBA-Test-Context", ""), permit._admission
            )
        )
    return (
        job in {"standings-refresh", "standings-script"}
        and threading.get_ident() == permit._owner
    )


def authorize_transition_test_job(job):
    permit = _ACTIVE
    if (
        type(permit) is not GuardedHarness
        or not permit._ready
        or permit.characterization_scope not in {"NC-02C3", "NC-02D2", "NC-02F1"}
        or job not in {"season-rollover", "leaderboard-snapshot", "score-recompute"}
    ):
        return False
    permit._require_lease()
    from flask import has_request_context, request

    if not has_request_context() or not hmac.compare_digest(
        request.headers.get("X-NBA-Test-Context", ""), permit._admission
    ):
        return False
    return request.method == "POST" and (
        (permit._transition_active and request.path == "/admin/season/rollover")
        or (
            permit.characterization_scope in {"NC-02D2", "NC-02F1"}
            and getattr(permit, "_snapshot_active", False)
            and job in {"leaderboard-snapshot", "score-recompute"}
            and request.path == "/admin/leaderboard/snapshot"
        )
    )


def authorize_scoring_test_job(job):
    permit = _ACTIVE
    if (
        type(permit) is not GuardedHarness
        or not permit._ready
        or job != "score-recompute"
    ):
        return False
    permit._require_lease()
    from flask import has_request_context, request

    if not has_request_context() or not hmac.compare_digest(
        request.headers.get("X-NBA-Test-Context", ""), permit._admission
    ):
        return False
    if (
        permit.characterization_scope in {"NC-02D1", "NC-02D2", "NC-02F1"}
        and permit._scoring_active
    ):
        return request.method == "POST" and (
            request.path == "/admin/score/recompute"
            or request.path
            in {"/admin/score/master/" + bid + "/recompute" for bid in permit._brackets}
        )
    # Existing registered mutation scenarios must exercise the new production auto path.
    # Admission does not permit manual maintenance, snapshots or any other job.
    if request.method == "POST" and request.path == "/bracket/create":
        return True
    if request.method != "PATCH":
        return False
    return request.path in (
        {f"/bracket/{bid}/match/{mid}" for bid, mid in permit._matches}
        | {f"/bracket/match/{mid}/games" for _, mid in permit._matches}
    )
