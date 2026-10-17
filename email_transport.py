"""Environment-specific email seam. Test content stays in deliberate memory capture."""

import os
from dataclasses import dataclass
from threading import Lock
from urllib.parse import urlencode, urlsplit, urlunsplit

from environment_safety import (
    SafetyError,
    load_test_config,
    load_enrollments,
    validate_test_target,
    validate_test_email_settings,
)


@dataclass(frozen=True, repr=False)
class CapturedEmail:
    sequence: int
    recipient: str
    subject: str
    body: str

    def __repr__(self):
        return f"<CapturedEmail sequence={self.sequence} contents=private>"

    @property
    def metadata(self):
        return {"transport": "capture", "sequence": self.sequence}


class CaptureMailbox:
    def __init__(self):
        self._messages = []
        self._lock = Lock()

    def send(self, recipient, subject, body):
        with self._lock:
            self._messages.append(
                CapturedEmail(len(self._messages) + 1, recipient, subject, body)
            )
        return True

    def inspect_messages(self):
        """Explicit sensitive-content inspection for tests; never serialize to logs."""
        with self._lock:
            return tuple(self._messages)

    def clear(self):
        with self._lock:
            self._messages.clear()


class BrevoTransport:
    def __init__(self, sender):
        self._sender = sender

    def send(self, recipient, subject, body):
        return self._sender(recipient, subject, body)


_TEST_MAILBOX = CaptureMailbox()


def test_mailbox():
    """Deliberate in-process inspection only; no HTTP mailbox endpoint or persistence."""
    return _TEST_MAILBOX


def select_email_transport(
    settings, production_sender, mailbox=None, enrollments=None, ambient=None
):
    identity = settings.get("NBA_CORNER_ENV")
    if identity in {None, "production"}:
        if settings.get("NBA_CORNER_TEST_CONFIG") is not None:
            raise SafetyError("Production email cannot use test configuration.")
        return BrevoTransport(production_sender)
    if identity != "test":
        raise SafetyError("Unrecognized email environment identity.")
    target = validate_test_target(
        settings,
        load_enrollments() if enrollments is None else enrollments,
        identity_only=True,
    )
    validate_test_email_settings(settings, target, ambient=ambient)
    if mailbox is not None and type(mailbox) is not CaptureMailbox:
        raise SafetyError("Test transport must be the in-process capture mailbox.")
    return _TEST_MAILBOX if mailbox is None else mailbox


def runtime_email_settings():
    identity = os.environ.get("NBA_CORNER_ENV")
    filename = os.environ.get("NBA_CORNER_TEST_CONFIG")
    if identity == "test" or filename is not None:
        if identity not in {None, "test"}:
            raise SafetyError("Production email cannot use test configuration.")
        return load_test_config(filename)
    if identity not in {None, "production"}:
        raise SafetyError("Unrecognized email environment identity.")
    return {
        "NBA_CORNER_ENV": identity,
        "FRONTEND_ORIGIN": os.environ.get("FRONTEND_ORIGIN"),
    }


def deliver_email(production_sender, recipient, subject, body):
    return select_email_transport(runtime_email_settings(), production_sender).send(
        recipient, subject, body
    )


def frontend_reset_origin(settings):
    """Validate the explicit public frontend origin; never infer it from API config."""
    value = settings.get("FRONTEND_ORIGIN")
    message = "Frontend reset origin is unavailable or invalid."
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or any(c.isspace() or ord(c) < 32 for c in value)
        or any(c in value for c in "\\\"'<>`")
    ):
        raise SafetyError(message)
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port
        if (
            parsed.scheme != "https"
            or not host
            or parsed.username is not None
            or parsed.password is not None
            or "%" in parsed.netloc
            or parsed.netloc.endswith(":")
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or "?" in value
            or "#" in value
            or port == 0
        ):
            raise ValueError()
        ascii_host = host.encode("idna").decode("ascii").rstrip(".")
        if ":" not in ascii_host and any(
            not label
            or label.startswith("-")
            or label.endswith("-")
            or not all(c.isascii() and (c.isalnum() or c == "-") for c in label)
            for label in ascii_host.split(".")
        ):
            raise ValueError()
        # This is an origin, not a configurable route or arbitrary URL template.
        return urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
    except (ValueError, UnicodeError):
        raise SafetyError(message) from None


def reset_link_for_settings(token, settings, enrollments=None, ambient=None):
    if settings.get("NBA_CORNER_ENV") in {None, "production"}:
        if settings.get("NBA_CORNER_TEST_CONFIG") is not None:
            raise SafetyError("Production reset link cannot use test configuration.")
        origin = frontend_reset_origin(settings)
    else:
        if settings.get("NBA_CORNER_ENV") != "test":
            raise SafetyError("Unrecognized reset-link environment identity.")
        target = validate_test_target(
            settings,
            load_enrollments() if enrollments is None else enrollments,
            identity_only=True,
        )
        # Preserve the independently enrolled capture-only origin and all gates.
        origin = validate_test_email_settings(settings, target, ambient=ambient)
    return urlunsplit(
        (*urlsplit(origin)[:2], "/reset-password", urlencode({"token": token}), "")
    )


def build_reset_link(token):
    return reset_link_for_settings(token, runtime_email_settings())
