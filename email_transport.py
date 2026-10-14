"""Environment-specific email seam. Test content stays in deliberate memory capture."""

import os
from dataclasses import dataclass
from threading import Lock
from urllib.parse import urlencode

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
    return {"NBA_CORNER_ENV": identity}


def deliver_email(production_sender, recipient, subject, body):
    return select_email_transport(runtime_email_settings(), production_sender).send(
        recipient, subject, body
    )


def reset_link_for_settings(token, settings, enrollments=None, ambient=None):
    if settings.get("NBA_CORNER_ENV") in {None, "production"}:
        if settings.get("NBA_CORNER_TEST_CONFIG") is not None:
            raise SafetyError("Production reset link cannot use test configuration.")
        # Preserve exact effective production URL/string construction.
        return f"https://nbacorner.onrender.com/reset-password?token={token}"
    if settings.get("NBA_CORNER_ENV") != "test":
        raise SafetyError("Unrecognized reset-link environment identity.")
    target = validate_test_target(
        settings,
        load_enrollments() if enrollments is None else enrollments,
        identity_only=True,
    )
    origin = validate_test_email_settings(settings, target, ambient=ambient)
    return origin + "/reset-password?" + urlencode({"token": token})


def build_reset_link(token):
    return reset_link_for_settings(token, runtime_email_settings())
