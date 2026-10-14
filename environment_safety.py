"""Fail-closed mutation guards and separate read-only LOCAL identity verification."""

import base64
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlsplit

PRODUCTION_PROJECTS = frozenset({"rpwesmvzmgoctrokrbhy"})
PRODUCTION_HOSTS = frozenset(
    {
        "rpwesmvzmgoctrokrbhy.supabase.co",
        "db.rpwesmvzmgoctrokrbhy.supabase.co",
        "nbacorner.onrender.com",
        "nbacorner.com",
    }
)
REGISTRY_PATH = Path(__file__).with_name("test_environments.json")
CONFIG_FIELDS = frozenset(
    {
        "NBA_CORNER_ENV",
        "NBA_CORNER_ALLOW_MUTATING_TESTS",
        "NBA_CORNER_TEST_TARGET",
        "NBA_CORNER_EXPECTED_PROJECT_REF",
        "SUPABASE_URL",
        "NBACORNER_BASE_URL",
        "SUPABASE_KEY",
        "SUPABASE_SERVICE_ROLE_KEY",
        "JWT_SECRET",
        "JWT_ALGORITHM",
        "CURRENT_SEASON_CODE",
        "REGULAR_SEASON_END_UTC",
        "PLAYOFFS_START_UTC",
        "HEALTHCHECK_TOKEN",
        "STANDINGS_CRON_TOKEN",
        "BCRYPT_ROUNDS",
        "FRONTEND_ORIGIN",
        "NBA_STANDINGS_SEASON",
        "NBA_CORNER_EMAIL_MODE",
        "NBA_CORNER_RESET_LINK_ORIGIN",
        "NBA_CORNER_PROVIDER_MODE",
        "NBA_CORNER_JOBS_ENABLED",
    }
)


class SafetyError(RuntimeError):
    """Errors deliberately omit supplied URLs, credentials and file contents."""


@dataclass(frozen=True)
class TestTarget:
    name: str
    project_ref: str
    supabase_origin: str
    backend_origin: str
    marker_id: str
    marker_version: str


def reject_production(value):
    normalized = unquote(unquote(str(value))).lower()
    if any(ref in normalized for ref in PRODUCTION_PROJECTS):
        raise SafetyError("Known production project is prohibited for tests.")
    try:
        host = urlsplit(normalized).hostname or normalized.rstrip(".")
    except ValueError:
        raise SafetyError("Malformed target.") from None
    host = host.rstrip(".")
    if any(host == h or host.endswith("." + h) for h in PRODUCTION_HOSTS):
        raise SafetyError("Known production hostname is prohibited for tests.")


def normalize_origin(value):
    if not isinstance(value, str) or not value or value != value.strip():
        raise SafetyError("Explicit, well-formed target origin is required.")
    reject_production(value)
    if any(c.isspace() or ord(c) < 32 for c in value) or "\\" in value:
        raise SafetyError("Malformed target origin.")
    try:
        parsed = urlsplit(value)
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
    except ValueError:
        raise SafetyError("Malformed target origin.") from None
    if parsed.username is not None or parsed.password is not None:
        raise SafetyError("Credential-bearing target URLs are prohibited.")
    if parsed.scheme.lower() not in {"http", "https"} or not host:
        raise SafetyError("HTTP(S) origin required.")
    if "%" in parsed.netloc or parsed.query or parsed.fragment:
        raise SafetyError("Encoded hosts, query strings and fragments are prohibited.")
    if parsed.path not in {"", "/"}:
        raise SafetyError("Configure an origin, not an application URL path.")
    if parsed.scheme.lower() == "http" and host not in {
        "localhost",
        "127.0.0.1",
        "::1",
    }:
        raise SafetyError("Remote test origins must use HTTPS.")
    if parsed.netloc.endswith(":"):
        raise SafetyError("Malformed empty URL port.")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise SafetyError("Malformed hostname.") from None
    reject_production(host)
    authority = f"[{host}]" if ":" in host else host
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    if port is not None and port != default_port:
        authority += f":{port}"
    return f"{parsed.scheme.lower()}://{authority}"


def project_reference(origin):
    host = urlsplit(normalize_origin(origin)).hostname
    match = re.fullmatch(r"([a-z]{20})\.supabase\.co", host or "")
    if not match:
        raise SafetyError("Expected an enrolled Supabase project API hostname.")
    return match.group(1)


def is_local_target(target):
    return target.project_ref.startswith("local:")


def validate_local_enrollment(target):
    reject_production(target.project_ref)
    if not re.fullmatch(
        r"local:[a-z][a-z0-9-]{0,62}", target.project_ref
    ) or not target.name.startswith("local-"):
        raise SafetyError("Explicit LOCAL TEST ONLY enrollment identity is required.")
    for origin in (target.supabase_origin, target.backend_origin):
        parsed = urlsplit(normalize_origin(origin))
        if (
            parsed.scheme != "http"
            or parsed.hostname != "127.0.0.1"
            or parsed.port is None
        ):
            raise SafetyError(
                "Local enrollment requires exact numeric loopback origins and ports."
            )


def load_enrollments():
    try:
        document = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        if document.get("version") != 1 or not isinstance(
            document.get("targets"), list
        ):
            raise ValueError
        targets = tuple(TestTarget(**item) for item in document["targets"])
        if len({target.name for target in targets}) != len(targets):
            raise ValueError
        for target in targets:
            if not all(
                isinstance(getattr(target, field), str)
                for field in TestTarget.__dataclass_fields__
            ):
                raise ValueError
            if is_local_target(target):
                validate_local_enrollment(target)
            elif project_reference(target.supabase_origin) != target.project_ref:
                raise ValueError
            normalize_origin(target.backend_origin)
            if not target.name or not target.marker_id or not target.marker_version:
                raise ValueError
        return targets
    except (OSError, ValueError, TypeError, KeyError):
        raise SafetyError(
            "Invalid or missing reviewed test enrollment registry."
        ) from None


def validate_test_target(settings, enrollments, *, identity_only=False):
    if settings.get("NBA_CORNER_ENV") != "test":
        raise SafetyError("Mutating tooling requires explicit NBA_CORNER_ENV=test.")
    if not identity_only and settings.get("NBA_CORNER_ALLOW_MUTATING_TESTS") != "1":
        raise SafetyError("Explicit mutating-test opt-in is required.")
    expected = settings.get("NBA_CORNER_EXPECTED_PROJECT_REF", "")
    if not isinstance(expected, str):
        raise SafetyError("Explicit expected test identity is required.")
    reject_production(expected)
    local = expected.startswith("local:")
    if not (
        re.fullmatch(r"local:[a-z][a-z0-9-]{0,62}", expected)
        if local
        else re.fullmatch(r"[a-z]{20}", expected)
    ):
        raise SafetyError("Explicit expected test project reference is required.")
    supabase_origin = normalize_origin(settings.get("SUPABASE_URL"))
    backend_origin = normalize_origin(settings.get("NBACORNER_BASE_URL"))
    if not local and project_reference(supabase_origin) != expected:
        raise SafetyError("Configured project and Supabase host disagree.")
    matches = [
        t for t in enrollments if t.name == settings.get("NBA_CORNER_TEST_TARGET")
    ]
    if len(matches) != 1:
        raise SafetyError("Target is not enrolled. NC-ENV-03 enrollment is required.")
    target = matches[0]
    if local:
        validate_local_enrollment(target)
    if (
        target.project_ref != expected
        or normalize_origin(target.supabase_origin) != supabase_origin
        or normalize_origin(target.backend_origin) != backend_origin
        or not target.marker_id
        or not target.marker_version
    ):
        raise SafetyError("Configuration does not match reviewed target enrollment.")
    for field in ("SUPABASE_KEY", "SUPABASE_SERVICE_ROLE_KEY"):
        key = settings.get(field)
        if not key:
            continue
        if key.startswith("sb_secret_"):
            continue  # Opaque keys still require authenticated live verification later.
        try:
            parts = key.split(".")
            if len(parts) != 3:
                raise ValueError
            payload = json.loads(
                base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))
            )
            if not isinstance(payload, dict):
                raise ValueError
            reject_production(payload.get("ref", ""))
            credential_ref = payload.get("ref")
            ref_matches = credential_ref == expected or (
                local
                and credential_ref is None
                and payload.get("iss") in {"supabase", "supabase-demo"}
            )
            if not ref_matches or payload.get("role") != "service_role":
                raise SafetyError(
                    "Server credential metadata does not match enrollment."
                )
        except (ValueError, TypeError, KeyError, UnicodeError):
            raise SafetyError("Malformed server credential metadata.") from None
    return target


def validate_identity_evidence(target, database_marker, backend_identity):
    """Pure future interface, NOT proof of origin/authenticity or an execution permit."""
    required = {
        "environment": "test",
        "project_ref": target.project_ref,
        "marker_id": target.marker_id,
        "marker_version": target.marker_version,
    }
    if any(database_marker.get(k) != v for k, v in required.items()):
        raise SafetyError("Database non-production identity is missing or mismatched.")
    if any(backend_identity.get(k) != v for k, v in required.items()):
        raise SafetyError("Backend non-production identity is missing or mismatched.")
    if backend_identity.get("backend_origin") != target.backend_origin:
        raise SafetyError("Backend origin disagrees with enrollment.")
    if (
        backend_identity.get("email_mode") != "capture"
        or backend_identity.get("provider_mode") != "fixtures"
        or backend_identity.get("jobs_enabled") is not False
    ):
        raise SafetyError("Non-production side-effect safety has not been established.")


def refuse_redirect(target, destination):
    reject_production(destination)
    raise SafetyError("Redirects are prohibited for guarded test traffic.")


def validate_local_marker(target, marker):
    validate_local_enrollment(target)
    baseline = json.loads(
        (Path(__file__).parent / "db/baseline/manifest.json").read_text(
            encoding="utf-8"
        )
    )
    expected = {
        "environment": "test",
        "project_ref": target.project_ref,
        "marker_id": target.marker_id,
        "marker_version": target.marker_version,
        "baseline_version": baseline["baseline_version"],
        "baseline_checkpoint": baseline["backend_checkpoint"],
        "baseline_commit": "2e9d6752ce0a5f559673b99221d88c7f51c9d8ea",
        "fixture_state": "UNSEEDED",
    }
    if not isinstance(marker, dict) or any(
        marker.get(k) != v for k, v in expected.items()
    ):
        raise SafetyError(
            "Local database marker/baseline identity is missing or mismatched."
        )
    return marker


def verify_live_local_identity(settings, enrollments=None):
    """Authenticated loopback GET only. Success NEVER enables mutation/startup."""
    import http.client

    target = validate_test_target(
        settings,
        load_enrollments() if enrollments is None else enrollments,
        identity_only=True,
    )
    if not is_local_target(target):
        raise SafetyError(
            "Read-only live identity is implemented for LOCAL targets only."
        )
    validate_local_enrollment(target)
    key = settings.get("SUPABASE_SERVICE_ROLE_KEY") or settings.get("SUPABASE_KEY")
    if not key or any(c in key for c in "\r\n"):
        raise SafetyError("Explicit local server credential is required.")
    origin = urlsplit(normalize_origin(target.supabase_origin))
    connection = http.client.HTTPConnection("127.0.0.1", origin.port, timeout=5)
    try:
        connection.request(
            "GET",
            "/rest/v1/test_environment_identity?select=environment,project_ref,marker_id,marker_version,baseline_version,baseline_checkpoint,baseline_commit,fixture_state&limit=2",
            headers={
                "apikey": key,
                "Authorization": "Bearer " + key,
                "Accept-Profile": "nba_corner_test_control",
            },
        )
        response = connection.getresponse()
        if response.status != 200:
            raise SafetyError(
                "Local identity read failed; redirects and non-success responses are prohibited."
            )
        raw = response.read(16385)
        if len(raw) > 16384:
            raise SafetyError("Local identity response exceeds allowed size.")
        rows = json.loads(raw)
        if not isinstance(rows, list) or len(rows) != 1:
            raise SafetyError(
                "Exactly one authoritative local identity marker is required."
            )
        marker = validate_local_marker(target, rows[0])
        return {
            "identity_verified": True,
            "target": target.name,
            "marker": marker,
            "mutation_permitted": False,
        }
    except SafetyError:
        raise
    except (OSError, ValueError, TypeError, http.client.HTTPException):
        raise SafetyError("Local identity verification failed.") from None
    finally:
        connection.close()


def validate_test_email_settings(settings, target, ambient=None):
    """Pure capture/reset-origin gate; no credentials, content or URLs in errors."""
    ambient = os.environ if ambient is None else ambient
    for source in (settings, ambient):
        if any(
            value and (name.startswith("BREVO_") or name.startswith("SENDINBLUE_"))
            for name, value in source.items()
        ):
            raise SafetyError(
                "Live email provider configuration is prohibited in test mode."
            )
    if (
        settings.get("NBA_CORNER_ENV") != "test"
        or settings.get("NBA_CORNER_EMAIL_MODE") != "capture"
    ):
        raise SafetyError("Test email mode must explicitly select local capture.")
    origin = normalize_origin(settings.get("NBA_CORNER_RESET_LINK_ORIGIN"))
    if origin != normalize_origin(target.backend_origin):
        raise SafetyError(
            "Reset-link origin must match the enrolled test backend origin."
        )
    return origin


def verify_test_email_readiness(settings):
    target = validate_test_target(settings, load_enrollments(), identity_only=True)
    origin = validate_test_email_settings(settings, target)
    identity = verify_live_local_identity(settings)
    return {
        "identity_verified": identity["identity_verified"],
        "email_gate_passed": True,
        "email_mode": "capture",
        "reset_link_origin": origin,
        "mutation_permitted": False,
    }


def require_live_identity(target):
    # Identity-only verification never permits application startup/mutation.
    # No opt-in, marker, caller dictionary or enrollment bypasses later gates.
    raise SafetyError(
        "Mutation/startup remains blocked: UNSEEDED fixtures and unverified "
        "provider/job/reset/harness safety must be resolved in later phases."
    )


def load_test_config(filename):
    if not filename:
        raise SafetyError("Explicit ignored test configuration file is required.")
    path = Path(filename)
    if not path.is_absolute() or not re.fullmatch(
        r"\.env\.test(?:\.[a-zA-Z0-9_-]+)?\.local", path.name
    ):
        raise SafetyError(
            "Use an absolute path to an ignored .env.test[.name].local file."
        )
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        raise SafetyError("Test configuration cannot be read.") from None
    settings = {}
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, separator, value = line.partition("=")
        name, value = name.strip(), value.strip()
        if not separator or name not in CONFIG_FIELDS or name in settings:
            raise SafetyError(
                "Unknown, duplicated or malformed test configuration field."
            )
        if value.startswith(("'", '"')):
            if len(value) < 2 or value[-1] != value[0]:
                raise SafetyError("Malformed quoted test configuration value.")
            value = value[1:-1]
        if "$" in value or "\x00" in value:
            raise SafetyError("Test configuration interpolation is prohibited.")
        settings[name] = value
    return settings


def controlled_child_environment(settings, filename, parent=None):
    parent = os.environ if parent is None else parent
    child = {
        k: parent[k]
        for k in ("SYSTEMROOT", "SystemRoot", "WINDIR", "PATH", "TEMP", "TMP")
        if k in parent
    }
    child.update(
        {
            k: v
            for k, v in settings.items()
            if k in CONFIG_FIELDS and k not in OPERATIONAL_SECRETS
        }
    )
    child.update(
        NBA_CORNER_TEST_CONFIG=str(Path(filename).resolve()),
        PYTHONUTF8="1",
        PYTHONDONTWRITEBYTECODE="1",
    )
    return child


def prepare_runtime_environment(dotenv_loader=None):
    """Legacy production loading preserved; test requests refuse before client creation."""
    identity = os.environ.get("NBA_CORNER_ENV")
    config = os.environ.get("NBA_CORNER_TEST_CONFIG")
    if identity not in {None, "production", "test"}:
        raise SafetyError("Unrecognized explicit environment identity.")
    if identity == "production" and config is not None:
        raise SafetyError("Production identity cannot use a test configuration.")
    if identity == "test" or config is not None:
        settings = load_test_config(config)
        target = validate_test_target(settings, load_enrollments())
        validate_test_email_settings(settings, target)
        validate_test_provider_settings(settings, target)
        validate_test_job_settings(settings)
        require_live_identity(target)
        return
    if dotenv_loader is None:
        from dotenv import load_dotenv

        dotenv_loader = load_dotenv
    dotenv_loader()
    # A hidden test identity in the ordinary .env must not initialize a client.
    if (
        os.environ.get("NBA_CORNER_ENV") not in {None, "production"}
        or os.environ.get("NBA_CORNER_TEST_CONFIG") is not None
    ):
        raise SafetyError("Test identity must use explicit controlled configuration.")


class GuardedTestClient:
    def __init__(self):
        settings = load_test_config(os.environ.get("NBA_CORNER_TEST_CONFIG"))
        self.target = validate_test_target(settings, load_enrollments())
        require_live_identity(self.target)

    def request(self, method, path, **kwargs):
        # Transport intentionally unavailable in this phase, even for GET.
        raise SafetyError("Guarded test transport is not enabled.")


def get_test_client():
    return GuardedTestClient()


PROVIDER_PREFIXES = (
    "BALLDONTLIE_",
    "ESPN_",
    "NBA_STATS_",
    "BREVO_",
    "SENDINBLUE_",
    "GA_",
    "GOOGLE_ANALYTICS_",
)
OPERATIONAL_SECRETS = frozenset(
    {"STANDINGS_CRON_TOKEN", "HEALTHCHECK_TOKEN", "JWT_SECRET"}
)


def runtime_safety_settings():
    identity = os.environ.get("NBA_CORNER_ENV")
    config = os.environ.get("NBA_CORNER_TEST_CONFIG")
    if identity == "test" or config is not None:
        if identity not in {None, "test"}:
            raise SafetyError("Production cannot use controlled test configuration.")
        return load_test_config(config)
    if identity not in {None, "production"}:
        raise SafetyError("Unrecognized environment identity.")
    return {"NBA_CORNER_ENV": identity}


def validate_test_provider_settings(settings, target, ambient=None):
    ambient = os.environ if ambient is None else ambient
    validate_local_enrollment(target)
    if (
        settings.get("NBA_CORNER_ENV") != "test"
        or settings.get("NBA_CORNER_PROVIDER_MODE") != "fixtures"
    ):
        raise SafetyError("Test provider mode must explicitly select fixtures.")
    for source in (settings, ambient):
        if any(
            v
            and (
                k.upper().startswith(PROVIDER_PREFIXES)
                or k.upper() in OPERATIONAL_SECRETS
            )
            for k, v in source.items()
        ):
            raise SafetyError(
                "Live provider and operational credentials/configuration are prohibited in test mode."
            )
    return "fixtures"


def jobs_enabled(settings):
    if settings.get("NBA_CORNER_ENV") == "test":
        if settings.get("NBA_CORNER_JOBS_ENABLED") not in {None, "false"}:
            raise SafetyError("Automatic test jobs cannot be enabled.")
        return False
    if settings.get("NBA_CORNER_ENV") not in {None, "production"}:
        raise SafetyError("Unrecognized job environment identity.")
    return True  # production schedules/authorization retain their original behavior


def validate_test_job_settings(settings):
    if jobs_enabled(settings) or settings.get("NBA_CORNER_JOBS_ENABLED") != "false":
        raise SafetyError("Readiness requires an explicit jobs-disabled state.")
    return False


def verify_provider_job_readiness(settings):
    target = validate_test_target(settings, load_enrollments(), identity_only=True)
    validate_test_email_settings(settings, target)
    validate_test_provider_settings(settings, target)
    validate_test_job_settings(settings)
    identity = verify_live_local_identity(settings)
    return {
        "identity_verified": identity["identity_verified"],
        "database_marker": "PASS",
        "email": "PASS",
        "providers": "PASS",
        "external_credentials": "PASS",
        "jobs": "PASS",
        "jobs_enabled": False,
        "fixture_state": identity["marker"]["fixture_state"],
        "fixtures_reset": "UNMET",
        "integration_harness": "UNMET",
        "mutation_permitted": False,
    }


def validate_test_destination(target, url):
    """Pure allowlist for future local traffic; does not enable a transport."""
    validate_local_enrollment(target)
    parsed = urlsplit(url)
    if parsed.username or parsed.password or parsed.fragment or "\\" in url:
        raise SafetyError("Unexpected test destination.")
    origin = normalize_origin(f"{parsed.scheme}://{parsed.netloc}")
    if origin not in {target.supabase_origin, target.backend_origin}:
        raise SafetyError("Only enrolled numeric-loopback destinations are allowed.")
    return origin
