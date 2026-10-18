"""NC-04A5 isolated process and HTTP proof; no NBA application or production IO."""

import ast
import http.client
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
CHILD = r"""
import os, sys, socket, runpy, importlib.abc
class NoApplication(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in {
            'app', 'supabase', 'postgrest', 'psycopg', 'psycopg2', 'asyncpg',
            'requests', 'httpx', 'smtplib', 'flask', 'email_transport',
            'job_safety', 'standings_service', 'season_transition_service',
            'integration_harness', 'sqlalchemy', 'alembic'
        }:
            raise AssertionError('Forbidden application/provider import')
sys.meta_path.insert(0, NoApplication())
def audit(event, args):
    if event in {'socket.connect', 'socket.getaddrinfo', 'socket.gethostbyname', 'socket.gethostbyaddr', 'subprocess.Popen', 'os.system', 'os.remove', 'os.rename', 'os.mkdir'}:
        raise AssertionError('Forbidden outbound IO or mutation')
    if event == 'open':
        flags = args[2]
        if isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
            raise AssertionError('File mutation forbidden')
sys.addaudithook(audit)
assert not any(k.startswith(('SUPABASE', 'BREVO', 'JWT', 'NBA_CORNER')) for k in os.environ)
runpy.run_path(sys.argv[1], run_name='__main__')
"""


class MaintenanceFenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            cls.port = probe.getsockname()[1]
        env = {
            k: os.environ[k]
            for k in ("SYSTEMROOT", "WINDIR", "PATH")
            if k in os.environ
        }
        env["PORT"] = str(cls.port)
        cls.process = subprocess.Popen(
            [sys.executable, "-B", "-c", CHILD, str(ROOT / "maintenance_app.py")],
            env=env,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for _ in range(100):
            try:
                with socket.create_connection(("127.0.0.1", cls.port), timeout=0.1):
                    return
            except OSError:
                if cls.process.poll() is not None:
                    raise AssertionError("Isolated maintenance startup failed")
                time.sleep(0.05)
        cls.process.terminate()
        raise AssertionError("Maintenance listener did not start")

    @classmethod
    def tearDownClass(cls):
        cls.process.terminate()
        out, err = cls.process.communicate(timeout=10)
        if out or err:
            raise AssertionError("Maintenance emitted unexpected logs")

    def request(self, method, path, body=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        try:
            connection.request(method, path, body=body)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def assert_maintenance(self, method, path, body=None):
        status, headers, content = self.request(method, path, body)
        self.assertEqual(status, 503)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["Retry-After"], "300")
        self.assertEqual(headers["Server"], "")
        self.assertEqual(
            content,
            (
                b""
                if method == "HEAD"
                else b"NBA Corner is temporarily unavailable for maintenance.\n"
            ),
        )
        self.assertNotIn("Access-Control-Allow-Origin", headers)
        self.assertNotIn(b"Python", content)

    def test_root_and_normal_api_paths(self):
        for path in [
            "/",
            "/health",
            "/season",
            "/brackets",
            "/leagues",
            "/__debug/master-status",
            "/missing",
            "/__maintenance_health/",
            "/__maintenance_health/extra",
        ]:
            with self.subTest(path=path):
                self.assert_maintenance("GET", path)

    def test_all_write_methods_and_unknown_method(self):
        for method in ["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CUSTOM"]:
            with self.subTest(method=method):
                self.assert_maintenance(method, "/auth/login", "synthetic")
                self.assert_maintenance(method, "/__maintenance_health", "synthetic")

    def test_health_is_exact_fixed_get_head_only(self):
        for method in ["GET", "HEAD"]:
            status, headers, body = self.request(method, "/__maintenance_health")
            self.assertEqual(status, 200)
            self.assertEqual(body, b"OK\n" if method == "GET" else b"")
            self.assertEqual(headers["Cache-Control"], "no-store")

    def test_head_normal_and_query_no_reflection(self):
        self.assert_maintenance("HEAD", "/health")
        self.assert_maintenance("GET", "/unknown?token=synthetic-do-not-reflect")

    def test_no_application_provider_network_or_file_mutation(self):
        self.assertIsNone(self.process.poll())
        self.assert_maintenance("POST", "/admin/season/rollover", "synthetic")
        self.assert_maintenance("POST", "/auth/forgot-password", "synthetic")
        self.assertEqual(self.request("GET", "/__maintenance_health")[0], 200)

    def test_static_import_and_environment_contract(self):
        tree = ast.parse((ROOT / "maintenance_app.py").read_text())
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(n.name for n in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.add(node.module)
        self.assertEqual(imports, {"os", "socketserver", "wsgiref.simple_server"})
        env_reads = [
            n
            for n in ast.walk(tree)
            if isinstance(n, ast.Subscript)
            and isinstance(n.value, ast.Attribute)
            and isinstance(n.value.value, ast.Name)
            and n.value.value.id == "os"
            and n.value.attr == "environ"
        ]
        self.assertEqual([ast.literal_eval(n.slice) for n in env_reads], ["PORT"])
        requirements = (ROOT / "requirements.txt").read_text().splitlines()
        self.assertFalse(
            [line for line in requirements if line.strip() and not line.startswith("#")]
        )
