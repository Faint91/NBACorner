"""Replace only the superseded source-fallback expectation; retain NC-01 evidence."""

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def mark_signing_config_acceptance(klass):
    original = klass.current_behavior__auth__implementation_defaults

    def explicit_signing_configuration(self):
        source = self.backend()
        tree = ast.parse(source)
        assignment = next(
            node
            for node in tree.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(t, ast.Name) and t.id == "JWT_SECRET" for t in node.targets
            )
        )
        self.assertIsInstance(assignment.value, ast.Call)
        self.assertIsInstance(assignment.value.func, ast.Name)
        self.assertEqual(assignment.value.func.id, "runtime_jwt_secret")
        self.assertEqual(assignment.value.args, [])
        self.assertEqual(assignment.value.keywords, [])
        self.assertIn("timedelta(days=7)", source)
        self.assertIn("rounds=BCRYPT_ROUNDS", source)
        self.assertIn('os.getenv("BCRYPT_ROUNDS", "12")', source)
        self.assertIn(
            "MINIMUM_SECRET_CHARACTERS = 32",
            (ROOT / "jwt_configuration.py").read_text(encoding="utf-8"),
        )

    explicit_signing_configuration.metadata = dict(
        original.metadata,
        phase="NC-03R1",
        previous_metadata=dict(original.metadata),
        current_behavior="Explicit runtime signing key required; original seven-day expiry, algorithm and G1 hasher unchanged; NC03-SEC-001 fallback assertion superseded.",
    )
    klass.current_behavior__auth__implementation_defaults = (
        explicit_signing_configuration
    )
