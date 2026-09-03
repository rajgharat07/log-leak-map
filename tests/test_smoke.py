"""Smoke tests for Log Leak Map."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "fixtures" / "leak-demo"
CLI = ROOT / "log_leak.py"

sys.path.insert(0, str(ROOT))


class TestLogLeakSmoke(unittest.TestCase):
    def test_demo_verdict_and_counts(self) -> None:
        from log_leak import run_scan

        report, output = run_scan(str(FIXTURE), output_format="text")
        self.assertEqual(report.verdict, "LEAKING")
        self.assertEqual(len(report.findings), 5)
        self.assertEqual(len(report.confirmed), 3)
        self.assertEqual(len(report.sensitive), 1)
        self.assertEqual(len(report.suspicious), 1)
        keys = [(f.path, f.line) for f in report.findings]
        self.assertEqual(len(keys), len(set(keys)), "one finding per path:line")
        self.assertIn("LEAKING — 3 CONFIRMED SINKS, 1 SENSITIVE, 1 SUSPICIOUS", output)
        # every ledger class row is accounted in the banner
        self.assertEqual(
            len(report.confirmed) + len(report.sensitive) + len(report.suspicious),
            len(report.findings),
        )

    def test_planted_classes_present(self) -> None:
        from log_leak import run_scan

        report, _ = run_scan(str(FIXTURE))
        present: set[str] = set()
        for f in report.findings:
            present.add(f.leak_class)
            present.update(f.also)
        for required in (
            "SECRET-IN-LOG",
            "PII-IN-LOG",
            "REQUEST-DUMP",
            "EXCEPTION-LEAK",
        ):
            self.assertIn(required, present, f"missing class {required}")
        self.assertNotIn("SENSITIVE-DEBUG", present)

    def test_debug_is_modifier(self) -> None:
        from log_leak import run_scan

        report, _ = run_scan(str(FIXTURE))
        js = next(f for f in report.findings if f.path.endswith("utils.js"))
        self.assertEqual(js.leak_class, "SECRET-IN-LOG")
        self.assertIn("DEBUG", js.modifiers)
        auth = next(f for f in report.findings if "auth.py" in f.path)
        self.assertEqual(auth.leak_class, "SECRET-IN-LOG")
        self.assertIn("DEBUG", auth.modifiers)
        self.assertIn("PII-IN-LOG", auth.also)

    def test_reconstructed_shapes(self) -> None:
        from log_leak import run_scan

        report, _ = run_scan(str(FIXTURE))
        payments = [f for f in report.findings if "payments.py" in f.path]
        self.assertEqual(len(payments), 1)
        joined = payments[0].reconstructed + payments[0].source
        self.assertTrue(
            "STRIPE" in joined or "sk_live" in joined or "••••" in joined,
            joined,
        )

    def test_benign_server_not_flagged(self) -> None:
        from log_leak import run_scan

        report, output = run_scan(str(FIXTURE))
        server_hits = [f for f in report.findings if "server.py" in f.path]
        self.assertEqual(server_hits, [], "benign startup logs must not be flagged")
        self.assertNotIn("Server started on port 8080", output)

    def test_every_finding_has_path_line(self) -> None:
        from log_leak import run_scan

        report, _ = run_scan(str(FIXTURE))
        self.assertEqual(len(report.findings), 5)
        for finding in report.findings:
            self.assertTrue(finding.path)
            self.assertGreater(finding.line, 0)
            self.assertGreater(finding.col, 0)
            self.assertTrue(finding.source)
            self.assertTrue(finding.reconstructed)

    def test_js_env_key(self) -> None:
        from log_leak import run_scan

        report, _ = run_scan(str(FIXTURE))
        js_hits = [f for f in report.findings if f.path.endswith("utils.js")]
        self.assertEqual(len(js_hits), 1)
        self.assertIn("API_KEY", js_hits[0].source + js_hits[0].evidence)

    def test_severity_split(self) -> None:
        from log_leak import run_scan

        report, output = run_scan(str(FIXTURE))
        self.assertIn("CONFIRMED SINK", output)
        pii = [f for f in report.findings if f.leak_class == "PII-IN-LOG"]
        self.assertTrue(pii)
        self.assertTrue(all(f.severity == "SENSITIVE" for f in pii))
        req = [f for f in report.findings if f.leak_class == "REQUEST-DUMP"]
        self.assertTrue(req)
        self.assertTrue(all(f.severity == "SUSPICIOUS" for f in req))
        secrets = [f for f in report.findings if f.leak_class == "SECRET-IN-LOG"]
        self.assertTrue(all(f.severity == "CONFIRMED SINK" for f in secrets))

    def test_secret_count(self) -> None:
        from log_leak import run_scan

        report, _ = run_scan(str(FIXTURE))
        secrets = [f for f in report.findings if f.leak_class == "SECRET-IN-LOG"]
        self.assertEqual(len(secrets), 3)

    def test_reproducibility(self) -> None:
        from log_leak import run_scan

        report_a, out_a = run_scan(str(FIXTURE))
        report_b, out_b = run_scan(str(FIXTURE))
        keys_a = [
            (f.leak_class, f.path, f.line, f.col, f.severity, tuple(f.modifiers), f.reconstructed)
            for f in report_a.findings
        ]
        keys_b = [
            (f.leak_class, f.path, f.line, f.col, f.severity, tuple(f.modifiers), f.reconstructed)
            for f in report_b.findings
        ]
        self.assertEqual(keys_a, keys_b)
        self.assertEqual(out_a, out_b)

    def test_cli_exit_codes(self) -> None:
        null = os.devnull
        result = subprocess.run(
            [sys.executable, str(CLI), str(FIXTURE), "--fail-on", "confirmed", "--out", null],
            capture_output=True,
            cwd=str(ROOT),
        )
        self.assertEqual(result.returncode, 1)

        with tempfile.TemporaryDirectory() as tmp:
            clean = subprocess.run(
                [sys.executable, str(CLI), tmp, "--fail-on", "confirmed", "--out", null],
                capture_output=True,
                cwd=str(ROOT),
            )
            self.assertEqual(clean.returncode, 0)

    def test_missing_path_degrades(self) -> None:
        from log_leak import run_scan

        report, _ = run_scan(str(ROOT / "definitely-does-not-exist-xyz"))
        self.assertEqual(report.verdict, "CLEAN")
        self.assertEqual(report.files_scanned, 0)


if __name__ == "__main__":
    unittest.main()
