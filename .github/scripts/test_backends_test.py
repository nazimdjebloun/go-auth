"""Regression tests for CI's missing-test and skipped-backend failure gates."""

import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("test_backends", Path(__file__).with_name("test_backends.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class BackendEvidenceTests(unittest.TestCase):
    def test_signup_lock_evidence_is_required_for_selected_backend(self):
        package = runner.MODULE + "internal/service"
        for backend, prefix in [("sqlite", None), ("postgres", "Postgres"), ("mysql", "MySQL")]:
            for stress in [False, True]:
                with self.subTest(backend=backend, stress=stress):
                    expected = runner.required_tests(backend, stress)
                    self.assertIn((package, "TestAppSignupAvoidsGlobalAuthorizationLocks"), expected)
                    self.assertIn((package, "TestAppSignupBaselineFailureRollsBack"), expected)
                    for candidate in ["Postgres", "MySQL"]:
                        key = (package, f"Test{candidate}_AppSignupRoleLocksAcrossPools")
                        self.assertEqual(key in expected, candidate == prefix)

    def test_failure_gates(self):
        cases = [
            ("successful required test", [{"Action": "pass", "Test": "required", "Package": "pkg"}], {"required"}, False),
            ("empty suite", [], {"required"}, True),
            ("wrong selection", [{"Action": "pass", "Test": "other", "Package": "pkg"}], {"required"}, True),
            ("skipped database", [{"Action": "skip", "Test": "required", "Package": "pkg"}], {"required"}, True),
            ("assertion failure", [{"Action": "fail", "Test": "required", "Package": "pkg"}], {"required"}, True),
            ("package failure", [{"Action": "pass", "Test": "required", "Package": "pkg"}, {"Action": "fail", "Package": "pkg"}], {"required"}, True),
            ("subtest cannot replace parent", [{"Action": "pass", "Test": "required/subtest", "Package": "pkg"}], {"required"}, True),
            ("wrong package", [{"Action": "pass", "Test": "required", "Package": "wrong"}], {"required"}, True),
        ]
        for name, events, expected, fails in cases:
            with self.subTest(name=name):
                _, problems = runner.analyze(events, {("pkg", name) for name in expected})
                self.assertEqual(bool(problems), fails)

    def test_every_required_repetition_must_pass(self):
        event = {"Action": "pass", "Test": "required", "Package": "pkg"}
        for count, fails in [(1, True), (3, True), (4, False)]:
            with self.subTest(count=count):
                _, problems = runner.analyze([event] * count, {("pkg", "required")}, repetitions=4)
                self.assertEqual(bool(problems), fails)


if __name__ == "__main__":
    unittest.main()
