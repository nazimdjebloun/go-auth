"""Regression tests for CI's missing-test and skipped-backend failure gates."""

import importlib.util
from pathlib import Path
import re
import unittest

spec = importlib.util.spec_from_file_location("test_backends", Path(__file__).with_name("test_backends.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class BackendEvidenceTests(unittest.TestCase):
    def test_published_catalog_prefixes_are_required_only_in_full_mode(self):
        key = (runner.MODULE + "internal/migrations", "TestSelectedBackendPublishedCatalogUpgradePrefixes")
        self.assertNotRegex(key[1], runner.STRESS_PATTERN)
        for backend in ["sqlite", "postgres", "mysql"]:
            with self.subTest(backend=backend):
                expected = runner.required_tests(backend)
                self.assertIn(key, expected)
                self.assertNotIn(key, runner.required_tests(backend, stress=True))
                events = [{"Action": "pass", "Package": package, "Test": name} for package, name in expected if (package, name) != key]
                self.assertTrue(runner.analyze(events, expected)[1])
                events.append({"Action": "pass", "Package": key[0], "Test": key[1]})
                self.assertFalse(runner.analyze(events, expected)[1])

    def test_migration_upgrade_and_recovery_evidence_is_required(self):
        package = runner.MODULE + "internal/migrations"
        for backend in ["sqlite", "postgres", "mysql"]:
            for stress in [False, True]:
                with self.subTest(backend=backend, stress=stress):
                    expected = runner.required_tests(backend, stress)
                    self.assertIn((package, "TestSelectedBackendUpgradeFailureRecovery"), expected)
                    self.assertIn((package, "TestSelectedBackendVerifiedRetry"), expected)
                    for name in ["TestSelectedBackendOwnedTableRetirement", "TestSelectedBackendOwnedTableRetry", "TestSelectedBackendOwnedObjectNamespaces"]:
                        self.assertIn((package, name), expected)
                        self.assertRegex(name, runner.STRESS_PATTERN)
                    self.assertEqual((package, "TestSelectedBackendPopulatedUpgrade") in expected, not stress)
                    self.assertEqual((package, "TestSQLiteRebuildRejectsHostOrphansAndRestoresSettings") in expected, backend == "sqlite")

    def test_authorization_coverage_is_required_in_full_and_stress_modes(self):
        coverage = {
            (runner.MODULE.rstrip("/"), name) for name in [
                "TestAppAuthorizationRouteInventory", "TestAppAuthorizationRouteCoverage",
                "TestAppAuthorizationHTTPPolicyMatrix", "TestAppAuthorizationMountedRoutesDenyUnprivileged",
            ]
        } | {
            (runner.MODULE + "internal/service", name) for name in [
                "TestAppAuthorizationServiceInventory", "TestAppAuthorizationServiceCoverage",
            ]
        }
        for backend in ["sqlite", "postgres", "mysql"]:
            for stress in [False, True]:
                with self.subTest(backend=backend, stress=stress):
                    self.assertTrue(coverage <= runner.required_tests(backend, stress))
                    for _, name in coverage:
                        self.assertRegex(name, runner.STRESS_PATTERN)

    def test_root_authorization_http_tests_run_on_every_backend(self):
        self.assertIn(".", runner.PACKAGES)
        root = runner.MODULE.rstrip("/")
        for backend in ["sqlite", "postgres", "mysql"]:
            for stress in [False, True]:
                with self.subTest(backend=backend, stress=stress):
                    expected = runner.required_tests(backend, stress)
                    for name in ["TestAppPermissionsTargetAccessHTTP", "TestAppPermissionsStatsAuthorization", "TestAppPermissionsSameRoleAssignmentPreservesAccessRevision"]:
                        self.assertIn((root, name), expected)

    def test_native_deadlock_and_snapshot_evidence_cannot_be_omitted(self):
        package = runner.MODULE + "internal/service"
        for backend, prefix in [("sqlite", None), ("postgres", "Postgres"), ("mysql", "MySQL")]:
            for stress in [False, True]:
                with self.subTest(backend=backend, stress=stress):
                    expected = runner.required_tests(backend, stress)
                    for candidate in ["Postgres", "MySQL"]:
                        self.assertEqual((package, f"Test{candidate}_AppAuthorizationDeadlockRollsBackAcrossPools") in expected, candidate == prefix)
                    self.assertEqual((package, "TestMySQL_AppAuthorizationRejectsRevokedSessionFromOldSnapshot") in expected, backend == "mysql")
                    for _, name in expected:
                        if stress:
                            self.assertRegex(name, re.compile(runner.STRESS_PATTERN))

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
