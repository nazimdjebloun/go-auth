#!/usr/bin/env python3
"""Run required live-backend tests and retain reproducible CI evidence."""

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import subprocess
import sys


PACKAGES = ["./integration", "./internal/service", "./internal/sqlstore", "./cmd/goauth/cmd"]
MODULE = "github.com/nazimdjebloun/go-auth/"
REQUIRED = {
    (MODULE + package, name)
    for package, names in {
        "integration": ["TestMigrations_CreateTables", "TestHTTPBackendSecurityContract"],
        "cmd/goauth/cmd": ["TestApplySchema_SelectedBackend"],
        "internal/service": ["TestLoginCredentialReplacementCannotIssueSessionOrChallenge", "TestTwoFactorVerifyReassertsCodeAndExpiryAtClaim", "TestAppSignupAvoidsGlobalAuthorizationLocks", "TestAppSignupBaselineFailureRollsBack", "TestAppSignupInviteDuplicatePreservesClaimError", "TestAppSignupInviteClaimFailureRollsBack"],
        "internal/sqlstore": ["TestRecoveryClaimIsExclusiveAndStaleCompletionCannotDeleteReclaimedJob", "TestAdminGuard_ConcurrentReductionsAcrossPools", "TestBackendTokenClaimConcurrentAcrossPools", "TestBackendProviderIdentityIsExact", "TestBackendRefreshZeroGraceRejectsFutureRotation", "TestBackendSessionAssuranceRoundTrip", "TestAppDefaultRoleSharedReadRequiresTransaction", "TestAppPermissionNamespaceOwnership"],
    }.items()
    for name in names
}
STRESS_PATTERN = (
    "Concurrent|RollsBack|Rollback|TestBackend|TestRecovery|"
    "TestLoginCredentialReplacement|TestTwoFactorVerify|"
    "TestAdminGuard|TestAdminAccessRequires|TestOrgMutationChecks|"
    "TestInviteRevocationCannot|TestOAuthUnlinkCounts|"
    "TestAppSignup|Test(Postgres|MySQL)_AppSignup|TestAppDefaultRole|TestAppPermissionNamespaceOwnership"
)


def required_tests(backend, stress=False):
    excluded = {"TestMigrations_CreateTables", "TestApplySchema_SelectedBackend", "TestHTTPBackendSecurityContract"} if stress else set()
    expected = {key for key in REQUIRED if key[1] not in excluded}
    prefix = {"postgres": "Postgres", "mysql": "MySQL"}.get(backend)
    if prefix:
        expected.add((MODULE + "internal/service", f"Test{prefix}_AppSignupRoleLocksAcrossPools"))
    return expected


def analyze(events, expected, repetitions=1):
    counts = Counter((e["Package"], e["Test"]) for e in events if e.get("Action") == "pass" and "Test" in e)
    passed = set(counts)
    skipped = {e["Test"] for e in events if e.get("Action") == "skip" and "Test" in e}
    failed = {e.get("Test", e["Package"]) for e in events if e.get("Action") == "fail"}
    problems = []
    if skipped:
        problems.append("Unexpected skips: " + ", ".join(sorted(skipped)))
    if failed:
        problems.append("Failures: " + ", ".join(sorted(failed)))
    missing = {key for key in expected if counts[key] < repetitions}
    if missing:
        problems.append(f"Required tests need {repetitions} passing runs: " + ", ".join(package + ":" + name for package, name in sorted(missing)))
    if not passed:
        problems.append("No tests executed")
    return passed, problems


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("backend", choices=["sqlite", "postgres", "mysql"])
    parser.add_argument("--stress", action="store_true")
    parser.add_argument("--count", type=int, default=25)
    args = parser.parse_args()
    if not 1 <= args.count <= 100:
        parser.error("--count must be between 1 and 100")
    env = os.environ.copy()
    env["GOAUTH_TEST_DRIVER"] = args.backend
    required_dsn = {"postgres": "GOAUTH_POSTGRES_DSN", "mysql": "GOAUTH_MYSQL_TEST_DSN"}.get(args.backend)
    if required_dsn and not env.get(required_dsn):
        parser.error(f"{required_dsn} is required; CI must not skip its backend")
    mode = "stress" if args.stress else "full"
    artifacts = Path(".test-results") / args.backend / mode
    artifacts.mkdir(parents=True, exist_ok=True)
    excluded = []
    if args.backend != "postgres":
        excluded.append("^TestPostgres_")
    if args.backend != "mysql":
        excluded.extend(["^TestMySQL_", "^TestApplySchema_MySQL$"])
    command = ["go", "test", "-json", "-race", "-shuffle=on", "-count=" + str(args.count if args.stress else 1)]
    command += ["-timeout=" + ("90m" if args.stress else "30m")]
    if excluded:
        command += ["-skip=" + "|".join(excluded)]
    if args.stress:
        command += ["-cpu=1,4", "-run=" + STRESS_PATTERN]
    else:
        command += ["-covermode=atomic", "-coverpkg=./...", "-coverprofile=" + str(artifacts / "coverage.out")]
    command += PACKAGES
    (artifacts / "command.json").write_text(json.dumps(command, indent=2) + "\n")
    print(f"Running {args.backend} {mode}: {' '.join(command)}", flush=True)
    events = []
    with (artifacts / "tests.jsonl").open("w") as capture, (artifacts / "output.log").open("w") as log:
        process = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in process.stdout:
            capture.write(line)
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                print(line, end="", flush=True)
                log.write(line)
                continue
            events.append(event)
            output = event.get("Output", "")
            log.write(output)
            if "-test.shuffle" in output or (event.get("Action") in ("fail", "skip")) or (not event.get("Test") and event.get("Action") == "pass"):
                print(output or json.dumps(event), end="" if output else "\n", flush=True)
        status = process.wait()
    expected = required_tests(args.backend, args.stress)
    passed, problems = analyze(events, expected, repetitions=2 * args.count if args.stress else 1)
    summary = f"{args.backend} {mode}: {len(passed)} distinct passing test cases; process exit {status}\n"
    if problems:
        summary += "\n".join(problems) + "\n"
    if status or problems:
        # Show assertion context while keeping successful audit output quiet.
        failed_tests = {(e["Package"], e.get("Test")) for e in events if e.get("Action") == "fail" and "Test" in e}
        for event in events:
            if (event.get("Package"), event.get("Test")) in failed_tests:
                print(event.get("Output", ""), end="")
    print(summary, flush=True)
    (artifacts / "summary.txt").write_text(summary)
    if github_summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(github_summary, "a") as output:
            output.write("```text\n" + summary + "```\n")
    if not args.stress and (artifacts / "coverage.out").exists():
        with (artifacts / "coverage.txt").open("w") as output:
            subprocess.run(["go", "tool", "cover", "-func=" + str(artifacts / "coverage.out")], stdout=output, check=True)
    return 1 if status or problems else 0


if __name__ == "__main__":
    sys.exit(main())
