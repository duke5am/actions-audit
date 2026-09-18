"""Test suite for actions-audit.

Run with either:
    python3 -m unittest discover -s tests -v
    python3 run_tests.py

The suite is standard-library-only.  It exercises both YAML backends explicitly
(PyYAML when importable, and the native reader always) and asserts that they
produce identical findings for the same input.
"""

from __future__ import annotations

import io
import json
import os
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from aaudit import auditor, miniyaml  # noqa: E402
import actions_audit as cli  # noqa: E402

FIXTURES = os.path.join(HERE, "fixtures")
INVALID = os.path.join(FIXTURES, "invalid")

BAD = os.path.join(FIXTURES, "bad-workflow.yml")
HARDENED = os.path.join(FIXTURES, "hardened.yml")
ON_TRAP = os.path.join(FIXTURES, "on-trap.yml")
PRT = os.path.join(FIXTURES, "pull-request-target.yml")
FORKSECRETS = os.path.join(FIXTURES, "fork-secrets.yml")
WORKFLOW_RUN = os.path.join(FIXTURES, "workflow-run.yml")
MALFORMED = os.path.join(INVALID, "malformed.yml")
EMPTY = os.path.join(INVALID, "empty.yml")


def audit_string(source: str, prefer_native: bool = False):
    """Audit an inline workflow; returns (findings, meta)."""
    return auditor.audit_source("<inline>", "<inline>", source,
                                prefer_native=prefer_native)


def rules_hit(findings) -> set:
    return {finding.rule_id for finding in findings}


def findings_for(findings, rule_id):
    return [finding for finding in findings if finding.rule_id == rule_id]


MINIMAL_JOB = "    runs-on: ubuntu-latest\n    timeout-minutes: 5\n"


def workflow(body: str, triggers: str = "  push:\n",
             permissions: str = "permissions:\n  contents: read\n") -> str:
    """Wrap a jobs body into a complete, otherwise-clean workflow."""
    if permissions and not permissions.endswith("\n"):
        permissions += "\n"
    return "name: Inline\non:\n%s%sjobs:\n%s" % (triggers, permissions, body)


# --------------------------------------------------------------------------
# Rule registry
# --------------------------------------------------------------------------


class TestRuleRegistry(unittest.TestCase):
    def test_fourteen_rules_registered(self):
        self.assertEqual(len(auditor.RULES), 14)

    def test_rule_ids_are_unique(self):
        ids = [entry.id for entry in auditor.RULES]
        self.assertEqual(len(ids), len(set(ids)))

    def test_expected_rule_ids_present(self):
        expected = {
            "mutable-action-ref",
            "pull-request-target-code-execution",
            "permissions-missing",
            "permissions-write-all",
            "script-injection",
            "fork-secret-unavailable",
            "job-timeout-missing",
            "concurrency-missing-deploy",
            "checkout-persist-credentials",
            "continue-on-error-deploy",
            "self-hosted-runner",
            "workflow-run-checkout",
            "cache-key-no-lockfile",
            "always-on-publish",
        }
        self.assertEqual({entry.id for entry in auditor.RULES}, expected)
        self.assertEqual(len(expected), 14)

    def test_every_rule_declares_valid_severity(self):
        for entry in auditor.RULES:
            self.assertIn(entry.severity, auditor.SEVERITIES, entry.id)

    def test_every_rule_has_non_empty_metadata(self):
        for entry in auditor.RULES:
            with self.subTest(rule=entry.id):
                self.assertTrue(entry.title.strip())
                self.assertTrue(entry.rationale.strip())
                self.assertTrue(entry.fix.strip())
                self.assertGreater(len(entry.fix), 20)
                self.assertTrue(entry.tags)

    def test_catalogue_serialises(self):
        catalogue = auditor.rule_catalogue()
        self.assertEqual(len(catalogue), 14)
        json.dumps(catalogue)  # must not raise
        for entry in catalogue:
            self.assertEqual(set(entry), {"id", "title", "severity",
                                          "rationale", "fix", "tags"})


# --------------------------------------------------------------------------
# Rule behaviour
# --------------------------------------------------------------------------


class TestMutableActionRef(unittest.TestCase):
    def test_tag_ref_flagged_high(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB +
            "    steps:\n      - uses: actions/checkout@v4\n"))
        hits = findings_for(findings, "mutable-action-ref")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, "high")
        self.assertIn("@v4", hits[0].message)
        self.assertIn("actions/checkout", hits[0].message)

    def test_branch_ref_flagged(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB +
            "    steps:\n      - uses: some/action@main\n"))
        self.assertEqual(len(findings_for(findings, "mutable-action-ref")), 1)

    def test_master_branch_flagged(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB +
            "    steps:\n      - uses: some/action@master\n"))
        self.assertEqual(len(findings_for(findings, "mutable-action-ref")), 1)

    def test_major_version_tag_flagged(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB +
            "    steps:\n      - uses: actions/setup-node@v4\n"))
        self.assertEqual(len(findings_for(findings, "mutable-action-ref")), 1)

    def test_sha_pin_not_flagged(self):
        sha = "a" * 40
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB +
            "    steps:\n      - uses: actions/checkout@%s\n" % sha))
        self.assertEqual(findings_for(findings, "mutable-action-ref"), [])

    def test_short_sha_still_flagged(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB +
            "    steps:\n      - uses: actions/checkout@11bd719\n"))
        self.assertEqual(len(findings_for(findings, "mutable-action-ref")), 1)

    def test_local_action_not_flagged(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB +
            "    steps:\n      - uses: ./.github/actions/local\n"))
        self.assertEqual(findings_for(findings, "mutable-action-ref"), [])

    def test_docker_action_not_flagged(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB +
            "    steps:\n      - uses: docker://alpine:3.20\n"))
        self.assertEqual(findings_for(findings, "mutable-action-ref"), [])

    def test_fix_names_the_pinned_form(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB +
            "    steps:\n      - uses: actions/checkout@v4\n"))
        fix = findings_for(findings, "mutable-action-ref")[0].fix
        self.assertIn("actions/checkout@<40-char-commit-sha>", fix)
        self.assertIn("git ls-remote", fix)

    def test_line_points_at_the_step(self):
        source = workflow(
            "  build:\n" + MINIMAL_JOB +
            "    steps:\n      - name: one\n        run: echo one\n"
            "      - uses: actions/checkout@v4\n")
        findings, _ = audit_string(source)
        hit = findings_for(findings, "mutable-action-ref")[0]
        # Line 13: the step's first key ("uses"), not the "-" dash on line 12.
        self.assertEqual(hit.line, 13)
        self.assertIn("actions/checkout@v4", source.splitlines()[hit.line - 1])

    def test_multiple_steps_report_distinct_lines(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB +
            "    steps:\n      - uses: actions/checkout@v4\n"
            "      - uses: actions/cache@v4\n"))
        hits = findings_for(findings, "mutable-action-ref")
        self.assertEqual(len(hits), 2)
        self.assertNotEqual(hits[0].line, hits[1].line)


class TestPullRequestTarget(unittest.TestCase):
    def test_pr_target_head_checkout_flagged(self):
        findings, _ = audit_string(workflow(
            "  preview:\n" + MINIMAL_JOB +
            "    steps:\n      - uses: actions/checkout@%s\n"
            "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n" % ("b" * 40),
            triggers="  pull_request_target:\n"))
        hits = findings_for(findings, "pull-request-target-code-execution")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, "high")

    def test_pr_target_without_checkout_clean(self):
        findings, _ = audit_string(workflow(
            "  label:\n" + MINIMAL_JOB +
            "    steps:\n      - uses: actions/labeler@%s\n" % ("c" * 40),
            triggers="  pull_request_target:\n"))
        self.assertEqual(findings_for(findings, "pull-request-target-code-execution"), [])

    def test_pull_request_event_not_flagged(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB +
            "    steps:\n      - uses: actions/checkout@%s\n"
            "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n" % ("d" * 40),
            triggers="  pull_request:\n"))
        self.assertEqual(findings_for(findings, "pull-request-target-code-execution"), [])

    def test_pr_target_shell_interpolation_flagged(self):
        findings, _ = audit_string(workflow(
            "  preview:\n" + MINIMAL_JOB +
            "    steps:\n      - run: echo \"${{ github.event.pull_request.title }}\"\n",
            triggers="  pull_request_target:\n"))
        hits = findings_for(findings, "pull-request-target-code-execution")
        self.assertEqual(len(hits), 1)
        self.assertIn("pull_request.title", hits[0].message)

    def test_fixture_reports_the_rule(self):
        findings, _ = auditor.audit_paths([PRT])
        self.assertIn("pull-request-target-code-execution", rules_hit(findings))


class TestPermissions(unittest.TestCase):
    def test_missing_permissions_flagged(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB +
            "    steps:\n      - run: echo hi\n", permissions=""))
        hits = findings_for(findings, "permissions-missing")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, "medium")

    def test_explicit_read_permissions_not_flagged(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB + "    steps:\n      - run: echo hi\n"))
        self.assertEqual(findings_for(findings, "permissions-missing"), [])

    def test_empty_permissions_block_not_flagged(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB + "    steps:\n      - run: echo hi\n",
            permissions="permissions: {}\n"))
        self.assertEqual(findings_for(findings, "permissions-missing"), [])

    def test_write_all_string_flagged(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB + "    steps:\n      - run: echo hi\n",
            permissions="permissions: write-all\n"))
        hits = findings_for(findings, "permissions-write-all")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, "high")
        self.assertEqual(hits[0].line, 4)

    def test_job_level_write_all_flagged(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB +
            "    permissions: write-all\n    steps:\n      - run: echo hi\n"))
        hits = findings_for(findings, "permissions-write-all")
        self.assertEqual(len(hits), 1)
        self.assertIn("build", hits[0].message)

    def test_scoped_write_not_flagged(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB +
            "    permissions:\n      contents: write\n"
            "    steps:\n      - run: echo hi\n"))
        self.assertEqual(findings_for(findings, "permissions-write-all"), [])


class TestScriptInjection(unittest.TestCase):
    def test_pr_title_in_run_flagged(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB +
            "    steps:\n      - run: echo \"${{ github.event.pull_request.title }}\"\n"))
        hits = findings_for(findings, "script-injection")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, "high")

    def test_head_ref_in_run_flagged(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB +
            "    steps:\n      - run: git checkout ${{ github.head_ref }}\n"))
        self.assertEqual(len(findings_for(findings, "script-injection")), 1)

    def test_commit_message_in_run_flagged(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB +
            "    steps:\n      - run: echo \"${{ github.event.head_commit.message }}\"\n"))
        self.assertEqual(len(findings_for(findings, "script-injection")), 1)

    def test_issue_body_in_run_flagged(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB +
            "    steps:\n      - run: echo \"${{ github.event.issue.body }}\"\n"))
        self.assertEqual(len(findings_for(findings, "script-injection")), 1)

    def test_workflow_dispatch_input_in_run_flagged(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB +
            "    steps:\n      - run: ./deploy.sh ${{ inputs.environment }}\n"))
        self.assertEqual(len(findings_for(findings, "script-injection")), 1)

    def test_env_interpolation_is_not_flagged(self):
        """The safe pattern: expression into env:, variable into the script."""
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB +
            "    steps:\n      - env:\n"
            "          TITLE: ${{ github.event.pull_request.title }}\n"
            "        run: printf '%s\\n' \"$TITLE\"\n"))
        self.assertEqual(findings_for(findings, "script-injection"), [])

    def test_env_interpolation_does_not_trigger_any_rule(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB +
            "    steps:\n      - env:\n"
            "          TITLE: ${{ github.event.pull_request.title }}\n"
            "          BRANCH: ${{ github.head_ref }}\n"
            "        run: printf '%s %s\\n' \"$TITLE\" \"$BRANCH\"\n"))
        self.assertEqual(findings, [])

    def test_trusted_context_in_run_not_flagged(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB +
            "    steps:\n      - run: echo \"${{ github.repository }} ${{ github.sha }}\"\n"))
        self.assertEqual(findings_for(findings, "script-injection"), [])

    def test_trusted_pr_number_not_flagged(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB +
            "    steps:\n      - run: echo ${{ github.event.pull_request.number }}\n"))
        self.assertEqual(findings_for(findings, "script-injection"), [])

    def test_shell_assignment_of_untrusted_value_flagged(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB +
            "    steps:\n      - run: |\n"
            "          VERSION=${{ github.event.release.tag_name }}\n"
            "          echo \"$VERSION\"\n"))
        self.assertGreaterEqual(len(findings_for(findings, "script-injection")), 1)

    def test_fix_recommends_env_mapping(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB +
            "    steps:\n      - run: echo \"${{ github.head_ref }}\"\n"))
        fix = findings_for(findings, "script-injection")[0].fix
        self.assertIn("env:", fix)
        self.assertIn("$VAR", fix)

    def test_line_is_inside_the_run_step(self):
        source = workflow(
            "  build:\n" + MINIMAL_JOB +
            "    steps:\n      - name: a\n        run: echo a\n"
            "      - name: b\n        run: echo \"${{ github.head_ref }}\"\n")
        findings, _ = audit_string(source)
        hit = findings_for(findings, "script-injection")[0]
        self.assertIn("head_ref", source.splitlines()[hit.line - 1])


class TestForkSecrets(unittest.TestCase):
    def test_secret_in_pull_request_flagged(self):
        findings, _ = audit_string(workflow(
            "  test:\n" + MINIMAL_JOB +
            "    steps:\n      - run: ./x.sh\n"
            "        env:\n          TOKEN: ${{ secrets.CHANGEME_TOKEN }}\n",
            triggers="  pull_request:\n"))
        hits = findings_for(findings, "fork-secret-unavailable")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, "medium")
        self.assertIn("secrets.CHANGEME_TOKEN", hits[0].message)

    def test_secret_in_push_workflow_not_flagged(self):
        findings, _ = audit_string(workflow(
            "  test:\n" + MINIMAL_JOB +
            "    steps:\n      - run: ./x.sh\n"
            "        env:\n          TOKEN: ${{ secrets.CHANGEME_TOKEN }}\n",
            triggers="  push:\n"))
        self.assertEqual(findings_for(findings, "fork-secret-unavailable"), [])

    def test_pull_request_target_secret_handled_by_other_rule(self):
        findings, _ = audit_string(workflow(
            "  test:\n" + MINIMAL_JOB +
            "    steps:\n      - run: ./x.sh\n"
            "        env:\n          TOKEN: ${{ secrets.CHANGEME_TOKEN }}\n",
            triggers="  pull_request_target:\n"))
        self.assertEqual(findings_for(findings, "fork-secret-unavailable"), [])

    def test_workflow_run_makes_secrets_available(self):
        findings, _ = audit_string(workflow(
            "  test:\n" + MINIMAL_JOB +
            "    steps:\n      - run: ./x.sh\n"
            "        env:\n          TOKEN: ${{ secrets.CHANGEME_TOKEN }}\n",
            triggers="  pull_request:\n  workflow_run:\n    workflows: [CI]\n"))
        self.assertEqual(findings_for(findings, "fork-secret-unavailable"), [])

    def test_no_secret_reference_no_finding(self):
        findings, _ = audit_string(workflow(
            "  test:\n" + MINIMAL_JOB + "    steps:\n      - run: ./x.sh\n",
            triggers="  pull_request:\n"))
        self.assertEqual(findings_for(findings, "fork-secret-unavailable"), [])

    def test_secret_value_is_not_echoed_verbatim_as_a_value(self):
        findings, _ = audit_string(workflow(
            "  test:\n" + MINIMAL_JOB +
            "    steps:\n      - run: ./x.sh\n"
            "        env:\n          TOKEN: ${{ secrets.CHANGEME_TOKEN }}\n",
            triggers="  pull_request:\n"))
        hit = findings_for(findings, "fork-secret-unavailable")[0]
        self.assertNotIn("=", hit.message.split("references")[1].split("in a")[0])


class TestJobTimeout(unittest.TestCase):
    def test_missing_timeout_flagged(self):
        findings, _ = audit_string(
            "name: x\non:\n  push:\npermissions:\n  contents: read\njobs:\n"
            "  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
        hits = findings_for(findings, "job-timeout-missing")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, "medium")
        self.assertIn("build", hits[0].message)

    def test_present_timeout_not_flagged(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB + "    steps:\n      - run: echo hi\n"))
        self.assertEqual(findings_for(findings, "job-timeout-missing"), [])

    def test_zero_timeout_counts_as_present(self):
        findings, _ = audit_string(workflow(
            "  build:\n    runs-on: ubuntu-latest\n    timeout-minutes: 0\n"
            "    steps:\n      - run: echo hi\n"))
        self.assertEqual(findings_for(findings, "job-timeout-missing"), [])


class TestConcurrency(unittest.TestCase):
    def test_deploy_job_without_concurrency_flagged(self):
        findings, _ = audit_string(workflow(
            "  deploy:\n" + MINIMAL_JOB + "    steps:\n      - run: ./deploy.sh\n"))
        hits = findings_for(findings, "concurrency-missing-deploy")
        self.assertEqual(len(hits), 1)
        self.assertIn("deploy", hits[0].message)

    def test_non_deploy_job_not_flagged(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB + "    steps:\n      - run: echo hi\n"))
        self.assertEqual(findings_for(findings, "concurrency-missing-deploy"), [])

    def test_concurrency_present_not_flagged(self):
        findings, _ = audit_string(
            "name: x\non:\n  push:\npermissions:\n  contents: read\n"
            "concurrency:\n  group: deploy\n  cancel-in-progress: false\n"
            "jobs:\n  deploy:\n" + MINIMAL_JOB + "    steps:\n      - run: ./deploy.sh\n")
        self.assertEqual(findings_for(findings, "concurrency-missing-deploy"), [])

    def test_environment_keyword_marks_a_deploy(self):
        findings, _ = audit_string(workflow(
            "  ship:\n    runs-on: ubuntu-latest\n    timeout-minutes: 5\n"
            "    environment: production\n    steps:\n      - run: echo hi\n"))
        self.assertEqual(len(findings_for(findings, "concurrency-missing-deploy")), 1)

    def test_publish_keyword_marks_a_deploy(self):
        findings, _ = audit_string(workflow(
            "  publish-package:\n" + MINIMAL_JOB + "    steps:\n      - run: echo hi\n"))
        self.assertEqual(len(findings_for(findings, "concurrency-missing-deploy")), 1)


class TestPersistCredentials(unittest.TestCase):
    def test_checkout_without_persist_false_flagged(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB +
            "    steps:\n      - uses: actions/checkout@%s\n"
            "      - run: npm test\n" % ("e" * 40),
            triggers="  pull_request:\n"))
        hits = findings_for(findings, "checkout-persist-credentials")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, "medium")

    def test_persist_false_not_flagged(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB +
            "    steps:\n      - uses: actions/checkout@%s\n"
            "        with:\n          persist-credentials: false\n"
            "      - run: npm test\n" % ("e" * 40),
            triggers="  pull_request:\n"))
        self.assertEqual(findings_for(findings, "checkout-persist-credentials"), [])

    def test_explicit_token_not_flagged(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB +
            "    steps:\n      - uses: actions/checkout@%s\n"
            "        with:\n          token: ${{ secrets.CHANGEME_TOKEN }}\n"
            "      - run: npm test\n" % ("e" * 40),
            triggers="  pull_request:\n"))
        self.assertEqual(findings_for(findings, "checkout-persist-credentials"), [])

    def test_no_later_steps_not_flagged(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB +
            "    steps:\n      - uses: actions/checkout@%s\n" % ("e" * 40),
            triggers="  push:\n"))
        self.assertEqual(findings_for(findings, "checkout-persist-credentials"), [])

    def test_line_points_at_the_checkout_step(self):
        source = workflow(
            "  build:\n" + MINIMAL_JOB +
            "    steps:\n      - name: warm\n        run: echo warm\n"
            "      - uses: actions/checkout@%s\n      - run: npm test\n" % ("e" * 40),
            triggers="  pull_request:\n")
        findings, _ = audit_string(source)
        hit = findings_for(findings, "checkout-persist-credentials")[0]
        self.assertIn("actions/checkout", source.splitlines()[hit.line - 1])


class TestContinueOnErrorDeploy(unittest.TestCase):
    def test_job_level_continue_on_error_on_deploy_flagged(self):
        findings, _ = audit_string(workflow(
            "  deploy:\n    runs-on: ubuntu-latest\n    timeout-minutes: 5\n"
            "    continue-on-error: true\n    steps:\n      - run: ./deploy.sh\n"))
        hits = findings_for(findings, "continue-on-error-deploy")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, "high")

    def test_job_level_continue_on_error_on_build_not_flagged(self):
        findings, _ = audit_string(workflow(
            "  build:\n    runs-on: ubuntu-latest\n    timeout-minutes: 5\n"
            "    continue-on-error: true\n    steps:\n      - run: echo hi\n"))
        self.assertEqual(findings_for(findings, "continue-on-error-deploy"), [])

    def test_step_level_on_publish_step_flagged(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB +
            "    steps:\n      - name: Publish package\n"
            "        continue-on-error: true\n        run: ./publish.sh\n"))
        hits = findings_for(findings, "continue-on-error-deploy")
        self.assertEqual(len(hits), 1)

    def test_step_level_on_test_step_not_flagged(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB +
            "    steps:\n      - name: Run tests\n"
            "        continue-on-error: true\n        run: ./test.sh\n"))
        self.assertEqual(findings_for(findings, "continue-on-error-deploy"), [])

    def test_string_true_also_detected(self):
        findings, _ = audit_string(workflow(
            "  deploy:\n    runs-on: ubuntu-latest\n    timeout-minutes: 5\n"
            "    continue-on-error: \"true\"\n    steps:\n      - run: ./deploy.sh\n"))
        self.assertEqual(len(findings_for(findings, "continue-on-error-deploy")), 1)


class TestSelfHosted(unittest.TestCase):
    def test_self_hosted_label_flagged(self):
        findings, _ = audit_string(workflow(
            "  build:\n    runs-on: self-hosted\n    timeout-minutes: 5\n"
            "    steps:\n      - run: echo hi\n"))
        hits = findings_for(findings, "self-hosted-runner")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, "medium")

    def test_self_hosted_list_label_flagged(self):
        findings, _ = audit_string(workflow(
            "  build:\n    runs-on: [self-hosted, linux]\n    timeout-minutes: 5\n"
            "    steps:\n      - run: echo hi\n"))
        self.assertEqual(len(findings_for(findings, "self-hosted-runner")), 1)

    def test_github_hosted_not_flagged(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB + "    steps:\n      - run: echo hi\n"))
        self.assertEqual(findings_for(findings, "self-hosted-runner"), [])

    def test_fix_mentions_visibility_caveat(self):
        findings, _ = audit_string(workflow(
            "  build:\n    runs-on: self-hosted\n    timeout-minutes: 5\n"
            "    steps:\n      - run: echo hi\n"))
        hit = findings_for(findings, "self-hosted-runner")[0]
        self.assertIn("visibility", hit.fix)


class TestWorkflowRunCheckout(unittest.TestCase):
    TRIGGER = "  workflow_run:\n    workflows: [CI]\n"

    def test_head_sha_checkout_flagged(self):
        findings, _ = audit_string(workflow(
            "  publish:\n" + MINIMAL_JOB +
            "    steps:\n      - uses: actions/checkout@%s\n"
            "        with:\n          ref: ${{ github.event.workflow_run.head_sha }}\n" % ("f" * 40),
            triggers=self.TRIGGER))
        hits = findings_for(findings, "workflow-run-checkout")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, "high")

    def test_head_branch_checkout_flagged(self):
        findings, _ = audit_string(workflow(
            "  publish:\n" + MINIMAL_JOB +
            "    steps:\n      - uses: actions/checkout@%s\n"
            "        with:\n          ref: ${{ github.event.workflow_run.head_branch }}\n" % ("f" * 40),
            triggers=self.TRIGGER))
        self.assertEqual(len(findings_for(findings, "workflow-run-checkout")), 1)

    def test_pinned_sha_checkout_not_flagged(self):
        findings, _ = audit_string(workflow(
            "  publish:\n" + MINIMAL_JOB +
            "    steps:\n      - uses: actions/checkout@%s\n"
            "        with:\n          ref: %s\n" % ("f" * 40, "a" * 40),
            triggers=self.TRIGGER))
        self.assertEqual(findings_for(findings, "workflow-run-checkout"), [])

    def test_default_checkout_not_flagged(self):
        findings, _ = audit_string(workflow(
            "  publish:\n" + MINIMAL_JOB +
            "    steps:\n      - uses: actions/checkout@%s\n" % ("f" * 40),
            triggers=self.TRIGGER))
        self.assertEqual(findings_for(findings, "workflow-run-checkout"), [])

    def test_pr_head_checkout_without_workflow_run_not_flagged(self):
        findings, _ = audit_string(workflow(
            "  publish:\n" + MINIMAL_JOB +
            "    steps:\n      - uses: actions/checkout@%s\n"
            "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n" % ("f" * 40),
            triggers="  push:\n"))
        self.assertEqual(findings_for(findings, "workflow-run-checkout"), [])


class TestCacheKey(unittest.TestCase):
    def test_cache_without_key_flagged(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB +
            "    steps:\n      - uses: actions/cache@%s\n"
            "        with:\n          path: ~/.npm\n" % ("1" * 40)))
        self.assertEqual(len(findings_for(findings, "cache-key-no-lockfile")), 1)

    def test_static_key_flagged(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB +
            "    steps:\n      - uses: actions/cache@%s\n"
            "        with:\n          path: ~/.npm\n          key: npm-static\n" % ("1" * 40)))
        hits = findings_for(findings, "cache-key-no-lockfile")
        self.assertEqual(len(hits), 1)
        self.assertIn("npm-static", hits[0].message)

    def test_lockfile_hash_key_not_flagged(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB +
            "    steps:\n      - uses: actions/cache@%s\n"
            "        with:\n          path: ~/.npm\n"
            "          key: ${{ runner.os }}-${{ hashFiles('**/package-lock.json') }}\n" % ("1" * 40)))
        self.assertEqual(findings_for(findings, "cache-key-no-lockfile"), [])

    def test_setup_node_cache_without_lockfile_path_flagged(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB +
            "    steps:\n      - uses: actions/setup-node@%s\n"
            "        with:\n          node-version: 20\n          cache: npm\n" % ("2" * 40)))
        self.assertEqual(len(findings_for(findings, "cache-key-no-lockfile")), 1)

    def test_setup_node_with_lockfile_path_not_flagged(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB +
            "    steps:\n      - uses: actions/setup-node@%s\n"
            "        with:\n          node-version: 20\n          cache: npm\n"
            "          cache-dependency-path: package-lock.json\n" % ("2" * 40)))
        self.assertEqual(findings_for(findings, "cache-key-no-lockfile"), [])

    def test_setup_node_without_cache_at_all_not_flagged(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB +
            "    steps:\n      - uses: actions/setup-node@%s\n"
            "        with:\n          node-version: 20\n" % ("2" * 40)))
        self.assertEqual(findings_for(findings, "cache-key-no-lockfile"), [])

    def test_severity_is_low(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB +
            "    steps:\n      - uses: actions/cache@%s\n"
            "        with:\n          path: ~/.npm\n          key: static\n" % ("1" * 40)))
        hit = findings_for(findings, "cache-key-no-lockfile")[0]
        self.assertEqual(hit.severity, "low")


class TestAlwaysOnPublish(unittest.TestCase):
    def test_always_on_publish_step_flagged(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB +
            "    steps:\n      - name: Publish\n        if: always()\n"
            "        run: npm publish\n"))
        hits = findings_for(findings, "always-on-publish")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, "medium")

    def test_always_on_test_step_not_flagged(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB +
            "    steps:\n      - name: Upload logs\n        if: always()\n"
            "        run: ./upload-logs.sh\n"))
        self.assertEqual(findings_for(findings, "always-on-publish"), [])

    def test_always_on_deploy_action_flagged(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB +
            "    steps:\n      - if: always()\n"
            "        uses: actions/deploy-pages@%s\n" % ("3" * 40)))
        self.assertEqual(len(findings_for(findings, "always-on-publish")), 1)

    def test_always_on_gh_pages_action_flagged(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB +
            "    steps:\n      - if: always()\n"
            "        uses: peaceiris/actions-gh-pages@%s\n" % ("4" * 40)))
        self.assertEqual(len(findings_for(findings, "always-on-publish")), 1)

    def test_success_guard_not_flagged(self):
        findings, _ = audit_string(workflow(
            "  build:\n" + MINIMAL_JOB +
            "    steps:\n      - name: Publish\n        if: success()\n"
            "        run: npm publish\n"))
        self.assertEqual(findings_for(findings, "always-on-publish"), [])

    def test_line_points_at_the_if(self):
        source = workflow(
            "  build:\n" + MINIMAL_JOB +
            "    steps:\n      - name: Publish\n        if: always()\n"
            "        run: npm publish\n")
        findings, _ = audit_string(source)
        hit = findings_for(findings, "always-on-publish")[0]
        self.assertIn("always()", source.splitlines()[hit.line - 1])


# --------------------------------------------------------------------------
# Negative control and full fixtures
# --------------------------------------------------------------------------


class TestNegativeControl(unittest.TestCase):
    """A genuinely hardened workflow must yield exactly zero findings."""

    def test_hardened_fixture_is_clean_default_backend(self):
        findings, _ = auditor.audit_paths([HARDENED])
        self.assertEqual([f.as_dict() for f in findings], [],
                         "hardened fixture must be completely clean")

    def test_hardened_fixture_is_clean_native_backend(self):
        findings, _ = auditor.audit_paths([HARDENED], prefer_native=True)
        self.assertEqual(findings, [])

    def test_hardened_fixture_parses_with_jobs(self):
        _, metas = auditor.audit_paths([HARDENED])
        self.assertEqual(metas[0]["jobs"], ["build", "test"])
        self.assertFalse(metas[0]["has_jobs"] is False)

    def test_on_trap_fixture_is_clean(self):
        findings, _ = auditor.audit_paths([ON_TRAP])
        self.assertEqual(findings, [])


class TestFixtureFindings(unittest.TestCase):
    def test_bad_fixture_hits_eleven_rules(self):
        findings, _ = auditor.audit_paths([BAD])
        self.assertGreaterEqual(len(findings), 15)
        self.assertEqual(
            rules_hit(findings),
            {
                "mutable-action-ref",
                "permissions-write-all",
                "script-injection",
                "job-timeout-missing",
                "concurrency-missing-deploy",
                "checkout-persist-credentials",
                "continue-on-error-deploy",
                "self-hosted-runner",
                "workflow-run-checkout",
                "cache-key-no-lockfile",
                "always-on-publish",
            },
        )

    def test_bad_fixture_has_high_findings(self):
        findings, _ = auditor.audit_paths([BAD])
        summary = auditor.summarize(findings)
        self.assertGreaterEqual(summary["high"], 8)
        self.assertGreaterEqual(summary["medium"], 5)
        self.assertGreaterEqual(summary["low"], 2)
        self.assertEqual(summary["total"],
                         summary["high"] + summary["medium"] + summary["low"])

    def test_findings_sorted_by_severity_then_rule(self):
        findings, _ = auditor.audit_paths([BAD])
        ranks = [auditor.SEVERITY_RANK[f.severity] for f in findings]
        self.assertEqual(ranks, sorted(ranks, reverse=True))

    def test_every_finding_carries_a_fix(self):
        findings, _ = auditor.audit_paths([FIXTURES])
        self.assertGreater(len(findings), 20)
        for finding in findings:
            with self.subTest(rule=finding.rule_id):
                self.assertTrue(finding.fix.strip())
                self.assertGreaterEqual(finding.line, 1)
                self.assertIn(finding.severity, auditor.SEVERITIES)

    def test_workflow_run_fixture(self):
        findings, _ = auditor.audit_paths([WORKFLOW_RUN])
        self.assertIn("workflow-run-checkout", rules_hit(findings))

    def test_fork_secrets_fixture(self):
        findings, _ = auditor.audit_paths([FORKSECRETS])
        hits = findings_for(findings, "fork-secret-unavailable")
        self.assertEqual(len(hits), 1)


# --------------------------------------------------------------------------
# YAML backends
# --------------------------------------------------------------------------


class TestYamlBackends(unittest.TestCase):
    def test_native_reader_parses_a_mapping(self):
        data, lines, backend = miniyaml.load_string(
            "name: x\njobs:\n  a:\n    runs-on: ubuntu-latest\n",
            prefer_native=True)
        self.assertEqual(backend, "native")
        self.assertEqual(data["name"], "x")
        self.assertEqual(data["jobs"]["a"]["runs-on"], "ubuntu-latest")

    def test_native_reader_parses_flow_sequences(self):
        data, _, _ = miniyaml.load_string(
            "on:\n  pull_request:\n    branches: [main, dev]\n",
            prefer_native=True)
        # The native backend keeps mapping keys as written, so the trigger key
        # is the string "on" (PyYAML would coerce it to True; see TestOnKeyTrap).
        triggers = miniyaml.get_workflow_triggers(data)
        self.assertEqual(triggers["pull_request"]["branches"], ["main", "dev"])

    def test_native_reader_parses_flow_mapping(self):
        data, _, _ = miniyaml.load_string(
            "permissions: {contents: read, id-token: write}\n", prefer_native=True)
        self.assertEqual(data["permissions"],
                         {"contents": "read", "id-token": "write"})

    def test_native_reader_parses_block_scalar(self):
        source = ("run: |\n  line one\n  line two\n")
        data, _, _ = miniyaml.load_string(source, prefer_native=True)
        self.assertEqual(data["run"], "line one\nline two\n")

    def test_native_reader_folds_block_scalar(self):
        source = "run: >\n  line one\n  line two\n"
        data, _, _ = miniyaml.load_string(source, prefer_native=True)
        self.assertIn("line one line two", data["run"])

    def test_native_reader_strips_chomping_indicator(self):
        data, _, _ = miniyaml.load_string("run: |-\n  a\n  b\n", prefer_native=True)
        self.assertEqual(data["run"], "a\nb")

    def test_native_reader_handles_quoted_values_and_comments(self):
        data, _, _ = miniyaml.load_string(
            'a: "hello: world"  # trailing comment\nb: 12\nc: true\nd: null\n',
            prefer_native=True)
        self.assertEqual(data["a"], "hello: world")
        self.assertEqual(data["b"], 12)
        self.assertIs(data["c"], True)
        self.assertIsNone(data["d"])

    def test_native_reader_joins_multiline_flow_collection(self):
        source = "key: [\n  one,\n  two\n]\n"
        data, _, _ = miniyaml.load_string(source, prefer_native=True)
        self.assertEqual(data["key"], ["one", "two"])

    def test_native_reader_nested_sequence_of_mappings(self):
        source = ("steps:\n"
                  "  - name: one\n"
                  "    uses: a/b@v1\n"
                  "  - name: two\n"
                  "    run: echo hi\n")
        data, _, _ = miniyaml.load_string(source, prefer_native=True)
        self.assertEqual(len(data["steps"]), 2)
        self.assertEqual(data["steps"][0]["uses"], "a/b@v1")
        self.assertEqual(data["steps"][1]["run"], "echo hi")

    def test_native_reader_reports_line_numbers(self):
        source = "name: x\n\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
        _, lines, _ = miniyaml.load_string(source, prefer_native=True)
        # Containers report their first child's line, matching PyYAML: "build"
        # starts on line 4 and declares runs-on on line 5.
        self.assertEqual(lines["jobs.build"], 5)
        self.assertEqual(lines["jobs.build.runs-on"], 5)
        self.assertEqual(lines["name"], 1)

    def test_native_reader_step_line_numbers(self):
        source = ("jobs:\n"
                  "  build:\n"
                  "    steps:\n"
                  "      - name: one\n"
                  "        run: echo one\n"
                  "      - uses: a/b@v1\n")
        _, lines, _ = miniyaml.load_string(source, prefer_native=True)
        self.assertEqual(lines["jobs.build.steps[0]"], 4)
        self.assertEqual(lines["jobs.build.steps[0].run"], 5)
        self.assertEqual(lines["jobs.build.steps[1]"], 6)
        self.assertEqual(lines["jobs.build.steps[1].uses"], 6)

    def test_duplicate_key_is_an_error(self):
        with self.assertRaises(miniyaml.YamlError):
            miniyaml.load_string("a: 1\na: 2\n", prefer_native=True)

    def test_malformed_indentation_is_an_error(self):
        with open(MALFORMED, "r", encoding="utf-8") as handle:
            source = handle.read()
        with self.assertRaises(miniyaml.YamlError):
            miniyaml.load_string(source, prefer_native=True)

    def test_unbalanced_flow_is_an_error(self):
        with self.assertRaises(miniyaml.YamlError):
            miniyaml.load_string("a: [1, 2\nb: 3\n", prefer_native=True)

    def test_comments_only_is_an_error(self):
        with self.assertRaises(miniyaml.YamlError):
            miniyaml.load_string("# only a comment\n", prefer_native=True)

    def test_multi_document_is_a_split_error(self):
        with self.assertRaises(miniyaml.SplitError):
            miniyaml.load_string("a: 1\n---\nb: 2\n", prefer_native=True)

    def test_multi_document_is_rejected_by_every_backend(self):
        # PyYAML reports this as a compose error rather than a split; either way
        # it must be a YamlError so the CLI exits 2 instead of auditing half a file.
        with self.assertRaises(miniyaml.YamlError):
            miniyaml.load_string("a: 1\n---\nb: 2\n")

    def test_single_leading_document_marker_is_accepted(self):
        data, _, _ = miniyaml.load_string("---\na: 1\n", prefer_native=True)
        self.assertEqual(data, {"a": 1})

    def test_trailing_document_end_marker_is_accepted(self):
        data, _, _ = miniyaml.load_string("a: 1\n...\n", prefer_native=True)
        self.assertEqual(data, {"a": 1})

    def test_split_error_is_a_yaml_error(self):
        self.assertTrue(issubclass(miniyaml.SplitError, miniyaml.YamlError))

    @unittest.skipUnless(miniyaml.pyyaml_available(), "PyYAML not importable")
    def test_pyyaml_backend_is_used_when_available(self):
        _, _, backend = miniyaml.load_string("a: 1\n")
        self.assertEqual(backend, "pyyaml")
        self.assertEqual(miniyaml.backend_name(), "pyyaml")

    @unittest.skipUnless(miniyaml.pyyaml_available(), "PyYAML not importable")
    def test_pyyaml_reports_malformed_yaml_as_yamlerror(self):
        with open(MALFORMED, "r", encoding="utf-8") as handle:
            source = handle.read()
        with self.assertRaises(miniyaml.YamlError) as caught:
            miniyaml.load_string(source)
        self.assertIsNotNone(caught.exception.line)

    def test_backend_parity_across_all_fixtures(self):
        """Both backends must produce byte-identical findings."""
        for name in sorted(os.listdir(FIXTURES)):
            if not name.endswith((".yml", ".yaml")):
                continue
            path = os.path.join(FIXTURES, name)
            with self.subTest(fixture=name):
                with open(path, "r", encoding="utf-8") as handle:
                    source = handle.read()
                native, _ = auditor.audit_source(path, name, source, prefer_native=True)
                if not miniyaml.pyyaml_available():
                    continue
                pyyaml_findings, _ = auditor.audit_source(path, name, source,
                                                         prefer_native=False)
                self.assertEqual([f.as_dict() for f in native],
                                 [f.as_dict() for f in pyyaml_findings])


class TestOnKeyTrap(unittest.TestCase):
    """The YAML 1.1 `on:` -> boolean True trap, in both directions."""

    SOURCE = "name: x\non:\n  pull_request:\npermissions:\n  contents: read\n"

    def test_unquoted_on_retrievable_by_either_spelling(self):
        data, _, _ = miniyaml.load_string(self.SOURCE, prefer_native=True)
        self.assertEqual(miniyaml.get_workflow_triggers(data),
                         {"pull_request": None})
        self.assertEqual(miniyaml.trigger_names(
            miniyaml.get_workflow_triggers(data)), ["pull_request"])

    def test_boolean_true_key_is_accepted_directly(self):
        data = {"name": "x", True: {"pull_request": None}}
        self.assertEqual(miniyaml.get_workflow_triggers(data),
                         {"pull_request": None})

    def test_string_true_key_is_accepted_directly(self):
        data = {"name": "x", "True": {"pull_request": None}}
        self.assertEqual(miniyaml.get_workflow_triggers(data),
                         {"pull_request": None})

    def test_string_on_key_is_accepted(self):
        data = {"name": "x", "on": {"push": None}}
        self.assertEqual(miniyaml.get_workflow_triggers(data), {"push": None})

    def test_missing_trigger_key_returns_none(self):
        self.assertIsNone(miniyaml.get_workflow_triggers({"name": "x"}))
        self.assertEqual(miniyaml.trigger_names(None), [])

    def test_rules_see_the_trigger_not_the_boolean(self):
        """A pull_request rule must fire even though the key parsed as True."""
        source = (
            "name: x\non:\n  pull_request:\npermissions:\n  contents: read\n"
            "jobs:\n  test:\n    runs-on: ubuntu-latest\n    timeout-minutes: 5\n"
            "    steps:\n      - run: ./x.sh\n"
            "        env:\n          T: ${{ secrets.CHANGEME_TOKEN }}\n")
        findings, meta = audit_string(source)
        self.assertEqual(meta["on_key_parsed_as"], "true")
        self.assertIn("pull_request", meta["triggers"])
        self.assertEqual(len(findings_for(findings, "fork-secret-unavailable")), 1)

    def test_quoted_on_key_is_a_string_and_still_works(self):
        source = (
            'name: x\n"on":\n  pull_request:\npermissions:\n  contents: read\n'
            "jobs:\n  test:\n    runs-on: ubuntu-latest\n    timeout-minutes: 5\n"
            "    steps:\n      - run: ./x.sh\n"
            "        env:\n          T: ${{ secrets.CHANGEME_TOKEN }}\n")
        findings, meta = audit_string(source)
        self.assertEqual(meta["on_key_parsed_as"], "on")
        self.assertIn("pull_request", meta["triggers"])
        self.assertEqual(len(findings_for(findings, "fork-secret-unavailable")), 1)

    @unittest.skipUnless(miniyaml.pyyaml_available(), "PyYAML not importable")
    def test_pyyaml_really_turns_on_into_a_boolean(self):
        """Documents the observed PyYAML behaviour, and that we survive it."""
        import yaml
        parsed = yaml.safe_load(self.SOURCE)
        self.assertIn(True, parsed,
                      "PyYAML is expected to parse an unquoted 'on:' key as True")
        self.assertNotIn("on", parsed)
        data, _, backend = miniyaml.load_string(self.SOURCE)
        self.assertEqual(backend, "pyyaml")
        self.assertEqual(miniyaml.on_key_kind(data), "true")
        self.assertEqual(miniyaml.get_workflow_triggers(data),
                         {"pull_request": None})

    def test_on_key_kind_reports_absent(self):
        self.assertIsNone(miniyaml.on_key_kind({"name": "x"}))

    def test_trigger_map_normalises_list_and_string_forms(self):
        self.assertEqual(auditor.trigger_map({"on": "push"}), {"push": None})
        self.assertEqual(auditor.trigger_map({"on": ["push", "pull_request"]}),
                         {"push": None, "pull_request": None})
        self.assertEqual(auditor.trigger_map({}), {})

    def test_workflow_without_triggers_reports_empty(self):
        findings, meta = audit_string(
            "name: x\npermissions:\n  contents: read\njobs:\n  a:\n"
            "    runs-on: ubuntu-latest\n    timeout-minutes: 5\n"
            "    steps:\n      - run: echo hi\n")
        self.assertEqual(meta["triggers"], [])
        self.assertEqual(findings, [])


class TestMalformedInputs(unittest.TestCase):
    def test_audit_source_rejects_malformed_yaml(self):
        with self.assertRaises(auditor.RuleError):
            audit_string("name: x\njobs:\n  a:\n    runs-on: y\n      steps:\n")

    def test_audit_paths_rejects_malformed_fixture(self):
        with self.assertRaises(auditor.RuleError) as caught:
            auditor.audit_paths([MALFORMED])
        self.assertIn("line", str(caught.exception))

    def test_audit_paths_rejects_comment_only_fixture(self):
        with self.assertRaises(auditor.RuleError):
            auditor.audit_paths([EMPTY])

    def test_top_level_sequence_is_rejected(self):
        with self.assertRaises(auditor.RuleError) as caught:
            audit_string("- one\n- two\n")
        self.assertIn("mapping", str(caught.exception))

    def test_missing_path_is_rejected(self):
        with self.assertRaises(auditor.RuleError):
            auditor.audit_paths([os.path.join(FIXTURES, "does-not-exist.yml")])

    def test_directory_without_workflows_is_rejected(self):
        empty_dir = os.path.join(HERE, "_empty_dir_for_test")
        os.makedirs(empty_dir, exist_ok=True)
        try:
            with self.assertRaises(auditor.RuleError):
                auditor.audit_paths([empty_dir])
        finally:
            os.rmdir(empty_dir)


# --------------------------------------------------------------------------
# Path expansion
# --------------------------------------------------------------------------


class TestPathExpansion(unittest.TestCase):
    def test_single_file(self):
        self.assertEqual(auditor.expand_paths([BAD]), [BAD])

    def test_workflows_directory(self):
        found = auditor.expand_paths([FIXTURES])
        self.assertIn(BAD, found)
        self.assertIn(HARDENED, found)
        self.assertEqual(len(found), len(set(found)))

    def test_repository_root_finds_github_workflows(self):
        repo = os.path.join(HERE, "_repo_for_test")
        workflows = os.path.join(repo, ".github", "workflows")
        os.makedirs(workflows, exist_ok=True)
        target = os.path.join(workflows, "ci.yml")
        with open(target, "w", encoding="utf-8") as handle:
            handle.write("name: ci\non:\n  push:\npermissions:\n  contents: read\n"
                         "jobs:\n  a:\n    runs-on: ubuntu-latest\n"
                         "    timeout-minutes: 5\n    steps:\n      - run: echo hi\n")
        try:
            found = auditor.expand_paths([repo])
            self.assertEqual(found, [target])
            findings, _ = auditor.audit_paths([repo])
            self.assertEqual(findings, [])
        finally:
            os.remove(target)
            os.rmdir(workflows)
            os.rmdir(os.path.join(repo, ".github"))
            os.rmdir(repo)

    def test_yaml_extension_is_accepted(self):
        directory = os.path.join(HERE, "_yaml_ext_for_test")
        os.makedirs(directory, exist_ok=True)
        target = os.path.join(directory, "ci.yaml")
        with open(target, "w", encoding="utf-8") as handle:
            handle.write("name: ci\n")
        try:
            self.assertEqual(auditor.expand_paths([directory]), [target])
        finally:
            os.remove(target)
            os.rmdir(directory)

    def test_non_yaml_files_are_ignored(self):
        directory = os.path.join(HERE, "_mixed_for_test")
        os.makedirs(directory, exist_ok=True)
        keep = os.path.join(directory, "ci.yml")
        skip = os.path.join(directory, "notes.txt")
        for path in (keep, skip):
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("name: x\n")
        try:
            self.assertEqual(auditor.expand_paths([directory]), [keep])
        finally:
            os.remove(keep)
            os.remove(skip)
            os.rmdir(directory)

    def test_inline_directory_named_workflows(self):
        directory = os.path.join(HERE, "_wf_dir_for_test")
        os.makedirs(directory, exist_ok=True)
        target = os.path.join(directory, "a.yml")
        with open(target, "w", encoding="utf-8") as handle:
            handle.write("name: x\n")
        try:
            self.assertEqual(auditor.expand_paths([directory]), [target])
        finally:
            os.remove(target)
            os.rmdir(directory)


# --------------------------------------------------------------------------
# Rendering and CLI
# --------------------------------------------------------------------------


class TestRendering(unittest.TestCase):
    def test_human_output_lists_rule_line_and_fix(self):
        findings, metas = auditor.audit_paths([BAD])
        text = auditor.render_human(findings, metas)
        self.assertIn("[HIGH] mutable-action-ref", text)
        self.assertIn("fix:", text)
        self.assertIn("finding(s):", text)
        self.assertIn("bad-workflow.yml:", text)

    def test_human_output_notes_the_on_key_trap(self):
        findings, metas = auditor.audit_paths([BAD])
        text = auditor.render_human(findings, metas)
        self.assertIn("parsed as: true", text)
        self.assertIn("YAML 1.1", text)

    def test_quiet_output_has_no_header(self):
        findings, metas = auditor.audit_paths([BAD])
        text = auditor.render_human(findings, metas, quiet=True)
        self.assertNotIn("yaml backend:", text)
        self.assertIn("finding(s):", text)

    def test_clean_render_says_zero(self):
        findings, metas = auditor.audit_paths([HARDENED])
        text = auditor.render_human(findings, metas)
        self.assertIn("0 finding(s): 0 high, 0 medium, 0 low", text)

    def test_json_output_is_valid_and_complete(self):
        findings, metas = auditor.audit_paths([BAD])
        payload = json.loads(auditor.render_json(findings, metas, "1.0.0"))
        self.assertEqual(payload["tool"], "actions-audit")
        self.assertEqual(len(payload["findings"]), len(findings))
        self.assertEqual(payload["summary"]["total"], len(findings))
        self.assertEqual(payload["files"][0]["backend"],
                         miniyaml.backend_name())
        first = payload["findings"][0]
        self.assertEqual(set(first), {"rule", "severity", "path", "line",
                                      "message", "fix", "evidence"})

    def test_summarize_counts_by_severity(self):
        findings, _ = auditor.audit_paths([BAD])
        summary = auditor.summarize(findings)
        self.assertEqual(summary["total"], len(findings))
        self.assertEqual(set(summary), {"high", "medium", "low", "total"})


class TestCli(unittest.TestCase):
    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_clean_exit_zero(self):
        code, out, _ = self.run_cli([HARDENED])
        self.assertEqual(code, 0)
        self.assertIn("0 finding(s)", out)

    def test_findings_exit_one(self):
        code, _, _ = self.run_cli([BAD])
        self.assertEqual(code, 1)

    def test_malformed_exit_two(self):
        code, _, err = self.run_cli([MALFORMED])
        self.assertEqual(code, 2)
        self.assertIn("error", err.lower())

    def test_missing_path_exit_two(self):
        code, _, err = self.run_cli([os.path.join(FIXTURES, "nope.yml")])
        self.assertEqual(code, 2)
        self.assertIn("does not exist", err)

    def test_no_path_exit_two(self):
        code, _, err = self.run_cli([])
        self.assertEqual(code, 2)
        self.assertIn("path is required", err)

    def test_severity_high_threshold_passes_on_medium_only(self):
        code, _, _ = self.run_cli([FORKSECRETS, "--severity", "high"])
        self.assertEqual(code, 0)

    def test_severity_medium_threshold_fails_on_medium_only(self):
        code, _, _ = self.run_cli([FORKSECRETS, "--severity", "medium"])
        self.assertEqual(code, 1)

    def test_severity_low_still_reports_but_default_does_not_fail_on_low(self):
        directory = os.path.join(HERE, "_lowonly_for_test")
        os.makedirs(directory, exist_ok=True)
        target = os.path.join(directory, "ci.yml")
        with open(target, "w", encoding="utf-8") as handle:
            handle.write(
                "name: ci\non:\n  push:\npermissions:\n  contents: read\n"
                "jobs:\n  build:\n    runs-on: ubuntu-latest\n"
                "    timeout-minutes: 5\n    steps:\n"
                "      - uses: actions/cache@%s\n"
                "        with:\n          path: ~/.npm\n          key: static\n"
                % ("1" * 40))
        try:
            code, out, _ = self.run_cli([directory])
            self.assertEqual(code, 0, "low findings must not fail the default run")
            self.assertIn("[LOW] cache-key-no-lockfile", out)
            code_low, _, _ = self.run_cli([directory, "--severity", "low"])
            self.assertEqual(code_low, 1)
        finally:
            os.remove(target)
            os.rmdir(directory)

    def test_json_mode_is_parseable_and_suppresses_text(self):
        code, out, _ = self.run_cli([BAD, "--json"])
        self.assertEqual(code, 1)
        payload = json.loads(out)  # --json must emit one clean JSON document
        self.assertEqual(payload["tool"], "actions-audit")
        self.assertGreater(payload["summary"]["total"], 10)
        self.assertNotIn("yaml backend used", out)

    def test_quiet_mode(self):
        code, out, _ = self.run_cli([BAD, "--quiet", "--no-color"])
        self.assertEqual(code, 1)
        self.assertNotIn("yaml backend:", out)

    def test_list_rules(self):
        code, out, _ = self.run_cli(["--list-rules"])
        self.assertEqual(code, 0)
        for entry in auditor.RULES:
            self.assertIn(entry.id, out)
        self.assertIn("actions-audit", out)

    def test_list_rules_json(self):
        code, out, _ = self.run_cli(["--list-rules", "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(len(payload), 14)

    def test_native_yaml_flag_switches_backend(self):
        code, out, _ = self.run_cli([HARDENED, "--native-yaml", "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["files"][0]["backend"], "native")
        code2, out2, _ = self.run_cli([HARDENED, "--native-yaml"])
        self.assertEqual(code2, 0)
        self.assertIn("yaml backend used: native", out2)

    def test_directory_input(self):
        code, out, _ = self.run_cli([FIXTURES, "--quiet"])
        self.assertEqual(code, 1)
        self.assertIn("bad-workflow.yml", out)

    def test_multiple_paths_are_combined(self):
        code, out, _ = self.run_cli([HARDENED, FORKSECRETS, "--quiet"])
        self.assertEqual(code, 1)
        self.assertIn("fork-secrets.yml", out)

    def test_stdout_is_not_coloured_without_a_tty(self):
        _, out, _ = self.run_cli([BAD, "--quiet"])
        self.assertNotIn("\033[", out)

    def test_version_string_is_wired(self):
        parser = cli.build_parser()
        action = [a for a in parser._actions if a.dest == "version"]
        self.assertEqual(len(action), 1)
        self.assertEqual(cli.VERSION, "1.0.0")

    def test_default_fail_severity_is_medium(self):
        self.assertEqual(cli.DEFAULT_FAIL_SEVERITY, "medium")


class TestFixtureHygiene(unittest.TestCase):
    """Fixtures must not contain anything resembling a real credential."""

    # Assembled from fragments on purpose: the prefixes of real credential
    # formats must not appear as literals anywhere in this repository, or a
    # secret scanner (GitHub push protection among them) may flag the scanner's
    # own source. Even bare prefixes can trip naive detectors.
    FORBIDDEN = (
        "gh" + "p_",                       # classic GitHub personal access token
        "github" + "_pat_",                # fine-grained GitHub token
        "AK" + "IA",                       # AWS access key id
        "-" * 5 + "BEGIN",                 # PEM private key header
        "sk" + "-",                        # OpenAI-style API key
        "xox" + "b-",                      # Slack bot token
    )

    def test_no_realistic_secret_patterns_in_fixtures(self):
        for directory in (FIXTURES, INVALID):
            for name in sorted(os.listdir(directory)):
                if not name.endswith((".yml", ".yaml")):
                    continue
                with open(os.path.join(directory, name), "r", encoding="utf-8") as handle:
                    text = handle.read()
                for needle in self.FORBIDDEN:
                    with self.subTest(fixture=name, needle=needle):
                        self.assertNotIn(needle, text)

    def test_fake_secret_names_are_obviously_fake(self):
        with open(BAD, "r", encoding="utf-8") as handle:
            text = handle.read()
        self.assertIn("CHANGEME", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
