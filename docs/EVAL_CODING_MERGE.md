# Coding eval — merge point for the v0.6 proving ground

**Lane:** v0.7 Lane D (coding proving ground), branch `v07-laneD-codingeval`
**Sibling:** v0.6 coordinator / Lane A (security proving ground),
branch `v06-laneA-eval`, worktree `/home/hatch/workspace/aegis-wt-eval`

## What Lane D added (all additive, no v0.6 files touched)

| File | Kind | Notes |
|---|---|---|
| `aegis/eval_coding.py` | NEW | Self-contained coding battery. Does **not** import `eval_runner` — works pre- and post-merge. |
| `evals/COD-001.yaml` … `evals/COD-011.yaml` | NEW | 11 coding tasks (python×5, javascript×4, c×2). New `COD-*` glob — no collision with `EVL-*`. |
| `tests/test_codingeval_v07.py` | NEW | Harness tests. |
| `docs/SCORECARD_CODING.md` | NEW (generated) | Standalone coding scorecard section; staged by `aegis eval`. |
| `aegis/cli.py` | MODIFIED | Superset `cmd_eval` + `--suite` flag on the `eval` subcommand. **This is the one file that will conflict with v0.6's branch — see below.** |

Go and Rust are **UNBUILT** (no toolchains in this environment, no network
to install them). They are omitted from the battery rather than simulated —
see `test_language_type_coverage`.

## Merge recipe (for the v0.7 coordinator)

1. Merge `v06-laneA-eval` first (it owns `aegis/eval_runner.py`,
   `evals/EVL-*.yaml`, `docs/SCORECARD.md`, `tests/test_eval_v06.py`).
2. Merge this branch. Expect **one conflict region** in `aegis/cli.py`:
   both branches add an `eval` subparser and a `cmd_eval`.
   **Resolution: keep Lane D's version** (the superset — it runs the v0.6
   security suite via a lazy `from .eval_runner import ...` import when
   present, plus the coding suite). Delete v0.6's original `cmd_eval`.
3. Publish the combined scorecard:
   `aegis eval --suite all` regenerates `docs/SCORECARD.md` with the v0.6
   security section followed by the coding section (spliced by the
   `<!-- CODING-EVAL-SECTION -->` markers — idempotent).
   Alternatively: `cat docs/SCORECARD_CODING.md >> docs/SCORECARD.md`.
4. Run the full suite: `pytest tests/test_eval_v06.py tests/test_codingeval_v07.py`
   — both must stay green.

## Runtime contract

- `aegis eval` → both suites (default `--suite all`)
- `aegis eval --suite security` → v0.6 guard battery only
- `aegis eval --suite coding` → coding battery only
- `--json` → machine-readable results per suite
- Exit 1 on any enforced failure (CI signal), 2 on harness failure.

## Design invariants (do not break)

- Scoring is **never** self-graded: hidden tests execute via subprocess
  (timeout-capped, fixture cwd under `/tmp`).
- Fixtures are hermetic: temp dirs removed after each task; the repo tree
  is byte-identical before/after a run (asserted by
  `test_fixtures_are_hermetic`).
- Every surfaced string passes through `aegis.detect.secrets.redact`
  (asserted by `test_secrets_redacted_in_surfaced_output`).
- `aegis/eval_coding.py` stays independent of `eval_runner.py` so either
  suite can evolve without breaking the other.
