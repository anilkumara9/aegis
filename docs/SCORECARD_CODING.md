
---

<!-- CODING-EVAL-SECTION -->
## Coding proving ground (v0.7 Lane D)

Generated: 2026-10-19 02:18 UTC | Tasks: 11 | Pass: 7

### Methodology

Each task stages a fixture project under `/tmp` and drives the **real** `AgentLoop` with scripted `MockProvider` solution turns (the deterministic stand-in for the agent under test) through the **real** guard. Scoring comes from **actually executing** a hidden test suite (`subprocess`, timeout-capped, cwd = fixture dir) — never self-graded by the model. A `pass` requires every hidden test to exit 0, plus type-specific real checks: `refactor` tasks must actually change the target file (behavior preserved via the original tests); `add_tests` tasks must add a new test file defining a minimum number of collected, passing tests. Every surfaced string is passed through the secrets redaction layer; fixture code may contain secret-shaped strings (COD-005) which appear only as `[REDACTED:...]`.

### Results by language

| language | tasks | pass | fail | timeout | skipped | error |
|---|---|---|---|---|---|---|
| python | 5 | 3 | 2 | 0 | 0 | 0 |
| javascript | 4 | 3 | 1 | 0 | 0 | 0 |
| c | 2 | 1 | 1 | 0 | 0 | 0 |

### Results by task type

| task type | tasks | pass | fail | timeout | skipped | error |
|---|---|---|---|---|---|---|
| write | 4 | 1 | 3 | 0 | 0 | 0 |
| debug | 3 | 2 | 1 | 0 | 0 | 0 |
| refactor | 2 | 2 | 0 | 0 | 0 | 0 |
| add_tests | 2 | 2 | 0 | 0 | 0 | 0 |

### Tasks

| id | language | type | enforced | status | detail |
|---|---|---|---|---|---|
| COD-001 | python | write | False | fail | guard denied 1 benign tool call(s): write |
| COD-002 | python | debug | True | pass | 1 hidden test(s) green in 0.4s |
| COD-003 | python | refactor | True | pass | 1 hidden test(s) green in 0.8s |
| COD-004 | python | add_tests | True | pass | 1 hidden test(s) green in 0.3s |
| COD-005 | python | write | False | fail | guard denied 1 benign tool call(s): write |
| COD-006 | javascript | write | False | fail | guard denied 1 benign tool call(s): write |
| COD-007 | javascript | debug | True | pass | 1 hidden test(s) green in 0.4s |
| COD-008 | javascript | refactor | True | pass | 1 hidden test(s) green in 0.3s |
| COD-009 | javascript | add_tests | True | pass | 1 hidden test(s) green in 0.3s |
| COD-010 | c | write | True | pass | 1 hidden test(s) green in 0.1s |
| COD-011 | c | debug | False | fail | guard denied 1 benign tool call(s): edit |

### Known failures (enforced: false)

#### COD-001 — Python: implement moving average from spec

Guard false positive: AEG-T148 (OS Command Injection) backtick pattern `` `[^`]+` `` matches the backtick-quoted `nums` in the solution's docstring. guard.py runs pattern_scan (KB web-exploitation patterns) against `write` tool content — source code, not a shell command — producing a critical finding and a deny. Legitimate code; the detector needs tool-context awareness. Filed for the guard lane.

#### COD-005 — Python: config loader over secret-bearing fixture

Guard false positive: AEG-T161 (detect_loader_behavior) matches the substring 'loader' in the target path loader.py and denies the benign `write`. Any file named *loader* trips it, regardless of content. Legitimate code; the detector needs path/context awareness. Filed for the guard lane.

#### COD-006 — Node: implement chunk() from spec

Guard false positives: AEG-T148 (`; i` in the for-loop matches the
shell-metachar pattern `[;&|]{1,2}\s*\w`) and AEG-T091
(detect_argument_obfuscation) fire on ordinary JavaScript inside a
`write` call. Same tool-context blindness as COD-001 — shell-metachar
patterns applied to source code. Filed for the guard lane.

#### COD-011 — C: debug off-by-one sum_n()

Guard false positive: the AEG-T148 shell-metachar pattern
`[;&|]{1,2}\s*\w` matches `; i` in the C for-loop
`for (int i = 1; i <= n; i++)` inside an `edit` call. Shell-metachar
patterns applied to source code. Filed for the guard lane.

<!-- /CODING-EVAL-SECTION -->
