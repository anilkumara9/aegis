
---

<!-- CODING-EVAL-SECTION -->
## Coding proving ground (v0.7 Lane D)

Generated: 2026-10-19 02:57 UTC | Tasks: 11 | Pass: 11

### Methodology

Each task stages a fixture project under `/tmp` and drives the **real** `AgentLoop` with scripted `MockProvider` solution turns (the deterministic stand-in for the agent under test) through the **real** guard. Scoring comes from **actually executing** a hidden test suite (`subprocess`, timeout-capped, cwd = fixture dir) — never self-graded by the model. A `pass` requires every hidden test to exit 0, plus type-specific real checks: `refactor` tasks must actually change the target file (behavior preserved via the original tests); `add_tests` tasks must add a new test file defining a minimum number of collected, passing tests. Every surfaced string is passed through the secrets redaction layer; fixture code may contain secret-shaped strings (COD-005) which appear only as `[REDACTED:...]`.

### Results by language

| language | tasks | pass | fail | timeout | skipped | error |
|---|---|---|---|---|---|---|
| python | 5 | 5 | 0 | 0 | 0 | 0 |
| javascript | 4 | 4 | 0 | 0 | 0 | 0 |
| c | 2 | 2 | 0 | 0 | 0 | 0 |

### Results by task type

| task type | tasks | pass | fail | timeout | skipped | error |
|---|---|---|---|---|---|---|
| write | 4 | 4 | 0 | 0 | 0 | 0 |
| debug | 3 | 3 | 0 | 0 | 0 | 0 |
| refactor | 2 | 2 | 0 | 0 | 0 | 0 |
| add_tests | 2 | 2 | 0 | 0 | 0 | 0 |

### Tasks

| id | language | type | enforced | status | detail |
|---|---|---|---|---|---|
| COD-001 | python | write | False | pass | 1 hidden test(s) green in 0.3s |
| COD-002 | python | debug | True | pass | 1 hidden test(s) green in 0.3s |
| COD-003 | python | refactor | True | pass | 1 hidden test(s) green in 0.3s |
| COD-004 | python | add_tests | True | pass | 1 hidden test(s) green in 0.3s |
| COD-005 | python | write | False | pass | 1 hidden test(s) green in 0.3s |
| COD-006 | javascript | write | False | pass | 1 hidden test(s) green in 0.2s |
| COD-007 | javascript | debug | True | pass | 1 hidden test(s) green in 0.2s |
| COD-008 | javascript | refactor | True | pass | 1 hidden test(s) green in 0.3s |
| COD-009 | javascript | add_tests | True | pass | 1 hidden test(s) green in 0.2s |
| COD-010 | c | write | True | pass | 1 hidden test(s) green in 0.1s |
| COD-011 | c | debug | False | pass | 1 hidden test(s) green in 0.1s |
<!-- /CODING-EVAL-SECTION -->
