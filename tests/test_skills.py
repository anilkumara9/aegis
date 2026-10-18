"""/hunt skill: audits OWN local code; refuses anything non-local."""

from aegis.skills import hunt

FAKE = "sk-ant-TESTANTHROPICFixture000000000001"


def test_hunt_finds_issues(kb, tmp_path):
    (tmp_path / "evil.py").write_text(
        "import os\npassword = 'hunter2secretvalue'\n"
        "eval(user_input)\n"
        f"key = '{FAKE}'\n")
    report = hunt(str(tmp_path), kb)
    assert "dangerous_eval" in report
    assert "hardcoded_secret" in report
    assert "secret_material" in report
    assert FAKE not in report  # redacted even in the report
    assert "Files scanned: 1" in report


def test_hunt_clean_dir(kb, tmp_path):
    (tmp_path / "ok.py").write_text("def add(a, b):\n    return a + b\n")
    report = hunt(str(tmp_path), kb)
    assert "No matches" in report


def test_hunt_refuses_urls(kb):
    assert "refused" in hunt("https://evil.example/app", kb)
    assert "refused" in hunt("evil.example/app", kb)


def test_hunt_refuses_missing_dir(kb):
    assert "refused" in hunt("/nope-not-here-xyz-123", kb)
