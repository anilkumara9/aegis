"""Lane B (secure-by-construction) tests: aegis/secwrite.py + guard hook + `aegis review`.

Every secwrite pattern gets a positive fixture (must fire with the right
KB technique id + severity) and a negative fixture (safe code that must
NOT fire that rule). Guard integration proves the agent's own writes are
screened pre-execution; redaction tests prove no output path leaks secret
material from fixture code.
"""

import json
import time

import pytest

from aegis import guard as guard_mod
from aegis import secwrite
from aegis.guard import Policy

# (rule, language, positive_fixture, negative_fixture)
FIXTURES: list[tuple[str, str, str, str]] = [
    # -- Python -----------------------------------------------------------
    ("py_sqli_fstring", "python",
     'cur.execute(f"SELECT * FROM users WHERE name = \'{name}\'")',
     'cur.execute("SELECT * FROM users WHERE name = %s", (name,))'),
    ("py_sqli_percent", "python",
     'cur.execute("SELECT * FROM t WHERE x = \'%s\'" % user_input)',
     'cur.execute("SELECT * FROM t WHERE x = %s", (user_input,))'),
    ("py_xss_template_string", "python",
     'return render_template_string(f"<h1>Hello {name}</h1>")',
     'return render_template("hello.html", name=name)'),
    ("py_cmd_fstring", "python",
     'os.system(f"convert {fname} out.png")',
     'subprocess.run(["convert", fname, "out.png"], check=True)'),
    ("py_cmd_concat", "python",
     'os.system("cat " + fname)',
     'subprocess.run(["cat", fname], check=True)'),
    ("py_shell_true", "python",
     "subprocess.run(cmd, shell=True)",
     'subprocess.run(["ls", "-la"], shell=False)'),
    ("py_ssrf_unvalidated", "python",
     "requests.get(user_url)",
     'requests.get("https://api.example.com/status")'),
    ("py_pickle_loads", "python",
     "obj = pickle.loads(blob)",
     "obj = json.loads(blob)"),
    ("py_yaml_unsafe_load", "python",
     "cfg = yaml.load(f)",
     "cfg = yaml.safe_load(f)"),
    ("py_hardcoded_secret", "python",
     'api_key = "sk-test-AAAAAAAAAAAAAAAA"',
     'api_key = os.environ["API_KEY"]'),
    ("py_path_traversal_join", "python",
     "p = os.path.join(BASE, user_file)",
     'p = os.path.join(BASE, "static", "index.html")'),
    ("py_path_traversal_open", "python",
     'data = open(f"/srv/files/{name}")',
     'data = open("/srv/files/default.txt")'),
    ("py_weak_crypto", "python",
     "h = hashlib.md5(data).hexdigest()",
     "h = hashlib.sha256(data).hexdigest()"),
    # -- JavaScript / TypeScript -------------------------------------------
    ("js_sqli_template", "javascript",
     "db.query(`SELECT * FROM u WHERE id = ${id}`)",
     'db.query("SELECT * FROM u WHERE id = $1", [id])'),
    ("js_xss_sink", "javascript",
     "el.innerHTML = userName;",
     "el.textContent = userName;"),
    ("js_cmd_exec_template", "javascript",
     "exec(`convert ${f} out.png`)",
     'execFile("convert", [f, "out.png"])'),
    ("js_eval", "javascript",
     "eval(userCode)",
     "JSON.parse(userCode)"),
    ("js_new_function", "javascript",
     'const fn = new Function("a", "b", body);',
     "const fn = (a, b) => a + b;"),
    ("js_ssrf_unvalidated", "javascript",
     "fetch(url)",
     'fetch("https://api.example.com/x")'),
    ("js_hardcoded_secret", "javascript",
     'const apiKey = "sk-test-AAAAAAAAAAAAAAAA";',
     "const apiKey = process.env.API_KEY;"),
    ("js_path_traversal", "javascript",
     "fs.readFile(path.join(dir, req.query.f))",
     'fs.readFile(path.join(dir, "static", "index.html"))'),
    ("js_weak_crypto", "javascript",
     'crypto.createHash("md5")',
     'crypto.createHash("sha256")'),
    # -- Go ----------------------------------------------------------------
    ("go_sqli_sprintf", "go",
     'db.Query(fmt.Sprintf("SELECT * FROM u WHERE id = %d", id))',
     'db.Query("SELECT * FROM u WHERE id = $1", id)'),
    ("go_sqli_concat", "go",
     'db.Query("SELECT * FROM u WHERE name = \'" + name + "\'")',
     'db.Query("SELECT * FROM u WHERE name = $1", name)'),
    ("go_xss_template_html", "go",
     "w.Write([]byte(string(template.HTML(body))))",
     "tmpl.Execute(w, data)"),
    ("go_cmd_shell", "go",
     'exec.Command("sh", "-c", cmd)',
     'exec.Command("convert", f, "out.png")'),
    ("go_cmd_sprintf", "go",
     'exec.Command(fmt.Sprintf("convert %s out.png", f))',
     'exec.Command("convert", f, "out.png")'),
    ("go_ssrf_unvalidated", "go",
     "http.Get(targetURL)",
     'http.Get("https://api.example.com/health")'),
    ("go_gob_untrusted", "go",
     "dec := gob.NewDecoder(conn)",
     "dec := json.NewDecoder(conn)"),
    ("go_hardcoded_secret", "go",
     'apiKey := "sk-test-AAAAAAAAAAAAAAAA"',
     'apiKey := os.Getenv("API_KEY")'),
    ("go_path_traversal", "go",
     'os.ReadFile(filepath.Join(base, r.URL.Query().Get("f")))',
     'os.ReadFile(filepath.Join(base, "static", "index.html"))'),
    ("go_weak_crypto", "go",
     "h := md5.New()",
     "h := sha256.New()"),
    # -- Rust ---------------------------------------------------------------
    ("rs_sqli_format", "rust",
     'let q = format!("SELECT * FROM u WHERE id = {}", id);',
     'sqlx::query("SELECT * FROM u WHERE id = $1")'),
    ("rs_xss_format_html", "rust",
     'let html = format!("<h1>{}</h1>", name);',
     'let msg = format!("hello {}", name);'),
    ("rs_cmd_shell", "rust",
     'Command::new("sh").arg("-c").arg(cmd)',
     'Command::new("convert").arg(f).arg("out.png")'),
    ("rs_ssrf_unvalidated", "rust",
     "reqwest::get(url).await",
     'reqwest::get("https://api.example.com/x").await'),
    ("rs_deser_bincode", "rust",
     "let v: T = bincode::deserialize(&bytes).unwrap();",
     "let v: T = serde_json::from_slice(&bytes).unwrap();"),
    ("rs_hardcoded_secret", "rust",
     'let api_key = "sk-test-AAAAAAAAAAAAAAAA";',
     'let api_key = std::env::var("API_KEY").unwrap();'),
    ("rs_path_traversal", "rust",
     "let data = fs::read(user_path).unwrap();",
     'let data = fs::read("/etc/app/config.toml").unwrap();'),
    ("rs_weak_crypto", "rust",
     "let d = md5::compute(data);",
     "let d = Sha256::digest(data);"),
    # -- Java ---------------------------------------------------------------
    ("java_sqli_concat", "java",
     'st.executeQuery("SELECT * FROM u WHERE id = " + id)',
     'ps = con.prepareStatement("SELECT * FROM u WHERE id = ?");'),
    ("java_xss_unescaped", "java",
     'out.write(request.getParameter("name"));',
     'out.write("<b>hello</b>");'),
    ("java_cmd_exec", "java",
     "Runtime.getRuntime().exec(cmd)",
     'new ProcessBuilder("convert", f, "out.png").start()'),
    ("java_cmd_concat", "java",
     'new ProcessBuilder("convert " + f + " out.png")',
     'new ProcessBuilder("convert", f, "out.png")'),
    ("java_ssrf_unvalidated", "java",
     "new URL(userUrl).openConnection()",
     'new URL("https://api.example.com/x").openConnection()'),
    ("java_deser_objectinput", "java",
     "ObjectInputStream ois = new ObjectInputStream(in);",
     "ObjectMapper mapper = new ObjectMapper();"),
    ("java_hardcoded_secret", "java",
     'String apiKey = "sk-test-AAAAAAAAAAAAAAAA";',
     'String apiKey = System.getenv("API_KEY");'),
    ("java_path_traversal", "java",
     "File f = new File(baseDir, userFile);",
     'File f = new File(baseDir, "static/index.html");'),
    ("java_weak_crypto", "java",
     'MessageDigest.getInstance("MD5")',
     'MessageDigest.getInstance("SHA-256")'),
    # -- C++ ----------------------------------------------------------------
    ("cpp_sqli_concat", "cpp",
     'db.exec("SELECT * FROM u WHERE id = " + id);',
     "stmt.bind(1, id);"),
    ("cpp_sqli_sprintf", "cpp",
     'sprintf(buf, "SELECT * FROM u WHERE id = %d", id);',
     'snprintf(buf, sizeof(buf), "id=%d", id);'),
    ("cpp_xss_stream", "cpp",
     "cout << user_input;",
     'cout << "hello";'),
    ("cpp_cmd_system", "cpp",
     "system(userCmd);",
     'system("ls -la");'),
    ("cpp_ssrf_unvalidated", "cpp",
     "curl_easy_setopt(curl, CURLOPT_URL, userUrl);",
     'curl_easy_setopt(curl, CURLOPT_URL, "https://api.example.com/x");'),
    ("cpp_deser_cast", "cpp",
     "auto* hdr = reinterpret_cast<Header*>(buffer);",
     "Header hdr; memcpy(&hdr, buffer, sizeof(hdr));"),
    ("cpp_hardcoded_secret", "cpp",
     'std::string api_key = "sk-test-AAAAAAAAAAAAAAAA";',
     'std::string api_key = getenv("API_KEY");'),
    ("cpp_path_traversal", "cpp",
     "std::ifstream f(base + userFile);",
     'std::ifstream f("/etc/app/config");'),
    ("cpp_weak_crypto", "cpp",
     "MD5(data, len, out);",
     "SHA256(data, len, out);"),
]

def _rule_kb(rule: str) -> str:
    for r, _lang, _rx, kb_id, _sev, _fix in secwrite.SECWRITE_PATTERNS:
        if r == rule:
            return kb_id
    raise AssertionError(f"rule {rule} not in SECWRITE_PATTERNS")


def _rule_sev(rule: str) -> str:
    for r, _lang, _rx, _kb_id, sev, _fix in secwrite.SECWRITE_PATTERNS:
        if r == rule:
            return sev
    raise AssertionError(f"rule {rule} not in SECWRITE_PATTERNS")


def test_fixtures_cover_every_pattern():
    defined = {r for r, _, _, _, _, _ in secwrite.SECWRITE_PATTERNS}
    fixtured = {r for r, _, _, _ in FIXTURES}
    assert fixtured == defined, f"unfixtured rules: {defined - fixtured}"


@pytest.mark.parametrize("rule,lang,pos,neg", FIXTURES,
                         ids=[f[0] for f in FIXTURES])
def test_pattern_positive(rule, lang, pos, neg, kb):
    findings = secwrite.screen_source(pos, lang, kb=kb)
    hit = [f for f in findings if f.rule == rule]
    assert hit, f"{rule}: no finding on positive fixture"
    f = hit[0]
    assert f.technique_id == _rule_kb(rule), f"{rule}: wrong technique id"
    assert f.severity == _rule_sev(rule), f"{rule}: wrong severity"
    assert f.technique_id in kb.by_id, f"{rule}: technique id not in KB"
    assert f.fix, f"{rule}: empty fix suggestion"


@pytest.mark.parametrize("rule,lang,pos,neg", FIXTURES,
                         ids=[f[0] for f in FIXTURES])
def test_pattern_negative(rule, lang, pos, neg):
    findings = secwrite.screen_source(neg, lang, kb=None)
    assert not [f for f in findings if f.rule == rule], \
        f"{rule}: false positive on safe fixture: {neg!r}"


def test_safe_python_file_produces_zero_findings(kb):
    safe = '''
import os, hashlib, subprocess, json
uid = int(request.args["id"])
cur.execute("SELECT * FROM users WHERE id = %s", (uid,))
subprocess.run(["ls", "-la", path], check=False)
h = hashlib.sha256(data).hexdigest()
api_key = os.environ["API_KEY"]
r = requests.get("https://api.example.com/status")
cfg = yaml.safe_load(open("/etc/app/config.yaml"))
'''
    assert secwrite.screen_source(safe, "python", kb=kb) == []


def test_detect_language():
    assert secwrite.detect_language("app.py") == "python"
    assert secwrite.detect_language("a.ts") == "javascript"
    assert secwrite.detect_language("a.tsx") == "javascript"
    assert secwrite.detect_language("main.go") == "go"
    assert secwrite.detect_language("lib.rs") == "rust"
    assert secwrite.detect_language("Main.java") == "java"
    assert secwrite.detect_language("x.cpp") == "cpp"
    assert secwrite.detect_language("x.HPP") == "cpp"
    assert secwrite.detect_language("notes.txt") is None
    assert secwrite.detect_language("Makefile") is None


def test_screen_tool_call_routing(kb):
    sqli = 'cur.execute(f"SELECT * FROM u WHERE id = {uid}")'
    fs = secwrite.screen_tool_call("write", {"path": "app.py",
                                             "content": sqli}, kb)
    assert any(f.rule == "py_sqli_fstring" for f in fs)
    fs = secwrite.screen_tool_call("edit", {"path": "app.py",
                                            "old_text": "x",
                                            "new_text": sqli}, kb)
    assert any(f.rule == "py_sqli_fstring" for f in fs)
    # unknown extension -> not screened (no language attribution)
    assert secwrite.screen_tool_call(
        "write", {"path": "notes.txt", "content": sqli}, kb) == []
    # non-write tools untouched
    assert secwrite.screen_tool_call(
        "bash", {"cmd": "ls"}, kb) == []


# -- guard integration --------------------------------------------------------


def _sess(kb):
    return guard_mod.create_session(Policy(name="secwrite-test"), kb)


def test_guard_blocks_sqli_write(kb):
    sess = _sess(kb)
    verdict = sess.check_call("write", {
        "path": "app.py",
        "content": 'cur.execute(f"SELECT * FROM users WHERE id = {uid}")\n'})
    assert verdict.decision == "deny"
    assert any(f.technique_id == "AEG-T139" for f in verdict.findings)
    assert "AEG-T139" in verdict.reason
    # deny reason must not echo raw code
    assert "{uid}" not in verdict.reason


def test_guard_blocks_edit_with_sqli(kb):
    sess = _sess(kb)
    verdict = sess.check_call("edit", {
        "path": "app.py", "old_text": "x = 1",
        "new_text": 'cur.execute("SELECT * FROM t WHERE x = \'%s\'" % user_input)'})
    assert verdict.decision == "deny"
    assert any(f.technique_id == "AEG-T139" for f in verdict.findings)


def test_guard_warns_medium_severity(kb):
    sess = _sess(kb)
    verdict = sess.check_call("write", {
        "path": "ui.js", "content": "el.innerHTML = userName;\n"})
    assert verdict.decision == "needs_approval"
    assert any(f.technique_id == "AEG-T140" for f in verdict.findings)


def test_guard_allows_safe_write(kb):
    sess = _sess(kb)
    verdict = sess.check_call("write", {
        "path": "app.py",
        "content": 'cur.execute("SELECT * FROM users WHERE id = %s", (uid,))\n'})
    assert verdict.decision == "allow"


def test_guard_secwrite_respects_plan_mode(kb):
    sess = guard_mod.create_session(Policy(name="plan-test", mode="plan"), kb)
    verdict = sess.check_call("write", {"path": "app.py", "content": "x = 1"})
    assert verdict.decision == "deny"  # plan-mode read-only denial, not secwrite


# -- redaction on every new output path ----------------------------------------

SECRET_CODE = 'api_key = "sk-test-AAAAAAAAAAAAAAAAAAAAAAAA"\n'


def test_review_output_redacts_secrets(tmp_path, kb):
    (tmp_path / "app.py").write_text(SECRET_CODE)
    report = secwrite.review_report(str(tmp_path), kb)
    assert "sk-test-AAAAAAAAAAAAAAAAAAAAAAAA" not in report
    assert "AEG-T031" in report  # still flagged, value redacted


def test_guard_verdict_redacts_secrets(kb):
    sess = _sess(kb)
    verdict = sess.check_call("write", {"path": "app.py",
                                        "content": SECRET_CODE})
    blob = json.dumps({"reason": verdict.reason,
                       "findings": [f.to_dict() for f in verdict.findings],
                       "args": verdict.redacted_args})
    assert "sk-test-AAAAAAAAAAAAAAAAAAAAAAAA" not in blob
    assert any(f.technique_id == "AEG-T031" for f in verdict.findings)


# -- `aegis review` CLI ---------------------------------------------------------

def _write_fixture_project(root):
    (root / "vuln.py").write_text(
        'import pickle\n'
        'cur.execute(f"SELECT * FROM users WHERE id = {uid}")\n'
        'data = pickle.loads(blob)\n')
    (root / "safe.py").write_text(
        'cur.execute("SELECT * FROM users WHERE id = %s", (uid,))\n')
    (root / "app.js").write_text("el.innerHTML = userName;\n")


def test_review_command_on_project(tmp_path, kb, capsys):
    from aegis.cli import main
    _write_fixture_project(tmp_path)
    rc = main(["review", str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "vuln.py:2" in out
    assert "AEG-T139" in out and "AEG-T142" in out
    assert "AEG-T140" in out and "app.js:1" in out
    assert "Fix:" in out
    assert "[HIGH]" in out and "[MEDIUM]" in out
    assert "safe.py" not in out  # safe file produces no findings


def test_review_command_single_file(tmp_path, capsys):
    from aegis.cli import main
    f = tmp_path / "one.go"
    f.write_text('db.Query(fmt.Sprintf("SELECT * FROM u WHERE id = %d", id))\n')
    rc = main(["review", str(f)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "AEG-T139" in out and "one.go:1" in out


def test_review_refuses_remote(capsys):
    from aegis.cli import main
    rc = main(["review", "https://example.com/repo"])
    out = capsys.readouterr().out
    assert rc == 2
    assert "refused" in out.lower()


def test_review_refuses_missing(capsys):
    from aegis.cli import main
    rc = main(["review", "/nonexistent-dir-xyz-123"])
    assert rc == 2


def test_review_redacts_secrets_in_output(tmp_path, capsys):
    from aegis.cli import main
    (tmp_path / "cfg.py").write_text(SECRET_CODE)
    rc = main(["review", str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "sk-test-AAAAAAAAAAAAAAAAAAAAAAAA" not in out
    assert "AEG-T031" in out


def test_screen_performance():
    big = ("x = 1\n" * 200_000)  # ~1.2MB, over the cap
    t0 = time.perf_counter()
    findings = secwrite.screen_source(big, "python", kb=None)
    dt = time.perf_counter() - t0
    assert findings == []
    assert dt < 2.0, f"screening took {dt:.2f}s"
