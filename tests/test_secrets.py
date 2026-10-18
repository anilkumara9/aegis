"""Secret detection + redaction, including adversarial cases."""

from aegis.detect import secrets as sec


def test_openai_key_redacted():
    text = "key=sk-TESTOPENAIFIxture00000000000000001 done"
    red, hits = sec.redact(text)
    assert hits and hits[0].kind == "openai_key"
    assert "sk-TEST" not in red
    assert "[REDACTED:openai_key]" in red


def test_anthropic_key_redacted():
    text = "x: sk-ant-TESTANTHROPICFixture000000000001"
    red, hits = sec.redact(text)
    assert hits[0].kind == "anthropic_key"
    assert "sk-ant-TEST" not in red


def test_aws_key_redacted():
    red, hits = sec.redact("AKIAIOSFODNN7EXAMPLE connected")
    assert hits[0].kind == "aws_access_key"
    assert "AKIAIOSFODNN7EXAMPLE" not in red


def test_private_key_redacted():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."
    red, hits = sec.redact(text)
    assert hits[0].kind == "private_key"
    assert "PRIVATE KEY" not in red


def test_github_token_redacted():
    red, hits = sec.redact("token ghp_TESTGITHUBTOKEN000000000001 ok")
    assert hits and "ghp_TEST" not in red


def test_url_credentials_redacted():
    red, hits = sec.redact("https://admin:s3cretpass@db.internal:5432/x")
    assert hits[0].kind == "url_credentials"
    assert "s3cretpass" not in red
    assert "https://" in red and "@db.internal" in red  # structure kept


def test_split_token_across_whitespace():
    # Adversarial: token broken across a newline.
    text = "key = sk-\n  ant-TESTSPLITFixture00000000000001"
    red, hits = sec.redact(text)
    assert hits, "split token not detected"
    assert "TESTSPLIT" not in red


def test_split_token_across_spaces():
    text = "AKIA IOSF ODNN 7EXAMPLE"
    red, hits = sec.redact(text)
    assert hits, "space-split AWS key not detected"
    assert "IOSF" not in red


def test_env_var_indirection_flagged():
    assert sec.is_secret_bearing("curl -H \"Authorization: Bearer $OPENAI_API_KEY\"")
    assert sec.is_secret_bearing("key=${AWS_SECRET_ACCESS_KEY}")
    refs = sec.find_secret_references("export TOKEN=$GITHUB_TOKEN")
    assert "GITHUB_TOKEN" in refs
    # Non-secret env vars are not flagged.
    assert not sec.is_secret_bearing("echo $HOME && ls $PATH")


def test_base64_encoded_secret_redacted():
    import base64
    raw = "sk-ant-TESTB64Fixture0000000000000001"
    blob = base64.b64encode(raw.encode()).decode()
    text = f"data: {blob}"
    red, hits = sec.redact(text)
    assert any(h.kind == "base64_secret" for h in hits), "b64 secret missed"
    assert blob not in red


def test_benign_text_untouched():
    benign = ("The quick brown fox jumps over the lazy dog. "
              "API keys should be stored in a secret manager. "
              "Contact support@example.com for help.")
    red, hits = sec.redact(benign)
    assert hits == [] and red == benign


def test_suspicious_token_heuristic():
    assert sec.suspicious_token("payload=" + "aB3dE5gH7jK9mN2pQ4rS6tU8vW0xY" * 2)
    assert not sec.suspicious_token("hello world this is normal text here")


def test_redaction_at_every_boundary():
    # Args AND outputs both come back clean.
    args = '{"cmd": "curl https://x.test -d sk-TESTOPENAIFIxture00000000000000001"}'
    out = "response ok, key was sk-TESTOPENAIFIxture00000000000000001"
    for blob in (args, out):
        red, _ = sec.redact(blob)
        assert "sk-TEST" not in red
