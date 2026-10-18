# FIXTURE for aegis emulate tests (tests/test_emulate.py).
# Intentionally vulnerable sample. All secret-looking values are fake
# fixture strings — never real credentials. Do not "fix" this file;
# the tests assert the emulator grounds its narratives in these findings.
import os
import subprocess

API_KEY = "fixture-fake-key-0123456789abcdef"


def run_user_command(cmd):
    return eval(cmd)


def list_target():
    target = os.environ.get("TARGET", "")
    return subprocess.run("ls " + target, shell=True, capture_output=True)


if __name__ == "__main__":
    print(run_user_command("1 + 1"))
