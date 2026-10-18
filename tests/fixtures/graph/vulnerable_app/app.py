"""Deliberately weak demo app — a fixture for the attack-graph lane.

It commits secrets, runs a container as root, ships a dependency manifest,
runs CI, and has login + debug code. Real graph signals, fake everything.
"""
import os

import flask

app = flask.Flask(__name__)

# Hardcoded provider key (fixture value, not real).
STRIPE_API_KEY = "sk-test_1234567890abcdef"


@app.route("/login", methods=["POST"])
def login():
    password = flask.request.form.get("password", "")
    if password == os.environ.get("ADMIN_PASSWORD", "changeme"):
        flask.session["user"] = "admin"
        return "ok"
    return "denied", 401


@app.route("/debug/status")
def debug_status():
    return {"env": dict(os.environ)}


@app.route("/items")
def items():
    q = flask.request.args.get("q", "")
    # toy query builder, no DB here
    return "results for " + q


if __name__ == "__main__":
    app.run(debug=True)
