#!/bin/sh
# Aegis installer — one-command setup, OpenCode/Claude Code style.
#
#   curl -fsSL https://raw.githubusercontent.com/<your-github-user>/aegis/main/install.sh | bash
#
# What it does:
#   1. Checks for python3 >= 3.10 (and curl/wget when it must download).
#   2. Gets the Aegis source: a local dir (AEGIS_SOURCE_DIR) or the GitHub
#      release tarball — nothing else, ever.
#   3. Creates an isolated venv at $HOME/.aegis/venv and installs Aegis into it.
#   4. Symlinks the venv's `aegis` into $HOME/.local/bin and, only if needed,
#      adds $HOME/.local/bin to PATH via an idempotent block in
#      ~/.bashrc / ~/.zshrc.
#   5. Verifies with `aegis version` and prints next steps.
#
# Idempotent: re-running is safe. The venv is rebuilt only when missing or
# when `--reinstall` is passed. Never uses sudo. Everything it writes lives
# under $HOME. Defensive product: this script fetches nothing except the Aegis
# source tarball (or a local directory) and the package's PyPI dependencies.
set -eu

# ---------------------------------------------------------------- FOUNDER ---
# After pushing to GitHub, replace the placeholder org/user below with the
# real one. Until then the download path below will 404 on purpose.
AEGIS_TARBALL_URL="https://github.com/<your-github-user>/aegis/archive/refs/heads/main.tar.gz"
# ----------------------------------------------------------------------------

AEGIS_HOME="${AEGIS_HOME:-$HOME/.aegis}"
VENV_DIR="$AEGIS_HOME/venv"
BIN_DIR="${AEGIS_BIN_DIR:-$HOME/.local/bin}"
TARGET="$BIN_DIR/aegis"
REINSTALL=0

for arg in "$@"; do
  case "$arg" in
    --reinstall) REINSTALL=1 ;;
    -h|--help)
      echo "Usage: $0 [--reinstall]"
      echo "  Installs Aegis into \$HOME/.aegis/venv and links it as \$HOME/.local/bin/aegis."
      echo "  Env: AEGIS_SOURCE_DIR=<local dir> (skip the download), AEGIS_HOME, AEGIS_BIN_DIR."
      exit 0 ;;
    *) echo "Unknown option: $arg" >&2; exit 1 ;;
  esac
done

die() { echo "aegis-install: error: $*" >&2; exit 1; }
say() { echo "aegis-install: $*"; }

# --- 1. OS + prerequisites -------------------------------------------------
case "$(uname -s)" in
  Linux|Darwin) ;;
  *) die "unsupported OS: $(uname -s) (need Linux or macOS)" ;;
esac

command -v python3 >/dev/null 2>&1 || die "python3 not found — install Python 3.10+ first."
PYVER="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
PYMAJ="${PYVER%%.*}"; PYMIN="${PYVER#*.}"
if [ "$PYMAJ" -lt 3 ] || { [ "$PYMAJ" -eq 3 ] && [ "$PYMIN" -lt 10 ]; }; then
  die "python3 is $PYVER — Aegis needs Python >= 3.10."
fi
python3 -c "import venv, ensurepip" 2>/dev/null \
  || die "python3-venv is missing (python3 -m venv fails). On Debian/Ubuntu: sudo apt install python3.12-venv"

DOWNLOADER=""
if [ -z "${AEGIS_SOURCE_DIR:-}" ]; then
  if command -v curl >/dev/null 2>&1; then DOWNLOADER=curl
  elif command -v wget >/dev/null 2>&1; then DOWNLOADER=wget
  else die "need curl or wget to download the Aegis source (or set AEGIS_SOURCE_DIR=<dir>)."
  fi
fi

# --- 2. Source acquisition --------------------------------------------------
SRC_DIR=""
if [ -n "${AEGIS_SOURCE_DIR:-}" ]; then
  [ -d "$AEGIS_SOURCE_DIR" ] || die "AEGIS_SOURCE_DIR=$AEGIS_SOURCE_DIR is not a directory."
  [ -f "$AEGIS_SOURCE_DIR/pyproject.toml" ] \
    || die "AEGIS_SOURCE_DIR=$AEGIS_SOURCE_DIR has no pyproject.toml — not an Aegis source tree."
  SRC_DIR="$AEGIS_SOURCE_DIR"
  say "using local source: $SRC_DIR"
else
  TMPDL="$(mktemp -d)"
  trap 'rm -rf "$TMPDL"' EXIT INT TERM
  TARBALL="$TMPDL/aegis.tar.gz"
  say "downloading Aegis source..."
  if [ "$DOWNLOADER" = "curl" ]; then
    curl -fsSL -o "$TARBALL" "$AEGIS_TARBALL_URL" || die "download failed: $AEGIS_TARBALL_URL"
  else
    wget -qO "$TARBALL" "$AEGIS_TARBALL_URL" || die "download failed: $AEGIS_TARBALL_URL"
  fi
  tar -xzf "$TARBALL" -C "$TMPDL"
  for d in "$TMPDL"/*/; do
    if [ -f "${d}pyproject.toml" ]; then SRC_DIR="${d%/}"; break; fi
  done
  [ -n "$SRC_DIR" ] || die "downloaded archive contains no Aegis source tree."
  say "downloaded to $SRC_DIR"
fi

# --- 3. Isolated venv --------------------------------------------------------
mkdir -p "$AEGIS_HOME"
if [ ! -x "$VENV_DIR/bin/python" ] || [ "$REINSTALL" -eq 1 ]; then
  say "creating venv at $VENV_DIR ..."
  rm -rf "$VENV_DIR"
  python3 -m venv "$VENV_DIR" || die "python3 -m venv failed."
else
  say "reusing existing venv at $VENV_DIR"
fi
say "installing Aegis into the venv ..."
"$VENV_DIR/bin/pip" -q install --upgrade pip 2>&1 | grep -v '^$' || true
"$VENV_DIR/bin/pip" install "$SRC_DIR" || die "pip install failed."

# --- 4. Symlink + PATH -------------------------------------------------------
mkdir -p "$BIN_DIR"
[ -x "$VENV_DIR/bin/aegis" ] || die "install succeeded but $VENV_DIR/bin/aegis is missing."
ln -sf "$VENV_DIR/bin/aegis" "$TARGET"
say "linked $TARGET -> $VENV_DIR/bin/aegis"

PATH_BLOCK_MARK="# >>> aegis installer >>>"
PATH_BLOCK='# Added by the Aegis installer (install.sh). Safe to remove.
export PATH="$HOME/.local/bin:$PATH"'
case ":$PATH:" in
  *":$BIN_DIR:"*) say "\$HOME/.local/bin is already on PATH." ;;
  *)
    for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
      [ -f "$rc" ] || continue
      if grep -qF "$PATH_BLOCK_MARK" "$rc" 2>/dev/null; then
        say "PATH block already present in $rc"
      else
        { echo ""; echo "$PATH_BLOCK_MARK"; echo "$PATH_BLOCK"; echo "# <<< aegis installer <<<"; } >> "$rc"
        say "added \$HOME/.local/bin to PATH in $rc"
      fi
    done
    say "NOTE: restart your shell (or: export PATH=\"\$HOME/.local/bin:\$PATH\") to pick up the new PATH."
    ;;
esac

# --- 5. Verify + next steps --------------------------------------------------
say "verifying installation ..."
"$TARGET" version || die "verification failed: $TARGET version did not run."
echo ""
echo "Aegis is installed. Next steps:"
echo "  1. Set a provider key (pick one):"
echo "       export ANTHROPIC_API_KEY=...   # default model: claude-sonnet-4-5"
echo "       export OPENAI_API_KEY=...      # default model: gpt-4o"
echo "       export GOOGLE_API_KEY=...      # Google provider (v0.3+)"
echo "     ...or run keyless:  AEGIS_PROVIDER=ollama AEGIS_MODEL=<name> aegis"
echo "     ...or offline demo: AEGIS_PROVIDER=mock aegis"
echo "  2. Just type:  aegis"
echo ""
echo "Docs: https://github.com/<your-github-user>/aegis  (FOUNDER: replace after push)"
