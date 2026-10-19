# Codebase indexing: design & tradeoffs (v0.7 Lane A)

`aegis/index.py` maintains a per-repo code index so the agent can pull
relevant files per-request (`query_index()` / the `index_query` tool)
instead of loading everything into context.

## What is indexed

Per file: repo-relative path, language, size, mtime, sha256, exported
symbols (functions/classes), imports. **Never file contents or snippets.**
This is deliberate: the index cache cannot leak secret values even if the
cache file is copied elsewhere. Symbol extraction is AST-based for Python
and regex-based for JS/TS, Go, Rust, Java/Kotlin, C/C++/C#.

## Change detection: polling, not watchdog

The watcher (`IndexWatcher`) polls mtime+size per file and re-indexes
**only** changed files. We chose polling over the `watchdog` package
deliberately:

- **Dependency-free.** Aegis ships with exactly one runtime dependency
  (pyyaml). Every new dependency is supply-chain surface a defensive
  security tool must justify; an inotify wrapper did not clear that bar.
- **Portable and predictable.** Polling works identically on Linux, macOS,
  containers, and network mounts. Watchdog's backends differ per platform
  (inotify/kqueue/ReadDirectoryChangesW) and each has its own edge cases
  (event coalescing, overflow drops, recursive-watch costs).
- **Cost is fine at our scale.** A poll is one `stat()` per file — tens of
  thousands of files poll in well under a second. The expensive work
  (reading + parsing) happens only for changed files.

What polling gives up: sub-second event latency (we poll every ~2s) and
wake-on-idle efficiency (a poll pass costs CPU even when nothing changed).
For an interactive coding agent, 2s staleness is invisible; for a
CI-scale monorepo with millions of files, a native watcher would win.

## Full rescan vs incremental

Full rescans are O(total content) — re-reading and re-parsing every file.
Incremental check is O(file count) stats plus O(changed content) parsing.
The persisted cache (`~/.aegis/index/<sha1-of-repo>.json`) makes repeat
startups O(file count): records whose mtime+size still match are reused
as-is; stale ones are re-indexed on load.

## Why not embeddings

Vector / embedding retrieval would need: an embedding model (local
weights or a paid API), a vector store, a chunking strategy, and a
re-embedding pipeline on every change. Honest assessment:

- **Data leaves the machine** (or a large local model must be bundled) —
  unacceptable default for a defensive tool routinely pointed at private
  company codebases.
- **Nondeterministic and unauditable** — you cannot explain *why* a file
  ranked, which matters when the agent's context selection drives
  security-relevant code changes.
- **Cost and complexity** for a gain we have not measured.

Keyword + symbol matching is deterministic, offline, explainable
(scores are shown), and sufficient for "which files define or mention
X". If semantic search is ever wanted, it belongs as an *optional*
plugin (see `aegis/plugins.py`), not in the core.

## Cache invalidation

Cache key: sha1 of the resolved repo path. On load, each record's saved
(mtime, size) is compared against the live file; mismatches are
re-indexed, deletions dropped, new files picked up by `check()`. A
corrupt cache file is ignored (falls back to a fresh build) — the cache
is a pure performance optimization, never load-bearing.
