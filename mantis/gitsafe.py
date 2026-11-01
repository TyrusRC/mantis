"""Git invocations against an audited (untrusted) repository.

A target's own `.git/config` and hooks are attacker-controlled when the tree
was copied rather than freshly cloned: `core.fsmonitor` runs on status/diff,
`post-checkout` runs on `worktree add`. Every mantis git call goes through
this prefix so neither executes.

NOTE: repo-defined filter drivers (`filter.<x>.smudge` + .gitattributes) can
still run on checkout; git has no flag to ignore repository-local config.
Upgrade path: run git with an empty GIT_DIR config copy, or skip --fix on
untrusted copies.
"""
from __future__ import annotations

GIT = [
    "git",
    "-c", "core.hooksPath=/dev/null",
    "-c", "core.fsmonitor=false",
    "-c", "protocol.file.allow=user",
]
