# Claude Code instructions

Read and follow `AGENTS.md`, especially the mandatory external-write wrapper.
No externally visible text mutation may bypass
`scripts/safe_external_write.py`.

Before pushing, run `python3 scripts/local_check.py` — compile only, safe on any
machine. Never run the test phases outside a disposable VM; see "Checking before
you push" in `AGENTS.md`.
