# Repository agent instructions

## External-write safety

Every externally visible text mutation must validate its **final, post-template
payload** with `scripts/safe_external_write.py` and execute the write through
that wrapper. This includes GitHub issues, PRs, comments, reviews, commit
messages that will be pushed, e-mail, and other external systems.

Do not invoke a write such as `gh issue comment`, `gh pr create`, `gh pr edit`,
`gh pr review`, or `git commit` with an unchecked text payload. External
execution must use stdin so the child receives the exact bytes that were
validated, for example:

```sh
printf '%s' "$FINAL_BODY" | python3 scripts/safe_external_write.py --stdin -- \
  gh issue comment 123 --body-file -
```

`--payload-file` is check-only and cannot execute a child. The wrapper also
validates command arguments so an unsafe title cannot bypass a clean body.

Soyeht pane handles are internal routing identifiers. Never place them in an
external payload. Write `agent-khai` or `internal agent Khai`, without an
at-sign. HTML entities that render as an at-sign are also prohibited because
rendered text can be copied back into a live mention. An intentional GitHub
notification must be explicitly authorized and passed through
`--allow-mention`; the default allowlist is empty.

The wrapper rejects mention syntax after punctuation, Markdown, newlines, and
pasted diff prefixes. It deliberately fails closed on ambiguous strings such
as scoped package paths and rare e-mail local-parts. Do not weaken the regular
expression to make such input pass; rewrite the text without an at-sign or use
an explicitly authorized allowlist entry.
