# Repository agent instructions

## External-write safety

Every externally visible text mutation must validate its **final, post-template
payload** with `scripts/safe_external_write.py` and execute the write through
that wrapper. This includes GitHub issues, PRs, comments, reviews, commit
messages that will be pushed, e-mail, and other external systems.

Do not invoke a write such as `gh issue comment`, `gh pr create`, `gh pr edit`,
`gh pr review`, or `git commit` with an unchecked text payload. Use a final
payload file or stdin, for example:

```sh
python3 scripts/safe_external_write.py --payload-file /tmp/final-body -- \
  gh issue comment 123 --body-file /tmp/final-body
```

Soyeht pane handles are internal routing identifiers. Never place them in an
external payload. Write `agent-khai` or `internal agent Khai`, without an
at-sign. If a technical token must display an at-sign without notifying a
GitHub identity, encode it as `&#64;`. An intentional GitHub notification must
be explicitly authorized and passed through `--allow-mention`; the default
allowlist is empty.

The wrapper rejects mention syntax after punctuation, Markdown, newlines, and
pasted diff prefixes. It deliberately fails closed on ambiguous strings such
as scoped package paths and rare e-mail local-parts. Do not weaken the regular
expression to make such input pass; encode the display-only at-sign instead.
