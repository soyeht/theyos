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
  gh issue comment 123
```

`--payload-file` is check-only and cannot execute a child. The wrapper also
validates command arguments so an unsafe title cannot bypass a clean body. It
uses a closed command grammar and adds the stdin-reading body/message flag
itself; callers must not supply a body file or other payload channel. An
unsupported external writer remains blocked until a reviewed adapter and
adversarial test are added.

GitHub adapters are pinned to `github.com/soyeht/theyos`. Caller-supplied
`--repo` and inherited `GH_REPO`/`GH_HOST` cannot redirect a validated payload
to another destination. An explicit pull-request or issue target must be a
strict positive decimal identifier in that repository; absolute URLs,
`owner/repository#number` selectors, refs, branch names, zero, and leading-zero
forms fail before execution. The dedicated iOS adapters below are the only
cross-repository exceptions.

`git push` is intentionally not an adapter: its externally visible text is
the history already authored, not stdin. Create every commit message through
the guarded `git commit` adapter, then push without adding new prose. Custom
merge, tag, release, or e-mail text needs its own reviewed adapter first.

### Governed Soyeht macOS release objects

The `governed-release` adapter family is pinned separately to
`github.com/soyeht/soyeht-ios`; it does not relax the existing destination for
issue, pull-request, review, or commit adapters. It accepts only the complete
`refs/tags/mac-v<version>` ref and full commit/main OIDs. Its five operations
create one object at a time and then read that object back: annotated tag
object, tag ref, draft release, one asset upload, and release publication.
The tag message is fixed to `Soyeht <version>` and every later phase remains
bound to the original tag-object OID.

This family is **not usable for publication** until the corresponding
`soyeht-ios` consumer change is present in the target commit. The adapter must
fail closed when that workflow contract is absent, when the tag or release
already exists, or when any target, version, asset, digest, or readback differs.
The adapter pins the reviewed consumer execution quartet byte-for-byte: the
build-only release workflow, the required `build` workflow, its phase
dispatcher, and the dedicated release-contract checker. Change any of those
four files by updating and landing this adapter contract first, then re-anchor
the consumer. A pin-only follow-up, including one that corrects the consumer's
required-secret inventory guard or re-anchors a reviewed engine-pin and
provider-key-removal candidate, must change only these four digests, their
exact-value tests, and this narrow ordering policy; it must not broaden adapter
grammar or mutations. Land changes in this order: first the adapter pins and
tests in `theyos`; then re-anchor and land the byte-identical reviewed
`soyeht-ios` consumer candidate.
There is no direct `git tag`, `git push`, `gh release`, clobber, or
missing-guard fallback.

The consumer's required `build` context validates the release docs and both
matching agent-instruction blocks. That checker is versioned in the same head:
simultaneously removing the checker and its invocation can only be made
mechanically red by a trusted-base workflow or repository protection. Neither
external protection nor permanence against an administrator is claimed by
this adapter; its fail-closed boundary is the exact four-blob execution pin.

The only cross-repository pull-request writer is the separate
`governed-ios-pr-create` adapter. It can create exactly one draft PR in
`soyeht/soyeht-ios`, from `ci/governed-macos-release` to `main`, after proving
the remote branch is at the supplied full OID and no PR already exists. It must
read back the open draft with byte-exact title/body and exact head/base. It has
no edit, ready, review, merge, repository-selector, or fallback operation. This
adapter exists only to stage the consumer change after the `theyos` adapter PR
lands; it does not make the release family usable before that consumer is in
`soyeht-ios` main.

The separate `governed-ios-pr-body-update` adapter can update only the body of
that same fixed consumer PR number 16 while it is OPEN+DRAFT at the expected
full head OID. The repository, PR number, title, base, and head are hardcoded;
the old body digest and size are mandatory preconditions, and one body-only
PATCH is followed by byte-exact readback. It cannot change a title, create a
second mutation, or ready, review, merge, or redirect the PR. A post-mutation
readback failure is RED and has no automatic rollback.

### Governed theyos v0.1.26 tag

The dedicated `governed-theyos-v0126-tag` adapter is the only authorized
writer for the annotated backend tag `refs/tags/v0.1.26`. It is hardcoded to
the canonical `soyeht/theyos` origin, version, ref, and exact message
`theyos-engine v0.1.26\n`. The caller supplies only the full target and
expected-main OIDs, which must be identical to each other, `HEAD`,
`origin/main`, the remote main ref, and the GitHub API main ref.

Tag authorship and push are separate one-mutation operations. Authorship uses
annotated, unsigned, verbatim-message semantics and reads back the local tag
object, tagger, target, and exact message. Push sends one explicit refspec with
force, follow-tags, and Git push signing disabled, then reads back both the
remote tag object and peeled commit through Git and the GitHub API. Wrong
origin or push URL, dirty worktree, version drift, a branch/tag ambiguity,
an existing local or remote tag, unsafe push configuration, or any readback
mismatch is RED. A post-mutation mismatch has no automatic cleanup or retry.
Do not run raw `git tag` or a tag push as a fallback.

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
