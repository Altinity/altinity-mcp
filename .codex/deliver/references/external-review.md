# External review

Read this when the run requires an external reviewer. The coordinator calls
the selected provider directly. No dependency on `ship`, `chatgpt-review`,
an authenticated browser, or a workflow-runner plugin is required.

## Default Opus preset

Check that the CLI, configured credentials, and requested model are available.
Do not print credentials or include them, private customer data, or unrelated
files in the review packet. Supply the issue contract, exact full candidate
SHA, complete unit diff, relevant source/tests, known limitations, and prior
review/disposition text when applicable. A tools-disabled reviewer cannot
inspect omitted files: supply missing evidence before relying on its conclusion.

Write the packet to a local file and capture stdout and stderr separately:

```bash
claude -p \
  --model claude-opus-5-5 \
  --effort xhigh \
  --tools "" \
  --strict-mcp-config \
  --disable-slash-commands \
  --setting-sources "" \
  --no-session-persistence \
  < "$review_packet" > "$review_report" 2> "$review_errors"
```

The coordinator sets those paths under the run's local artifact directory.
On a subsequent invocation, include prior findings and dispositions in the
new packet: `--no-session-persistence` means history is not implicit.
The user may select another provider; preserve the same evidence and verdict
requirements rather than depending on this CLI's implementation.

Ask for concrete correctness, security, contract, and coverage defects,
distinguished from optional suggestions and unverified claims. Require the
last two non-empty lines to be:

```text
REVIEWED_SHA: the exact full candidate SHA
VERDICT: SHIP
```

The verdict may instead be `VERDICT: REVISE`. SHIP means no remaining material
concern; suggestions can remain. Check successful command completion,
non-empty output, exactly one final verdict, and equality of the reported SHA
to the frozen candidate. If a PR already exists, compare its actual head too;
if not, perform that comparison after PR creation and again before merging.
Missing or malformed output is
an incomplete review, never approval. Independently verify substantive claims.

Nonzero exit, empty output, or missing/malformed SHA or verdict is an
incomplete attempt. Allow one retry per candidate in total, including
malformed exit-zero responses. Retain the candidate and evidence; for protocol
repair, add the prior response and request the missing fields. An incomplete
attempt does not count as a completed round, but it consumes this retry budget.
A substantive re-review or rebuttal is a new round, not a tool retry. If the
review remains unavailable, retain any findings, report the failure, and leave
the affected unit unmerged unless the user explicitly changes the requirement.
