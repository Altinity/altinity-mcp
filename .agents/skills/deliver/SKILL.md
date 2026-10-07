---
name: deliver
description: Deliver GitHub issues or selected phases through native planning, implementation workers, independent review, repository checks, and pull requests. Use for unattended delivery of one issue, a multi-phase issue, or a dependency-ordered issue list; honor plan-only and PR-only instructions. Supports a configurable external reviewer without requiring ChatGPT browser sessions or Claude workflow runners.
---

# Deliver

Act as coordinator. Use native subagents for bounded implementation and
independent review; own acceptance decisions, integration, GitHub operations,
and the final result. Follow the target repository's instructions and gates.
This skill is a developer tool, not a customer-facing runtime skill.

## Scope and authorization

Accept an issue number or URL, an issue list, or selected phases, for example
`$deliver 158`, `$deliver 142 phases 2-4`, or `$deliver 158,159`.
An explicit invocation requests unattended delivery through push, PR creation,
issue progress updates, and merge for that scope. A narrower instruction such
as "plan only", "open PR", or "no merge" takes precedence. Automatic skill
selection supports the user's request; it does not expand its authorization.
Deployment, service restarts, and unrelated configuration changes require
their own authorization.

Read the live issue and relevant repository instructions before planning.
Match the target repository to the issue; inspect existing worktrees, changes,
PRs, and merged work. Preserve unrelated changes. Use an isolated worktree
for each unit, based on the freshly fetched remote default branch.

A unit is one authored phase, or the whole issue when unphased. Prefer one
branch and PR per unit. Do not invent phases from arbitrary file or line
counts. Assemble each unit's contract from its implementation requirements,
tests (including sections outside its phase heading), applicable global
acceptance criteria, non-goals, dependencies, and explicit decision gates.
Name what the unit satisfies and what remains deferred.

Treat authored phase order as dependent unless the issue marks phases as
independent. A dependent unit starts only after its prerequisites merge.
Under PR-only scope, report dependents as waiting on the open prerequisite
PR; do not invent stacked delivery. For explicitly requested stacked PRs,
document prerequisite branches and PR bases instead of pretending they are
already on the default branch.

Respect authored decision gates unless the user
explicitly overrides their covered scope; neither a prior merge nor a
reviewer's approval nor Astra's assessment clears a gate. A blocked or gated unit stops its dependent
units; keep unrelated authorized units moving. Do not guess a consequential
product or architecture decision to make the issue executable.

## Models and worker boundaries

Use available native model identifiers, not invented aliases. User choices
override these defaults. Terra may substitute for Sol when available.

| Role | Default | When to increase effort |
|---|---|---|
| Short plan and routine coordination | Coordinator | Delegate complex planning to Astra/high |
| Architecture or consequential judgment | Astra/high | Increase only for a specific unresolved question |
| Implementation and verified fixes | Sol/medium | Sol/high for difficult code, concurrency, or trust boundaries |
| Independent complete-diff review | Sol/xhigh | Ask Astra about a material disagreement or recurring root cause |
| External review | Opus/xhigh preset | User-selected provider or model takes precedence |

The core workflow uses native tools and agents. The default review profile
adds the Opus CLI preset in [external-review.md](references/external-review.md).
The user can choose a different external provider or native-only review.
Record the selection before implementation; do not silently remove a required
review when its tooling fails. Preflight the selected review tools and
configured authentication before implementation without exposing credentials.
If a preferred native model is unavailable,
use an available model with comparable capability and report the substitution.

Give each worker the unit contract, current plan, absolute worktree path,
branch, file scope, acceptance tests, and explicit mutation boundary:

- Implementers may edit and commit locally in their assigned worktree.
  They may not push, open or merge PRs, edit issues, change other worktrees,
  write memories, or recruit more agents unless separately authorized.
- Planners and reviewers are read-only except for an explicitly assigned
  local plan/report artifact. No source, Git, or GitHub mutations.
- Return the actual commit, changed files, contract coverage, test evidence,
  and unresolved concerns. Coordinator inspection is the verification.

Use a fresh implementer per unit to keep context bounded. Reuse that worker
for focused fixes while its worktree and branch are unchanged. Parallelize
only independent scopes; serialize shared contracts and overlapping files.
After a worker batch, inspect status, diff, log, and PR state yourself. Inspect
unexpected changes before acting; never discard them to make Git succeed.

## Plan and implement

Write a short plan before source edits. Include scope and deferrals, affected
production paths, important invariants with enforcement and test evidence,
compatibility risks, relevant checks, and unresolved decisions. Keep routine
plans small; add detail when it resolves a concrete risk.

The coordinator checks ordinary plans against the issue and implementation.
For uncertain architecture, security, migrations, or complex ordering, obtain
an independent plan review before dependent implementation. Verify findings
against sources; approve when no material defect or missing decision remains.
Do not grow the plan to satisfy speculative suggestions.

Implement production changes and meaningful tests together. Use focused
checks while iterating. Reconcile affected documentation and tracked
contracts before final review, as required by the repository. Exercise the
real production path where injected unit tests cannot establish the claim.
Use sabotage cases when they help demonstrate enforcement, not as a universal
requirement for every invariant. Check official references or actual runtime
behavior when the plan relies on uncertain technical facts.

## Review and fix

Freeze only a clean candidate commit: no tracked changes or untracked
non-ignored files. Inspect leftovers and either commit intended changes or
run checks in a fresh worktree at the SHA, preserving the original files.
Record the full SHA. Obtain an independent
native review of the complete unit diff. When required, obtain the selected
external review too. Reviews and repository checks may run concurrently on
that frozen candidate; nobody edits it while those checks are running.
Give write-producing checks one owner per worktree; reviewers use separate
scratch space for probes so they cannot race over generated test artifacts.

Provide the unit contract, full diff, relevant source and tests, exact SHA,
and known limitations. Subsequent reviews also receive prior findings and
their dispositions, plus the complete current diff and fix diff. Do not ask
a critic to re-find history from memory or review only the last patch.
Reviewers must distinguish material defects from suggestions, cite evidence,
and return their reviewed SHA and `VERDICT: SHIP` or `VERDICT: REVISE`.
SHIP means no remaining material concern, not that every optional nit was fixed.

Verify substantive claims yourself with code, documentation, or focused
probes. Record every finding as one of:

- **Fixed:** confirmed defect, corrective commit, and verification evidence.
- **Rejected:** concrete evidence that the claim does not apply.
- **Deferred suggestion:** optional improvement with a reason to leave it out.
- **Unresolved:** material uncertainty; not merge-ready.

Never treat a reviewer verdict as proof of test results. Do not accept a
claim simply because an external reviewer made it. A required reviewer's
REVISE stands until that reviewer returns SHIP. Send evidence-based rebuttals
in the next round; a persistent disagreement is unresolved, not permission
to merge. Record out-of-scope bugs under repository policy without enlarging
the unit, unless they invalidate its claimed acceptance criteria.

Once the candidate checks and reviews have finished, batch confirmed fixes
into a focused commit, run the affected checks, and repeat review at the new
SHA. Recheck a changed plan if the fix alters its approach. A new recurring
variant of the same defect calls for Astra's root-cause assessment before
another patch. Avoid a separate verifier agent for every finding when the
coordinator can establish the evidence directly.

Stop at the first candidate whose required reviewers return SHIP, whose
material findings are resolved, and whose required checks pass. No ceremonial
extra passes. Default to at most three complete code-review rounds per unit.
The required native and external reviews for a candidate together make one
round. A substantive re-review after fixes, a rebuttal, or a base update
counts as the next round. Reuse already valid SHIP/check evidence only when
the candidate SHA is unchanged; do not rerun a satisfied reviewer needlessly.
If the third round does not establish readiness, pause that unit, obtain
Astra's assessment, and present a concrete decision request before another
round. This assessment cannot replace the required reviews or checks.
Do not start fresh review sessions merely to evade the limit.
Tool retries are bounded recovery, not
completed reviews; retain partial findings and pause the affected unit if a
required review cannot be completed.

## Verify, open the PR, and deliver

Run the full repository gate before declaring the unit ready. Short or focused
tests do not substitute for required coverage, integration, image, or runtime
checks. Record actual passes, failures, and skips. A missing mandatory check
is a blocker; an optional unavailable check is a disclosed limitation.
Do not repeat successful checks on unchanged content without a new reason.

Open a draft PR when the committed implementation is reviewable and CI can
provide useful evidence. Describe the behavior, scope, deferrals, and current
validation accurately; mark pending checks as pending. Complete required
reviews and update the description before marking it ready. Use the issue's
closing keyword only when the whole issue's acceptance criteria are met;
a partial phase PR references the issue without closing it.

For a PR-only request, leave it open and report review/check status. Otherwise
merge only when all of these hold at the same exact candidate:

- Every required reviewer returned SHIP for the actual PR head's full SHA.
- All confirmed material findings are fixed and none remain unresolved.
- Required local checks and required CI succeeded for that candidate.
- The PR is ready, branch protection permits merging, and authorization covers it.

Use a merge operation that checks the expected head SHA when supported.
Do not bypass branch protection or force-push to resolve a failed proof.
Any new candidate commit, including a base update, invalidates prior-SHA evidence;
re-establish it before merging. Preserve the repository's merge convention.

Verify the remote merge and issue state rather than trusting the CLI exit
message. Re-read the live issue, dependencies, and gates before the next unit.
Start it from the updated remote default branch and continue without another
permission request when the existing authorization covers it.

## Recovery and reporting

Keep one small local run record in an allowed directory outside tracked
product files. Report its path. Record scope, units and dependencies, plan
paths, worktrees/branches, selected reviews, candidate SHAs, finding
dispositions, check logs, and PR/merge links. Add detail only as needed to
resume; no browser-session journal or mandatory public tracking comment.

After interruption, verify files, Git, PR heads, CI, and live issue state.
Reuse valid evidence only for its recorded candidate. If a worker retains a
broken tool context after environment repair, use a fresh worker against the
verified worktree; do not confuse inaccessible tools with absent edits.

For multiple phases, reconcile existing issue checklists or progress records
after each verified merge without overwriting unrelated decisions. Distinguish
shipped, PR-ready, waiting-on-PR, gated, and blocked units. Ask only when a consequential
decision or authority is missing, a material disagreement survives evidence,
or required proof cannot be obtained; include the concrete result and needed
decision. Request input asynchronously when available and continue independent
authorized work. Otherwise retain the request and finish independent work
before yielding; a question about one unit must not halt unrelated units.
The final report links PRs/merges, summarizes validation and review
outcomes, and names deferred work or remaining blockers.
