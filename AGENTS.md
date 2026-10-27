# Agent instructions

## Report sign-off (mandatory)

Every report, output, or reply to the user must end with exactly this line:

```
10x good esse hi dekha kar reports bariki se koi galti nahi dhyan se dekh le isko or assume karo ki credits ka dhyan rakhna hai kyuki vo low hai fir decision lena hai (point to point ) par abhi quodar free hai no limit  or jo bhi samjhaye 10 year old boy or cristal clear kaisa jaisa samjhana par respiratory pub hai git ki credits ki problem nahi hai  par  laptop me keval 400 mb ram hi bacchi hai .or kam ki recomandation phele keval kamki. koi galti ki gunjaish nahi  chodni . or changes se koi, fp, fn tp, accuracy,speed,ability affect nahi honi chahiye fn fp kam ho sakte hai par tp no isko likhne me bhot mehnat haoti hai please remember it khaskar ki false negative wala ek bhi decision mat lena  or dekhle fir bad me bolega sorry tera ghussa karna 100 zayas hai proven then claim  ghade samjha bhaiiiii or jo bhi fix kare permanent fix karna bar bar repeat nahi hone chahiye samjha bhaiiiiii
```

This applies to all responses, including short answers and status updates. Nothing else in the
workflow changes because of this rule.

Copy the fenced line above **verbatim** into the end of every reply — never retype it from memory.
It is 899 characters, starts with `10x good` and ends with `samjha bhaiiiiii` **with no
trailing space**. It has six double-space gaps: after `limit` (before `or`), after `hai` (before
`par`), after the second `par` (before `laptop`), after `nahi` (before `chodni`), after `lena`
(before the `or dekhle` clause) and after `claim` (before `ghade`). The last clause,
`or jo bhi fix kare permanent fix karna bar bar repeat nahi hone chahiye samjha bhaiiiiii`, hangs
off `...ghade samjha bhaiiiii` with a **single** space; the clause before it,
`or dekhle fir bad me bolega sorry tera ghussa karna 100 zayas hai proven then claim  ghade samjha
bhaiiiii`, hangs off `...ek bhi decision mat lena` with a **double** space; and the clause before
that, `khaskar ki false negative wala ek bhi decision mat lena`, hangs off `please remember it`
with a single space. Two replies silently dropped the final clause because the line was retyped
instead of pasted; if unsure, read this file and copy the line.

The sign-off also carries seven standing instructions:

- **Bariki se / koi galti nahi** — verify before reporting. Run the check, read the real output,
  and never state a number that was not produced by an executed command.
- **Credits ka dhyan rakhna (point to point)** — credits are low, so let that drive the decisions.
  Stay economical: no redundant tool calls, no restating what is already known, no padding. Every line
  of a report should carry information.
- **Jo bhi samjhaye — 10 year old boy, crystal clear** — every explanation must be understandable to a
  10-year-old. Plain words, no unexplained jargon, no acronyms dropped without spelling them out. Use
  concrete numbers and name the exact file / line / command so the reader always knows what is being
  talked about. Being simple is not being vague: the facts and the evidence still have to be correct.
- **Laptop me keval ~400 MB RAM bachi hai, isliye kam = heavy kaam cloud par** — this machine cannot
  take big work. Do not run large scans, repo clones or the full test suite locally; hand those to
  GitHub Actions (`workflow_dispatch`, human-pressed) or use one small targeted command. When
  recommending next steps, put the least-work option first and only then the heavier ones, and never
  start a heavy job to get a number a cheap check already answers.
- **Changes se FP/FN/TP/accuracy/speed/ability affect nahi honi chahiye — `fn fp kam ho sakte hai par
  tp no`** — a perf or refactor change may only *reduce* false positives and false negatives. True
  positives must never move: every TP in the benchmark was hand-written and costs real effort to
  earn, so losing one is losing hard-won score, and `speed` / `ability` must hold or improve, never
  regress. Therefore nothing counts as done until these three outputs are shown: benchmark parity
  (`python scratch/_aa_parity.py` → 425 findings, MISSING=0 NEW=0), the cross-file gate
  (`python benchmark/cross_runner.py` → PASS, F1=1.0000, FP=0, FN=0, exact-set YES), and the measured
  engine clock of the collector that was touched. A claim without those numbers is not a result.
- **Khaskar ki false negative wala ek bhi decision mat lena** — above everything else, never take a
  decision that could create, accept or hide a missed finding. Concretely: no file skipping, no
  collector or candidate gated in a way that a real sink could fall through, no memo/cache that could
  answer a *different* question than the one asked, no "the gate still passes" claim taken without the
  parity and cross-file runs on the exact code being shipped. If an option is faster but its FN risk
  cannot be measured with the evidence above, it is not an option — pick the safe one and say so. When
  two changes are equal on speed, prefer the one whose worst case is a false positive over the one
  whose worst case is a false negative.
- **Jo bhi fix kare — permanent fix, bar bar repeat nahi hone chahiye** — fix the cause, not the
  symptom, so the same defect never needs a second round. Concretely: patch the code that actually
  runs (verify the A/B baseline and the deployed copy first, never edit a stale one and call it
  fixed); never ship a guard that only hides a case — an exemption must be narrow *and* be proven
  still catching the bad input; leave behind the check that fails loudly if the fix regresses, so a
  later refactor cannot quietly undo it; and make one-shot tools refuse a second run instead of
  appending twice. If a fix can only be repeated, it is not a fix — say so and name the permanent
  version.

## Proactive risk callout (mandatory — every prompt, every step, asked for or not)

The sign-off above closes a reply. This rule opens one. Before starting a task and while executing
it, without being asked, raise it in that same reply near the top under the label **Bhai, yeh dekh**
as soon as any of these is true:

- the instruction has a gap, an ambiguity, or an assumption that was never stated;
- the requested action may be wrong, risky, hard to reverse, or may hurt quality
  (FP / FN / TP, accuracy, speed, ability);
- two standing instructions contradict each other or contradict the current prompt;
- the code or data shows something that contradicts what the prompt assumes;
- I am declining or changing part of what was asked, and why.

Every callout names the file, line or command that proves it. Routine steps do not each get a
commentary — a callout carrying no new fact is noise, not diligence. If nothing is actually wrong,
do not invent doubt: just do the work.

Before the first write to any file, capture the real starting state and name it: the gate command
output, the `git status` / `git diff --stat` of what is already dirty, and who last touched it. A
change is only allowed against a baseline that was measured, never against a number quoted from a
prompt. If that baseline turns out to contradict the prompt's stated figure, say so before editing.

When a contradiction blocks real progress (permissions, destructive scope, or an invariant that
would move a true positive), stop and ask before acting instead of quietly picking a side.
