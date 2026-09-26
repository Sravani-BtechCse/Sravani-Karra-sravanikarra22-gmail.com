# Discovery rubric — organiser-only

**Do not ship this file.** It is the answer key for the reflection and the script for the live
round. The candidate-facing half is `DISCOVERY-BRIEF.md`, which ships inside `starter/`.

Grading split: **50% hidden tier · 30% `BUILD-LOG.md` + `DECISIONS.md` · 20% live walkthrough.**

Read `HARDENING.md` first. This document assumes the personalisation overlay exists and that
grading runs with a nonce the candidate never saw.

---

## 1. Run the mechanical checks before reading a word

These are cheap, and they decide how much the prose is worth. Do them in order; if check 1 fails,
the rest of the document is a story and should be scored as one.

| # | Check | Command | Reading |
|---|---|---|---|
| 1 | **Was the log grown, or delivered?** | `git log --follow --format='%h %ad %s' -- BUILD-LOG.md` | Entries must interleave with code commits. One commit at the end ⇒ cap the section at *Adequate* (19) regardless of quality. |
| 2 | **Does the log cover the phases actually completed?** | `git log --reverse --format='%h %ad %s'` vs the log's headings | A log missing the phases where the real work happened is a summary. |
| 3 | **Do the citations resolve?** | spot-check 5 from `DECISIONS.md` | Commit SHAs exist, test names exist, quoted error strings are real. Two dead citations ⇒ *Weak*. |
| 4 | **Does the claimed order match the commit order?** | compare | Claiming to have discovered something before the commit that could have revealed it is the single clearest fabrication signal. |
| 5 | **Are the three authenticity signals present?** | read | a wrong prediction, a reversed decision, an honest open thread. Absent all three ⇒ *Weak* at best. |

Check 4 deserves emphasis. Timelines are the hardest thing to fabricate consistently, because the
candidate has to align prose with `git log`, and the log is not under their control at grading
time.

---

## 2. The concepts worth having discovered

Calibration list, not a checklist. A candidate who discovers something not listed here and can
defend it scores higher, not lower. Tier A items are **absent from or contradicted by the
documents** — reading cannot produce them. Tier B items are stated in the documents but are
routinely *restated without being understood*; the discriminator is whether the log shows a test
that changed their model.

### Tier A — not derivable from the documents

| # | Concept | Why reading is not enough | What a genuine discovery looks like in the log |
|---|---|---|---|
| A1 | A removed membership row still exists, so re-invite must update, not insert | `UNIQUE(org_id, user_id)` in the schema, and nothing in the docs connects it to the invite path | A `500`/constraint error reproduced, then a branch on the existing row |
| A2 | The org-level view counts device-scoped grants, so a deny on **one** device locks that permission org-wide | Stated as a design note in one place, never as a consequence | "I expected the nav item to stay, it vanished, and the reason is the union" |
| A3 | The no-laundering check's scope argument, and what passing `null` does to it | The docs say "at that scope" without defining the check's scope | A trace of `deviceId` through the check, and an opinion on whether it is right |
| A4 | Suspension bumps the permission version, so a freshness check fires before the refusal can be reasoned about | Two documents state behaviours that cannot both hold | Quotes both, says which they built against, and why |
| A5 | Ungated routes bypass resolution entirely, so a status that "yields an empty set" does not restrict them | Only visible by asking which routes never call the engine | A map of gated vs ungated endpoints |
| A6 | Reading the token header before verifying the signature, so a malformed header is a crash not a rejection | Not mentioned anywhere | Any fuzzing at all, or a reasoned argument for why order matters |
| A7 | `end_reason` is constrained by a `CHECK` list, so new termination causes need an existing value | Schema-only knowledge, and it constrains what you can record | Noticing the vocabulary is closed and choosing deliberately |
| A8 | Default-org selection is alphabetical, which is why partial fixtures re-scope apparently unrelated tests | Emergent behaviour of "no server-side current org" | Any test that depended on org ordering and was debugged |

### Tier B — stated, but easy to restate without understanding

| # | Concept | Discriminator |
|---|---|---|
| B1 | Refusal outranks permission regardless of specificity | Did they implement precedence first and get corrected by an observation, or assert it as a rule? |
| B2 | The compound check needs two permissions on the **same** device, with distinguishable failures | Do they know which failure surfaces first, and why the order matters to the caller? |
| B3 | Grandfathering vs cascade — which events end a session in flight | Can they state the principle (authority snapshot) or only the list? |
| B4 | Invisible-not-forbidden is achieved structurally, not by filtering | Is it "I return 404" or "the token cannot name the org"? |
| B5 | Handing an invariant to the database rather than check-then-act | Did they test it, or just do it? Concurrency is the evidence |
| B6 | Any cache of resolved authority must not be keyed so it can cross an org boundary | Did they consider a cache, and can they say what would have gone wrong? |
| B7 | Time windows are half-open | Boundary behaviour at exactly the start/end instant |

---

## 3. Scoring the 30 points

| Band | Points | Looks like |
|---|---|---|
| **Excellent** | 26–30 | Log grown per phase with dates. ≥4 Tier A concepts with method and evidence, plus most of Tier B. Every `DECISIONS.md` section cites something real and names a rejected alternative with a specific failure. Names ≥1 genuine contradiction between documents with both statements quoted and a defended choice. Cites their own measurements. |
| **Good** | 20–25 | Log interleaves correctly. 2–3 Tier A, most Tier B. Citations resolve. One or two `Why:` sections are restatements. Honest open threads. |
| **Adequate** | 14–19 | Log delivered at the end, or covers only some phases. Mostly Tier B, mostly restated rather than observed. Rejected alternatives absent or generic. No measurements. |
| **Weak** | 7–13 | Linear narrative, no wrong predictions, no reversals. Vocabulary is the documents' vocabulary. Cannot name a single contradiction. |
| **Failed** | 0–6 | Contradicts the commit history, or contains claims the candidate cannot locate in their own repository. |

Award the full 30 only to a log you would have been glad to write yourself.

---

## 4. When the artifact and the document disagree

The live round decides. Two rules:

- **A rich document with an indefensible candidate is worth *Weak*, not Excellent.** The 20% is
  not an independent score; it is the verification of the 30%.
- **A thin, honest, defensible document beats a rich, indefensible one.** A candidate who wrote
  four short entries, all of which they can extend under pressure, has demonstrated more than one
  who wrote a polished report they cannot open the code for.
- If a candidate cannot account for code they submitted, **cap the artifact score too.** Not as a
  punishment — because you cannot attribute the work, and attribution is what the 50% is buying.

---

## 5. The live round — 20 minutes

The candidate's own log is the agenda. Do not prepare questions from the concepts list; prepare
them from what they actually wrote. This works because a genuine log contains its own attack
surface, and a fabricated one has no interior.

**Probe types, pick three at random from their document:**

1. **The prediction.** *"You expected X and got Y. Show me. What did you change?"* Then: *"Why was
   that the right fix rather than the other obvious one?"*
2. **The rejected alternative.** *"You rejected this. Suppose I insist you take it. What breaks,
   and on which line?"* — tests whether the rejection was reasoned or retrofitted.
3. **The contradiction.** *"You say these two documents cannot both hold. Demonstrate that, live."*
4. **The counterfactual they did not write about.** Pick a Tier B concept their log does not
   mention and ask it as a hypothetical. Excellent candidates answer from a model; memorisers
   cannot.
5. **The citation.** *"Take me to the line that makes this decision."*

**Then one live change, no assistance**, chosen to break a load-bearing assumption:

- add a permission to the catalogue and confirm it flows through resolution and the console
  catalogue without a second edit
- add a role and rank it between two existing ones, then ask who may modify whom
- delete the line that enforces the thing one of their `DECISIONS.md` sections is about, and ask
  them to predict the symptom before running the tests
- ask them to make a suspended membership unable to create an org

Score out of 20: 12 for the three probes, 8 for the live change. Deduct for answering from
documented text rather than from their implementation.

---

## 6. Calibration reference

A real submission built from this task, graded against an earlier version of this rubric:

- **Artifact:** all 169 shipped assertions passed. Genuinely strong engine; two 500-level bugs and
  one data-loss bug on paths the documents never mention.
- **Reflection (would have scored ~19/30):** A4 and A3 discovered and argued well, with the
  contradiction quoted and a defended choice — that part is Excellent. But the entire
  implementation arrived in a single 8,573-line commit, so check 1 caps the section. No Tier A
  items beyond those two; A1, A5, A6 were all missed, and each is exactly where the artifact
  failed.
- **The pattern worth internalising:** their two strong narrative items were about *documented
  contradictions*, and their three missed items were about *undocumented interactions*. A candidate
  who only reads finds contradictions; a candidate who builds finds interactions. That distinction
  is what this 30% exists to measure.

---

## 7. Adding the personalisation overlay to the reflection

The overlay gives the reflection an extra, verifiable question that costs one minute to ask:

> *"Your database has a role and a permission that no document mentions. Which are they, and what
> did your engine do with them?"*

A candidate whose engine reads the tables answers instantly and can name the mechanism. A
candidate who encoded the documented matrix cannot answer, and their artifact score already
reflects it. Use it as a cross-check on the artifact, not as a separate mark.
