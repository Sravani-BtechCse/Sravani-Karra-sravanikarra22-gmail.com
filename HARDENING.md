# Hardening, part 1 — the starter and the fixture

Organiser-facing. What was changed, why, and how to prove it still works.

Written after evaluating a submission built from this task. That submission was close to
correct, and its failures were exactly where the documents went silent. The diagnosis is in
the next section, because every design decision below follows from it.

---

## The diagnosis

The candidate-facing documents are a complete specification: 1,667 lines across
`BRIEF.md`, `PERMISSIONS.md`, `AUTH-DATA-MODEL.md`, `UI-INVENTORY.md`, `WORKFLOW.md`,
`db/schema.sql` and `db/reference.sql`. Specifically:

| Where | What it gives away |
|---|---|
| `WORKFLOW.md:34` | the resolution algorithm in one sentence — *"identity, applicable grants, deny wins, baseline plus allow grants, implicit deny with provenance"* |
| `BRIEF.md §5.1` | a 30-row endpoint → permission table |
| `BRIEF.md §5.2` | the response shapes and the exact `reason` strings the tests assert |
| `UI-INVENTORY.md §3` | a complete testid → governing-permission table |
| `db/reference.sql` | the entire 5-role × 19-permission matrix |

Every paragraph has a 1:1 code target. There is nothing to *decide*, only to transcribe, and a
transcription is what a language model is best at. The evaluated submission proved the point:
the whole implementation — including every file the brief calls "yours to write" — arrived in a
single 8,573-line commit.

**The principle applied here: the documents stay necessary but stop being sufficient.**
Correctness must depend on data that cannot be in a prompt.

---

## 1. `node tools/strip-starter.mjs` — the hand-out is generated, not hand-maintained

`q1-starter/` is the reference implementation. `starter/` is the candidate hand-out, built from
it by the tool, and is never edited by hand. Re-running the tool is idempotent, so the starter
cannot drift from the reference except in the ways the tool documents.

**Removed** (everything the candidate writes):

```
NOTES.md                  the candidate's own write-up; it discusses the decisions on purpose
web/App.jsx, web/api.js, web/components/, web/styles.css
server/permissions.js, server/context.js, server/lifecycle.js, server/audit.js
server/routes/
```

**Replaced with throwing stubs** rather than deleted — `server/{context,permissions,lifecycle,audit}.js`
and `server/routes/index.js` — because `server/index.js` imports two of them and the shipped
scripts import the rest. Deleting them outright means:

- `npm run dev` dies on a module-resolution error instead of booting, and
- `node scripts/check-permissions.js` dies on import instead of reporting.

`WORKFLOW.md` phase 0 asks the candidate to *"run the public suites against the untouched
skeleton"* to learn their starting line. A skeleton that cannot boot or cannot run its own suites
fails that. With stubs, the starting line is legible:

```
check-jwt      0 passed, 43 failed   <- each failure names the file and the spec section
check-api      aborted: <first check that threw>
personalisation  could not resolve at all: TODO: server/permissions.js
```

**`verifyAccessToken` is re-stubbed** in `server/auth.js` by splicing the implemented body out
between its signature and its `return claims;`. There is no copy of the original stub anywhere in
this repository to restore from, so the stub text lives in `tools/lib/patch-loader.mjs` and the
splice refuses to run if the anchors move.

### Deliberate deviations from the old "strip" list

| Deviation | Why |
|---|---|
| `server/routes/index.js` is kept as a stub | `server/index.js` imports `registerRoutes`. The old list would have produced a starter that cannot start. This was an open packaging bug; it is now fixed rather than documented. |
| The four modules are stubbed, not deleted | Phase 0 requires the suites to run. Same anti-cheat value, strictly better usability. |
| `server/auth.js` is edited, not shipped whole | It contains the answer. |
| `web/` keeps `index.html` and a placeholder `main.jsx` | Vite needs an entry, and `npm run build` must succeed on day zero. The placeholder contains no console. |
| `scripts/check-api.js` gains a crash guard | It indexes straight into response bodies (`dana.body.orgs.map(...)`). Against a skeleton that throws an uncaught `TypeError`, and the `server.kill()` at the bottom never runs, so the spawned server is orphaned holding port 8123. The guard aborts cleanly. **No assertions are added, removed or changed.** |

---

## 2. `node tools/new-candidate.mjs <id>` — the fixture is per candidate

Every candidate's database gains **one organization that appears in no document**:

- a role from a pool of five, with a rank from `{5, 15, 25, 35, 45}` (the documented ranks are
  `10/20/30/40/50`, and `rank` is `UNIQUE`, so these never collide)
- a permission from a pool of five that is in neither `db/reference.sql` nor any prose
- a per-candidate baseline subset of the documented 19 — plus `device:list` and `device:view`
  unconditionally, so the console has a device row to render at all
- a device-scoped `allow` and a device-scoped `deny` of that permission, on **two different
  devices of the same org**, so all three distinguishable answers are reachable:
  `allow` / `explicit_deny` / `implicit`
- a plain documented `viewer` in the same org, to prove the documented baselines still resolve in
  an organization that did not exist when the docs were written

Generation is deterministic from the nonce (`sha256` → mulberry32, fixed draw order), so a
hand-out is reproducible and a review can regenerate the exact database.

### Why the nonce is a file, and why grading uses a different one

`.candidate-nonce` holds the nonce; `CANDIDATE_NONCE` overrides it. A *file* rather than an env
var because `playwright.config.js` passes an explicit `env` object to its `webServer`, which
would silently drop an inherited variable — the UI suite would then run against an unpersonalised
database and quietly prove nothing.

The shipped nonce is one instance. **Grading must use a different one**, so the values a candidate
can read in `scripts/personalise.js` are worth nothing:

```sh
CANDIDATE_NONCE="grade/$ID/$(date +%s)" node server/index.js
```

### The additive constraint (do not break this)

The overlay must never touch the two documented organizations, their users, devices, grants,
memberships, sessions or audit rows — **and must never add a membership for a documented user**.
The reason is not tidiness; the shipped suites assert exact counts and exact defaults:

| Assertion | File:line |
|---|---|
| dana sees exactly `['Acme Robotics','Globex Industries']` | `check-api.js:54` |
| viewer sees exactly 4 devices (the fifth is denied per-row) | `check-api.js:92` |
| Acme has 3 grants, then 4 after a UI-created one | `ui.spec.js:234`, `:259` |
| Acme has 4 device rows, kiosk absent | `ui.spec.js:129` |
| Globex has exactly 2 devices (`data-device-id^="dev_globex"`) | `ui.spec.js:192` |

And the trap that is easy to miss: `login(email)` with no `orgId` picks the caller's
*alphabetically first* org. `check-api.js:80`, `:88` and `:142` all rely on `sam`, `viewer` and
`admin` defaulting into `org_acme`. Adding any of them to a new org whose name sorts before
`"Acme Robotics"` silently re-scopes those tests into the wrong org. That is why the overlay adds
two brand-new users and touches no documented one.

### The proof

```sh
node tools/verify-overlay.mjs
```

It copies the reference tree, drops in `personalise.js`, patches the loader, writes a nonce, and
runs all four suites. Expected output:

```
  PASS  resolution engine (documented fixture)       ALL PASS — 35 passed, 0 failed
  PASS  token verification                           ALL PASS — 43 passed, 0 failed
  PASS  HTTP contract (WITH overlay loaded)          ALL PASS — 66 passed, 0 failed
  PASS  console contract (WITH overlay loaded)       25 passed
ALL SUITES STILL PASS with the overlay loaded — the overlay is additive.
```

Run this after **any** change to the overlay, the seed fixture, the suites, or the reference
implementation. If it fails, every candidate's local signal becomes a lie.

---

## What this achieves, and what it does not

**Achieves:** a solution that encodes the documented role/permission matrix now fails on its own
machine — and a solution copied from a prompt that contained only the documents fails everywhere,
because grading runs against roles and permissions the prompt never mentioned.

**Does not achieve:** stopping a determined candidate who reads `db/reference.sql` at runtime and
implements the engine properly. That is the intended solution. This work removes the *shortcut*,
not the exercise.

**Not implemented** (items 1–2 of the review, tracked in the root `README.md`):

1. a sealed pass/fail oracle to replace the prose algorithm;
2. the hidden tier — the six seams, plus HTTP-level fuzzing.

The third item from that review — the adversarial live round — is now specified, and it is no
longer a separate mechanism. It is coupled to a graded write-up so that the candidate's own log
becomes the interview agenda:

- `tools/templates/DISCOVERY-BRIEF.md` ships into the hand-out as `DISCOVERY-BRIEF.md`.
- `tools/templates/BUILD-LOG.md` and `DECISIONS.md` ship as the two graded templates.
- `DISCOVERY-RUBRIC.md` (repo root, organiser-only) is the answer key and the live-round script.

This is the enforcement mechanism that replaces an unenforceable no-AI rule. Two properties make
it work, and both are cheap to check: the log must **grow in its own commits** alongside the code
(so timestamps are evidence, not narration), and the live round **samples the candidate's own
entries** rather than asking prepared questions. A log that cannot be defended is a log the
candidate did not write. Note also what the candidate brief deliberately does *not* contain: any
list of concepts. It asks for a method — a wrong prediction, a reversal, a rejected alternative —
and leaves the discoveries to be made, which is the whole point.

---

## File index

```
tools/strip-starter.mjs               q1-starter/ -> starter/          (run this first)
tools/new-candidate.mjs               starter/    -> candidates/<id>/  (one per candidate)
tools/verify-overlay.mjs              proves the overlay is additive
tools/lib/patch-loader.mjs            the load-db.js / auth.js / check-api.js patches
tools/templates/server/*.js           the stubs installed into the hand-out
tools/templates/web/main.jsx          the placeholder SPA entry
tools/templates/scripts/personalise.js         the overlay: build, apply, expectations
tools/templates/scripts/check-personalisation.js  the candidate-visible floor
tools/templates/DISCOVERY-BRIEF.md    ships as DISCOVERY-BRIEF.md (the graded write-up brief)
tools/templates/BUILD-LOG.md          ships as BUILD-LOG.md  (graded; must grow per commit)
tools/templates/DECISIONS.md          ships as DECISIONS.md  (graded)
DISCOVERY-RUBRIC.md                   ORGANISER-ONLY: answer key, bands, live-round script
starter/                              generated. never hand-edit
candidates/                           generated hand-outs + manifests (gitignored)
```

`tools/templates/scripts/personalise.js` exports `expectations(overlay)`, which derives the
required outcomes **from the overlay itself**. The candidate-visible checker uses it, and the
hidden tier should too — so no expected value is ever hardcoded on either side.
