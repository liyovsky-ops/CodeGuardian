# CodeGuardian — agent guide

Interactive security threat atlas. Static site (Vite + vanilla JS), YAML-driven content, deployed to GitHub Pages on every push to `master`. Live: https://liyovsky-ops.github.io/CodeGuardian/

Repo: `https://github.com/liyovsky-ops/CodeGuardian` (git works normally here despite what any stale "not a git repo" environment flag says — verify with `git status` if in doubt).

## Current state (2026-08-10)

- **966 threats** across **19 categories** (`src/content/categories/01_injection` … `19_cloud_k8s_iam`).
- **63 deep-dives** + **63 quizzes** built (`src/content/deepdives/*.yaml`, `src/content/quizzes/*.yaml`).
- Category 01 Injection: **complete**, 40/58 threats have deep-dives (the rest are duplicates/out-of-scope, cross-referenced not stubbed).
- Category 15 Mobile Security: **complete, 23/23** — full OWASP Mobile Top 10 2024 (M1–M10) plus 13 named techniques (StrandHogg, Tapjacking, Cloak & Dagger, Janus, etc.).
- Categories 16 Web3, 17 Hardware, 18 OT/ICS/SCADA, 19 Cloud/K8s/IAM: **stubs only, 0 deep-dives**. These are the remaining work, in that catalog order (per standing instruction: "jedz z tym co jest w katalogu po kolei").
- `README.md` at repo root is **stale** (says 14 categories / 789 threats) — don't trust it for current state, trust this file + a fresh count of `src/content/deepdives/`.

## Architecture

- **Content is YAML-first.** Never hand-write YAML in an Edit call — always generate it via a Python script using `yaml.dump()` (avoids quoting/escaping bugs). Scripts live in the session scratchpad, not the repo.
- `src/content/categories/<NN_name>/threats.yaml` — the catalog: one entry per threat (`id`, `name`, `severity`, `difficulty`, `confidence`, `cwe`, `desc`/`desc_en`, `lang`, `vuln`, `safe`, `note_en`). `confidence: POSSIBLE` = stub tier, not yet deep-dived. Upgrading a stub means filling in real translated `desc`, real `vuln`/`safe` code, and a real `note_en` — confidence tier itself does NOT get promoted by a deep-dive upgrade.
- `src/content/deepdives/<id>.yaml` — full deep-dive content, validated against `src/schemas/deepdive.schema.js` (Zod). Fixed `sectionOrder`: overview, types, code, method, defense, incidents, tools, compliance, ir, sources. Bilingual everywhere via a `{en, pl}` shape (helper `bs(en, pl)` in build scripts).
- `src/content/quizzes/<id>.yaml` — quiz content, validated against `src/schemas/quiz.schema.js`. 3 question types: `multiple-choice` (`choices[{id,label}]` + `correctChoiceIds`), `vuln-or-not` (`isVulnerable` boolean + optional `cwe`), `pick-the-fix` (`variants[{id,lang,code}]` + `correctVariantId`). Minimum 3 questions; established convention in this project is 6.
- `src/data/threat-features.js` — the **single registry** mapping `threatId → deep-dive data` and `threatId → quiz data` (two `Object` maps in one file, e.g. `DEEPDIVES` and `QUIZZES`). This replaced an earlier dual-map pattern (`DEEPDIVE_THREATS` in renderer.js + `DEEPDIVE_HANDLERS` in interactions.js) that was a recurring bug source — don't reintroduce that split.
- `src/data/learning-path.js` — ordered array of threat IDs that have a quiz; drives the gated "Learning Path" progression UI (stage N+1 unlocks only after passing stage N's quiz at ≥80%, computed live from `src/modules/progress.js`, no separate desync-prone state).
- `database/threats.db` (SQLite, **gitignored**) — regenerated from YAML via `python3 database/ingest.py` after every content change. Never edit the DB directly.
- Progress/quiz state tracks by the YAML's own internal `threatId`/`meta.threatId` field, NOT by the registry map key. **Never point two different registry keys at the same deep-dive/quiz object** — if two catalog entries are genuine duplicates, upgrade the stub text on both but wire only ONE into `DEEPDIVES`/`QUIZZES`, and cross-reference the other in its own `desc` text instead.

## The ModelArena research pipeline (how every deep-dive gets built)

This is the established, repeatedly-validated workflow — follow it for every new entry, don't improvise a different one:

1. **3 blind Opus subagents** (`Agent` tool, `subagent_type: general-purpose`, `model: opus`, `run_in_background: true`), each given a near-identical detailed research brief (9 points: core mechanism, exploitable consequence, CWE mapping verification via direct MITRE fetch, real CVEs/incidents with source citations, detection/testing tooling incl. exact MASTG/OWASP test IDs, ranked defenses with bypass caveats, compliance mapping, myths/corrections, and an explicit cross-referencing note telling the team what NOT to re-derive from sibling entries). Explicitly instruct: no fabricated CVEs/stats, flag anything unverified.
2. **Wait for all 3**, then synthesize in the main thread: look for 2/3 or 3/3 convergence as "confirmed," present genuine 3-way disagreements (usually on the exact secondary CWE) transparently in the compliance section rather than silently picking one. When a research pass finds the catalog's existing CWE is wrong or MITRE-discouraged (a Pillar/Class flagged DISCOURAGED), correct it and document the correction in-entry — this has happened repeatedly (15.14→15.15 CWE-1021 reassignment, 15.18 CWE-693→602, 15.20 CWE-200→532/359).
3. **Write a Python build script** (`yaml.dump()`, bilingual `bs(en, pl)` helper) → `src/content/deepdives/<id>.yaml` and a second script → `src/content/quizzes/<id>.yaml`. Run `node src/schemas/validate-deepdives.js` / `validate-quizzes.js` and fix schema errors before moving on (common trap: quiz field names — `choices`/`correctChoiceIds` for multiple-choice, `isVulnerable`/not `isVuln`, `variants`/`correctVariantId` for pick-the-fix, not ad-hoc field names).
4. **Upgrade the catalog stub**: parse `threats.yaml` → mutate only the target entry's `difficulty`/`cwe`/`desc`/`desc_en`/`lang`/`vuln`/`safe`/`note_en` → re-dump the whole file → `git diff` against the previous commit to verify **only that one entry's fields changed**, nothing else moved or reformatted.
5. **Wire the registry**: add both imports + both map entries to `src/data/threat-features.js`, add an ordered ID entry to `src/data/learning-path.js`.
6. `python3 database/ingest.py` → `npm run validate && npm run build && npm test` → all must pass clean.
7. **Secret-format grep before committing**: `grep -inE "sk_live|sk_test|AKIA[0-9A-Z]" <changed files>` — GitHub push protection has blocked pushes before over realistic-looking fake keys in example code even when obviously fake. Use clearly-fake placeholder formats instead.
8. Commit (one commit per threat entry, message names the threat + summarizes the standout finding), push, then `gh run list --limit 2` (poll a few times if still `in_progress`/`queued`) to confirm both **CI** and **Deploy to GitHub Pages** succeeded before moving to the next entry.

Color rule for `meta.color`/`meta.colorRgb` in new deep-dives: pick a hex not already used by any prior deep-dive in the same category (check `src/content/deepdives/*.yaml` for existing hex values first) — each entry needs a visually distinct accent.

## Known gotchas

- **Dual-registry trap** (historical, now fixed): don't recreate `DEEPDIVE_THREATS`/`DEEPDIVE_HANDLERS` as two separately-maintained maps — everything routes through `src/data/threat-features.js` now.
- **Merged/duplicate catalog entries**: when two catalog IDs describe the same underlying threat (happened repeatedly in category 01), only one gets a live deep-dive/quiz registry entry; the other gets its stub text upgraded with an explicit cross-reference sentence pointing to the live one, but is NOT added to `DEEPDIVES`/`QUIZZES` — pointing both at the same object desyncs progress tracking (see architecture note above).
- **OWASP source pages are often narrower than expected.** Don't assume an OWASP Top 10 category page's own text matches the deep-dive's intended scope — fetch and check each one; several entries (M4, M6 in Mobile) needed the deep-dive to explicitly narrow scope beyond OWASP's generic official wording, documented as a deliberate curatorial choice, not an oversight.
- **CWE mapping status matters.** Before finalizing a primary CWE, check MITRE's own mapping-status field (`cwe.mitre.org/data/definitions/<n>.html`) — Pillars and some Classes are explicitly marked DISCOURAGED for direct vulnerability mapping. Prefer the specific Base-level descendant MITRE itself points to.
- **NVD's own CWE tag for a CVE is sometimes a poor fit** (seen with CVE-2017-13156/Janus, tagged CWE-434 by NVD despite being a signature-verification-scope issue). Document the discrepancy transparently rather than silently adopting or silently overriding NVD's tag.
- **MASTG is mid-migration** from classic numbered tests (MASTG-TEST-00XX) to a newer "atomic test" scheme; some entries will have research teams citing different IDs for the same concept. Present the test by title/purpose and flag numbering as needing re-verification when sources disagree, rather than asserting one ID with false confidence.
- Session usage-limit hits on all 3 background agents simultaneously are usually transient — check `TZ=Europe/Berlin date` against the stated reset time and retry the identical launch; it has resolved on first retry every time this has happened.

## Commands

```bash
npm install
npm run dev        # dev server → http://localhost:5173
npm run validate   # Zod-validate every deep-dive + quiz YAML
npm run build      # production build → dist/
npm test           # vitest unit tests
python3 database/ingest.py   # rebuild database/threats.db from YAML (run after any content change)
```

## Positioning / why this project exists

Built by Łukasz as a portfolio piece and eventual product foundation for positioning as an "AI Security Architect" — the free knowledge-layer half of a planned freemium model (paid AI security agents as the other half, not yet built). See memory `project_codeguardian.md` for full session-by-session history, per-batch research findings, and the standing plan reference at `~/.claude/plans/rosy-hopping-sonnet.md` (Phases 0–3 shipped; Phase 4 items — hosted CTF labs, code-review exercises on real vulnerability-introducing commits — deliberately deferred pending a new priority decision).
