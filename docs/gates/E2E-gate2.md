# ★ Gate 2: end-to-end "fix everything" workflow

Branch `melvin/e2e-fix-all`. This asks for approval to commit and open the PR. Gate 1 rulings: `docs/gates/E2E-gate1.md` (10 Nov, plus the 12 Nov ruling "combined first").

## In plain words (read this first)
A junior DBA can now press **one button** and DBGuard tests a fix for every failed check on a throwaway copy:
- fixes that need no restart first, lowest risk to highest;
- then the restart fixes, with as few restarts as possible;
- a progress bar describes each step;
- a fix that fails is marked **FAILED** and left out, and the rest carry on.

The DBA then downloads **one package**:
- `sh harden.sh apply-all` applies every proven fix to the real database with all the existing safety checks;
- it takes **terminal screenshots there**, before and after;
- it tells the DBA exactly when to restart;
- `verify-all` confirms the fixes, and `rollback-all` undoes them.

The evidence zip can be uploaded on step 7, where DBGuard checks a fresh snapshot against the test.

Fixes that can lock out **other systems** (TLS, ciphers, network addresses, connection limits, password checker) carry a red, counted **"Client action required"** warning that must be acknowledged. "Needs restart" is now its own label instead of forcing high risk.

## Your decisions
1. **Approve the end-to-end work for commit and PR.** **Rec:** yes.
2. **Package pictures default to terminal mode** (Gate 1 decision 2). The security review suggested making rendered pictures the default, because terminal mode briefly runs a local terminal service on the DBA's machine. The README tells DBAs on shared machines to use `--screenshots rendered`. **Rec:** keep terminal as the default (your supervisor's requirement), with the README warning.
3. **Client-warning acknowledgement is enforced on the screen and by the package, not by the server's sandbox test.** The sandbox never touches a real database, and `apply-all` refuses to run without `--ack-client-impact`. **Rec:** record this as the design.
4. **md5 → SCRAM has no warning yet**, because there is no automatic fix for it to sit on (it is a manual checklist item). **Rec:** list it in HANDOVER as a follow-up.
5. **Known limits of the one-click test:**
   - the combined test uses each fix's approved template only; alternative templates are tried only when a fix is tested on its own after a failure;
   - when a restart fails and every restart fix passes on its own, that whole restart group is left out.

   **Rec:** accept and list in HANDOVER.

## 1. What was built
| Area | Files | What it does |
| --- | --- | --- |
| One-click run | `services/sandbox_poc/batch.py`, `batch_jobs.py`, `service.py`, `workflow.py`, `router.py`, `history.py` | Prepares every fix without a sandbox, combined test first, single tests only to explain a failure, two phases with one restart per restart round, FAILED fixes left out (PARTIAL), background job with plain progress, INTERRUPTED after a service restart, no 6-fix limit |
| Package | `review_bundle.py` (`build_combined_fix_files`), `package_assets.py`, `bundle_assets/package_runner.py`, `bundle_assets/terminal_evidence.py`, `runner.py`, `visual_evidence.py` | Folders built from the combined test; `harden.sh status / apply-all / verify-all / rollback-all`; pauses between restart rounds; terminal pictures with a private temporary connection file; rendered fallback with the address removed; evidence zip |
| Step 7 | `target_evidence.py`, `router.py`, `LiveUI.tsx` | Evidence-zip upload checked against the run and database (consistent, not authenticated); the server reassesses a fresh snapshot |
| Client warnings | `client_impact.py`, `planning.py`, `catalog_fixes.py`, `object_fixes.py`, `ClientImpact.tsx`, `clientWarnings.ts` | Red counted warnings, acknowledgement checkbox, `CLIENT-ACTIONS.txt`, `--ack-client-impact`, pending list on step 7 |
| Risk | `planning.py`, `ReviewPanel.tsx` | "Needs restart (brief downtime)" label; log collector, password checker and audit logger now medium |
| Sandbox | `runtime.py` | A small writable in-memory log folder (`/var/log/postgresql`) |
| Screen | `ReviewPanel.tsx`, `batchProgress.ts`, `liveStore.tsx` | One-click button, progress bar, result grouped as passed / failed / not eligible |
| Design | `docs/design/COMPANY_RULES.md` | Company custom rules (design only) |

## 2. Problems found and fixed during the build
- **Security review (11–12 Nov), pass with notes, all fixed:**
  - the step 7 wording claimed too much ("verified" became "consistent, not authenticated");
  - replica connections are now counted in client warnings;
  - `PG*` connection values are masked in error lines;
  - malformed uploads are rejected cleanly;
  - `verify-all` re-checks every fix.
- **Demo walkthrough (12 Nov):**
  - the log-folder and log-collector fixes could not restart together on the read-only copy, so a writable in-memory log folder was added;
  - one failed restart marked all 10 fixes as failed, so now only the restart group is left out and the rest are retried;
  - the package README disagreed about restarts.
- **The one-click test was slow** (186 s of 251 s spent testing fixes alone). It now goes combined first (ruled 12 Nov).
- **First live package test (12 Nov), fixed 16 Nov:**
  - `status` reported false drift for every fix after the first on an untouched database; now only the next fix due is drift-checked, and later fixes say "not applied yet";
  - `apply-all` wrote every restart fix and asked for one restart. But each restart fix's safety check expects the restart fixes before it to be **active**, so the second one stopped safely with "drift". This happened for the log collector + password checker, and for the password checker + audit logger. `apply-all` now **pauses for a restart after each restart fix** and prints the exact command to run next, and `verify-all` no longer re-checks a fix whose settings a later fix extended (password checker → audit logger). On the real database that is one restart per restart fix; the sandbox proves them with fewer. A follow-up could teach the checks the "written, waiting for restart" state, so the real database needs only one restart.

## 3. Tests (final code, 16 Nov 2026)
- **Unit:** `pytest -q`: 4520 passed, 117 skipped, 61 deselected, 4 xfailed. `validate_specs.py` passes.
- **Frontend:** typecheck clean; `npm test` 125/125.
- **Live** (`DBGUARD_POC_LIVE=1`, disposable Docker databases only, none left running):
  - `tests/test_e2e_fix_all_live.py`, **3/3** (210 s):
    - the one-click run through the background endpoints, PARTIAL with the failing pgaudit fix left out;
    - the package on a disposable target: `status`, refusals without the acknowledgements, `apply-all` with a restart after each restart fix, `verify-all`, reassessment confirmed, `rollback-all` back to the original settings, pictures, and the evidence zip checked and uploaded;
    - the chained password checker + audit logger package following its own printed restart instructions.
  - `tests/test_product_improvements_live.py`: 26 passed, 1 skipped.
- **The live package test found two more problems on 16 Nov, both fixed:**
  - the DBA runner compared configuration-file rows in the server's sort order, which ignores `_` in en_US, so a correct target looked changed; it now sorts exactly like the recorded states (`tests/test_runner_file_order.py`);
  - `status` after `apply-all` showed earlier fixes as "drift" because later fixes changed settings they also track; they now read "applied (later fixes … changed settings it also tracks, as tested)", and the last fix still carries the real check.
- **Reviews:**
  - db-security-reviewer passed the work in three rounds (11, 12 and 16 Nov), all findings fixed;
  - the 16 Nov round's one finding (the continue line must be a runnable command) was fixed and proven by the live chained test.

## 4. Known limits
- **Approvals are demo-labelled** (no real sign-in).
- **Terminal pictures** need VHS, ttyd, ffmpeg and psql on the DBA's machine (otherwise rendered), and should be used on single-user machines only.
- **Still manual:** pg_hba edits, turning TLS on, and installing add-ons.
- **Account and permission fixes** are hand-picked; including them automatically is recorded in the Architecture Plan.
