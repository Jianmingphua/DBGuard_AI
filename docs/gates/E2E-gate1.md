# ★ Gate 1: end-to-end "fix everything" workflow

Branch `melvin/e2e-fix-all` (from `main`). Plan approved by Melvin on 10 Nov 2026. This file records the rulings; all three decisions were approved on 10 Nov (see the end).

## Already ruled (10 Nov, in conversation)
- **One click tests a fix for every failed check.** Fixes that need no restart go first, lowest to highest risk. Fixes that need a restart go after them, lowest to highest risk, with **one** sandbox restart.
- **No 6-fix limit.** A request may contain only fixes that the snapshot's fix plan offers, each once.
- **Failed fixes are left out.** A fix that fails its test is labelled **FAILED** with the reason and left out; the rest continue. The run is **PARTIAL** if any fix failed.
- **Progress is visible.** The run happens in the background, with a **progress bar and a plain description of each step**.
- **Screenshots move to the package.** No screenshots are taken inside the sandbox any more. Screenshots are taken only by the package, on the real database.
- **Company custom rules: design only** (`docs/design/COMPANY_RULES.md`).

These are being built now.

## Your decisions

### 1. Risk levels: separate "risk" from "downtime"
Today any fix that needs a restart is forced to **high**. Proposal:
- Risk means only **what can break for applications and users**.
- A restart gets its own label, **"Needs restart (brief downtime)"**, shown next to the risk on the fix card, in the report and in the package README.

Proposed levels for the four restart fixes:

| Fix | Today | Proposed | Why |
| --- | --- | --- | --- |
| Log file collector (3.1.3) | high | **medium** | Logs move into files, so log shipping or `docker logs` must be adjusted. No effect on applications. |
| Password checker (5.6) | medium, forced to high | **medium** | Weak new passwords are refused, so account-creation scripts may fail. |
| Audit logger (3.2, pgaudit) | high | **medium** | Log volume grows. The package checks the add-on loads before the restart, so a missing add-on is caught first. |
| Network addresses (5.2, `listen_addresses`) | high | **high** | A wrong value cuts every remote client off. |

Fixes that need no restart keep their reviewed levels. The AI reviewer can still only raise a level, never lower it.

**Rec:** yes.

### 2. One package, one command, terminal screenshots on the real database
**Commands.** The combined package gets one script at the top:
- `sh harden.sh status`: shows which fixes are applied.
- `sh harden.sh apply-all --ack-prerequisites --ack-client-impact`: applies every proven fix in order. Every existing check still runs for each fix: package fingerprints, the database identity, "the setting is still as tested", and the lock against two runs at once.
  - It **stops at the first problem** and lists what was already applied.
  - After the restart fixes are written, it prints **"RESTART POSTGRESQL NOW, then run `sh harden.sh verify-all`"**. It never restarts the server itself.
- `sh harden.sh verify-all`: confirms every fix took effect.
- `sh harden.sh rollback-all`: undoes **only the fixes this package applied**, in reverse order. It uses a small local record that `apply-all` keeps.

**Terminal screenshots on the real database.** This changes your Task 2 Gate 1 ruling #6, which allowed only rendered pictures on the DBA's machine because of connection details. It uses the same safety design as the sandbox screenshots:
- **Three pictures:**
  - **before** (at the start of `apply-all`);
  - **after** (at the end of `verify-all`, after the restart);
  - **after undo** (`rollback-all`).
- **Connection details never appear.** The package writes a private, temporary PostgreSQL connection file and password file, readable only by the DBA's account and deleted straight after. VHS types one fixed command: `psql service=dbguard -X -e -v ON_ERROR_STOP=1 -f <private folder>/dbguard-<stage>.sql`. The address, user name and password are never typed or shown.
- **Only fixed, read-only checks:** the changed settings, and the one account or table for account fixes. They never ask for the server's address, passwords or keys. The masking from Task 2 also runs on the output.
- **The same recording safeguards as Task 2:** minimal environment, private folder, timeout, and every process the recording started is stopped. No browser download during a run.
- **When VHS isn't installed on the DBA's machine:** the package takes a rendered picture instead, with the server address and port removed, and says why. A screenshot problem **never** fails a patch.
- **Machine requirements.** The README says the machine needs VHS, ttyd and ffmpeg, installed once. It also warns to use terminal pictures only on a single-user machine, because the local terminal listens on that machine for a few seconds.

**Evidence back into DBGuard.** The package zips the three pictures, the query output and a fingerprint list into `target-evidence-<run>.zip`. On step 7, "Verify target", the DBA uploads it. DBGuard then:
1. checks every fingerprint, the run and the database identity;
2. shows the pictures in the run history;
3. reassesses a fresh snapshot against the package, fixing today's gap where step 7 only compared in the browser.

The upload accepts only that zip's known file names, PNG and JSON, with a size limit.

**Still manual, stated plainly:** login-rule file edits (pg_hba), turning on TLS (certificates) and installing add-on packages.

**Rec:** yes.

### 3. Client-impact warnings: direct, counted, acknowledged
Fixes that can break **other systems' connections** get a red **"Client action required"** box. It is never a footnote. The box covers:
- what breaks;
- **how many connections right now** would be affected, counted from the evidence already collected (no collector change);
- what must change on the client side;
- how to confirm afterwards.

Example:

> **⚠ CLIENT ACTION REQUIRED: this change will block clients that are not updated.**
> After this fix the server refuses TLS 1.0 and 1.1. **3 connections right now use TLS 1.1** (application `billing`, user `billing_svc`, private network). **Before applying:** upgrade these clients to TLS 1.2 or later. **After applying:** confirm each one reconnects. Your side being hardened does **not** mean these clients still work.

| Fix | What breaks | Counted from |
| --- | --- | --- |
| 6.9 Minimum TLS version | Clients that only speak TLS 1.0 or 1.1 can't connect | Current sessions' TLS version |
| 6.10 Allowed ciphers | TLS 1.2 clients without an allowed cipher fail; clients set to "prefer" TLS may silently connect without encryption | Current sessions' cipher |
| 5.2 Network addresses | Clients on addresses no longer listened on can't connect | Current sessions' address type |
| 5.5 Connection limits | The application is refused once it reaches the limit | Current connections per account vs the proposed limit |
| md5 → SCRAM passwords | Old drivers without SCRAM support can't log in | Accounts still on md5 |
| 5.6 Password checker | Account scripts that set weak passwords fail | No live count; script check only |

**Where it appears:**
- **On the fix card**, with a checkbox the DBA must tick before the fix can be tested or packaged.
- **At the top of the report.**
- **In `CLIENT-ACTIONS.txt`** in the package.
- **In the package command**, which refuses `apply-all` without `--ack-client-impact`.
- **On step 7**, which keeps a "Client changes still pending" list until each item is marked done.

**Rec:** yes.

## Build plan after your rulings
1. **Backend for the one-click run** (in progress; already ruled).
2. **Screen:** the one-click button, the progress bar with step descriptions, the result grouped into passed / failed / not eligible, and separate risk and restart badges.
3. **Decision 1:** the risk levels and the restart label.
4. **Decision 2:** the package commands, terminal pictures on the real database, and the evidence upload.
5. **Decision 3:** the client-impact warnings.
6. **Company rules design document.**
7. **test-writer:**
   - unit tests;
   - live: a one-click run of at least 10 fixes, including restart fixes and one that deliberately fails;
   - live: the package's `apply-all → restart → verify-all → rollback-all` on the **disposable demo source** database, never a real one.
8. **db-security-reviewer:** focused on the terminal capture on the DBA's machine, the evidence upload and the new commands.
9. **Demo check, then Gate 2.**

---

## Rulings (Melvin, 10 Nov 2026)
All three recommendations are approved:
1. **Risk levels:** "Needs restart (brief downtime)" becomes its own label. The log collector, password checker and audit logger go to **medium**; network addresses stays **high**.
2. **Package:** `apply-all`, `verify-all`, `rollback-all` and `status`, plus terminal screenshots on the real database and the evidence upload on step 7. This **replaces Task 2 Gate 1 ruling #6** (rendered pictures only on the DBA's machine).
3. **Client-impact warnings:** with live counts, the required checkbox, `CLIENT-ACTIONS.txt` and `--ack-client-impact`.
