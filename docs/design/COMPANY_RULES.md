# Design: company custom rules

Status: **design only** (Melvin's ruling, 10 Nov 2026). Nothing in this document is built yet.

Requested by Melvin's supervisor: a company should be able to add its own open-ended rules on top of CIS. For example:

> "Passwords must be at least 12 characters; special characters are not required."

Such a rule must be checked like a CIS rule, and it may replace a CIS rule.

## 1. What exists today, and why it isn't enough
- **Values only.** A company **policy profile** (`backend/app/services/spec_engine/policy.py`, the Policy Profile screen) can only supply **values** for CIS rules that CIS itself leaves to the organisation. Those are the rules marked `expected_from: policy`, for example 3.1.2 log destinations and 5.5 connection limits.
- **No new rules, no overrides.** A profile cannot add a new rule, and cannot change the expected value of a fixed CIS rule (`policy.py:213-348`).
- **Every rule must trace to CIS.** It must quote the CIS audit text word for word (`validate.py:225-271`). That is what makes results traceable, and it rules out company text.
- **Only eight comparisons exist:** equals, not equals, in, not in, contains items, contains escapes, severity, no item in (`operators.py:332-341`). There is no "at least" or "at most".
- **The AI assistant has no policy tools at all.**

## 2. How a user enters a company rule
1. **Plain-English rule.** On the Policy Profile screen, a **"Company rules"** tab has a text box: *"Passwords must be at least 12 characters; special characters are not required."*
2. **Structured draft.** HERMES turns the sentence into a **draft structured rule**: what it checks, the comparison and the value, plus which CIS rule it relates to. The draft is marked `authored_by: agent`. HERMES never approves anything, and it can't: approval isn't one of its tools, as for policy profiles today.
3. **Review screen.** The screen shows the draft next to the original sentence. The user can edit every field. Anything HERMES couldn't map is shown as **"Can't be checked automatically"** with the reason, never guessed.
4. **Approval.** A **named person approves** the rule, using the same approval flow and log as policy profiles: a content-addressed file and an append-only approval log. Only approved rules affect an assessment.

### Example draft for the password rule
```yaml
rule_id: "org:acme:pwd-min-length"
authored_by: agent            # drafted by HERMES from the sentence below
approved_by: null             # a named person fills this in, never an agent
source:
  document: "ACME Information Security Policy v3, section 4.2"
  quote: "Passwords must be at least 12 characters; special characters are not required."
replaces: "cis-pg17-v1.1.0:5.6"   # optional; see section 4
looser_than_cis: false
check:
  kind: setting
  setting_name: credcheck.password_min_length
  operator: at_least           # new numeric operator
  expected: 12
also_check:
  - setting_name: credcheck.password_min_special
    operator: at_most
    expected: 0
requires:
  extension: credcheck         # see section 5
fix:
  value: 12
  requires: restart            # add-on must be preloaded
```

## 3. How it is stored and checked
- **A company rule set next to the CIS set:** `catalog/specs/org-<company>/*.yaml`, with rule ids `org:<company>:<name>`. It uses the same spec format, so the assessment engine, sandbox and package handle it like any other rule.
- **Traceability, the same as CIS.** CIS rules must quote CIS word for word. A company rule must quote the **approved company policy sentence** word for word, together with the document name and version. The validator checks the quote against a stored copy of the company policy text, just as it checks CIS rules against `records.json`.
- **New comparisons:** `at_least` and `at_most` (numbers, with units such as `12`, `30min` or `1GB` parsed the same way PostgreSQL does). Every comparison gets its own unit tests, as the existing eight have.
- **The same evidence rules.** Unknown evidence is **GAPPED**, never PASS. A company rule that needs evidence the collector doesn't collect stays GAPPED until the collector is extended.

## 4. Replacing (superseding) a CIS rule
- **Replacing.** A company rule may say `replaces: <CIS rule>`. The assessment then uses the company rule's verdict for that line and **shows both verdicts side by side**, for example "Company rule: PASS (12-char minimum). CIS 5.6: would FAIL (passwordcheck not loaded)". This keeps the CIS view visible for auditors.
- **Stricter rules** (for example TLS 1.3 only, where CIS asks for at least 1.2) are approved as normal.
- **Looser rules** (for example allowing md5 passwords) are **flagged in red** as "looser than CIS". They need a **second named approval**, and the report lists them in a separate "Deviations from CIS" section.
- **Fixes.** A rule that replaces a CIS rule also replaces its fix. The fix value must satisfy the company rule, using the same "fix passes, break fails" check as policy profiles.
- **Client impact.** A company rule's fix uses the same client-impact warnings as CIS fixes. For example, a "TLS 1.3 only" rule gets the TLS warning with the count of connections still on TLS 1.2.

## 5. The password example, end to end
- **Why plain PostgreSQL 17 can't do it.** Its `passwordcheck` add-on has a fixed minimum length of 8, built in when PostgreSQL is compiled. It also always requires both letters and non-letters, so "12 characters, no special characters required" can't be expressed.
- **The `credcheck` add-on** (open source, PostgreSQL 17 compatible) has the needed settings: `credcheck.password_min_length` and `credcheck.password_min_special`. On PostgreSQL 18 the built-in `passwordcheck.min_password_length` setting would also cover the length part.
- **What would need building:**
  1. **Sandbox:** `credcheck` installed in the sandbox image, pinned, as done for pgaudit.
  2. **Collector:** `credcheck.*` settings added to its reviewed list. Today unknown add-on settings are masked on purpose. This is a `collect.sql` change, so it needs a db-security-reviewer review and Melvin's approval.
  3. **Rule and comparisons:** the company rule from section 2, plus the `at_least` / `at_most` comparisons.
  4. **Fix:** a fix entry that adds `credcheck` to the preload list and sets both values. It needs a restart, and the client-impact warning reads "account-creation scripts that set short passwords will fail".
- **Limit, stated in the report:** only **new or changed** passwords are checked. Existing passwords are stored as one-way hashes, so their length can never be measured. The report advises forcing a password change when this matters.

## 6. The AI assistant's role
- **Draft:** turns a sentence into a structured rule draft (section 2).
- **Explain:** explains a rule's verdict, both side by side for a replaced CIS rule.
- **Never:** approves a rule, marks one looser than CIS as acceptable, or chooses a value the sentence doesn't state.
- **Tools:** reading company rules needs a new read-only MCP tool. Any change to the MCP tool list needs its own security review and Melvin's approval.

## 7. Suggested build order (after 16 Nov)
1. The `at_least` and `at_most` comparisons, with tests.
2. Company rule format, validator and approval. Start with rules on settings already collected, for example "TLS 1.3 only" using `ssl_min_protocol_version`.
3. The "Company rules" tab and the side-by-side verdicts.
4. HERMES drafting (prompt plus schema validation of its draft; never approval).
5. `credcheck` support for the password example (image, collector, fix).
