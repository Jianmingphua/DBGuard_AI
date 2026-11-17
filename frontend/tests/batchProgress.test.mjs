import { test } from "node:test"
import assert from "node:assert/strict"
import {
  fixAllSelection,
  formatDuration,
  groupFixes,
  outcomeSentence,
  progressLines,
  progressPercent,
  stepDescription,
} from "../src/live/batchProgress.ts"

test("progress: percent is bounded and safe on bad input", () => {
  assert.equal(progressPercent({ done: 7, total: 23 }), 30)
  assert.equal(progressPercent({ done: 30, total: 23 }), 100)
  assert.equal(progressPercent({ done: -1, total: 23 }), 0)
  assert.equal(progressPercent({ done: 1, total: 0 }), 0)
  assert.equal(progressPercent(null), 0)
  assert.equal(progressPercent({ done: "x", total: 3 }), 0)
})

test("progress: durations read naturally and refuse nonsense", () => {
  assert.equal(formatDuration(45), "45 s")
  assert.equal(formatDuration(185), "3 min 05 s")
  assert.equal(formatDuration(3720), "1 h 02 min")
  assert.equal(formatDuration(null), null)
  assert.equal(formatDuration(-3), null)
  assert.equal(formatDuration("abc"), null)
})

test("progress: the step description and completed lines", () => {
  assert.equal(
    stepDescription({
      status: "RUNNING",
      step_text:
        "Testing fix 7 of 23 on its own: log_rotation_size (low risk)…",
    }),
    "Testing fix 7 of 23 on its own: log_rotation_size (low risk)…",
  )
  assert.equal(stepDescription({ status: "RUNNING" }), "Working…")
  assert.equal(
    stepDescription({ status: "VERIFIED", step_text: "" }),
    "Finished.",
  )
  const lines = progressLines({
    steps: [
      {
        at: "t1",
        text: "Fix 9 of 23 FAILED its test and was left out: listen_addresses",
        fix_id: "fix-5.2",
        status: "FAILED",
      },
      { at: "t2", text: "" },
      "junk",
    ],
  })
  assert.equal(lines.length, 1)
  assert.equal(lines[0].status, "FAILED")
  assert.equal(lines[0].fixId, "fix-5.2")
})

test("result: fixes are grouped, and an unknown status is never shown as passed", () => {
  const groups = groupFixes(
    {
      fixes: [
        { fix_id: "a", status: "PASSED", stage: "combined" },
        {
          fix_id: "b",
          status: "FAILED",
          stage: "individual",
          reason: "health check failed",
        },
        {
          fix_id: "c",
          status: "NOT_ELIGIBLE",
          stage: "planning",
          reason: "conflict",
        },
        { fix_id: "d", status: "WEIRD" },
        { fix_id: "a", status: "FAILED" },
        { status: "PASSED" },
      ],
    },
    [
      { fix_id: "e", reason: "company policy missing" },
      { fix_id: "c", reason: "dup" },
    ],
  )
  assert.deepEqual(
    groups.passed.map((f) => f.fix_id),
    ["a"],
  )
  assert.deepEqual(
    groups.failed.map((f) => f.fix_id),
    ["b", "d"],
  )
  assert.deepEqual(
    groups.notEligible.map((f) => f.fix_id),
    ["c", "e"],
  )
  assert.equal(groups.failed[0].reason, "health check failed")
})

test("result: outcome sentences", () => {
  const groups = { passed: [1, 2, 3], failed: [1], notEligible: [] }
  assert.match(outcomeSentence("VERIFIED", groups), /All 3 fixes passed/)
  assert.match(
    outcomeSentence("PARTIAL", groups),
    /PARTIAL: 3 passed .* 1 failed and was left out/,
  )
  assert.match(outcomeSentence("FAILED", groups), /no DBA package/)
  assert.match(outcomeSentence("INTERRUPTED", groups), /interrupted/)
})

test("fix all: ticks every setting fix, keeps the DBA's account fixes, never adds account fixes", () => {
  const plan = {
    recommended_order: [{ spec_id: "s1" }, { spec_id: "s2" }, {}],
    object_proposals: [{ proposals: [{ fix_id: "fix-4.4-role-x" }] }],
  }
  assert.deepEqual(fixAllSelection(plan, []), ["s1", "s2"])
  assert.deepEqual(fixAllSelection(plan, ["fix-4.3-role-y", "s2"]), [
    "s1",
    "s2",
    "fix-4.3-role-y",
  ])
  assert.deepEqual(fixAllSelection(null, ["fix-4.3-role-y"]), [
    "fix-4.3-role-y",
  ])
})
