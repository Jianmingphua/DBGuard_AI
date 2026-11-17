import { test } from "node:test"
import assert from "node:assert/strict"
import {
  ackKey,
  cleared,
  clientWarning,
  pendingClientActions,
} from "../src/live/clientWarnings.ts"
import { fixAllSelection } from "../src/live/batchProgress.ts"

const W = {
  required: true,
  headline:
    "CLIENT ACTION REQUIRED: this change will block clients that are not updated.",
  what_breaks: "After this fix the server refuses TLSv1 and TLSv1.1.",
  count_line: "3 connections right now would be affected.",
  before_applying: "Upgrade every client.",
  after_applying: "Confirm each reconnects.",
  reminder: "Your side being hardened does NOT mean these clients still work.",
  affected: [
    { application: "billing", user: "billing_svc", connections: 3 },
    "junk",
  ],
}

test("warning: read only from the server's fixed fields; malformed means none", () => {
  const w = clientWarning({ client_impact: W })
  assert.equal(w.headline, W.headline)
  assert.equal(w.affected.length, 1)
  assert.equal(clientWarning({}), null)
  assert.equal(
    clientWarning({ client_impact: { ...W, required: false } }),
    null,
  )
  assert.equal(clientWarning({ client_impact: { ...W, headline: "" } }), null)
  assert.equal(clientWarning(null), null)
})

test("acknowledgement: needed only for warned fixes, per snapshot", () => {
  const fix = { fix_id: "fix-ssl", client_impact: W }
  assert.equal(cleared(fix, [], "snap-1", "fix-ssl"), false)
  assert.equal(
    cleared(fix, [ackKey("snap-1", "fix-ssl")], "snap-1", "fix-ssl"),
    true,
  )
  assert.equal(
    cleared(fix, [ackKey("snap-2", "fix-ssl")], "snap-1", "fix-ssl"),
    false,
  )
  assert.equal(cleared({ fix_id: "fix-log" }, [], "snap-1", "fix-log"), true)
})

test("one click leaves out unacknowledged warned fixes", () => {
  const plan = {
    recommended_order: [
      { spec_id: "s-log", fix_id: "fix-log" },
      { spec_id: "s-ssl", fix_id: "fix-ssl", client_impact: W },
    ],
  }
  const ok = (acks) => (f) => cleared(f, acks, "snap-1", f.fix_id)
  assert.deepEqual(fixAllSelection(plan, [], ok([])), ["s-log"])
  assert.deepEqual(
    fixAllSelection(plan, [], ok([ackKey("snap-1", "fix-ssl")])),
    ["s-log", "s-ssl"],
  )
})

test("step 7: pending client changes for the package's passed fixes only", () => {
  const batch = {
    fixes: [
      { fix_id: "fix-ssl", status: "PASSED" },
      { fix_id: "fix-ciphers", status: "FAILED" },
    ],
    risk_reviews: [
      { fix_id: "fix-ssl", title: "TLS minimum", client_impact: W },
      { fix_id: "fix-ciphers", title: "Ciphers", client_impact: W },
      { fix_id: "fix-log", title: "Log" },
    ],
  }
  const items = pendingClientActions(batch, null, "run-1")
  assert.deepEqual(
    items.map((i) => [i.key, i.title]),
    [["run-1:fix-ssl", "TLS minimum"]],
  )
  const single = pendingClientActions(
    null,
    {
      fix_unit: { fix_id: "fix-x" },
      proposal: { fix_id: "fix-x", title: "Limit", client_impact: W },
    },
    "run-2",
  )
  assert.deepEqual(
    single.map((i) => i.key),
    ["run-2:fix-x"],
  )
  assert.deepEqual(pendingClientActions(null, null, null), [])
})
