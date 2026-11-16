// Client-impact warnings (E2E Gate 1, decision 3): fixes that harden the server but can
// lock out clients that are not updated. The DBA must acknowledge each warning before the
// fix can be tested or packaged, and step 7 keeps the client changes listed as pending
// until each is marked done. Text comes only from the server's fixed warning fields.
// This file must stay free of React and "@/" imports so node --test can load it.

export type ClientWarning = {
  headline: string
  whatBreaks: string
  countLine: string
  beforeApplying: string
  afterApplying: string
  reminder: string
  affected: Record<string, string | number | null>[]
}

const str = (value: unknown, max = 600): string =>
  typeof value === "string" ? value.slice(0, max) : ""

// The server's warning, or null when the fix has none (or it is malformed).
export function clientWarning(source: any): ClientWarning | null {
  const w = source?.client_impact
  if (!w || typeof w !== "object" || w.required !== true) return null
  const headline = str(w.headline)
  const whatBreaks = str(w.what_breaks)
  if (!headline || !whatBreaks) return null
  return {
    headline,
    whatBreaks,
    countLine: str(w.count_line),
    beforeApplying: str(w.before_applying),
    afterApplying: str(w.after_applying),
    reminder: str(w.reminder),
    affected: (Array.isArray(w.affected) ? w.affected : [])
      .filter((a: unknown) => a && typeof a === "object")
      .slice(0, 50),
  }
}

export const ackKey = (snapshotId: string | null | undefined, fixId: string) =>
  `${snapshotId ?? ""}:${fixId}`

// True when the fix may be tested or packaged: no warning, or the warning is acknowledged.
export function cleared(
  source: any,
  acks: string[],
  snapshotId: string | null | undefined,
  fixId: string,
): boolean {
  return !clientWarning(source) || acks.includes(ackKey(snapshotId, fixId))
}

export type PendingAction = {
  key: string
  fixId: string
  title: string
  warning: ClientWarning
}

// Client changes for the fixes in the package being verified: the combined test's
// passing fixes (or the single-fix test), each with its warning.
export function pendingClientActions(
  batch: any,
  result: any,
  runId: string | null,
): PendingAction[] {
  const out: PendingAction[] = []
  const seen = new Set<string>()
  const add = (fixId: unknown, title: unknown, source: any) => {
    const warning = clientWarning(source)
    if (!warning || typeof fixId !== "string" || seen.has(fixId)) return
    seen.add(fixId)
    out.push({
      key: `${runId ?? ""}:${fixId}`,
      fixId,
      title: typeof title === "string" && title ? title : fixId,
      warning,
    })
  }
  if (batch) {
    const passed = new Set(
      (Array.isArray(batch.fixes) ? batch.fixes : [])
        .filter((f: any) => f?.status === "PASSED")
        .map((f: any) => f.fix_id),
    )
    const all = !Array.isArray(batch.fixes)
    for (const r of Array.isArray(batch.risk_reviews) ? batch.risk_reviews : [])
      if (all || passed.has(r?.fix_id)) add(r?.fix_id, r?.title, r)
  } else if (result) {
    const r = result.risk_review ?? result.proposal
    add(r?.fix_id ?? result.fix_unit?.fix_id, r?.title, r)
  }
  return out
}
