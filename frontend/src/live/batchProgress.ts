// Helpers for the one-click "Test fixes for all failed checks" run: the progress bar,
// the step description and the result grouped into passed / failed / not eligible.
// The backend (GET /api/v1/sandbox/batches/{id}) reports progress; these only format.

export const RUNNING = "RUNNING"

export type FixLine = {
  fix_id: string
  status: string
  stage: string | null
  reason: string | null
}

export type FixGroups = {
  passed: FixLine[]
  failed: FixLine[]
  notEligible: FixLine[]
}

export type ProgressLine = {
  at: string
  text: string
  fixId: string | null
  status: string | null
}

const text = (value: unknown): string | null =>
  typeof value === "string" && value.trim() ? value.trim().slice(0, 400) : null

// Whole-number percentage of the work done, 0..100; 0 when the total is unknown.
export function progressPercent(progress: any): number {
  const done = Number(progress?.done)
  const total = Number(progress?.total)
  if (!Number.isFinite(done) || !Number.isFinite(total) || total <= 0) return 0
  return Math.max(0, Math.min(100, Math.round((done / total) * 100)))
}

// "45 s", "3 min 05 s", "1 h 02 min"; null for missing or negative values.
export function formatDuration(seconds: unknown): string | null {
  const n = Number(seconds)
  if (seconds === null || seconds === undefined || !Number.isFinite(n) || n < 0)
    return null
  const s = Math.round(n)
  if (s < 60) return `${s} s`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m} min ${String(s % 60).padStart(2, "0")} s`
  return `${Math.floor(m / 60)} h ${String(m % 60).padStart(2, "0")} min`
}

// The plain-English line under the bar.
export function stepDescription(progress: any): string {
  return (
    text(progress?.step_text) ??
    (progress?.status === RUNNING ? "Working…" : "Finished.")
  )
}

// Completed steps, oldest first, for the list beneath the bar.
export function progressLines(progress: any): ProgressLine[] {
  const steps = Array.isArray(progress?.steps) ? progress.steps : []
  return steps
    .map((step: any) => ({
      at: typeof step?.at === "string" ? step.at : "",
      text: text(step?.text) ?? "",
      fixId: text(step?.fix_id),
      status: text(step?.status),
    }))
    .filter((line: ProgressLine) => line.text)
}

function line(entry: any): FixLine | null {
  const fixId = text(entry?.fix_id)
  const status = text(entry?.status)
  if (!fixId || !status) return null
  return {
    fix_id: fixId,
    status,
    stage: text(entry?.stage),
    reason: text(entry?.reason),
  }
}

// The result's fixes, grouped. Anything that is not PASSED or NOT_ELIGIBLE counts as
// failed, so an unexpected status is never shown as passed.
export function groupFixes(result: any, notEligible: any = []): FixGroups {
  const groups: FixGroups = { passed: [], failed: [], notEligible: [] }
  const seen = new Set<string>()
  const add = (entry: any) => {
    const l = line(entry)
    if (!l || seen.has(l.fix_id)) return
    seen.add(l.fix_id)
    if (l.status === "PASSED") groups.passed.push(l)
    else if (l.status === "NOT_ELIGIBLE") groups.notEligible.push(l)
    else groups.failed.push(l)
  }
  for (const entry of Array.isArray(result?.fixes) ? result.fixes : [])
    add(entry)
  for (const entry of Array.isArray(notEligible) ? notEligible : [])
    add({ ...entry, status: "NOT_ELIGIBLE" })
  return groups
}

// The headline for a finished run.
export function outcomeSentence(status: unknown, groups: FixGroups): string {
  const passed = groups.passed.length
  const failed = groups.failed.length
  if (status === "VERIFIED")
    return `All ${passed} fixes passed on their own and together. They are all in the DBA package.`
  if (status === "PARTIAL")
    return `PARTIAL: ${passed} passed and are in the DBA package; ${failed} failed and ${
      failed === 1 ? "was" : "were"
    } left out.`
  if (status === "INTERRUPTED")
    return "The run was interrupted (the DBGuard service restarted). Run it again."
  if (status === "CLEANUP_FAILED")
    return "The fixes ran, but the throwaway copy could not be cleaned up. No package was made; check the test details."
  return "No fix passed together, so no DBA package was made. Check the reasons below."
}

// The fixes to tick for "all failed checks": every setting and add-on fix the plan
// offers, plus any account fixes the DBA already ticked. Account fixes are never
// ticked automatically: each can lock out an application account.
// A fix whose client-impact warning is not yet acknowledged (``cleared`` false) is left
// out: it can only be tested once the DBA has acknowledged the warning.
export function fixAllSelection(
  plan: any,
  selected: string[],
  cleared: (fix: any) => boolean = () => true,
): string[] {
  const offered = (
    Array.isArray(plan?.recommended_order) ? plan.recommended_order : []
  ).filter((f: any) => typeof f?.spec_id === "string" && !!f.spec_id)
  const settings = offered.map((f: any) => f.spec_id as string)
  const ready = offered
    .filter((f: any) => cleared(f))
    .map((f: any) => f.spec_id as string)
  const keep = selected.filter((key) => !settings.includes(key))
  return [...new Set([...ready, ...keep])]
}
