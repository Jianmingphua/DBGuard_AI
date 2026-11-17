import { useLive } from "@/store/liveStore"
import { ackKey, clientWarning, type ClientWarning } from "./clientWarnings"

// The red "Client action required" box on a fix card, with the acknowledgement the DBA
// must tick before the fix can be tested or packaged (E2E Gate 1, decision 3).
export function ClientImpactBox({
  source,
  fixId,
}: {
  source: any
  fixId: string
}) {
  const live = useLive()
  const s = live.state
  const warning = clientWarning(source)
  if (!warning) return null
  const key = ackKey(s.snapshot?.snapshot_id, fixId)
  const acked = s.clientAcks.includes(key)
  return (
    <div
      className="rounded border-2 border-red-300 bg-red-50 p-3 space-y-2 text-sm text-red-950"
      role="alert"
    >
      <WarningText warning={warning} />
      <label className="flex gap-2 items-start font-medium">
        <input
          type="checkbox"
          className="mt-1"
          aria-label={`Acknowledge the client warning for ${fixId}`}
          checked={acked}
          onChange={(e) =>
            live.patch({
              clientAcks: e.target.checked
                ? [...s.clientAcks, key]
                : s.clientAcks.filter((k) => k !== key),
            })
          }
        />
        I have read this. The affected clients will be prepared before this fix
        is applied. (Required before this fix can be tested or added to the
        package.)
      </label>
    </div>
  )
}

export function WarningText({ warning }: { warning: ClientWarning }) {
  return (
    <>
      <p className="font-semibold">⚠ {warning.headline}</p>
      <p>{warning.whatBreaks}</p>
      {warning.countLine && (
        <p>
          <strong>Right now:</strong> {warning.countLine}
        </p>
      )}
      {warning.affected.length > 0 && (
        <ul className="list-disc pl-5">
          {warning.affected.map((a, i) => (
            <li key={i}>
              {Object.entries(a)
                .filter(([, v]) => v !== null && v !== "")
                .map(([k, v]) => `${k}: ${String(v)}`)
                .join(" · ")}
            </li>
          ))}
        </ul>
      )}
      {warning.beforeApplying && (
        <p>
          <strong>Before applying:</strong> {warning.beforeApplying}
        </p>
      )}
      {warning.afterApplying && (
        <p>
          <strong>After applying:</strong> {warning.afterApplying}
        </p>
      )}
      {warning.reminder && <p className="font-medium">{warning.reminder}</p>}
    </>
  )
}
