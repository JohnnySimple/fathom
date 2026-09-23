"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { api, Posture, Validation } from "@/lib/api";
import { Badge, Button, Panel, Stat } from "@/components/ui";

export default function CompilePage() {
  const [runId, setRunId] = useState<string | null>(null);
  const [validation, setValidation] = useState<Validation | null>(null);
  const [posture, setPosture] = useState<Posture | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showLog, setShowLog] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);

  const load = useCallback(async (id: string) => {
    setRunId(id);
    window.localStorage.setItem("fathom.runId", id);
    const [v, p] = await Promise.all([api.validation(id), api.posture(id)]);
    setValidation(v);
    setPosture(p);
  }, []);

  useEffect(() => {
    // Reuse a run from a previous visit so a page refresh mid-demo does not
    // force a recompile.
    const stored = window.localStorage.getItem("fathom.runId");
    if (!stored) return;
    load(stored).catch(() => window.localStorage.removeItem("fathom.runId"));
  }, [load]);

  async function run(action: () => Promise<{ run_id: string }>) {
    setBusy(true);
    setError(null);
    try {
      await load((await action()).run_id);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <Panel
        title="Compile"
        subtitle="ScubaResults.json is parsed, compiled to five OSCAL artifacts, and validated against NIST's own schemas. No model is involved in any of it."
        actions={
          <div className="flex gap-2">
            <Button onClick={() => fileInput.current?.click()} disabled={busy} variant="ghost">
              Upload scan
            </Button>
            <Button onClick={() => run(api.compileSample)} disabled={busy}>
              {busy ? "Compiling…" : "Compile CISA sample"}
            </Button>
          </div>
        }
      >
        <input
          ref={fileInput}
          type="file"
          accept="application/json,.json"
          className="hidden"
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) run(() => api.upload(file));
          }}
        />

        {error && (
          <p className="rounded-lg border border-bad/40 bg-bad/10 px-3 py-2 text-sm text-bad">
            {error}
          </p>
        )}

        {!validation && !error && (
          <p className="text-sm text-muted">
            No run compiled yet. Compile CISA&rsquo;s published sample scan to walk the whole
            pipeline without a Microsoft 365 tenant.
          </p>
        )}

        {validation && (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center gap-3">
              <Badge tone={validation.all_valid ? "ok" : "bad"}>
                {validation.all_valid
                  ? "Valid against NIST OSCAL schemas"
                  : "Validation failed"}
              </Badge>
              <span className="mono text-xs text-muted">
                OSCAL {validation.artifacts[0]?.oscal_version} &middot; run {validation.run_id.slice(0, 8)}
              </span>
              <button
                className="ml-auto text-xs text-muted underline hover:text-white"
                onClick={() => setShowLog((v) => !v)}
              >
                {showLog ? "Hide" : "Show"} validation log
              </button>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="text-left text-xs text-muted">
                  <tr>
                    <th className="py-2 font-normal">Artifact</th>
                    <th className="font-normal">Size</th>
                    <th className="font-normal">SHA-256</th>
                    <th className="font-normal">Schema</th>
                  </tr>
                </thead>
                <tbody>
                  {validation.artifacts.map((a) => (
                    <tr key={a.model} className="border-t border-edge">
                      <td className="py-2 font-medium">{a.model}</td>
                      <td className="text-muted">{a.bytes.toLocaleString()} B</td>
                      <td className="mono text-xs text-muted">{a.sha256.slice(0, 16)}…</td>
                      <td>
                        <Badge tone={a.valid ? "ok" : "bad"}>
                          {a.valid ? "valid" : `${a.report.issues.length} issue(s)`}
                        </Badge>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {showLog && (
              <pre className="mono max-h-60 overflow-auto rounded-lg border border-edge bg-ink p-3 text-[11px] leading-relaxed text-muted">
                {validation.artifacts
                  .map(
                    (a) =>
                      `${a.model}: ${a.valid ? "VALID" : "INVALID"} [${a.report.validator}]` +
                      a.report.issues.map((i) => `\n    ${i.path || "<root>"}: ${i.message}`).join("")
                  )
                  .join("\n")}
              </pre>
            )}

            {posture?.warnings?.length ? (
              <div className="rounded-lg border border-warn/40 bg-warn/10 px-3 py-2 text-xs text-warn">
                {posture.warnings.map((w) => (
                  <p key={w}>{w}</p>
                ))}
              </div>
            ) : null}
          </div>
        )}
      </Panel>

      {posture && (
        <>
          <Panel
            title="Posture"
            subtitle={`Tenant ${posture.tenant_alias} · scanned ${new Date(
              posture.scanned_at
            ).toLocaleString()} · ScubaGear ${posture.scubagear_version}`}
          >
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <Stat label="Satisfied" value={posture.passed} tone="ok" />
              <Stat label="Failing SHALL" value={posture.failed_shall} tone="bad" />
              <Stat label="Failing SHOULD" value={posture.failed_should} tone="warn" />
              <Stat
                label="Unverified"
                value={posture.unverified_manual}
                hint="No automated check exists. Neither passing nor failing — Fathom will not guess."
              />
            </div>

            <div className="mt-5 overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="text-left text-xs text-muted">
                  <tr>
                    <th className="py-2 font-normal">Product</th>
                    <th className="font-normal">Assessed</th>
                    <th className="font-normal">Pass</th>
                    <th className="font-normal">Fail</th>
                    <th className="font-normal">SHALL failures</th>
                  </tr>
                </thead>
                <tbody>
                  {posture.by_product.map((row) => (
                    <tr key={row.product} className="border-t border-edge">
                      <td className="py-2 font-medium">{row.product}</td>
                      <td className="text-muted">{row.total}</td>
                      <td className="text-ok">{row.passed}</td>
                      <td className={row.failed ? "text-warn" : "text-muted"}>{row.failed}</td>
                      <td className={row.shall_failed ? "text-bad" : "text-muted"}>
                        {row.shall_failed}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>

          <Panel title="Top risks" subtitle="SHALL-level failures, ordered by Fathom's deterministic risk score">
            <ul className="space-y-2">
              {posture.top_risks.slice(0, 8).map((f) => (
                <li
                  key={f.finding_uuid}
                  className="flex items-start gap-3 rounded-lg border border-edge px-3 py-2"
                >
                  <span className="mono w-32 shrink-0 text-xs text-accent">{f.policy_id}</span>
                  <span className="flex-1 text-sm">{f.statement}</span>
                  <Badge tone="bad">{f.risk_score ?? "—"}</Badge>
                </li>
              ))}
            </ul>
          </Panel>
        </>
      )}
    </div>
  );
}
