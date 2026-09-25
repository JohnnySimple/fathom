"use client";

import { useEffect, useState } from "react";
import { Answer, Claim, api, resolvePointer } from "@/lib/api";
import { Badge, Button, Panel } from "@/components/ui";

const SUGGESTIONS = [
  "Which failing requirements leave us open to phishing?",
  "What is on the POA&M?",
  "Which NIST 800-53 controls are affected by our failures?",
  "Confirm we are fully compliant with MFA requirements.",
  "Which policies could not be automatically verified?",
];

// Verdicts the verifier assigns to claims it removed, mapped to plain English.
const REJECTION_LABELS: Record<string, string> = {
  "unsupported-no-citation": "no citation",
  "unsupported-unresolvable-citation": "citation does not exist",
  "contradicted-by-evidence": "contradicted by the artifacts",
  "unsupported-number": "number not in the evidence",
};

export default function AskPage() {
  const [runId, setRunId] = useState<string | null>(null);
  const [question, setQuestion] = useState(SUGGESTIONS[0]);
  const [answer, setAnswer] = useState<Answer | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [node, setNode] = useState<{ uuid: string; artifact: string; pointer: string; json: unknown } | null>(null);

  useEffect(() => {
    const stored = window.localStorage.getItem("fathom.runId");
    if (stored) {
      setRunId(stored);
      return;
    }
    // No run yet: fall back to whatever the API already has.
    api
      .runs()
      .then((r) => r.runs[0] && setRunId(r.runs[0].id))
      .catch(() => undefined);
  }, []);

  async function ask() {
    if (!runId) return;
    setBusy(true);
    setError(null);
    setNode(null);
    try {
      setAnswer(await api.ask(runId, question));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function openCitation(uuid: string) {
    if (!runId) return;
    try {
      const resolved = await api.resolve(runId, uuid);
      if (!resolved.artifact || !resolved.json_pointer) return;
      const document = await api.artifact(runId, resolved.artifact);
      setNode({
        uuid,
        artifact: resolved.artifact,
        pointer: resolved.json_pointer,
        json: resolvePointer(document, resolved.json_pointer),
      });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  if (!runId) {
    return (
      <Panel title="Ask" subtitle="No compiled run yet">
        <p className="text-sm text-muted">
          Compile a scan first on the Compile &amp; Posture screen.
        </p>
      </Panel>
    );
  }

  const verification = answer?.verification;
  const rejected = verification?.claims.filter((c) => REJECTION_LABELS[c.verdict]) ?? [];

  return (
    <div className="space-y-6">
      <Panel
        title="Ask"
        subtitle="The analyst reads through typed queries only. Every factual sentence is re-checked against the artifacts before you see it."
      >
        <div className="flex gap-2">
          <input
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && !busy && ask()}
            placeholder="Ask about this tenant's posture…"
            className="h-9 min-w-0 flex-1 rounded-[4px] border border-edge bg-panel px-3 text-sm outline-none transition-colors placeholder:text-muted focus:border-fg/40"
          />
          <Button onClick={ask} disabled={busy || !question.trim()}>
            {busy ? "Verifying…" : "Ask"}
          </Button>
        </div>

        <div className="mt-3 flex flex-wrap gap-2">
          {SUGGESTIONS.map((s) => (
            <button
              key={s}
              onClick={() => setQuestion(s)}
              className="rounded-full border border-edge px-3 py-1 text-xs text-muted transition hover:border-fg/30 hover:text-fg"
            >
              {s}
            </button>
          ))}
        </div>

        {error && <p className="mt-3 text-sm text-bad">{error}</p>}
      </Panel>

      {answer && verification && (
        <Panel
          title="Answer"
          subtitle={`${answer.mode} · ${answer.latency_ms} ms · tools: ${
            answer.tool_calls.map((t) => t.name).join(", ") || "none"
          }`}
          actions={
            <Badge tone={verification.rejected_count ? "warn" : "ok"}>
              Verifier: {verification.badge}
            </Badge>
          }
        >
          <div className="space-y-3">
            {verification.claims
              .filter((c) => !REJECTION_LABELS[c.verdict])
              .map((claim, i) => (
                <ClaimLine key={i} claim={claim} onCite={openCitation} />
              ))}
          </div>

          {rejected.length > 0 && (
            <div className="mt-5 rounded-md border border-bad/30 bg-bad/10 p-3">
              <p className="text-xs font-medium text-bad">
                {rejected.length} claim{rejected.length > 1 ? "s" : ""} removed before display
              </p>
              <ul className="mt-2 space-y-2">
                {rejected.map((claim, i) => (
                  <li key={i} className="text-xs">
                    <span className="mr-2 rounded border border-bad/40 px-1.5 py-0.5 text-bad">
                      {REJECTION_LABELS[claim.verdict]}
                    </span>
                    <span className="text-muted line-through">{claim.text}</span>
                    {claim.reason && (
                      <p className="mt-1 pl-1 text-[11px] text-bad/80">{claim.reason}</p>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </Panel>
      )}

      {node && (
        <Panel
          title="Evidence"
          subtitle={`${node.artifact}.json ${node.pointer}`}
          actions={
            <Button variant="ghost" onClick={() => setNode(null)}>
              Close
            </Button>
          }
        >
          <pre className="mono max-h-96 overflow-auto rounded-md border border-edge bg-ink p-3 text-[11px] leading-relaxed">
            {JSON.stringify(node.json, null, 2)}
          </pre>
        </Panel>
      )}
    </div>
  );
}

function ClaimLine({
  claim,
  onCite,
}: {
  claim: Claim;
  onCite: (uuid: string) => void;
}) {
  const interpretation = claim.verdict === "interpretation";
  // Strip the raw UUIDs out of the prose and render them as clickable chips;
  // a 36-character hex string inline is noise, but it is the whole point of the
  // system, so it becomes a control instead of being hidden.
  const prose = claim.text.replace(/\s*\[[0-9a-fA-F-]{36}\]/g, "");

  return (
    <div
      className={`rounded-md border px-4 py-3 ${
        interpretation ? "border-edge/60 bg-ink" : "border-edge"
      }`}
    >
      <p className={`text-sm ${interpretation ? "italic text-muted" : ""}`}>{prose}</p>
      {claim.citations.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1.5">
          {claim.citations.map((uuid) => {
            const resolved = claim.resolved.find((r) => r.uuid === uuid);
            return (
              <button
                key={uuid}
                onClick={() => onCite(uuid)}
                title={uuid}
                className="mono rounded-[4px] border border-accent/30 bg-accent/10 px-2 py-0.5 text-[11px] text-accent transition hover:bg-accent/20"
              >
                {resolved?.policy_id ?? resolved?.kind ?? "evidence"} &middot; {uuid.slice(0, 8)}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}
