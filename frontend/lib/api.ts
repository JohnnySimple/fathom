// Typed client for the Fathom API. Requests go to same-origin /api/* and are
// proxied to the FastAPI process by next.config.mjs.

export type Validation = {
  run_id: string;
  all_valid: boolean;
  artifacts: {
    model: string;
    oscal_version: string;
    sha256: string;
    bytes: number;
    valid: boolean;
    report: { validator: string; issues: { path: string; message: string }[] };
  }[];
};

export type Finding = {
  finding_uuid: string;
  policy_id: string;
  product: string;
  state: string;
  oscal_status: string;
  criticality: string;
  statement: string;
  group_name: string;
  risk_score: number | null;
};

export type Posture = {
  run_id: string;
  tenant_alias: string;
  scanned_at: string;
  scubagear_version: string;
  oscal_artifacts_all_valid: boolean;
  findings_total: number;
  passed: number;
  failed_shall: number;
  failed_should: number;
  unverified_manual: number;
  by_product: {
    product: string;
    total: number;
    passed: number;
    failed: number;
    shall_failed: number;
  }[];
  top_risks: Finding[];
  unverified: { risk_uuid: string; policy_id: string; status: string }[];
  warnings: string[];
};

export type Claim = {
  text: string;
  citations: string[];
  verdict: string;
  reason: string | null;
  resolved: { uuid: string; kind: string; policy_id: string | null }[];
};

export type Answer = {
  question: string;
  answer: string;
  raw_answer: string;
  mode: string;
  refused: boolean;
  latency_ms: number;
  verification: {
    badge: string;
    confirmed: number;
    factual_total: number;
    rejected_count: number;
    claims: Claim[];
  };
  tool_calls: { name: string; arguments: Record<string, unknown> }[];
};

export type Resolved = {
  uuid: string;
  object: Record<string, unknown> & { kind: string; policy_id: string | null };
  artifact: string | null;
  json_pointer: string | null;
};

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, { cache: "no-store", ...init });
  if (!response.ok) {
    const detail = await response.json().catch(() => ({}));
    throw new Error(detail.detail ?? `${response.status} ${response.statusText}`);
  }
  return response.json() as Promise<T>;
}

export const api = {
  health: () => request<{ status: string; oscal_version: string; llm_configured: boolean }>("/api/health"),
  runs: () => request<{ count: number; runs: { id: string; tenant_alias: string; started_at: string }[] }>("/api/runs"),
  compileSample: () => request<{ run_id: string; all_valid: boolean }>("/api/runs/compile-sample", { method: "POST" }),
  upload: (file: File) => {
    const body = new FormData();
    body.append("file", file);
    return request<{ run_id: string; all_valid: boolean }>("/api/runs", { method: "POST", body });
  },
  validation: (runId: string) => request<Validation>(`/api/runs/${runId}/validation`),
  posture: (runId: string) => request<Posture>(`/api/runs/${runId}/posture`),
  ask: (runId: string, question: string) =>
    request<Answer>("/api/ask", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ run_id: runId, question }),
    }),
  resolve: (runId: string, uuid: string) =>
    request<Resolved>(`/api/resolve/${uuid}?run_id=${encodeURIComponent(runId)}`),
  artifact: (runId: string, model: string) =>
    request<Record<string, unknown>>(`/api/runs/${runId}/artifacts/${model}`),
};

// Walk a JSON pointer, so a citation can be shown as the exact node it refers
// to rather than the whole 370 KB document.
export function resolvePointer(document: unknown, pointer: string): unknown {
  return pointer
    .replace(/^\//, "")
    .split("/")
    .reduce<unknown>((node, segment) => {
      if (node === undefined || node === null) return undefined;
      const container = node as Record<string, unknown> | unknown[];
      return Array.isArray(container)
        ? container[Number(segment)]
        : container[segment];
    }, document);
}
