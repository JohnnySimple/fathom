"use client";

import { ReactNode } from "react";

export function Panel({
  title,
  subtitle,
  children,
  actions,
}: {
  title: string;
  subtitle?: string;
  children: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <section className="rounded-xl border border-edge bg-panel">
      <div className="flex items-start gap-4 border-b border-edge px-5 py-4">
        <div>
          <h2 className="font-medium">{title}</h2>
          {subtitle && <p className="mt-0.5 text-xs text-muted">{subtitle}</p>}
        </div>
        {actions && <div className="ml-auto">{actions}</div>}
      </div>
      <div className="px-5 py-4">{children}</div>
    </section>
  );
}

export function Stat({
  label,
  value,
  tone = "default",
  hint,
}: {
  label: string;
  value: ReactNode;
  tone?: "default" | "ok" | "warn" | "bad";
  hint?: string;
}) {
  const tones = {
    default: "text-white",
    ok: "text-ok",
    warn: "text-warn",
    bad: "text-bad",
  };
  return (
    <div className="rounded-lg border border-edge px-4 py-3">
      <div className="text-xs text-muted">{label}</div>
      <div className={`mt-1 text-2xl font-semibold ${tones[tone]}`}>{value}</div>
      {hint && <div className="mt-1 text-[11px] leading-snug text-muted">{hint}</div>}
    </div>
  );
}

export function Badge({
  children,
  tone = "default",
}: {
  children: ReactNode;
  tone?: "default" | "ok" | "warn" | "bad";
}) {
  const tones = {
    default: "border-edge text-muted",
    ok: "border-ok/40 bg-ok/10 text-ok",
    warn: "border-warn/40 bg-warn/10 text-warn",
    bad: "border-bad/40 bg-bad/10 text-bad",
  };
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs ${tones[tone]}`}
    >
      {children}
    </span>
  );
}

export function Button({
  children,
  onClick,
  disabled,
  variant = "primary",
}: {
  children: ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  variant?: "primary" | "ghost";
}) {
  const styles =
    variant === "primary"
      ? "bg-accent/15 border-accent/40 text-accent hover:bg-accent/25"
      : "border-edge text-muted hover:text-white";
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={`rounded-lg border px-3.5 py-2 text-sm transition disabled:opacity-40 ${styles}`}
    >
      {children}
    </button>
  );
}
