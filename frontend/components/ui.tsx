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
    <section className="rounded-md border border-edge bg-panel shadow-[0_1px_2px_rgba(20,19,15,0.04)]">
      <div className="flex flex-wrap items-start gap-4 border-b border-edge px-6 py-5">
        <div>
          <h2 className="text-base font-medium tracking-[-0.01em]">{title}</h2>
          {subtitle && <p className="mt-1 max-w-2xl text-sm leading-relaxed text-muted">{subtitle}</p>}
        </div>
        {actions && <div className="ml-auto">{actions}</div>}
      </div>
      <div className="px-6 py-5">{children}</div>
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
    default: "text-fg",
    ok: "text-ok",
    warn: "text-warn",
    bad: "text-bad",
  };
  return (
    <div className="rounded-md border border-edge bg-ink px-4 py-4">
      <div className="mono text-[11px] tracking-[0.06em] text-muted uppercase">{label}</div>
      <div className={`mt-2 text-3xl font-medium tracking-[-0.02em] ${tones[tone]}`}>{value}</div>
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
    default: "border-edge bg-ink text-muted",
    ok: "border-ok/30 bg-ok/10 text-ok",
    warn: "border-warn/30 bg-warn/10 text-warn",
    bad: "border-bad/30 bg-bad/10 text-bad",
  };
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium ${tones[tone]}`}
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
      ? "border-fg bg-fg text-panel hover:bg-[#2a2823]"
      : "border-edge bg-panel text-fg hover:bg-ink";
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={`inline-flex h-9 items-center justify-center rounded-[4px] border px-4 text-sm font-medium whitespace-nowrap transition-colors disabled:pointer-events-none disabled:opacity-50 ${styles}`}
    >
      {children}
    </button>
  );
}
