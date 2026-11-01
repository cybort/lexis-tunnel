import type { ButtonHTMLAttributes, ReactNode } from "react";

type Kind = "solid" | "ghost" | "ember";

export function Btn({
  kind = "solid",
  className = "",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { kind?: Kind }) {
  const skin =
    kind === "solid"
      ? "bg-sage text-ink hover:bg-fg"
      : kind === "ember"
        ? "bg-ember text-ink hover:bg-paper"
        : "border border-line bg-panel text-fg hover:border-sage";
  return (
    <button
      className={`inline-flex min-h-11 items-center justify-center gap-2 rounded-sm px-4 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${skin} ${className}`}
      {...props}
    />
  );
}

export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="flex flex-col gap-2 text-sm">
      <span className="text-mist">{label}</span>
      {children}
    </label>
  );
}

export const control =
  "min-h-11 w-full rounded-sm border border-line bg-ink px-3 text-base text-fg";

export function Panel({
  title,
  action,
  children,
}: {
  title: string;
  action?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="rounded-md border border-line bg-panel p-4">
      <div className="mb-4 flex items-center justify-between gap-3">
        <h2 className="text-base font-medium">{title}</h2>
        {action}
      </div>
      {children}
    </section>
  );
}

export function Paper({ kicker, children }: { kicker?: string; children: ReactNode }) {
  return (
    <div className="rounded-md bg-paper px-4 py-4 text-paper-ink">
      {kicker ? <p className="mb-2 font-mono text-xs text-paper-mist">{kicker}</p> : null}
      <div className="text-base leading-relaxed break-words">{children}</div>
    </div>
  );
}
