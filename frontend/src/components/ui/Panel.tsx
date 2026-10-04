import type { ReactNode } from "react";

interface PanelProps {
  title: string;
  icon?: string;
  action?: ReactNode;
  className?: string;
  children: ReactNode;
}

export function Panel({ title, icon, action, className = "", children }: PanelProps) {
  return (
    <section
      className={`flex flex-col rounded-xl border border-soc-border bg-soc-panel/80 ${className}`}
    >
      <header className="flex items-center justify-between border-b border-soc-border px-4 py-2.5">
        <h2 className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-400">
          {icon && <span aria-hidden>{icon}</span>}
          {title}
        </h2>
        {action}
      </header>
      <div className="min-h-0 flex-1 p-4">{children}</div>
    </section>
  );
}
