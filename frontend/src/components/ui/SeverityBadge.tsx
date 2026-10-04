import { severityColor } from "../../lib/format";
import type { Severity } from "../../types/api";

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`rounded-md border px-2 py-0.5 text-xs font-bold uppercase tracking-wide ${severityColor[severity]}`}
    >
      {severity}
    </span>
  );
}
