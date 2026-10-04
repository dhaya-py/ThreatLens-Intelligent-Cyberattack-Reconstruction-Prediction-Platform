"""AI investigation assistant.

Answers analyst questions about an incident. The LLM (when configured) receives
*only* the structured evidence bundle for that incident and is instructed to use
nothing else, to separate observed facts from inference, and never to invent
hosts, timestamps or techniques. When no LLM is configured, a deterministic
responder answers from the same bundle, so the assistant always works.
"""

import json
from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import Incident
from app.repositories.incidents import IncidentRepository
from app.services.llm import LLMProvider, get_provider

SYSTEM_PROMPT = (
    "You are a SOC investigation assistant for the ThreatLens platform. You answer "
    "ONLY from the structured incident evidence provided in the user message.\n"
    "Rules you must follow:\n"
    "- Use only the supplied evidence. If the evidence does not contain the answer, "
    "say so plainly.\n"
    "- Clearly distinguish observed facts from inference/assessment.\n"
    "- Never invent timestamps, hosts, usernames, IP addresses or ATT&CK techniques. "
    "Only reference ones present in the evidence.\n"
    "- Explain uncertainty where the evidence is incomplete.\n"
    "- Be concise and concrete; cite hostnames, technique IDs and times from the evidence.\n"
    "This is a prototype pattern-based reconstruction, not authoritative threat intelligence."
)

SUGGESTED_QUESTIONS = [
    "How did the attacker enter the network?",
    "Why is BACKUP-01 at risk?",
    "Show the lateral movement path.",
    "What evidence supports the root cause?",
    "What should the analyst investigate next?",
]


@dataclass
class InvestigationAnswer:
    answer: str
    mode: str  # "llm" | "deterministic"
    used_evidence: list[str] = field(default_factory=list)
    suggested_questions: list[str] = field(default_factory=lambda: list(SUGGESTED_QUESTIONS))


class InvestigationError(ValueError):
    pass


class InvestigationService:
    def __init__(self, db: Session, provider: LLMProvider | None = None):
        self.db = db
        self._provider = provider if provider is not None else get_provider(get_settings())

    def investigate(self, incident_id: int, question: str) -> InvestigationAnswer:
        incident = IncidentRepository(self.db).get(incident_id)
        if incident is None:
            raise InvestigationError("incident not found")
        question = (question or "").strip()
        if not question:
            raise InvestigationError("question must not be empty")

        bundle = build_evidence_bundle(incident)

        if self._provider is not None and self._provider.available():
            user_prompt = (
                f"Incident evidence (JSON):\n{json.dumps(bundle, indent=2)}\n\n"
                f"Analyst question: {question}\n\n"
                "Answer using only the evidence above."
            )
            text = self._provider.generate(SYSTEM_PROMPT, user_prompt)
            if text:
                return InvestigationAnswer(answer=text, mode="llm", used_evidence=["llm"])

        return _deterministic_answer(bundle, question)


# --- evidence bundle --------------------------------------------------------------


def build_evidence_bundle(incident: Incident) -> dict:
    """The structured, self-contained evidence the assistant may reason over."""
    return {
        "reference": incident.reference,
        "title": incident.title,
        "severity": incident.severity,
        "risk_score": incident.risk_score,
        "first_seen": incident.first_seen.isoformat(),
        "last_seen": incident.last_seen.isoformat(),
        "root_cause": incident.root_cause or {},
        "timeline": [
            {
                "sequence": s.sequence,
                "time": s.timestamp.strftime("%H:%M"),
                "tactic": s.tactic,
                "technique_id": s.technique_id,
                "technique_name": s.technique_name,
                "host": s.host.hostname if s.host else None,
                "description": s.description,
            }
            for s in sorted(incident.steps, key=lambda s: s.sequence)
        ],
        "lateral_movements": [
            {
                "source": m.source_host.hostname,
                "destination": m.destination_host.hostname,
                "protocol": m.protocol,
                "username": m.username,
                "confidence": m.confidence,
                "reason": m.reason,
            }
            for m in sorted(incident.lateral_movements, key=lambda m: m.timestamp)
        ],
        "host_risks": [
            {
                "host": hr.host.hostname,
                "score": hr.score,
                "status": hr.status,
                "factors": hr.factors or [],
            }
            for hr in sorted(incident.host_risks, key=lambda hr: -hr.score)
        ],
        "prediction": [
            {"host": p.host.hostname, "rank": p.rank, "score": p.score, "reasons": p.reasons or []}
            for p in sorted(incident.predictions, key=lambda p: p.rank)
        ],
        "hosts": sorted({hr.host.hostname for hr in incident.host_risks}),
    }


# --- deterministic responder ------------------------------------------------------


def _host_mentioned(bundle: dict, question: str) -> str | None:
    q = question.upper()
    for host in bundle["hosts"] + [p["host"] for p in bundle["prediction"]]:
        if host.upper() in q:
            return host
    return None


def _deterministic_answer(bundle: dict, question: str) -> InvestigationAnswer:
    q = question.lower()
    root = bundle["root_cause"]

    if any(w in q for w in ("enter", "initial", "get in", "got in", "entry", "how did")):
        return _entry_answer(bundle, root)
    if "lateral" in q or "movement" in q or "path" in q or "spread" in q or "pivot" in q:
        return _movement_answer(bundle)
    if "evidence" in q or "support" in q or "prove" in q or "justif" in q:
        return _evidence_answer(bundle, root)
    if "next" in q or "investigate" in q or "recommend" in q or "should" in q or "do now" in q:
        return _next_answer(bundle)
    if "risk" in q or "why" in q:
        return _risk_answer(bundle, _host_mentioned(bundle, question))
    if "technique" in q or "mitre" in q or "att&ck" in q or "attack" in q:
        return _technique_answer(bundle)
    return _summary_answer(bundle)


def _answer(text: str, evidence: list[str]) -> InvestigationAnswer:
    return InvestigationAnswer(answer=text, mode="deterministic", used_evidence=evidence)


def _entry_answer(bundle: dict, root: dict) -> InvestigationAnswer:
    if not root.get("host"):
        return _answer("No initial-access host could be determined from the evidence.", [])
    lines = [
        f"Observed: {root['host']} shows the earliest correlated suspicious activity"
        + (f" at {root['first_seen'][11:16]}" if root.get("first_seen") else "")
        + (f", originating from external IP {root['source_ip']}" if root.get("source_ip") else "")
        + ".",
    ]
    first_steps = [s for s in bundle["timeline"] if s["host"] == root["host"]][:3]
    if first_steps:
        seq = "; ".join(f"{s['time']} {s['technique_name']}" for s in first_steps)
        lines.append(f"Observed: the first actions on {root['host']} were — {seq}.")
    lines.append(f"Assessment: {root.get('explanation', '')}")
    return _answer(" ".join(lines).strip(), [root["host"], "root_cause", "timeline"])


def _movement_answer(bundle: dict) -> InvestigationAnswer:
    moves = bundle["lateral_movements"]
    if not moves:
        return _answer(
            "Observed: no host-to-host lateral movement was detected in this incident.", []
        )
    path_nodes = [moves[0]["source"]] + [m["destination"] for m in moves]
    path = " → ".join(path_nodes)
    lines = [f"Observed lateral movement path: {path}."]
    for m in moves:
        lines.append(
            f"Observed: {m['source']} → {m['destination']} over {m['protocol'].upper()}"
            + (f" as {m['username']}" if m["username"] else "")
            + f" (confidence {m['confidence']:.2f})."
        )
    return _answer(
        " ".join(lines), [m["source"] for m in moves] + [m["destination"] for m in moves]
    )


def _evidence_answer(bundle: dict, root: dict) -> InvestigationAnswer:
    lines = [f"The root-cause assessment for {root.get('host', 'the incident')} rests on:"]
    for e in root.get("evidence", [])[:6]:
        lines.append(f"• {e}")
    techniques = {s["technique_id"]: s["technique_name"] for s in bundle["timeline"]}
    if techniques:
        lines.append(
            "Corroborating ATT&CK techniques: "
            + ", ".join(f"{tid} ({name})" for tid, name in list(techniques.items())[:6])
            + "."
        )
    return _answer("\n".join(lines), ["root_cause.evidence", "timeline"])


def _next_answer(bundle: dict) -> InvestigationAnswer:
    pred = bundle["prediction"]
    lines = []
    if pred:
        top = pred[0]
        lines.append(
            f"Likely next target (assessment): {top['host']} (score {top['score']}/100). Reasons: "
            + "; ".join(top["reasons"][:4])
            + "."
        )
        lines.append(
            f"Recommended: prioritise containment and monitoring of {top['host']}, and review "
            "any credentials it shares with already-compromised hosts."
        )
    compromised = [
        h["host"] for h in bundle["host_risks"] if h["status"] in ("initial_entry", "compromised")
    ]
    if compromised:
        lines.append(
            "Also investigate the confirmed compromised hosts for persistence and isolate them: "
            + ", ".join(compromised)
            + "."
        )
    return _answer(
        " ".join(lines) or "No follow-up actions could be derived.", ["prediction", "host_risks"]
    )


def _risk_answer(bundle: dict, host: str | None) -> InvestigationAnswer:
    risks = bundle["host_risks"]
    target = None
    if host:
        target = next((h for h in risks if h["host"] == host), None)
        if target is None:
            pred = next((p for p in bundle["prediction"] if p["host"] == host), None)
            if pred:
                reasons = "; ".join(pred["reasons"][:4])
                return _answer(
                    f"Assessment: {host} is flagged as a likely next target "
                    f"(score {pred['score']}/100), not yet compromised. Reasons: {reasons}.",
                    ["prediction"],
                )
    if target is None and risks:
        target = risks[0]
    if target is None:
        return _answer("No risk information is available for that host.", [])
    factors = "; ".join(f"{f['name']} (+{f['points']}: {f['evidence']})" for f in target["factors"])
    return _answer(
        f"Observed: {target['host']} has risk {target['score']}/100, status '{target['status']}'. "
        f"Contributing factors — {factors}.",
        [target["host"], "host_risks"],
    )


def _technique_answer(bundle: dict) -> InvestigationAnswer:
    by_tactic: dict[str, list[str]] = {}
    for s in bundle["timeline"]:
        by_tactic.setdefault(s["tactic"], []).append(f"{s['technique_id']} {s['technique_name']}")
    lines = ["Observed ATT&CK techniques by tactic:"]
    for tactic, techs in by_tactic.items():
        uniq = sorted(set(techs))
        lines.append(f"• {tactic}: {', '.join(uniq)}")
    lines.append("(Explainable prototype mapping from observed patterns, not authoritative intel.)")
    return _answer("\n".join(lines), ["timeline"])


def _summary_answer(bundle: dict) -> InvestigationAnswer:
    root = bundle["root_cause"]
    moves = bundle["lateral_movements"]
    pred = bundle["prediction"]
    path = ""
    if moves:
        path = " → ".join([moves[0]["source"]] + [m["destination"] for m in moves])
    text = (
        f"Observed: {bundle['reference']} is a {bundle['severity']} incident "
        f"(risk {bundle['risk_score']}/100) spanning {bundle['first_seen'][11:16]}–"
        f"{bundle['last_seen'][11:16]}. "
        f"Initial access on {root.get('host', 'an unknown host')}"
        + (f" from {root['source_ip']}" if root.get("source_ip") else "")
        + ". "
        + (f"Lateral movement: {path}. " if path else "")
        + (
            f"Likely next target (assessment): {pred[0]['host']} ({pred[0]['score']}/100)."
            if pred
            else ""
        )
    )
    return _answer(text.strip(), ["root_cause", "lateral_movements", "prediction"])
