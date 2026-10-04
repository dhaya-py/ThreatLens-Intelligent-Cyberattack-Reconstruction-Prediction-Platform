import { useRef, useState } from "react";

import { Panel } from "./ui/Panel";
import { api } from "../services/api";
import type { InvestigateResponse } from "../types/api";

interface Message {
  role: "user" | "assistant";
  text: string;
  mode?: "llm" | "deterministic";
}

const DEFAULT_SUGGESTIONS = [
  "How did the attacker enter the network?",
  "Why is BACKUP-01 at risk?",
  "Show the lateral movement path.",
  "What should the analyst investigate next?",
];

export function AssistantPanel({ incidentId }: { incidentId: number }) {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [suggestions, setSuggestions] = useState<string[]>(DEFAULT_SUGGESTIONS);
  const scrollRef = useRef<HTMLDivElement>(null);

  const ask = async (question: string) => {
    if (!question.trim() || busy) return;
    setMessages((m) => [...m, { role: "user", text: question }]);
    setInput("");
    setBusy(true);
    try {
      const res: InvestigateResponse = await api.investigate(incidentId, question);
      setMessages((m) => [...m, { role: "assistant", text: res.answer, mode: res.mode }]);
      if (res.suggested_questions.length) setSuggestions(res.suggested_questions);
    } catch (e) {
      setMessages((m) => [
        ...m,
        { role: "assistant", text: `Could not answer: ${(e as Error).message}` },
      ]);
    } finally {
      setBusy(false);
      requestAnimationFrame(() => scrollRef.current?.scrollTo(0, scrollRef.current.scrollHeight));
    }
  };

  return (
    <Panel title="Investigation assistant" icon="🤖" className="h-full">
      <div className="flex h-full flex-col">
        <div ref={scrollRef} className="flex-1 space-y-3 overflow-y-auto pr-1">
          {messages.length === 0 && (
            <p className="text-sm text-slate-500">
              Ask about this incident. Answers are grounded only in the reconstructed evidence.
            </p>
          )}
          {messages.map((m, i) => (
            <div key={i} className={m.role === "user" ? "text-right" : ""}>
              <div
                className={`inline-block max-w-[90%] whitespace-pre-wrap rounded-lg px-3 py-2 text-sm ${
                  m.role === "user"
                    ? "bg-soc-accent/15 text-slate-100"
                    : "bg-soc-bg/60 text-slate-200"
                }`}
              >
                {m.text}
                {m.role === "assistant" && m.mode && (
                  <span className="mt-1 block text-[10px] uppercase tracking-wider text-slate-600">
                    {m.mode === "llm" ? "LLM" : "evidence-based"}
                  </span>
                )}
              </div>
            </div>
          ))}
          {busy && <div className="text-sm text-slate-500">Thinking…</div>}
        </div>

        <div className="mt-3 flex flex-wrap gap-1.5">
          {suggestions.slice(0, 4).map((s) => (
            <button
              key={s}
              onClick={() => ask(s)}
              disabled={busy}
              className="rounded-full border border-soc-border px-2.5 py-1 text-[11px] text-slate-400 hover:border-soc-accent/50 hover:text-slate-200 disabled:opacity-50"
            >
              {s}
            </button>
          ))}
        </div>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            ask(input);
          }}
          className="mt-2 flex gap-2"
        >
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask about this incident…"
            className="flex-1 rounded-lg border border-soc-border bg-soc-bg/60 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:border-soc-accent focus:outline-none"
          />
          <button
            type="submit"
            disabled={busy || !input.trim()}
            className="rounded-lg bg-soc-accent px-3 py-2 text-sm font-medium text-soc-bg hover:bg-sky-300 disabled:opacity-50"
          >
            Ask
          </button>
        </form>
      </div>
    </Panel>
  );
}
