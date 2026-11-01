import type { FeedEvent } from "./api";
import { clock } from "./utils";

export type FeedLine = { key: string; text: string; tone: "bad" | "accent" | "neutral"; when: string };

/** Plain-language activity lines; repeated identical events collapse to "×N". */
export function toLines(events: FeedEvent[]): FeedLine[] {
  const out: (FeedLine & { sig: string; n: number })[] = [];
  for (const e of events) {                       // events arrive newest first
    const base =
      e.kind === "blocked" ? `Blocked ${e.name || "a connection"}`
      : e.kind === "flagged" ? `Flagged ${e.name || "a connection"}`
      : e.kind === "rule_added" ? `Rule added: ${e.rule}`
      : e.kind === "rule_removed" ? `Rule #${e.name} removed`
      : e.kind === "capture_stopped" ? "Capture paused"
      : e.kind === "capture_started" ? "Capture resumed" : e.kind;
    const sig = `${e.kind}|${base}`;
    const last = out[out.length - 1];
    if (last && last.sig === sig) { last.n++; continue; }
    out.push({ key: String(e.id), sig, n: 1, text: base, when: clock(e.ts),
      tone: e.kind === "blocked" ? "bad" : e.kind === "flagged" ? "accent" : "neutral" });
  }
  return out.map((l) => ({ key: l.key, tone: l.tone, when: l.when, text: l.n > 1 ? `${l.text} (×${l.n})` : l.text }));
}
