"use client";
import { useState } from "react";
import { AppWindow } from "lucide-react";
import { useData } from "@/lib/data";
import { bytes } from "@/lib/utils";
import { Card } from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import { Empty } from "@/components/empty";

const NOT_BLOCKABLE = new Set(["Unknown", "Local network", "Other"]);

export default function Apps() {
  const { stats, rules, addRule, deleteRule } = useData();
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState("");

  const ruleFor = (app: string) => rules.find((r) => r.type === "app" && r.action === "block" && r.value === app.toLowerCase());
  const names = new Set((stats?.apps ?? []).map((a) => a.app));
  // blocked apps that have no traffic any more still need a card, so they can be unblocked
  const extra = rules.filter((r) => r.type === "app" && r.action === "block" && ![...names].some((n) => n.toLowerCase() === r.value))
    .map((r) => ({ app: r.value, flows: 0, bytes: 0 }));
  const list = [...(stats?.apps ?? []), ...extra].filter((a) => a.bytes > 0 || ruleFor(a.app));

  const toggle = async (app: string, block: boolean) => {
    setErr(""); setBusy(app);
    try {
      if (block) await addRule("app", app, "block");
      else { const r = ruleFor(app); if (r) await deleteRule(r.id); }
    } catch (e) { setErr(String(e instanceof Error ? e.message : e)); }
    setBusy("");
  };

  return (
    <div className="space-y-5">
      <h1 className="text-xl font-semibold">Apps</h1>
      {err && <p className="text-sm text-bad">Could not change that: {err}</p>}
      {list.length === 0 ? (
        <Empty icon={<AppWindow size={28} />} title="No apps seen yet" hint="Use your browser or an app for a moment. Each one shows up here with a switch to block it." />
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {list.map((a) => {
            const r = ruleFor(a.app);
            const blockable = !NOT_BLOCKABLE.has(a.app);
            return (
              <Card key={a.app} className="flex items-center justify-between gap-3 p-5">
                <div className="min-w-0">
                  <p className="truncate font-medium">{a.app}</p>
                  <p className="text-sm text-muted">{bytes(a.bytes)} · {a.flows} connection{a.flows !== 1 && "s"}</p>
                  {r && <p className="mt-1 text-xs text-bad">{r.detail}</p>}
                </div>
                {blockable ? (
                  <div className="flex shrink-0 items-center gap-2">
                    <Badge tone={r ? "bad" : "neutral"}>{r ? "Blocked" : "Allowed"}</Badge>
                    <Switch checked={!!r} disabled={busy === a.app} aria-label={`Block ${a.app}`} onCheckedChange={(v) => toggle(a.app, v)} />
                  </div>
                ) : <Badge>Can’t block as a group</Badge>}
              </Card>);
          })}
        </div>
      )}
    </div>
  );
}
