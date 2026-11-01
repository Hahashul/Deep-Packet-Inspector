"use client";
import { useState } from "react";
import { ListChecks, Trash2 } from "lucide-react";
import { useData } from "@/lib/data";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Empty } from "@/components/empty";
import { cn } from "@/lib/utils";

const DOT: Record<string, string> = { working: "bg-good", leaking: "bg-bad", inactive: "bg-bad", waiting: "bg-muted", flagging: "bg-accent" };
const LABEL: Record<string, string> = { working: "Working", leaking: "Leaking", inactive: "Not enforced", waiting: "Waiting for traffic", flagging: "Flag only" };
const sel = "h-9 rounded-md border bg-card px-2 text-sm";

export default function Rules() {
  const { rules, addRule, deleteRule } = useData();
  const [type, setType] = useState("domain");
  const [value, setValue] = useState("");
  const [action, setAction] = useState("block");
  const [err, setErr] = useState("");

  const submit = async (e: React.FormEvent) => {
    e.preventDefault(); setErr("");
    if (!value.trim()) return;
    try { await addRule(type, value, action); setValue(""); } catch (x) { setErr(String(x instanceof Error ? x.message : x)); }
  };

  return (
    <div className="space-y-5">
      <h1 className="text-xl font-semibold">Rules</h1>
      <Card className="p-4">
        <form onSubmit={submit} className="flex flex-wrap gap-2">
          <select className={sel} value={type} onChange={(e) => setType(e.target.value)} aria-label="Rule type">
            <option value="domain">Site (domain)</option><option value="app">App</option><option value="ip">IP address</option>
          </select>
          <Input className="min-w-48 flex-1" placeholder={type === "domain" ? "youtube.com" : type === "app" ? "youtube" : "1.2.3.4"} value={value} onChange={(e) => setValue(e.target.value)} />
          <select className={sel} value={action} onChange={(e) => setAction(e.target.value)} aria-label="Action">
            <option value="block">Block</option><option value="flag">Flag only</option>
          </select>
          <Button type="submit">Add rule</Button>
        </form>
        {err && <p className="mt-2 text-sm text-bad">{err}</p>}
      </Card>

      {rules.length === 0 ? (
        <Empty icon={<ListChecks size={28} />} title="No rules yet" hint="Add a site like youtube.com above, or flip a switch on the Apps page." />
      ) : (
        <Card className="divide-y">
          {rules.map((r) => (
            <div key={r.id} className="flex items-center gap-3 p-4">
              <span className={cn("h-2.5 w-2.5 shrink-0 rounded-full", DOT[r.status])} title={LABEL[r.status]} />
              <div className="min-w-0 flex-1">
                <p className="truncate"><b>{r.value}</b> <span className="text-xs text-muted">{r.type}</span></p>
                <p className={cn("text-xs", r.status === "working" ? "text-good" : r.status === "leaking" || r.status === "inactive" ? "text-bad" : "text-muted")}>{LABEL[r.status]}: {r.detail}</p>
              </div>
              <Badge tone={r.action === "block" ? "bad" : "accent"}>{r.action === "block" ? "Block" : "Flag"}</Badge>
              {r.action === "block" && <span className="w-24 text-right text-sm tabular-nums text-muted">{r.blocked_attempts} stopped</span>}
              <Button size="icon" variant="ghost" aria-label={`Delete rule ${r.value}`} onClick={() => deleteRule(r.id)}><Trash2 size={15} /></Button>
            </div>))}
        </Card>)}
    </div>
  );
}
