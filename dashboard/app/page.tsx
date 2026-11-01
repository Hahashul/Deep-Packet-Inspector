"use client";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Activity, CheckCircle2, Radio, ShieldQuestion, XCircle } from "lucide-react";
import { useData } from "@/lib/data";
import { toLines } from "@/lib/feed";
import { bytes } from "@/lib/utils";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Empty } from "@/components/empty";
import { cn } from "@/lib/utils";

const HIDDEN_APPS = new Set(["Unknown", "Local network"]);

function Stat({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <Card><CardHeader><CardTitle>{label}</CardTitle></CardHeader>
      <CardContent><div className="text-2xl font-semibold tabular-nums">{value}</div>
        {hint && <div className="mt-1 text-xs text-muted">{hint}</div>}</CardContent></Card>
  );
}

export default function Overview() {
  const { stats, rules, events } = useData();
  const blockRules = rules.filter((r) => r.action === "block");
  const apps = (stats?.apps ?? []).filter((a) => !HIDDEN_APPS.has(a.app) && a.bytes > 0).slice(0, 8)
    .map((a) => ({ name: a.app, mb: +(a.bytes / 1048576).toFixed(2), bytes: a.bytes }));
  const lines = toLines(events).slice(0, 12);

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold">Overview</h1>
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat label="Total traffic" value={bytes(stats?.total_bytes ?? 0)} hint={`↓ ${bytes(stats?.bytes_down ?? 0)}  ↑ ${bytes(stats?.bytes_up ?? 0)}`} />
        <Stat label="Active apps" value={String((stats?.apps ?? []).filter((a) => !HIDDEN_APPS.has(a.app) && a.bytes > 0).length)} />
        <Stat label="Blocked attempts" value={String(stats?.blocked_attempts ?? 0)} hint="connections stopped" />
        <Stat label="Flagged connections" value={String(stats?.flagged_flows ?? 0)} hint="matching a rule right now" />
      </div>

      <Card>
        <CardHeader><CardTitle>Is my block working?</CardTitle></CardHeader>
        <CardContent>
          {blockRules.length === 0 ? (
            <p className="flex items-center gap-2 text-sm text-muted"><ShieldQuestion size={16} /> Nothing is blocked. Turn on a block on the Apps page or add a rule.</p>
          ) : (
            <ul className="space-y-2">
              {blockRules.map((r) => {
                const good = r.status === "working";
                const bad = r.status === "leaking" || r.status === "inactive";
                return (
                  <li key={r.id} className="flex items-start gap-2 text-sm">
                    {good ? <CheckCircle2 size={16} className="mt-0.5 text-good" /> : bad ? <XCircle size={16} className="mt-0.5 text-bad" /> : <Radio size={16} className="mt-0.5 text-muted" />}
                    <span><b>{r.value}</b> <span className={cn(good ? "text-good" : bad ? "text-bad" : "text-muted")}>— {r.detail}</span></span>
                  </li>
                );
              })}
            </ul>
          )}
        </CardContent>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader><CardTitle>Top apps by traffic (MB)</CardTitle></CardHeader>
          <CardContent>
            {apps.length === 0 ? <p className="py-10 text-center text-sm text-muted">No app traffic seen yet. Open a website and it will show up here.</p> : (
              <div className="h-64">
                <ResponsiveContainer>
                  <BarChart data={apps} layout="vertical" margin={{ left: 10 }}>
                    <CartesianGrid horizontal={false} stroke="#232834" />
                    <XAxis type="number" stroke="#8b93a7" fontSize={12} />
                    <YAxis type="category" dataKey="name" stroke="#8b93a7" fontSize={12} width={90} />
                    <Tooltip cursor={{ fill: "rgba(255,255,255,0.04)" }} contentStyle={{ background: "#12151c", border: "1px solid #232834", borderRadius: 8 }}
                      formatter={(_v, _n, p) => [bytes((p.payload as { bytes: number }).bytes), "Traffic"]} />
                    <Bar dataKey="mb" fill="#38bdf8" radius={[0, 4, 4, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>)}
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle>Live activity</CardTitle></CardHeader>
          <CardContent>
            {lines.length === 0 ? <p className="py-10 text-center text-sm text-muted">Quiet so far. Blocks and flags appear here as they happen.</p> : (
              <ul className="space-y-2 text-sm">
                {lines.map((l) => (
                  <li key={l.key} className="flex justify-between gap-3">
                    <span className={cn(l.tone === "bad" && "text-bad", l.tone === "accent" && "text-accent")}>{l.text}</span>
                    <span className="shrink-0 text-muted tabular-nums">{l.when}</span>
                  </li>))}
              </ul>)}
          </CardContent>
        </Card>
      </div>
      {!stats && <Empty icon={<Activity />} title="Waiting for the analyzer" hint="Start it from an Administrator PowerShell with .\run.ps1, then reload." />}
    </div>
  );
}
