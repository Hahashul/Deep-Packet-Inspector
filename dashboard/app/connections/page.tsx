"use client";
import { Fragment, useEffect, useState } from "react";
import { ChevronDown, ChevronRight, Network } from "lucide-react";
import { api, type Flow } from "@/lib/api";
import { bytes, dateTime } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Empty } from "@/components/empty";

export default function Connections() {
  const [flows, setFlows] = useState<Flow[] | null>(null);
  const [q, setQ] = useState("");
  const [open, setOpen] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    const load = () => api<Flow[]>("/flows?limit=500").then((f) => live && setFlows(f)).catch(() => {});
    load();
    const t = setInterval(load, 2000);
    return () => { live = false; clearInterval(t); };
  }, []);

  const needle = q.trim().toLowerCase();
  const rows = (flows ?? []).filter((f) => !needle ||
    [f.name, f.dns_name, f.app, f.server, f.client, f.matched_rule].some((s) => (s || "").toLowerCase().includes(needle)));

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-xl font-semibold">Connections</h1>
        <Input className="max-w-xs" placeholder="Search site, app or address" value={q} onChange={(e) => setQ(e.target.value)} />
      </div>
      {flows && flows.length === 0 ? (
        <Empty icon={<Network size={28} />} title="No connections yet" hint="Nothing has been captured. Check the status bar: capture should say Capturing." />
      ) : rows.length === 0 ? (
        <Empty icon={<Network size={28} />} title="No match" hint={`Nothing matches “${q}”.`} />
      ) : (
        <Card className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-left text-xs text-muted">
              <tr><th className="w-8 p-3" /><th className="p-3">Site</th><th className="p-3">App</th><th className="p-3">Protocol</th><th className="p-3 text-right">Traffic</th><th className="p-3">Status</th></tr>
            </thead>
            <tbody>
              {rows.map((f) => (
                <Fragment key={f.id}>
                  <tr className="cursor-pointer border-t hover:bg-white/5" onClick={() => setOpen(open === f.id ? null : f.id)}>
                    <td className="p-3 text-muted">{open === f.id ? <ChevronDown size={14} /> : <ChevronRight size={14} />}</td>
                    <td className="p-3">{f.name || f.dns_name || <span className="text-muted">{f.server}</span>}</td>
                    <td className="p-3">{f.app}</td>
                    <td className="p-3 text-muted">{f.protocol}</td>
                    <td className="p-3 text-right tabular-nums">{bytes(f.total_bytes)}</td>
                    <td className="p-3">{f.action === "block" ? <Badge tone="bad">Blocked</Badge> : f.action === "flag" ? <Badge tone="accent">Flagged</Badge> : <Badge>Allowed</Badge>}</td>
                  </tr>
                  {open === f.id && (
                    <tr className="border-t bg-black/20">
                      <td />
                      <td colSpan={5} className="p-3">
                        <dl className="grid grid-cols-2 gap-x-6 gap-y-1 text-xs sm:grid-cols-3">
                          {([["Your PC", f.client], ["Server", f.server], ["Name source", f.name ? "TLS / HTTP / QUIC" : f.dns_name ? "DNS (guess)" : "none"],
                            ["Sent", bytes(f.bytes_sent)], ["Received", bytes(f.bytes_recv)], ["Packets", String(f.packets)],
                            ["First seen", dateTime(f.first_seen)], ["Last seen", dateTime(f.last_seen)],
                            ["Matched rule", f.matched_rule || "none"], ["Joined mid-stream", f.midstream ? "yes" : "no"]] as [string, string][]).map(([k, v]) => (
                            <div key={k}><dt className="text-muted">{k}</dt><dd className="break-all">{v}</dd></div>))}
                        </dl>
                      </td>
                    </tr>)}
                </Fragment>))}
            </tbody>
          </table>
        </Card>)}
    </div>
  );
}
