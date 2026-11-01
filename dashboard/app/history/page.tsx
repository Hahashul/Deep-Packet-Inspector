"use client";
import { Fragment, useEffect, useState } from "react";
import { ChevronDown, ChevronRight, History as HistoryIcon } from "lucide-react";
import { api } from "@/lib/api";
import { bytes, dateTime } from "@/lib/utils";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Empty } from "@/components/empty";

type Session = { session_id: number; start_time: number; end_time: number | null; interface: string; flow_count: number };
type SFlow = { flow_id: string; dst_ip: string; dst_port: number; protocol: string; sni: string; http_host: string; app_label: string; bytes_sent: number; bytes_recv: number; status: string };
type Alert = { alert_id: number; session_id: number; flow_id: string; rule: string; timestamp: number };

export default function History() {
  const [sessions, setSessions] = useState<Session[] | null>(null);
  const [alerts, setAlerts] = useState<Alert[] | null>(null);
  const [open, setOpen] = useState<number | null>(null);
  const [flows, setFlows] = useState<SFlow[]>([]);

  useEffect(() => {
    api<Session[]>("/sessions").then(setSessions).catch(() => setSessions([]));
    api<Alert[]>("/alerts?limit=100").then(setAlerts).catch(() => setAlerts([]));
  }, []);

  const toggle = async (id: number) => {
    if (open === id) return setOpen(null);
    setOpen(id); setFlows([]);
    setFlows(await api<SFlow[]>(`/sessions/${id}/flows?limit=100`).catch(() => []));
  };

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold">History</h1>
      <Card>
        <CardHeader><CardTitle>Sessions</CardTitle></CardHeader>
        <CardContent>
          {sessions && sessions.length === 0 ? (
            <Empty icon={<HistoryIcon size={26} />} title="No sessions saved yet" hint="Each time the analyzer starts, a session is recorded here." />
          ) : (
            <table className="w-full text-sm">
              <thead className="text-left text-xs text-muted"><tr><th className="w-8 py-2" /><th>Started</th><th>Ended</th><th className="text-right">Connections</th></tr></thead>
              <tbody>
                {(sessions ?? []).map((s) => (
                  <Fragment key={s.session_id}>
                    <tr className="cursor-pointer border-t hover:bg-white/5" onClick={() => toggle(s.session_id)}>
                      <td className="py-2 text-muted">{open === s.session_id ? <ChevronDown size={14} /> : <ChevronRight size={14} />}</td>
                      <td>{dateTime(s.start_time)}</td>
                      <td>{s.end_time ? dateTime(s.end_time) : <Badge tone="good">running</Badge>}</td>
                      <td className="text-right tabular-nums">{s.flow_count}</td>
                    </tr>
                    {open === s.session_id && (
                      <tr className="border-t bg-black/20"><td /><td colSpan={3} className="py-3">
                        {flows.length === 0 ? <p className="text-xs text-muted">No connections stored for this session.</p> : (
                          <ul className="space-y-1 text-xs">
                            {flows.slice(0, 30).map((f) => (
                              <li key={f.flow_id} className="flex justify-between gap-3">
                                <span className="truncate">{f.sni || f.http_host || f.dst_ip} <span className="text-muted">· {f.app_label}</span></span>
                                <span className="shrink-0 text-muted">{bytes(f.bytes_sent + f.bytes_recv)} · {f.status}</span>
                              </li>))}
                          </ul>)}
                      </td></tr>)}
                  </Fragment>))}
              </tbody>
            </table>)}
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle>Alerts</CardTitle></CardHeader>
        <CardContent>
          {alerts && alerts.length === 0 ? <p className="py-6 text-center text-sm text-muted">No alerts. They appear when traffic matches a rule.</p> : (
            <ul className="divide-y text-sm">
              {(alerts ?? []).map((a) => (
                <li key={a.alert_id} className="flex justify-between gap-3 py-2">
                  <span><b>{a.rule}</b> <span className="text-muted">matched {a.flow_id.split("-").slice(2, 3).join("")}</span></span>
                  <span className="shrink-0 text-muted">{dateTime(a.timestamp)}</span>
                </li>))}
            </ul>)}
        </CardContent>
      </Card>
    </div>
  );
}
