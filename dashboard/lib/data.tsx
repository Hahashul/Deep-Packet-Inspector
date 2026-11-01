"use client";
import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import { api, getToken, type FeedEvent, type Flow, type Rule, type Stats } from "./api";

type Ctx = {
  stats: Stats | null; flows: Flow[]; rules: Rule[]; events: FeedEvent[];
  online: boolean; refresh: () => Promise<void>;
  setCapture: (on: boolean) => Promise<void>;
  addRule: (type: string, value: string, action: string) => Promise<void>;
  deleteRule: (id: number) => Promise<void>;
};
const DataCtx = createContext<Ctx | null>(null);
export const useData = () => {
  const c = useContext(DataCtx);
  if (!c) throw new Error("DataProvider missing");
  return c;
};

export function DataProvider({ children }: { children: React.ReactNode }) {
  const [stats, setStats] = useState<Stats | null>(null);
  const [flows, setFlows] = useState<Flow[]>([]);
  const [rules, setRules] = useState<Rule[]>([]);
  const [events, setEvents] = useState<FeedEvent[]>([]);
  const [online, setOnline] = useState(false);
  const alive = useRef(true);

  const refresh = useCallback(async () => {
    try {
      const [r, e] = await Promise.all([api<Rule[]>("/rules/status"), api<FeedEvent[]>("/events?limit=40")]);
      setRules(r); setEvents(e);
    } catch {}
  }, []);

  // live snapshot over the websocket, reconnecting if it drops
  useEffect(() => {
    alive.current = true;
    let ws: WebSocket | null = null;
    let timer: ReturnType<typeof setTimeout>;
    const connect = async () => {
      try {
        const token = await getToken();
        const proto = location.protocol === "https:" ? "wss:" : "ws:";
        ws = new WebSocket(`${proto}//${location.host}/ws?token=${encodeURIComponent(token)}`);
        ws.onopen = () => setOnline(true);
        ws.onmessage = (m) => { const d = JSON.parse(m.data); setStats(d.stats); setFlows(d.flows); };
        ws.onclose = () => { setOnline(false); if (alive.current) timer = setTimeout(connect, 2000); };
      } catch { setOnline(false); timer = setTimeout(connect, 2000); }
    };
    connect();
    return () => { alive.current = false; clearTimeout(timer); ws?.close(); };
  }, []);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 2000);
    return () => clearInterval(t);
  }, [refresh]);

  const setCapture = async (on: boolean) => { await api(on ? "/capture/start" : "/capture/stop", { method: "POST" }); await refresh(); };
  const addRule = async (type: string, value: string, action: string) => {
    await api("/rules", { method: "POST", body: JSON.stringify({ type, value, action }) }); await refresh();
  };
  const deleteRule = async (id: number) => { await api(`/rules/${id}`, { method: "DELETE" }); await refresh(); };

  return (
    <DataCtx.Provider value={{ stats, flows, rules, events, online, refresh, setCapture, addRule, deleteRule }}>
      {children}
    </DataCtx.Provider>
  );
}
