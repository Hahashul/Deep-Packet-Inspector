// Token handling: the page gets its per-run token from a same-origin endpoint, never from the HTML.
let tokenPromise: Promise<string> | null = null;

export function getToken(): Promise<string> {
  if (!tokenPromise) {
    tokenPromise = fetch("/api/session", { cache: "no-store" })
      .then((r) => { if (!r.ok) throw new Error(`session ${r.status}`); return r.json(); })
      .then((j) => j.token as string)
      .catch((e) => { tokenPromise = null; throw e; });
  }
  return tokenPromise;
}

export async function api<T = unknown>(path: string, init: RequestInit = {}): Promise<T> {
  const token = await getToken();
  const res = await fetch(`/api${path}`, {
    ...init,
    cache: "no-store",
    headers: { ...(init.headers || {}), "X-API-Token": token,
               ...(init.body ? { "Content-Type": "application/json" } : {}) },
  });
  if (!res.ok) {
    let msg = `${res.status}`;
    try { msg = (await res.json()).detail || msg; } catch {}
    throw new Error(msg);
  }
  return res.json();
}

export type Flow = {
  id: string; client: string; server: string; protocol: string; name: string; dns_name: string;
  app: string; bytes_sent: number; bytes_recv: number; total_bytes: number; packets: number;
  first_seen: number; last_seen: number; midstream: boolean; flagged: boolean;
  matched_rule: string; action: "" | "block" | "flag";
};
export type AppStat = { app: string; flows: number; bytes: number };
export type Stats = {
  active_flows: number; total_flows: number; total_bytes: number; bytes_up: number; bytes_down: number;
  flagged_flows: number; blocked_flows: number; blocked_attempts: number; capturing: boolean;
  armed: boolean; has_block_rules: boolean; enforcement: "windivert" | "legacy"; enforcement_error: string; dropped_packets: number; dropped: number; apps: AppStat[];
  top_domains: { domain: string; bytes: number }[];
};
export type Rule = {
  id: number; type: "domain" | "ip" | "app"; value: string; action: "flag" | "block";
  blocked_attempts: number; active_flows: number; leaked_bytes: number;
  status: "working" | "waiting" | "leaking" | "inactive" | "flagging"; detail: string;
};
export type FeedEvent = { id: number; ts: number; kind: string; name: string; app: string; rule: string };
