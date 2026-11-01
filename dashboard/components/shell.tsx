"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Activity, AppWindow, History, ListChecks, Network, Pause, Play, ShieldAlert, ShieldCheck, ShieldOff } from "lucide-react";
import { useData } from "@/lib/data";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

const NAV = [
  { href: "/", label: "Overview", icon: Activity },
  { href: "/apps/", label: "Apps", icon: AppWindow },
  { href: "/connections/", label: "Connections", icon: Network },
  { href: "/rules/", label: "Rules", icon: ListChecks },
  { href: "/history/", label: "History", icon: History },
];

function StatusBar() {
  const { stats, online, setCapture } = useData();
  if (!online || !stats)
    return <Badge tone="bad"><ShieldAlert size={13} /> Backend not reachable. Is the analyzer running as Administrator?</Badge>;
  const armed = stats.armed;
  return (
    <div className="flex flex-wrap items-center gap-2">
      <Badge tone={stats.capturing ? "good" : "neutral"}>
        <span className={cn("h-1.5 w-1.5 rounded-full", stats.capturing ? "bg-good" : "bg-muted")} />
        {stats.capturing ? "Capturing" : "Paused"}
      </Badge>
      <Badge tone={armed ? "good" : "neutral"}>
        {armed ? <ShieldCheck size={13} /> : <ShieldOff size={13} />}
        {armed ? "Blocking armed" : stats.has_block_rules ? "Blocking not armed (capture paused)" : "No block rules"}
      </Badge>
      {stats.enforcement === "windivert"
        ? <Badge tone="neutral">Engine: WinDivert</Badge>
        : <Badge tone="bad" title={stats.enforcement_error}>WinDivert off: using weaker fallback blocking</Badge>}
      <Button size="sm" variant="outline" onClick={() => setCapture(!stats.capturing)}>
        {stats.capturing ? <><Pause size={13} /> Pause</> : <><Play size={13} /> Resume</>}
      </Button>
    </div>
  );
}

export function Shell({ children }: { children: React.ReactNode }) {
  const path = usePathname();
  const active = (h: string) => (h === "/" ? path === "/" : path.startsWith(h.replace(/\/$/, "")));
  return (
    <div className="min-h-screen md:flex">
      <aside className="border-b md:w-52 md:border-b-0 md:border-r md:min-h-screen">
        <div className="px-5 py-4 text-sm font-semibold tracking-tight"><span className="text-accent">●</span> Traffic Analyzer</div>
        <nav className="flex gap-1 overflow-x-auto px-3 pb-3 md:flex-col md:pb-0">
          {NAV.map(({ href, label, icon: Icon }) => (
            <Link key={href} href={href}
              className={cn("flex items-center gap-2 rounded-md px-3 py-2 text-sm whitespace-nowrap",
                active(href) ? "bg-accent/15 text-accent" : "text-muted hover:bg-white/5 hover:text-foreground")}>
              <Icon size={16} /> {label}
            </Link>
          ))}
        </nav>
      </aside>
      <main className="flex-1 min-w-0 p-5 md:p-8">
        <div className="mb-6"><StatusBar /></div>
        {children}
        <p className="mt-10 text-xs text-muted">Blocking only affects this PC.</p>
      </main>
    </div>
  );
}
