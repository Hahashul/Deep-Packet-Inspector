import { Card } from "@/components/ui/card";

export function Empty({ icon, title, hint }: { icon: React.ReactNode; title: string; hint?: string }) {
  return (
    <Card className="flex flex-col items-center gap-2 px-6 py-14 text-center">
      <div className="text-muted">{icon}</div>
      <p className="font-medium">{title}</p>
      {hint && <p className="max-w-md text-sm text-muted">{hint}</p>}
    </Card>
  );
}
