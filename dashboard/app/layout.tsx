import "./globals.css";
import type { Metadata } from "next";
import { DataProvider } from "@/lib/data";
import { Shell } from "@/components/shell";

export const metadata: Metadata = { title: "Traffic Analyzer", description: "Which apps and sites this PC uses, and block them." };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <DataProvider><Shell>{children}</Shell></DataProvider>
      </body>
    </html>
  );
}
