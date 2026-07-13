import type { Metadata } from "next";
import "./globals.css";
import "./overrides.css";

export const metadata: Metadata = {
  title: "ThreatCommand Local",
  description: "Local-only threat intelligence and detection command center",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
