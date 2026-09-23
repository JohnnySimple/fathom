import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

export const metadata: Metadata = {
  title: "Fathom",
  description:
    "Compiles ScubaGear scans into validated OSCAL and answers verified questions about them.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen">
        <header className="border-b border-edge">
          <div className="mx-auto flex max-w-6xl items-center gap-6 px-6 py-4">
            <Link href="/" className="text-lg font-semibold tracking-tight">
              Fathom
            </Link>
            <span className="hidden text-xs text-muted sm:inline">
              ScubaGear &rarr; validated OSCAL &rarr; verified answers
            </span>
            <nav className="ml-auto flex gap-5 text-sm">
              <Link href="/" className="text-muted hover:text-white">
                Compile &amp; Posture
              </Link>
              <Link href="/ask" className="text-muted hover:text-white">
                Ask
              </Link>
            </nav>
          </div>
        </header>
        <main className="mx-auto max-w-6xl px-6 py-8">{children}</main>
      </body>
    </html>
  );
}
