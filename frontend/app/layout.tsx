import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import Link from "next/link";
import "./globals.css";

const sans = Geist({ subsets: ["latin"], variable: "--font-geist-sans" });
const mono = Geist_Mono({ subsets: ["latin"], variable: "--font-geist-mono" });

export const metadata: Metadata = {
  title: "Fathom",
  description:
    "Compiles ScubaGear scans into validated OSCAL and answers verified questions about them.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${sans.variable} ${mono.variable}`}>
      <body className="min-h-screen">
        <header className="border-b border-edge bg-ink/90">
          <div className="mx-auto flex max-w-6xl items-center gap-6 px-6 py-4">
            <Link
              href="/"
              className="text-[15px] font-medium tracking-[0.03em] uppercase transition-colors hover:text-accent"
            >
              Fathom
            </Link>
            <span className="hidden text-xs text-muted sm:inline">
              ScubaGear &rarr; validated OSCAL &rarr; verified answers
            </span>
            <nav className="ml-auto flex gap-5 text-sm font-medium">
              <Link href="/" className="text-muted transition-colors hover:text-fg">
                Compile &amp; Posture
              </Link>
              <Link href="/ask" className="text-muted transition-colors hover:text-fg">
                Ask
              </Link>
            </nav>
          </div>
        </header>
        <main className="mx-auto max-w-6xl px-6 py-10">{children}</main>
      </body>
    </html>
  );
}
