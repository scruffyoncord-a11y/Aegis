"use client";

// Ported from Epiderm's components.tsx -- only the generic, domain-neutral
// pieces (Card, SandboxNote). Epiderm's email/document-forensics-specific
// cards (HeaderCard, DocumentReadingCard, IdentifiersCard, etc.) don't apply
// to Aegis's vulnerability findings, so they weren't ported.

export function Card({ title, children, aside }: { title: string; children: React.ReactNode; aside?: React.ReactNode }) {
  return (
    <section className="tg-card p-5">
      <div className="flex items-baseline justify-between gap-3">
        <h2 className="text-xs font-semibold uppercase tracking-wide text-zinc-600 dark:text-zinc-300">{title}</h2>
        {aside}
      </div>
      <div className="mt-3">{children}</div>
    </section>
  );
}

/** Says plainly whether untrusted input (here: the target repo) was handled inside a private, throwaway container. */
export function SandboxNote({ container, what }: { container: boolean; what: string }) {
  return (
    <p className="mt-2 flex items-start gap-2 text-xs text-zinc-600 dark:text-zinc-300">
      <span
        className={`mt-0.5 inline-block size-2 shrink-0 rounded-full ${container ? "bg-emerald-500" : "bg-amber-500"}`}
        aria-hidden
      />
      <span>
        {container
          ? `${what} inside a private, throwaway container: no other network access, limited memory, and deleted afterwards.`
          : `${what} without a sandbox, because Docker or a Dockerfile is not available.`}
      </span>
    </p>
  );
}
