"use client";

// Ported from Epiderm's sandbox-badge.tsx. Adapted from "your files are safe in
// a per-session container" to Aegis's model: a fresh, disposable container is
// built and torn down for each active-probe run (see backend/app/sandbox.py).

import { LockKeyhole, ShieldAlert, ShieldCheck } from "lucide-react";
import { useState } from "react";

export type SandboxState = "standby" | "opening" | "active" | "off";

const LOOK: Record<SandboxState, { label: string; dot: string; text: string }> = {
  standby: { label: "Sandbox on standby", dot: "bg-zinc-400", text: "text-zinc-700 dark:text-zinc-200" },
  opening: { label: "Building sandbox…", dot: "bg-amber-400 animate-pulse", text: "text-amber-700 dark:text-amber-300" },
  active: { label: "Sandbox confirmed a finding", dot: "bg-emerald-500", text: "text-emerald-700 dark:text-emerald-300" },
  off: { label: "Sandbox not available", dot: "bg-amber-500", text: "text-amber-700 dark:text-amber-300" },
};

const POINTS: Record<SandboxState, { title: string; items: string[] }> = {
  standby: {
    title: "The active probe opens its own sandbox on demand",
    items: [
      "Each probe run builds the target repo's own Dockerfile into a fresh container.",
      "Nothing is scanned or probed until you click Run AI Pentest.",
    ],
  },
  opening: {
    title: "Building and starting a disposable container",
    items: ["This takes a few seconds. Nothing has been probed yet."],
  },
  active: {
    title: "The probe ran inside an isolated container",
    items: [
      "No other network access than what the app image itself needs to boot.",
      "Memory and process limits, always torn down after the probe finishes.",
      "Only a single, safe, read-only request was sent -- no exploit payloads.",
      "The reasoning model runs outside it, locally on this computer (Ollama).",
    ],
  },
  off: {
    title: "No sandbox is available right now",
    items: [
      "Docker is not running, or the target repo has no Dockerfile.",
      "The active-probe stage is skipped -- static findings (secrets, dependencies, config) still ran.",
      "Start Docker Desktop and add a Dockerfile to the repo to enable it.",
    ],
  },
};

/** A corner badge that says, honestly, whether the sandbox actually ran the current probe. */
export function SandboxBadge({ state }: { state: SandboxState }) {
  const [open, setOpen] = useState(false);
  const look = LOOK[state];
  const info = POINTS[state];
  const Icon = state === "active" ? ShieldCheck : state === "off" ? ShieldAlert : LockKeyhole;
  return (
    <div className="no-print fixed right-4 top-4 z-40 flex flex-col items-end gap-2 sm:right-8" onMouseLeave={() => setOpen(false)}>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        onMouseEnter={() => setOpen(true)}
        aria-expanded={open}
        aria-controls="sandbox-info"
        className={`tg-card flex items-center gap-2 !rounded-full px-4 py-2 text-sm font-semibold ${look.text} focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2`}
      >
        <span className={`size-2.5 rounded-full ${look.dot}`} aria-hidden />
        <Icon className="size-4" aria-hidden />
        {look.label}
      </button>
      {open && (
        <div id="sandbox-info" role="status" className="tg-card w-80 p-4 text-sm">
          <p className="font-semibold">{info.title}</p>
          <ul className="mt-2 list-disc space-y-1 pl-5 text-zinc-700 dark:text-zinc-300">
            {info.items.map((t) => (
              <li key={t}>{t}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
