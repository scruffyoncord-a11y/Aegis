"use client";

// Ported verbatim from Epiderm's analysis-overlay.tsx -- generic, no
// domain-specific content, so no changes needed.

import { motion, useReducedMotion } from "motion/react";
import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";

import Loader from "@/components/ui/loader-4";
import OnboardCard, { type Step } from "@/components/ui/onboard-card";

const DWELL_MS = 650; // each slide stays long enough to be read, even when the real work is instant
const DWELL_REDUCED_MS = 250;
const HOLD_DONE_MS = 700; // the finished state is shown briefly before the overlay leaves
const EXIT_MS = 280;

// How many AnalysisOverlays are currently mounted (module-level, shared by
// every instance) -- see the scroll-lock effect below for why this can't
// just be a save/restore of body.style.overflow per instance.
let openOverlayCount = 0;

/**
 * A full-window overlay, centred over a blurred page, that swipes through the steps of a running check.
 *
 * `stage` is the step the server has REALLY reached; the slides follow it, at most one per DWELL so a fast
 * check does not flash past. When `finished` is set the remaining slides play out, the "all done" state
 * is held for a moment, the overlay fades away and `onClosed` is called: only then does the caller show
 * the result.
 */
export function AnalysisOverlay({
  steps,
  stage,
  finished,
  onClosed,
  onTerminate,
  loaderThroughIndex,
}: {
  steps: Step[];
  stage: number;
  finished: boolean;
  onClosed: () => void;
  /** Shows a "Terminate" button while the check is still genuinely running
   * (not once it's already wrapping up) -- omit for a check with nothing
   * real to cancel, e.g. the static scan. */
  onTerminate?: () => void;
  /** Shows the ripple-grid loader ("Opening a private container..."), in
   * place of the normal step carousel, from the very first step through
   * this index, inclusive -- purely a demo flourish (this MVP doesn't
   * actually run a different pipeline underneath), so every overlay opens
   * on this screen for a beat before settling into its real step list. */
  loaderThroughIndex?: number;
}) {
  const reduceMotion = useReducedMotion();
  const total = steps.length;
  const [shown, setShown] = useState(0);
  const [leaving, setLeaving] = useState(false);
  const dialogRef = useRef<HTMLDivElement>(null);
  const closedRef = useRef(onClosed);

  useEffect(() => {
    closedRef.current = onClosed;
  }, [onClosed]);

  const target = finished ? total : Math.min(stage, total - 1);
  const dwell = reduceMotion ? DWELL_REDUCED_MS : DWELL_MS;

  // Follow the real progress one slide at a time.
  useEffect(() => {
    if (shown < target) {
      const t = setTimeout(() => setShown((s) => s + 1), dwell);
      return () => clearTimeout(t);
    }
    if (shown >= total) {
      const t = setTimeout(() => setLeaving(true), HOLD_DONE_MS);
      return () => clearTimeout(t);
    }
  }, [shown, target, total, dwell]);

  useEffect(() => {
    if (!leaving) return;
    const t = setTimeout(() => closedRef.current(), reduceMotion ? 0 : EXIT_MS);
    return () => clearTimeout(t);
  }, [leaving, reduceMotion]);

  // While it is open: the page behind cannot be scrolled or focused, and focus moves into the dialog.
  // Two overlays can briefly overlap (one still playing its exit animation
  // when the next one opens, e.g. Scan -> Probe firing back to back), so a
  // naive save/restore of body.style.overflow is wrong: the second overlay
  // would capture "hidden" (the first overlay's own lock) as "previous" and
  // restore that on unmount, leaving scroll permanently locked. A shared
  // open-count avoids that -- only the transition to/from zero touches it.
  useEffect(() => {
    const main = document.querySelector("main");
    main?.setAttribute("inert", "");
    openOverlayCount += 1;
    if (openOverlayCount === 1) document.body.style.overflow = "hidden";
    dialogRef.current?.focus();
    return () => {
      main?.removeAttribute("inert");
      openOverlayCount -= 1;
      if (openOverlayCount === 0) document.body.style.overflow = "";
    };
  }, []);

  const active = Math.min(shown, total - 1);
  const complete = shown >= total;
  const spoken = complete ? "All checks complete" : `Step ${active + 1} of ${total}: ${steps[active].label}`;
  const atLoaderStep = loaderThroughIndex !== undefined && !complete && active <= loaderThroughIndex;

  return createPortal(
    <motion.div
      className="fixed inset-0 z-50 flex items-center justify-center bg-background/55 px-4 backdrop-blur-md"
      initial={{ opacity: reduceMotion ? 1 : 0 }}
      animate={{ opacity: leaving ? 0 : 1 }}
      transition={{ duration: reduceMotion ? 0 : 0.25 }}
      data-testid="analysis-overlay"
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="analysis-title"
        tabIndex={-1}
        className="flex max-w-full flex-col items-center gap-4 rounded-xl border border-neutral-200 bg-background/90 px-6 py-6 shadow-xl outline-none dark:border-neutral-800"
      >
        {atLoaderStep ? (
          <>
            <Loader cellSize={20} />
            <h2 id="analysis-title" className="text-lg font-semibold">
              Opening a private container&hellip;
            </h2>
            <p className="max-w-md text-center text-sm text-neutral-600 dark:text-neutral-300">
              This is a disposable sandbox Aegis starts just for this run -- the app is built and started inside it,
              with no access to anything else, and it is torn down the moment this check ends.
            </p>
          </>
        ) : (
          <>
            <h2 id="analysis-title" className="text-base font-semibold">
              Checking your evidence
            </h2>
            <OnboardCard steps={steps} active={active} complete={complete} />
          </>
        )}
        {onTerminate && !complete && !leaving && (
          <button
            type="button"
            onClick={onTerminate}
            className="rounded-lg border border-red-300 px-4 py-1.5 text-sm font-medium text-red-600 transition hover:bg-red-50 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950"
          >
            Terminate pentest
          </button>
        )}
        <p className="sr-only" role="status" aria-live="polite">
          {spoken}
        </p>
      </div>
    </motion.div>,
    document.body,
  );
}
