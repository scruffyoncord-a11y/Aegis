import type { CSSProperties } from "react";

import { cn } from "@/lib/utils";

/*
 * Ported from Epiderm (adapted from the 21st.dev "loader-4", a 3x3 ripple grid).
 * Plain CSS (see `.tg-loader` in app/globals.css), no extra dependency, honours
 * "reduce motion". Purely decorative -- the surrounding component provides the
 * accessible status text.
 */
const DELAY_STEP = [0, 1, 2, 1, 2, 2, 3, 3, 4]; // diagonal wave, as in the original

export default function Loader({ cellSize = 52, className }: { cellSize?: number; className?: string }) {
  return (
    <div
      aria-hidden="true"
      className={cn("tg-loader", className)}
      style={{ "--cell-size": `${cellSize}px` } as CSSProperties}
    >
      {DELAY_STEP.map((step, i) => (
        <div key={i} className={cn("cell", `d-${step}`)} />
      ))}
    </div>
  );
}
