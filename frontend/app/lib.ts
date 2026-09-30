// Ported from Epiderm's lib.ts -- readStream() is generic (NDJSON line
// reader), no changes needed.

export const API = "http://localhost:8000";

/** Reads a newline-delimited JSON stream from the backend, calling onStage
 * for every real progress event, and resolving with the final `result` once
 * a {"stage": "done"} line arrives. Throws if the stream reports an error
 * or ends without ever sending one.
 *
 * `onStarted`, if given, gets the full first ("started") event -- not just
 * its stage name -- so a caller can pick extra fields off it (e.g.
 * probe/stream's `run_id`, which a "Terminate" button needs before any
 * later stage has even arrived). */
export async function readStream<T>(
  res: Response,
  onStage: (stage: string) => void,
  onStarted?: (event: Record<string, unknown>) => void,
): Promise<T> {
  if (!res.body) throw new Error("The server sent no answer.");
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let result: T | undefined;
  let finished = false;
  while (!finished) {
    const chunk = await reader.read();
    finished = chunk.done;
    buffer += decoder.decode(chunk.value, { stream: !chunk.done });
    let newline = buffer.indexOf("\n");
    while (newline >= 0) {
      const line = buffer.slice(0, newline).trim();
      buffer = buffer.slice(newline + 1);
      newline = buffer.indexOf("\n");
      if (!line) continue;
      const event = JSON.parse(line) as { stage: string; result?: T; detail?: string; [key: string]: unknown };
      if (event.stage === "error") throw new Error(event.detail ?? "The check failed.");
      if (event.stage === "done") result = event.result;
      else {
        if (event.stage === "started") onStarted?.(event);
        onStage(event.stage);
      }
    }
  }
  if (result === undefined) throw new Error("The check ended without a result.");
  return result;
}
