/**
 * A failure of the agent that **can reach the wire** — it carries a CODE, not a
 * sentence.
 *
 * ─── Why a separate error type ──────────────────────────────────────────────
 *
 * The tunnel's `err` message is `{code, params}`; the free-text field was
 * removed (rationale lives in `@nairotech/yeke-tunnel`, under `ErrorMessage`).
 * But most of the agent's failure points do a plain `throw`, and
 * `tunnel-client.ts` collects them in a single `catch`. That `catch` must be
 * able to answer "is the error in my hand mine, or a library's?":
 *
 *  · If it is **ours**, we already know the code and the parameters — that is
 *    what goes on the wire.
 *  · If it is a **library's** (undici, ws, Node), the text is a FOREIGN text and
 *    passing it through verbatim as `detail` is a deliberate convention.
 *
 * The `instanceof` check makes that distinction mechanical. Had the distinction
 * been made by inspecting the text, it would break again with every new
 * sentence.
 *
 * ─── Why `Error.message` is still filled in ─────────────────────────────────
 *
 * Stack traces and foreign code that catches us expect a text. Writing a
 * SENTENCE there would have reinstated, through the back door, the field that
 * was just removed; so `describeFailure` produces a machine-readable line
 * instead (`AUTH_PLUGIN_FAILED command=gcloud detail=…`) — language-independent,
 * greppable, and free of non-ASCII characters (the measured log-pipeline
 * rationale in README.md, "Conventions").
 */
import { describeFailure, type TunnelFailure } from "@nairotech/yeke-tunnel";

export class AgentFailure extends Error {
  readonly failure: TunnelFailure;

  constructor(failure: TunnelFailure) {
    super(describeFailure(failure));
    this.failure = failure;
    this.name = "AgentFailure";
  }
}

/**
 * Reduces a caught error to a failure that can be written to the wire.
 *
 * `fallback` builds the branch the caller picked and carries FOREIGN text only:
 * depending on context the caller says `UPSTREAM_ERROR` (request path) or
 * `EXEC_UPGRADE_UNREACHABLE` (stream path). Picking one fixed fallback branch
 * would collapse two different failures into one name and send the reader to
 * the wrong layer.
 */
export function failureOf(
  err: unknown,
  fallback: (detail: string) => TunnelFailure,
): TunnelFailure {
  if (err instanceof AgentFailure) return err.failure;
  const detail = err instanceof Error ? err.message : String(err);
  return fallback(detail);
}
