export interface AgentConfig {
  /** The control plane's WebSocket address, e.g. `ws://localhost:8080/tunnel`. */
  coreUrl: string;
  /** The cluster record this agent belongs to. */
  clusterId: string;
  /** Proof of identity towards the control plane. Carried in a header — never in the URL. */
  token: string;
  /** `in-cluster` is the production path; `kubeconfig` is for local development. */
  kubeMode: "in-cluster" | "kubeconfig";
  /** Context to use in `kubeconfig` mode (empty = the current context). */
  kubeContext?: string;
  reconnectMinMs: number;
  reconnectMaxMs: number;
}

// These two errors are thrown at startup, they bring the process down, and they
// never reach the wire — their reader is the operator running
// `kubectl logs yeke-agent` (see "Conventions" in README.md: a line's language
// follows its reader). They also avoid non-ASCII letters, which is a measured
// rule and not a stylistic one: an operator greps the ASCII spelling of a word
// and never matches its accented form, and `toLowerCase()` is locale-dependent
// (in a Turkish locale the uppercase I does not lower-case to the ASCII i), so
// the same log rule would not behave identically in every locale.
function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`missing required environment variable: ${name}`);
  return value;
}

export function loadConfig(): AgentConfig {
  const kubeMode = (process.env.YEKE_KUBE_MODE ?? "in-cluster") as AgentConfig["kubeMode"];
  if (kubeMode !== "in-cluster" && kubeMode !== "kubeconfig") {
    throw new Error(`invalid YEKE_KUBE_MODE: ${kubeMode}`);
  }
  return {
    coreUrl: required("YEKE_CORE_URL"),
    clusterId: required("YEKE_CLUSTER_ID"),
    token: required("YEKE_AGENT_TOKEN"),
    kubeMode,
    kubeContext: process.env.YEKE_KUBE_CONTEXT,
    reconnectMinMs: Number(process.env.YEKE_RECONNECT_MIN_MS ?? 1_000),
    reconnectMaxMs: Number(process.env.YEKE_RECONNECT_MAX_MS ?? 30_000),
  };
}
