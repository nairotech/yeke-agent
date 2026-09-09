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
  /**
   * Accept kubelet server certificates that the cluster CA cannot verify.
   *
   * Off by default, and the default is the decision. The metrics collector
   * verifies each kubelet's serving certificate against
   * `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`; in a large share of
   * real clusters that fails through no fault of the cluster's owner, because
   * kubeadm does not sign kubelet serving certificates with the cluster CA
   * unless `serverTLSBootstrap` is turned on. That is why metrics-server ships
   * `--kubelet-insecure-tls` in most installation guides.
   *
   * The rejected alternative was to fall back to an unverified connection
   * automatically when verification fails. It would make the product work
   * everywhere on the first day and would silently downgrade the security of
   * every cluster where the certificate was correct until the day it was not.
   * The rule this repository follows is the opposite one: an obstacle is
   * reported, never routed around. Without this flag the affected nodes carry
   * the `tls-unverified` state and produce no data; with it, the acceptance is
   * announced in the startup log and shown on the screen as a chip. The
   * precedent is the direct-mode import's `acknowledgeInsecureTLS`.
   */
  kubeletInsecureTls: boolean;
  /**
   * The operator's off switch for the metrics collector.
   *
   * On by default, because a cluster card with no series on it is a product
   * that looks broken, and the collector's cost is bounded by design (two
   * kubelet reads per node per 30 seconds, a 50m CPU budget, a ring with a
   * ceiling). But it stays a SWITCH, because the collector is the only part of
   * the agent that reads on a timer instead of on a user's request: an operator
   * investigating load on their own control plane has to be able to make it
   * stop without deleting the agent that keeps their cluster reachable.
   *
   * Note the asymmetry with `kubeletInsecureTls`, and that it is deliberate.
   * There, only the exact string `true` grants a weakening, so a typo cannot
   * lower anyone's security. Here, only the exact string `false` withdraws a
   * feature, so a typo cannot silently blind a fleet's monitoring. In both
   * cases the typo lands on the safe side, which is not the same side.
   */
  metricsEnabled: boolean;
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
    // Exactly the string `true`. A weakness is accepted deliberately or not at
    // all, and treating `1`, `yes` or `TRUE` as consent would mean a typo in a
    // manifest could disable certificate verification across a fleet.
    kubeletInsecureTls: process.env.YEKE_KUBELET_INSECURE_TLS === "true",
    metricsEnabled: process.env.YEKE_METRICS_ENABLED !== "false",
  };
}
