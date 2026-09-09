# yeke-agent

The cluster-side component of YEKE. It runs inside your Kubernetes cluster,
opens a single **outbound** WebSocket tunnel to the YEKE control plane, and
applies the requests that arrive over it to your cluster's own apiserver.

There is no inbound connection. The agent does not listen on a port, and the
control plane never dials into your network.

---

## Why this component is open source

The rest of YEKE — the management application — is closed source. This component
is not, and the dividing line is not arbitrary: **this is the part that runs in
your cluster, under a ServiceAccount you grant, with permissions you configure.**
Software with that position has to be readable by the people who install it. You
should be able to check what it connects to, what it forwards, and what it
refuses, without taking anyone's word for it.

The management application runs on our side and holds no privileges inside your
cluster; keeping it closed changes nothing you can verify. Keeping this closed
would.

The wire contract is open for the same reason and lives in its own package:
[`@nairotech/yeke-tunnel`](https://www.npmjs.com/package/@nairotech/yeke-tunnel)
(Apache-2.0).

---

## Security posture

Every claim below is meant to be checked against the source, so each one names
where to look.

**Outbound only, no listening socket.** The single connection is created in
`TunnelClient.#connect` (`src/tunnel-client.ts`) with `new WebSocket(coreUrl)`.
The agent never constructs a server. Verifiable in one line:

```bash
grep -rn "createServer\|\.listen(" src/    # no results
```

**The apiserver is the only reachable target, and only on allowlisted paths.**
`ALLOWED_PATH_PREFIXES` in `src/tunnel-client.ts` restricts requests to `/api`,
`/apis`, `/openapi`, `/version`, `/healthz`, `/livez`, `/readyz`. The check runs
on both paths that can reach the network — plain requests (`#handleRequest`) and
stream upgrades such as `exec` (`#openStream`) — and it rejects `..` outright.

This is defense in depth, and the threat it addresses is specific. A tunnel agent
is, structurally, a hole punched outward through your network perimeter; whoever
is on the other end can ask it to dial. If the set of reachable addresses were
open-ended, a compromised control plane could reach anything the pod's network
namespace can reach — other services, the container runtime socket, cloud
metadata endpoints. The allowlist makes that class of request unrepresentable
rather than merely unauthorized.

**Cluster credentials never leave the cluster.** The identity used against the
apiserver is built inside the agent (`src/kube.ts`): in in-cluster mode from
`/var/run/secrets/kubernetes.io/serviceaccount`, in kubeconfig mode from your
kubeconfig. The ServiceAccount token, the CA and any client certificate are used
locally to construct headers and TLS material — none of them is ever sent over
the tunnel.

This is a deliberate architectural choice, documented at the top of `src/kube.ts`.
A control plane that collects downstream cluster credentials becomes a single
place where compromising one system yields standing access to every managed
cluster. Leaving the credentials where they already are means the blast radius of
a control-plane compromise is bounded by what each agent's own ServiceAccount can
do — which you granted, and can revoke, per cluster.

**Authorization is decided by your cluster, not by us.** When the control plane
supplies an identity, requests carry `Impersonate-User` / `Impersonate-Group`,
so the effective decision belongs to Kubernetes RBAC and the real user appears in
your audit log. The agent implements no authorization logic of its own. Its
ceiling is whatever its ServiceAccount is granted — RBAC you apply and can
inspect.

**Bounded memory and flow control.** Request bodies are capped
(`MAX_REQUEST_BODY_BYTES`) and response bodies are governed by a credit window:
when credit runs out, the `for await` loop suspends and backpressure travels over
TCP down to the apiserver instead of accumulating in the agent's memory. On the
stream path the socket is explicitly paused for the same reason
(`src/stream.ts`).

**The protocol version is negotiated, not assumed.** The agent announces
`TUNNEL_PROTOCOL_VERSION` in its `hello`; the control plane answers with the
negotiated version in `welcome.protocol`, and a version outside the accepted
window closes the tunnel with WebSocket code `1008` rather than degrading
silently.

**Failures on the wire are codes, not sentences.** The agent sends
`{code, params}`; text that originates outside the agent (Node, `ws`, undici, a
credential plugin's `stderr`) travels verbatim in labelled fields, each under its
own owner. See `src/failure.ts` and the `AUTH_PLUGIN_FAILED` branch in
`src/kube.ts`.

What the agent does **not** do: it does not write to your cluster on its own
initiative, it does not phone home to anything other than the `YEKE_CORE_URL` you
configure, and it does not update itself.

---

## What the agent does under its own identity

Almost everything that reaches your apiserver through this agent carries a
USER's identity: the control plane supplies it and the request goes out with
`Impersonate-User` / `Impersonate-Group`, so RBAC decides and your audit log
names the person (`src/tunnel-client.ts`, the `impersonate` branches).

There are exactly three jobs that run under the agent's OWN ServiceAccount, and
this is the complete list:

1. **A `SelfSubjectReview` health probe** — "who am I, and did my token work?".
   It reads the agent's own identity and nothing else. Sent by the control plane
   through the tunnel as a request with no impersonation identity.
2. **CRD and APIService metadata watches** — the agent's connection carries a
   watch on `customresourcedefinitions` and `apiservices` so the control plane
   knows when a cluster's API surface changed. It observes that objects changed;
   it does not read what is in them. Also originated by the control plane.
3. **Kubelet statistics collection**, together with the node list and the
   pod/ReplicaSet metadata watches it needs to attribute a number to a workload.
   This one lives in the agent itself (`src/metrics/`): it reads
   `/stats/summary` and `/metrics/cadvisor` from each kubelet and watches
   `nodes`, `pods` and `replicasets`.

Properties that hold for all three, and that you can check in the source:

- **No object bodies.** Pods and ReplicaSets are requested as
  `PartialObjectMetadata` (`src/metrics/owners.ts`), so the apiserver serves
  `metadata` and never sends `spec`, `status` or `data`. Node objects ARE read in
  full, because the collector needs each node's address and `allocatable`; a node
  object carries no Secret. This is also why the collector does not report a
  container restart count: that number lives in a pod's `status`, and `status` is
  a body.
- **No Secrets, and no writes.** None of the three creates, updates, patches or
  deletes anything.
- **Nothing bypasses your RBAC on the way out.** Numbers collected under the
  agent's identity are not shown to a user until that user's own authorization
  has been confirmed with a `SelfSubjectAccessReview` submitted under their
  identity. A user who cannot list pods in a namespace does not see that
  namespace's series — or its name.

The list is closed on purpose. Adding a fourth entry is a design decision that
requires revising the document that defines it, not a patch: if a feature needs
more than these three, the feature is wrong rather than the rule.

---

## Protocol and versioning

The wire contract lives in `@nairotech/yeke-tunnel`, published to npm under
Apache-2.0. Its **major version is the wire protocol version**: `4.x` means
protocol v4. That is a deliberate deviation from ordinary semver — a breaking
TypeScript API change that leaves the wire untouched moves the minor, not the
major — and it exists so that a dependency line can be read as a statement about
the wire.

The dependency here is pinned to an **exact version**, not a range:

```json
"@nairotech/yeke-tunnel": "4.0.1"
```

`^4.0.1` would say "any minor of protocol v4", and the day a minor changed a
frame, an agent built from an unchanged commit would start speaking a different
wire than the one this commit was tested against. While the agent lived in the
product monorepo it was compiled from the same checkout as the control plane, so
the two could not disagree — that safety was a property of the build, and
splitting the repository removed it. An exact pin puts it back: the wire becomes
a property of the commit.

`src/boundary.test.ts` enforces this. It fails if the pin is a range, if the
pinned major stops matching `TUNNEL_PROTOCOL_VERSION`, if the installed version
differs from the pin, if any dependency resolves from outside the registry
(`workspace:`, `link:`, `file:`, `portal:`), or if the source imports any product
package other than the contract.

---

## Lockstep with the control plane

**The agent image tag must equal the version of the control plane that manages
it.** This is not a convention, it is how the installation manifest is produced:
the control plane derives the agent image tag from its own version.

If `nairotech/yeke-agent:<version>` does not exist for a control-plane version,
a user who presses the update button pulls the agent towards an image that is not
there. The pod falls into `ImagePullBackOff`, the tunnel never comes back, and
**the cluster becomes unmanageable** — the very connection needed to fix it is
the one that is down.

So a release is two images with the same `$V`: the control plane's, and this one.

```bash
docker buildx build --platform linux/amd64,linux/arm64 \
  --build-arg YEKE_VERSION=$V \
  -t nairotech/yeke-agent:$V --push .
```

`YEKE_VERSION` is the only source of the version the agent reports to the control
plane; without it the agent reports `"unknown"`, which is deliberate — see the
header of `src/tunnel-client.ts` for the failure that produced this rule. The
`version` field in `package.json` is a fixed placeholder and is not a release
number.

---

## Configuration

All configuration is environment variables (`src/config.ts`). The three without
a default are required; the agent refuses to start without them.

| Variable | Default | Meaning |
|---|---|---|
| `YEKE_CORE_URL` | — | WebSocket address of the control plane, e.g. `wss://…/tunnel` |
| `YEKE_CLUSTER_ID` | — | The cluster record this agent belongs to |
| `YEKE_AGENT_TOKEN` | — | Proof of identity to the control plane; sent in a header, never in the URL |
| `YEKE_KUBE_MODE` | `in-cluster` | `in-cluster` for production, `kubeconfig` for local development |
| `YEKE_KUBE_CONTEXT` | current context | Only used in `kubeconfig` mode |
| `YEKE_RECONNECT_MIN_MS` | `1000` | Initial reconnect backoff |
| `YEKE_RECONNECT_MAX_MS` | `30000` | Backoff ceiling |
| `YEKE_KUBELET_INSECURE_TLS` | `false` | Accept kubelet serving certificates the cluster CA cannot verify. Off by default; see below |
| `YEKE_VERSION` | `unknown` | Set at image build time; reported to the control plane |

For kubeconfig mode the agent resolves identity itself and supports `exec`
credential plugins (GKE `gke-gcloud-auth-plugin`, EKS `aws eks get-token`,
`kubelogin`), `tokenFile`, static `token`, client certificates and
`username`/`password`. The removed `auth-provider` forms (`gcp`, `oidc`, `azure`)
are refused loudly at startup rather than dropped silently; the rationale is in
`selectCredentialLoader`.

`YEKE_KUBELET_INSECURE_TLS` concerns the metrics collector only. Each kubelet's
serving certificate is verified against the cluster CA; a node whose certificate
does not verify produces NO data and is reported with the state
`tls-unverified` rather than being quietly skipped or silently downgraded. In
many clusters that verification fails through no fault of yours — kubeadm does
not sign kubelet serving certificates with the cluster CA unless
`serverTLSBootstrap` is enabled, which is why metrics-server ships
`--kubelet-insecure-tls` in most installation guides. Setting this variable to
the exact string `true` accepts that weakness explicitly; the agent announces it
in one line at startup and the control plane shows it on screen. The two
alternatives are to give your kubelets CA-signed serving certificates, or to
leave those nodes without statistics.

---

## Build and run

Requires Node 22+ and pnpm.

```bash
pnpm install
pnpm build                 # tsc → dist/
pnpm start                 # node dist/index.js
pnpm dev                   # tsx watch, for local development
```

Gates — all four must pass before a change is finished:

```bash
pnpm install
pnpm exec tsc --noEmit
pnpm test
docker build -t yeke-agent:dev .
```

`pnpm test` runs the boundary and pin gates (`src/boundary.test.ts`), the
identity-classification tests (`src/kube.test.ts`) and the metrics collector's
own suite (`src/metrics/*.test.ts`). The TLS tests in that suite need `openssl`
on PATH: they generate a throwaway CA and two serving certificates rather than
carrying a private key in a public repository, and when `openssl` is missing
they FAIL with a message saying the claim was not measured, instead of passing
quietly.

There is also a measurement harness for the collector, which is not a gate:

```bash
pnpm exec tsx src/metrics/measure.ts --nodes 50 --pods 30 --minutes 5
```

It forks a process serving 50 fake kubelets and reports the collector's CPU and
memory. Its header says what it does and does not prove.

To try it against a local cluster without a registry:

```bash
docker build -t yeke-agent:dev .
docker save yeke-agent:dev -o /tmp/agent.tar
docker cp /tmp/agent.tar <k3s-container>:/tmp/agent.tar
docker exec <k3s-container> ctr -n k8s.io images import /tmp/agent.tar
```

---

## Conventions

Useful to know before reading the source or opening a pull request.

**Comments explain WHY, not what.** Where a decision had a plausible alternative,
the comment says which one was rejected and why; where something was measured,
the comment carries the measurement. A wrong comment is treated as worse than
missing code — there is a documented case in `src/tunnel-client.ts` where an
incorrect comment kept anyone from looking at a bug for months, and the
correction was left in place rather than quietly deleted.

**A line's language follows its reader.** Everything in this repository is
English: comments, log lines, thrown errors, test names. Log lines and error
messages additionally avoid non-ASCII letters, and that is a measured rule
rather than a stylistic one — an operator greps the ASCII spelling of a word and
never matches its accented form, and `toLowerCase()` is locale-dependent, so the
same log rule would not behave identically in every locale.

**Text that reaches the wire is a code, not a sentence.** The control plane and
its user interface compose the sentence in the reader's own language; the agent
sends `{code, params}`. Foreign text (Node's, a library's, a credential plugin's)
is passed through verbatim in its own labelled field and is never translated.

**Dated measurements refer to history in the product monorepo.** This repository
was split out of it, so some comments cite a measurement from a day when the
agent still lived there. Those measurements are kept: the fact they establish is
still the reason the code looks the way it does. They are not links to anything
you can open, and they are not meant to be.

---

## License

Apache-2.0. See [LICENSE](LICENSE).

Apache-2.0 was chosen over MIT for its explicit patent grant and for alignment
with the Kubernetes ecosystem — the agent's largest dependency,
`@kubernetes/client-node`, is Apache-2.0; `ws` and `undici` are MIT and
compatible.
