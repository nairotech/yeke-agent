/**
 * The owner chain and the node decoder.
 *
 * The chain is what turns 12 000 pod series into the twenty workload series an
 * operator actually looks at. Its two interesting properties are what it does
 * when the index is INCOMPLETE (stop at the last known link, never guess the
 * next) and what it does when the graph is hostile (a cycle in owner references
 * is a hang, in someone else's cluster).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { type MetaRecord, decodeMeta, decodeNode, parseQuantity, resolveOwner } from "./owners.js";

function record(
  uid: string,
  kind: string,
  name: string,
  owner?: { kind: string; name: string; uid: string },
): MetaRecord {
  return {
    uid,
    kind,
    name,
    namespace: "ornek",
    owners: owner ? [{ ...owner, controller: true }] : [],
  };
}

function indexOf(...records: MetaRecord[]): Map<string, MetaRecord> {
  return new Map(records.map((item) => [item.uid, item]));
}

test("Pod -> ReplicaSet -> Deployment", () => {
  const deployment = { kind: "Deployment", name: "web", uid: "d-1" };
  const replicaSet = record("rs-1", "ReplicaSet", "web-5f9c", deployment);
  const pod = record("p-1", "Pod", "web-5f9c-abcde", {
    kind: "ReplicaSet",
    name: "web-5f9c",
    uid: "rs-1",
  });

  assert.deepEqual(resolveOwner(indexOf(replicaSet, pod), pod), {
    kind: "Deployment",
    name: "web",
    uid: "d-1",
  });
});

test("Pod -> Job -> CronJob, once a Job record is in the index", () => {
  // Phase 1 does not WATCH jobs (the ClusterRole in the identity decision grants
  // pods and replicasets only), so this shape is exercised with the record fed
  // in by hand. The walker is written against the index rather than against a
  // list of kinds, which is what makes adding `batch/jobs` later a registration
  // and not a rewrite.
  const cronJob = { kind: "CronJob", name: "yedek", uid: "cj-1" };
  const job = record("j-1", "Job", "yedek-28001", cronJob);
  const pod = record("p-2", "Pod", "yedek-28001-xyz", {
    kind: "Job",
    name: "yedek-28001",
    uid: "j-1",
  });

  assert.deepEqual(resolveOwner(indexOf(job, pod), pod), {
    kind: "CronJob",
    name: "yedek",
    uid: "cj-1",
  });
});

test("without the middle record the walk stops at the link it knows", () => {
  const pod = record("p-3", "Pod", "yedek-28001-xyz", {
    kind: "Job",
    name: "yedek-28001",
    uid: "j-1",
  });
  // The truthful answer is "this pod belongs to that Job", not a CronJob name
  // reconstructed from a naming convention.
  assert.deepEqual(resolveOwner(indexOf(pod), pod), {
    kind: "Job",
    name: "yedek-28001",
    uid: "j-1",
  });
});

test("a pod with no owner has no workload", () => {
  const pod = record("p-4", "Pod", "elle-acilmis");
  assert.equal(resolveOwner(indexOf(pod), pod), undefined);
});

test("the controller reference wins over a decorative one", () => {
  const pod: MetaRecord = {
    uid: "p-5",
    kind: "Pod",
    name: "web-0",
    namespace: "ornek",
    owners: [
      { kind: "ArgoCDApplication", name: "gozetmen", uid: "x-1", controller: false },
      { kind: "StatefulSet", name: "web", uid: "ss-1", controller: true },
    ],
  };
  assert.equal(resolveOwner(indexOf(pod), pod)?.kind, "StatefulSet");
});

test("a cycle in owner references terminates", () => {
  const a = record("a", "Kind", "a", { kind: "Kind", name: "b", uid: "b" });
  const b = record("b", "Kind", "b", { kind: "Kind", name: "a", uid: "a" });
  // Hand-written owner references can point in a circle. An unbounded walk here
  // is a hang inside a customer's cluster, not a bug report.
  const owner = resolveOwner(indexOf(a, b), a);
  assert.ok(owner !== undefined);
});

test("PartialObjectMetadata's own kind does not become the record's kind", () => {
  const decoded = decodeMeta(
    {
      kind: "PartialObjectMetadata",
      metadata: {
        uid: "u-1",
        name: "web-0",
        namespace: "ornek",
        ownerReferences: [{ kind: "ReplicaSet", name: "web-5f9c", uid: "rs-1", controller: true }],
      },
    },
    "Pod",
  );
  assert.equal(decoded?.kind, "Pod");
  assert.equal(decoded?.owners[0]?.kind, "ReplicaSet");
});

test("an owner reference missing a uid is dropped, not half-kept", () => {
  const decoded = decodeMeta(
    { metadata: { uid: "u-2", name: "x", ownerReferences: [{ kind: "ReplicaSet", name: "y" }] } },
    "Pod",
  );
  assert.deepEqual(decoded?.owners, []);
});

test("quantities: cores, milli-cores, binary and decimal SI", () => {
  assert.equal(parseQuantity("4"), 4);
  assert.equal(parseQuantity("3900m"), 3.9);
  assert.equal(parseQuantity("16Gi"), 16 * 1024 ** 3);
  assert.equal(parseQuantity("16G"), 16e9);
  assert.equal(parseQuantity("110"), 110);
  // An unknown suffix is refused rather than read as a bare number: a
  // denominator wrong by a factor of 1024 draws a utilisation chart that looks
  // entirely plausible.
  assert.equal(parseQuantity("16Xi"), undefined);
  assert.equal(parseQuantity(undefined), undefined);
});

test("the node decoder takes the InternalIP and the allocatable block", () => {
  const node = decodeNode({
    metadata: { name: "node-a", uid: "n-1" },
    status: {
      addresses: [
        { type: "Hostname", address: "node-a.internal" },
        { type: "InternalIP", address: "10.0.0.7" },
        { type: "ExternalIP", address: "203.0.113.9" },
      ],
      allocatable: { cpu: "3900m", memory: "16256000Ki", "ephemeral-storage": "50Gi", pods: "110" },
      capacity: { cpu: "4", memory: "16384000Ki" },
      conditions: [
        { type: "MemoryPressure", status: "False" },
        { type: "Ready", status: "True" },
      ],
      nodeInfo: { kubeletVersion: "v1.33.2" },
    },
  });

  // Not the hostname and not the external address: the agent dials this from
  // inside the cluster network.
  assert.equal(node?.address, "10.0.0.7");
  assert.equal(node?.ready, true);
  assert.equal(node?.kubeletVersion, "v1.33.2");
  assert.equal(node?.attributes["cpu.allocatable"], 3.9);
  assert.equal(node?.attributes["mem.allocatable"], 16_256_000 * 1024);
  assert.equal(node?.attributes["pods.allocatable"], 110);
  assert.equal(node?.attributes["cpu.capacity"], 4);
});

test("the kubelet port is read from the node, not assumed", () => {
  const moved = decodeNode({
    metadata: { name: "node-c" },
    status: {
      addresses: [{ type: "InternalIP", address: "10.0.0.9" }],
      daemonEndpoints: { kubeletEndpoint: { Port: 10260 } },
    },
  });
  // `--port` is a kubelet flag and the node object publishes the answer. A
  // cluster that moved it would otherwise show every node as unreachable with
  // no clue as to why. (The capital P is the API's.)
  assert.equal(moved?.port, 10260);

  const usual = decodeNode({
    metadata: { name: "node-d" },
    status: { addresses: [{ type: "InternalIP", address: "10.0.0.10" }] },
  });
  assert.equal(usual?.port, undefined, "an absent field must fall back to the client default");
});

test("a node with no InternalIP decodes without an address", () => {
  const node = decodeNode({
    metadata: { name: "node-b" },
    status: { addresses: [{ type: "Hostname", address: "node-b" }], conditions: [] },
  });
  assert.equal(node?.address, undefined);
  assert.equal(node?.ready, false);
});
