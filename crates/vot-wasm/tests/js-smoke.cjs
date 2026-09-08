"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");

const bindings = require(path.resolve(process.argv[2]));

assert.equal(typeof bindings.verifyRange, "function");
assert.equal(bindings.verify_range, undefined);

const data = Uint8Array.from([0x61, 0x62, 0x63]);
const builder = new bindings.ObjectBuilder(
  bindings.Suite.Sha256Bep52,
  3n,
  3n,
);
builder.update(data);
const prepared = builder.finish();
assert.equal(prepared.objectId.length, 3n);
assert.ok(prepared.objectId.root instanceof Uint8Array);

const proof = prepared.prove(0n, 3n);
assert.equal(proof.coveredOffset, 0n);
assert.equal(proof.coveredLength, 3n);
const verified = bindings.verifyRange(
  prepared.objectId,
  0n,
  data,
  proof.bytes(),
);
assert.deepEqual(verified.bytes(), data);

const directPath = new bindings.PackagePath();
directPath.push("file.bin");
const direct = bindings.PackageEntry.direct(directPath, prepared.objectId);
assert.equal(direct.packObjectId, undefined);

const packageBuilder = new bindings.PackageBuilder();
assert.equal(packageBuilder.push(direct), undefined);
const assembly = packageBuilder.finish();
const draft = assembly.takeFinalPage();
const finalizer = assembly.takeFinalizer();
assert.ok(finalizer.push(draft).bytes() instanceof Uint8Array);
assert.ok(finalizer.finish().bytes() instanceof Uint8Array);

const invalidPath = new bindings.PackagePath();
assert.throws(
  () => invalidPath.push("x".repeat(256)),
  (error) => error.code === bindings.ErrorCode.LimitExceeded,
);
assert.equal(invalidPath.length, 0);

// Parallel preparation: leaves hashed per segment join into the same object
// the sequential builder names.
assert.equal(typeof bindings.proofLeavesAt, "function");
assert.equal(bindings.proofLeafSize(), 65536n);
const leaf = Number(bindings.proofLeafSize());
const long = new Uint8Array(leaf * 2 + 5).map((_, i) => i % 251);
const sequential = new bindings.ObjectBuilder(bindings.Suite.Blake3Bao64, BigInt(long.length), BigInt(long.length));
sequential.update(long);
const sequentialId = sequential.finish().objectId;
const head = bindings.proofLeavesAt(bindings.Suite.Blake3Bao64, 0n, long.subarray(0, leaf), BigInt(long.length));
const tail = bindings.proofLeavesAt(bindings.Suite.Blake3Bao64, BigInt(leaf), long.subarray(leaf), BigInt(long.length));
assert.ok(head instanceof Uint8Array);
assert.equal(head.length, 32);
assert.equal(tail.length, 64);
const joined = new Uint8Array(head.length + tail.length);
joined.set(head, 0);
joined.set(tail, head.length);
const assembled = bindings.PreparedObject.fromProofLeaves(bindings.Suite.Blake3Bao64, BigInt(long.length), joined, BigInt(long.length));
assert.deepEqual(assembled.objectId.root, sequentialId.root);
assert.equal(assembled.objectId.length, sequentialId.length);
assert.throws(
  () => bindings.proofLeavesAt(bindings.Suite.Blake3Bao64, 0n, long.subarray(0, leaf - 1), BigInt(long.length)),
  (error) => error.code === bindings.ErrorCode.InvalidInput,
);
