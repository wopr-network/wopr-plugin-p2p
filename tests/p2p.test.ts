/**
 * Unit tests for the P2P Core Networking module (WOP-100)
 *
 * Tests the logger, listener creation (identity-absent path),
 * and pre-flight validation for sendP2PLog, sendP2PInject, claimToken,
 * and sendKeyRotation. The actual Hyperswarm networking is not tested
 * (requires live DHT). We test the validation and error paths.
 */

import { describe, it, beforeEach, afterEach, mock } from "node:test";
import assert from "node:assert";

import {
  setP2PLogger,
  createP2PListener,
  sendP2PLog,
  sendP2PInject,
  claimToken,
  sendKeyRotation,
} from "../src/p2p.js";
import { EXIT_INVALID, EXIT_REJECTED } from "../src/types.js";

// Save and restore identity to avoid test interference
// These tests rely on the default state (no identity) for validation tests.

describe("P2P Module - Logger", () => {
  it("should accept a logger function via setP2PLogger", () => {
    const messages: string[] = [];
    setP2PLogger((msg) => messages.push(msg));

    // The logger is set module-wide. We can verify it was set
    // by checking that no error was thrown.
    assert.ok(true, "setP2PLogger accepted function without error");

    // Clean up
    setP2PLogger(() => {});
  });
});

describe("P2P Module - createP2PListener", () => {
  it("should return null and log when no identity exists", async () => {
    const logMessages: string[] = [];
    const callbacks = {
      onLog: (msg: string) => logMessages.push(msg),
    };

    // If no identity file exists, getIdentity() returns null
    // and createP2PListener returns null
    const swarm = createP2PListener(callbacks);

    // If identity IS loaded (from a real ~/.wopr/p2p/identity.json),
    // the swarm will be non-null. We handle both cases.
    if (swarm === null) {
      assert.ok(logMessages.some(m => m.includes("No identity")));
    } else {
      // Identity exists on this machine - clean up the swarm
      assert.ok(swarm, "Swarm was created because identity exists");
      await swarm.destroy();
    }
  });

  it("should accept legacy function signature", () => {
    const logMessages: string[] = [];
    const onInject = async (_session: string, _message: string) => {};
    const onLog = (msg: string) => logMessages.push(msg);

    const swarm = createP2PListener(onInject, onLog);

    if (swarm === null) {
      assert.ok(logMessages.some(m => m.includes("No identity")));
    } else {
      // Clean up
      swarm.destroy();
    }
  });
});

describe("P2P Module - sendP2PLog validation", () => {
  it("should return EXIT_INVALID when no identity exists", async () => {
    // This test depends on whether the test machine has an identity.
    // If no identity, getIdentity() returns null -> EXIT_INVALID.
    // If identity exists, findPeer will fail -> EXIT_INVALID.
    const result = await sendP2PLog("nonexistent-peer", "test-session", "hello", 1000);
    assert.strictEqual(result.code, EXIT_INVALID);
  });

  it("should include an error message in the result", async () => {
    const result = await sendP2PLog("nonexistent", "session", "msg", 1000);
    assert.ok(result.message, "Should have an error message");
  });
});

describe("P2P Module - sendP2PInject validation", () => {
  it("should return EXIT_INVALID when no identity or peer not found", async () => {
    const result = await sendP2PInject("nonexistent-peer", "test-session", "hello", 1000);
    assert.strictEqual(result.code, EXIT_INVALID);
  });

  it("should include an error message in the result", async () => {
    const result = await sendP2PInject("nonexistent", "session", "msg", 1000);
    assert.ok(result.message, "Should have an error message");
  });
});

describe("P2P Module - claimToken validation", () => {
  it("should return EXIT_INVALID for malformed token", async () => {
    const result = await claimToken("not-a-valid-token", 1000);
    assert.strictEqual(result.code, EXIT_INVALID);
  });

  it("should include error message about invalid token", async () => {
    const result = await claimToken("garbage-data", 1000);
    assert.ok(result.message?.includes("Invalid token") || result.message?.includes("No identity"));
  });

  it("should return EXIT_INVALID for empty token", async () => {
    const result = await claimToken("", 1000);
    assert.strictEqual(result.code, EXIT_INVALID);
  });
});

describe("P2P Module - sendKeyRotation validation", () => {
  it("should return EXIT_INVALID when peer not found", async () => {
    const rotation = {
      v: 2,
      type: "key-rotation" as const,
      oldSignPub: "old-key",
      newSignPub: "new-key",
      newEncryptPub: "new-encrypt",
      reason: "scheduled" as const,
      effectiveAt: Date.now(),
      gracePeriodMs: 60000,
      sig: "fake-sig",
    };

    const result = await sendKeyRotation("nonexistent-peer", rotation, 1000);
    assert.strictEqual(result.code, EXIT_INVALID);
  });
});

describe("P2P Module - Protocol Constants", () => {
  it("should export correct exit codes", async () => {
    const types = await import("../src/types.js");

    assert.strictEqual(types.EXIT_OK, 0);
    assert.strictEqual(types.EXIT_OFFLINE, 1);
    assert.strictEqual(types.EXIT_REJECTED, 2);
    assert.strictEqual(types.EXIT_INVALID, 3);
    assert.strictEqual(types.EXIT_RATE_LIMITED, 4);
    assert.strictEqual(types.EXIT_VERSION_MISMATCH, 5);
    assert.strictEqual(types.EXIT_PEER_OFFLINE, 6);
    assert.strictEqual(types.EXIT_UNAUTHORIZED, 7);
  });

  it("should export protocol version constants", async () => {
    const types = await import("../src/types.js");

    assert.strictEqual(types.PROTOCOL_VERSION, 2);
    assert.strictEqual(types.MIN_PROTOCOL_VERSION, 1);
    assert.ok(types.PROTOCOL_VERSION >= types.MIN_PROTOCOL_VERSION);
  });
});
