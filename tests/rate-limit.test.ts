/**
 * Unit tests for the P2P Rate Limiting and Replay Protection module
 *
 * Tests rate limiting (per-minute/hour thresholds, banning, reset)
 * and replay protection (nonce deduplication, timestamp window).
 */

import { describe, it, beforeEach } from "node:test";
import assert from "node:assert";

import { getRateLimiter, getReplayProtector } from "../src/rate-limit.js";

describe("Rate Limiter", () => {
  let limiter: ReturnType<typeof getRateLimiter>;

  beforeEach(() => {
    limiter = getRateLimiter();
    // Reset state for the test peer between tests
    limiter.reset("test-peer");
  });

  describe("check", () => {
    it("should allow first request", () => {
      assert.strictEqual(limiter.check("test-peer", "injects"), true);
    });

    it("should allow requests under the per-minute limit", () => {
      // Default injects limit: 10 per minute
      for (let i = 0; i < 9; i++) {
        assert.strictEqual(limiter.check("test-peer", "injects"), true, `Request ${i + 1} should pass`);
      }
    });

    it("should ban when per-minute limit is exceeded", () => {
      // Default injects limit: 10 per minute
      for (let i = 0; i < 10; i++) {
        limiter.check("test-peer", "injects");
      }

      // 11th request should be denied (triggers ban at 10)
      assert.strictEqual(limiter.check("test-peer", "injects"), false);
    });

    it("should deny requests while banned", () => {
      // Exceed limit to trigger ban
      for (let i = 0; i < 10; i++) {
        limiter.check("test-peer", "injects");
      }

      // All subsequent requests should be denied
      assert.strictEqual(limiter.check("test-peer", "injects"), false);
      assert.strictEqual(limiter.check("test-peer", "injects"), false);
    });

    it("should track different actions independently", () => {
      // Fill up injects
      for (let i = 0; i < 10; i++) {
        limiter.check("test-peer", "injects");
      }

      // injects is now banned, but claims should still work
      assert.strictEqual(limiter.check("test-peer", "injects"), false);
      assert.strictEqual(limiter.check("test-peer", "claims"), true);
    });

    it("should track different peers independently", () => {
      limiter.reset("peer-b");

      // Fill up peer-a
      for (let i = 0; i < 10; i++) {
        limiter.check("test-peer", "injects");
      }

      // peer-a is banned, peer-b should still work
      assert.strictEqual(limiter.check("test-peer", "injects"), false);
      assert.strictEqual(limiter.check("peer-b", "injects"), true);

      limiter.reset("peer-b");
    });

    it("should use stricter limits for invalidMessages", () => {
      // invalidMessages: maxPerMinute is 3
      for (let i = 0; i < 3; i++) {
        limiter.check("test-peer", "invalidMessages");
      }

      assert.strictEqual(limiter.check("test-peer", "invalidMessages"), false);
    });

    it("should use stricter limits for claims", () => {
      // claims: maxPerMinute is 5
      for (let i = 0; i < 5; i++) {
        limiter.check("test-peer", "claims");
      }

      assert.strictEqual(limiter.check("test-peer", "claims"), false);
    });

    it("should fall back to injects config for unknown action", () => {
      // Unknown action should use injects defaults (10 per minute)
      for (let i = 0; i < 10; i++) {
        assert.strictEqual(limiter.check("test-peer", "unknown-action"), true, `Request ${i + 1} should pass`);
      }
      assert.strictEqual(limiter.check("test-peer", "unknown-action"), false);
    });
  });

  describe("reset", () => {
    it("should clear all rate limit state for a peer", () => {
      // Exceed limit
      for (let i = 0; i < 10; i++) {
        limiter.check("test-peer", "injects");
      }
      assert.strictEqual(limiter.check("test-peer", "injects"), false);

      // Reset
      limiter.reset("test-peer");

      // Should be allowed again
      assert.strictEqual(limiter.check("test-peer", "injects"), true);
    });

    it("should only reset the specified peer", () => {
      limiter.reset("peer-a");
      limiter.reset("peer-b");

      // Exceed limit for both
      for (let i = 0; i < 10; i++) {
        limiter.check("peer-a", "injects");
        limiter.check("peer-b", "injects");
      }

      // Reset only peer-a
      limiter.reset("peer-a");

      assert.strictEqual(limiter.check("peer-a", "injects"), true);
      assert.strictEqual(limiter.check("peer-b", "injects"), false);

      limiter.reset("peer-b");
    });
  });
});

describe("Replay Protector", () => {
  let protector: ReturnType<typeof getReplayProtector>;

  beforeEach(() => {
    protector = getReplayProtector();
    protector.reset();
  });

  describe("check", () => {
    it("should accept a valid nonce with current timestamp", () => {
      assert.strictEqual(protector.check("nonce-1", Date.now()), true);
    });

    it("should reject a duplicate nonce", () => {
      assert.strictEqual(protector.check("same-nonce", Date.now()), true);
      assert.strictEqual(protector.check("same-nonce", Date.now()), false);
    });

    it("should accept different nonces", () => {
      assert.strictEqual(protector.check("nonce-a", Date.now()), true);
      assert.strictEqual(protector.check("nonce-b", Date.now()), true);
      assert.strictEqual(protector.check("nonce-c", Date.now()), true);
    });

    it("should reject timestamps too far in the past (>5 minutes)", () => {
      const fiveMinutesAgo = Date.now() - 5 * 60 * 1000 - 1;
      assert.strictEqual(protector.check("old-nonce", fiveMinutesAgo), false);
    });

    it("should reject timestamps too far in the future (>5 minutes)", () => {
      const fiveMinutesFromNow = Date.now() + 5 * 60 * 1000 + 1;
      assert.strictEqual(protector.check("future-nonce", fiveMinutesFromNow), false);
    });

    it("should accept timestamps at the edge of the window", () => {
      // Just barely within 5 minutes
      const nearEdge = Date.now() - 4 * 60 * 1000;
      assert.strictEqual(protector.check("edge-nonce", nearEdge), true);
    });
  });

  describe("reset", () => {
    it("should clear all replay state", () => {
      protector.check("nonce-1", Date.now());
      protector.check("nonce-2", Date.now());

      protector.reset();

      // Previously seen nonces should now be accepted
      assert.strictEqual(protector.check("nonce-1", Date.now()), true);
      assert.strictEqual(protector.check("nonce-2", Date.now()), true);
    });
  });
});
