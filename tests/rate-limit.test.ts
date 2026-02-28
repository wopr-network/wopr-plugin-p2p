/**
 * Unit tests for the P2P Rate Limiting and Replay Protection module
 *
 * Tests rate limiting (per-minute/hour thresholds, banning, reset)
 * and replay protection (nonce deduplication, timestamp window).
 */

import { describe, it, beforeEach, expect } from "vitest";

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
      expect(limiter.check("test-peer", "injects")).toBe(true);
    });

    it("should allow requests under the per-minute limit", () => {
      // Default injects limit: 10 per minute
      for (let i = 0; i < 9; i++) {
        expect(limiter.check("test-peer", "injects")).toBe(true);
      }
    });

    it("should ban when per-minute limit is exceeded", () => {
      // Default injects limit: 10 per minute
      for (let i = 0; i < 10; i++) {
        limiter.check("test-peer", "injects");
      }

      // 11th request should be denied (triggers ban at 10)
      expect(limiter.check("test-peer", "injects")).toBe(false);
    });

    it("should deny requests while banned", () => {
      // Exceed limit to trigger ban
      for (let i = 0; i < 10; i++) {
        limiter.check("test-peer", "injects");
      }

      // All subsequent requests should be denied
      expect(limiter.check("test-peer", "injects")).toBe(false);
      expect(limiter.check("test-peer", "injects")).toBe(false);
    });

    it("should track different actions independently", () => {
      // Fill up injects
      for (let i = 0; i < 10; i++) {
        limiter.check("test-peer", "injects");
      }

      // injects is now banned, but claims should still work
      expect(limiter.check("test-peer", "injects")).toBe(false);
      expect(limiter.check("test-peer", "claims")).toBe(true);
    });

    it("should track different peers independently", () => {
      limiter.reset("peer-b");

      // Fill up peer-a
      for (let i = 0; i < 10; i++) {
        limiter.check("test-peer", "injects");
      }

      // peer-a is banned, peer-b should still work
      expect(limiter.check("test-peer", "injects")).toBe(false);
      expect(limiter.check("peer-b", "injects")).toBe(true);

      limiter.reset("peer-b");
    });

    it("should use stricter limits for invalidMessages", () => {
      // invalidMessages: maxPerMinute is 3
      for (let i = 0; i < 3; i++) {
        limiter.check("test-peer", "invalidMessages");
      }

      expect(limiter.check("test-peer", "invalidMessages")).toBe(false);
    });

    it("should use stricter limits for claims", () => {
      // claims: maxPerMinute is 5
      for (let i = 0; i < 5; i++) {
        limiter.check("test-peer", "claims");
      }

      expect(limiter.check("test-peer", "claims")).toBe(false);
    });

    it("should fall back to injects config for unknown action", () => {
      // Unknown action should use injects defaults (10 per minute)
      for (let i = 0; i < 10; i++) {
        expect(limiter.check("test-peer", "unknown-action")).toBe(true);
      }
      expect(limiter.check("test-peer", "unknown-action")).toBe(false);
    });
  });

  describe("reset", () => {
    it("should clear all rate limit state for a peer", () => {
      // Exceed limit
      for (let i = 0; i < 10; i++) {
        limiter.check("test-peer", "injects");
      }
      expect(limiter.check("test-peer", "injects")).toBe(false);

      // Reset
      limiter.reset("test-peer");

      // Should be allowed again
      expect(limiter.check("test-peer", "injects")).toBe(true);
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

      expect(limiter.check("peer-a", "injects")).toBe(true);
      expect(limiter.check("peer-b", "injects")).toBe(false);

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
      expect(protector.check("nonce-1", Date.now())).toBe(true);
    });

    it("should reject a duplicate nonce", () => {
      expect(protector.check("same-nonce", Date.now())).toBe(true);
      expect(protector.check("same-nonce", Date.now())).toBe(false);
    });

    it("should accept different nonces", () => {
      expect(protector.check("nonce-a", Date.now())).toBe(true);
      expect(protector.check("nonce-b", Date.now())).toBe(true);
      expect(protector.check("nonce-c", Date.now())).toBe(true);
    });

    it("should reject timestamps too far in the past (>5 minutes)", () => {
      const fiveMinutesAgo = Date.now() - 5 * 60 * 1000 - 1;
      expect(protector.check("old-nonce", fiveMinutesAgo)).toBe(false);
    });

    it("should reject timestamps too far in the future (>5 minutes)", () => {
      const fiveMinutesFromNow = Date.now() + 5 * 60 * 1000 + 1;
      expect(protector.check("future-nonce", fiveMinutesFromNow)).toBe(false);
    });

    it("should accept timestamps at the edge of the window", () => {
      // Just barely within 5 minutes
      const nearEdge = Date.now() - 4 * 60 * 1000;
      expect(protector.check("edge-nonce", nearEdge)).toBe(true);
    });
  });

  describe("reset", () => {
    it("should clear all replay state", () => {
      protector.check("nonce-1", Date.now());
      protector.check("nonce-2", Date.now());

      protector.reset();

      // Previously seen nonces should now be accepted
      expect(protector.check("nonce-1", Date.now())).toBe(true);
      expect(protector.check("nonce-2", Date.now())).toBe(true);
    });
  });
});
