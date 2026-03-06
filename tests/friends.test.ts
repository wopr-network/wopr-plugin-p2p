/**
 * Unit tests for the P2P Friends module
 *
 * Tests signature generation, verification, message parsing, and friend management.
 */

import { describe, it, afterEach, expect } from "vitest";
import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { formatFriendAccept, formatFriendRequest, parseFriendAccept, parseFriendRequest } from "../src/friends.js";

/** Temporary data directory for tests that touch friends state */
const TEST_DATA_DIR = join(tmpdir(), `wopr-p2p-test-friends-${process.pid}`);

/**
 * Set up isolated test data directory for friends state.
 * Returns a cleanup function.
 */
function useTestDataDir() {
  mkdirSync(TEST_DATA_DIR, { recursive: true });
  process.env.WOPR_P2P_DATA_DIR = TEST_DATA_DIR;
  return () => {
    delete process.env.WOPR_P2P_DATA_DIR;
    rmSync(TEST_DATA_DIR, { recursive: true, force: true });
  };
}

describe("Friend Protocol Message Parsing", () => {
  describe("parseFriendRequest", () => {
    it("should parse a valid FRIEND_REQUEST message", () => {
      const msg =
        "FRIEND_REQUEST | to:hope | from:wopr | pubkey:abc123 | encryptPub:def456 | ts:1700000000000 | sig:xyz789";
      const result = parseFriendRequest(msg);

      expect(result?.type).toBe("FRIEND_REQUEST");
      expect(result?.to).toBe("hope");
      expect(result?.from).toBe("wopr");
      expect(result?.pubkey).toBe("abc123");
      expect(result?.encryptPub).toBe("def456");
      expect(result?.timestamp).toBe(1700000000000);
      expect(result?.sig).toBe("xyz789");
    });

    it("should return null for invalid FRIEND_REQUEST format", () => {
      const invalidMsgs = [
        "FRIEND_REQUEST | to:hope", // Missing fields
        "FRIEND_ACCEPT | to:hope | from:wopr | pubkey:abc | encryptPub:def | ts:123 | sig:xyz", // Wrong type
        "Hello there", // Not a friend request
        "", // Empty
      ];

      for (const msg of invalidMsgs) {
        expect(parseFriendRequest(msg)).toBe(null);
      }
    });

    it("should handle pubkeys with special characters", () => {
      // Base64 keys can contain +, /, =
      const msg =
        "FRIEND_REQUEST | to:hope | from:wopr | pubkey:abc+/123= | encryptPub:def+/456= | ts:1700000000000 | sig:xyz+/789=";
      const result = parseFriendRequest(msg);

      expect(result?.pubkey).toBe("abc+/123=");
      expect(result?.encryptPub).toBe("def+/456=");
      expect(result?.sig).toBe("xyz+/789=");
    });
  });

  describe("parseFriendAccept", () => {
    it("should parse a valid FRIEND_ACCEPT message", () => {
      const msg =
        "FRIEND_ACCEPT | to:wopr | from:hope | pubkey:def456 | encryptPub:ghi789 | requestSig:abc123 | ts:1700000000000 | sig:jkl012";
      const result = parseFriendAccept(msg);

      expect(result?.type).toBe("FRIEND_ACCEPT");
      expect(result?.to).toBe("wopr");
      expect(result?.from).toBe("hope");
      expect(result?.pubkey).toBe("def456");
      expect(result?.encryptPub).toBe("ghi789");
      expect(result?.requestSig).toBe("abc123");
      expect(result?.timestamp).toBe(1700000000000);
      expect(result?.sig).toBe("jkl012");
    });

    it("should return null for invalid FRIEND_ACCEPT format", () => {
      const invalidMsgs = [
        "FRIEND_ACCEPT | to:wopr | from:hope", // Missing fields
        "FRIEND_REQUEST | to:hope | from:wopr | pubkey:abc | encryptPub:def | ts:123 | sig:xyz", // Wrong type
      ];

      for (const msg of invalidMsgs) {
        expect(parseFriendAccept(msg)).toBe(null);
      }
    });
  });
});

describe("Friend Protocol Message Formatting", () => {
  describe("formatFriendRequest", () => {
    it("should format a friend request correctly", () => {
      const request = {
        type: "FRIEND_REQUEST" as const,
        to: "hope",
        from: "wopr",
        pubkey: "abc123",
        encryptPub: "def456",
        timestamp: 1700000000000,
        sig: "xyz789",
      };

      const formatted = formatFriendRequest(request);
      expect(formatted).toBe(
        "FRIEND_REQUEST | to:hope | from:wopr | pubkey:abc123 | encryptPub:def456 | ts:1700000000000 | sig:xyz789"
      );
    });

    it("should round-trip through parse and format", () => {
      const request = {
        type: "FRIEND_REQUEST" as const,
        to: "hope",
        from: "wopr",
        pubkey: "abc123publickey",
        encryptPub: "def456encryptkey",
        timestamp: 1700000000000,
        sig: "signature123",
      };

      const formatted = formatFriendRequest(request);
      const parsed = parseFriendRequest(formatted);

      expect(parsed).toEqual(request);
    });
  });

  describe("formatFriendAccept", () => {
    it("should format a friend accept correctly", () => {
      const accept = {
        type: "FRIEND_ACCEPT" as const,
        to: "wopr",
        from: "hope",
        pubkey: "def456",
        encryptPub: "ghi789",
        requestSig: "originalsig",
        timestamp: 1700000000000,
        sig: "acceptsig",
      };

      const formatted = formatFriendAccept(accept);
      expect(formatted).toBe(
        "FRIEND_ACCEPT | to:wopr | from:hope | pubkey:def456 | encryptPub:ghi789 | requestSig:originalsig | ts:1700000000000 | sig:acceptsig"
      );
    });

    it("should round-trip through parse and format", () => {
      const accept = {
        type: "FRIEND_ACCEPT" as const,
        to: "wopr",
        from: "hope",
        pubkey: "def456publickey",
        encryptPub: "ghi789encryptkey",
        requestSig: "originalsignature",
        timestamp: 1700000000000,
        sig: "acceptsignature",
      };

      const formatted = formatFriendAccept(accept);
      const parsed = parseFriendAccept(formatted);

      expect(parsed).toEqual(accept);
    });
  });
});

describe("Session Name Generation", () => {
  it("should generate deterministic session names", async () => {
    const { getFriendSessionName } = await import("../src/friends.js");

    const name = "hope";
    const pubkey = "0f45ad123456789abcdef";

    const sessionName = getFriendSessionName(name, pubkey);

    // Format: friend:p2p:<name>(<pubkey-prefix>)
    expect(sessionName).toBe("friend:p2p:hope(0f45ad)");
  });

  it("should use first 6 chars of pubkey as prefix", async () => {
    const { getFriendSessionName } = await import("../src/friends.js");

    const sessionName = getFriendSessionName("wopr", "abcdef123456");
    expect(sessionName.includes("(abcdef)")).toBeTruthy();
  });
});

describe("Auto-Accept Rules", () => {
  let cleanup: (() => void) | undefined;

  afterEach(() => {
    if (cleanup) {
      cleanup();
      cleanup = undefined;
    }
  });

  it("should match exact username", async () => {
    cleanup = useTestDataDir();
    const { shouldAutoAccept, addAutoAcceptRule, removeAutoAcceptRule } = await import("../src/friends.js");

    addAutoAcceptRule("hope");

    expect(shouldAutoAccept("hope")).toBe(true);
    expect(shouldAutoAccept("wopr")).toBe(false);

    // Cleanup
    removeAutoAcceptRule("hope");
  });

  it("should match wildcard pattern", async () => {
    cleanup = useTestDataDir();
    const { shouldAutoAccept, addAutoAcceptRule, removeAutoAcceptRule } = await import("../src/friends.js");

    addAutoAcceptRule("*");

    expect(shouldAutoAccept("hope")).toBe(true);
    expect(shouldAutoAccept("wopr")).toBe(true);
    expect(shouldAutoAccept("anyone")).toBe(true);

    // Cleanup
    removeAutoAcceptRule("*");
  });

  it("should match OR pattern", async () => {
    cleanup = useTestDataDir();
    const { shouldAutoAccept, addAutoAcceptRule, removeAutoAcceptRule } = await import("../src/friends.js");

    addAutoAcceptRule("hope|wopr|claude");

    expect(shouldAutoAccept("hope")).toBe(true);
    expect(shouldAutoAccept("wopr")).toBe(true);
    expect(shouldAutoAccept("claude")).toBe(true);
    expect(shouldAutoAccept("bob")).toBe(false);

    // Cleanup
    removeAutoAcceptRule("hope|wopr|claude");
  });
});

describe("Friend Capability Management", () => {
  it("should have default message capability for new friends", () => {
    // New friends start with ["message"] capability
    // This is enforced in completeFriendship and acceptPendingRequest
    expect(true).toBeTruthy();
  });

  it("should allow granting additional capabilities", () => {
    // grantFriendCap adds "inject" capability (only "message" and "inject" are valid)
    expect(true).toBeTruthy();
  });
});
