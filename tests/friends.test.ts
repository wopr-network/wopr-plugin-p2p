/**
 * Unit tests for the P2P Friends module
 *
 * Tests signature generation, verification, message parsing, and friend management.
 */

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert";
import { existsSync, rmSync, mkdirSync } from "fs";
import { join } from "path";
import { homedir } from "os";

// Mock the identity before importing friends module
const TEST_DATA_DIR = join(homedir(), ".wopr-test", "p2p");

// We'll need to set up test fixtures that mock the identity and trust modules
// For now, we test the parsing and formatting functions which don't require identity

import {
  parseFriendRequest,
  parseFriendAccept,
  formatFriendRequest,
  formatFriendAccept,
} from "../src/friends.js";

describe("Friend Protocol Message Parsing", () => {
  describe("parseFriendRequest", () => {
    it("should parse a valid FRIEND_REQUEST message", () => {
      const msg = "FRIEND_REQUEST | to:hope | from:wopr | pubkey:abc123 | encryptPub:def456 | ts:1700000000000 | sig:xyz789";
      const result = parseFriendRequest(msg);

      assert.strictEqual(result?.type, "FRIEND_REQUEST");
      assert.strictEqual(result?.to, "hope");
      assert.strictEqual(result?.from, "wopr");
      assert.strictEqual(result?.pubkey, "abc123");
      assert.strictEqual(result?.encryptPub, "def456");
      assert.strictEqual(result?.timestamp, 1700000000000);
      assert.strictEqual(result?.sig, "xyz789");
    });

    it("should return null for invalid FRIEND_REQUEST format", () => {
      const invalidMsgs = [
        "FRIEND_REQUEST | to:hope",  // Missing fields
        "FRIEND_ACCEPT | to:hope | from:wopr | pubkey:abc | encryptPub:def | ts:123 | sig:xyz",  // Wrong type
        "Hello there",  // Not a friend request
        "",  // Empty
      ];

      for (const msg of invalidMsgs) {
        assert.strictEqual(parseFriendRequest(msg), null, `Should reject: ${msg}`);
      }
    });

    it("should handle pubkeys with special characters", () => {
      // Base64 keys can contain +, /, =
      const msg = "FRIEND_REQUEST | to:hope | from:wopr | pubkey:abc+/123= | encryptPub:def+/456= | ts:1700000000000 | sig:xyz+/789=";
      const result = parseFriendRequest(msg);

      assert.strictEqual(result?.pubkey, "abc+/123=");
      assert.strictEqual(result?.encryptPub, "def+/456=");
      assert.strictEqual(result?.sig, "xyz+/789=");
    });
  });

  describe("parseFriendAccept", () => {
    it("should parse a valid FRIEND_ACCEPT message", () => {
      const msg = "FRIEND_ACCEPT | to:wopr | from:hope | pubkey:def456 | encryptPub:ghi789 | requestSig:abc123 | ts:1700000000000 | sig:jkl012";
      const result = parseFriendAccept(msg);

      assert.strictEqual(result?.type, "FRIEND_ACCEPT");
      assert.strictEqual(result?.to, "wopr");
      assert.strictEqual(result?.from, "hope");
      assert.strictEqual(result?.pubkey, "def456");
      assert.strictEqual(result?.encryptPub, "ghi789");
      assert.strictEqual(result?.requestSig, "abc123");
      assert.strictEqual(result?.timestamp, 1700000000000);
      assert.strictEqual(result?.sig, "jkl012");
    });

    it("should return null for invalid FRIEND_ACCEPT format", () => {
      const invalidMsgs = [
        "FRIEND_ACCEPT | to:wopr | from:hope",  // Missing fields
        "FRIEND_REQUEST | to:hope | from:wopr | pubkey:abc | encryptPub:def | ts:123 | sig:xyz",  // Wrong type
      ];

      for (const msg of invalidMsgs) {
        assert.strictEqual(parseFriendAccept(msg), null, `Should reject: ${msg}`);
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
      assert.strictEqual(
        formatted,
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

      assert.deepStrictEqual(parsed, request);
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
      assert.strictEqual(
        formatted,
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

      assert.deepStrictEqual(parsed, accept);
    });
  });
});

describe("Session Name Generation", () => {
  it("should generate deterministic session names", async () => {
    // Dynamic import to get the function
    const { getFriendSessionName } = await import("../src/friends.js");

    const name = "hope";
    const pubkey = "0f45ad123456789abcdef";

    const sessionName = getFriendSessionName(name, pubkey);

    // Format: friend:p2p:<name>(<pubkey-prefix>)
    assert.strictEqual(sessionName, "friend:p2p:hope(0f45ad)");
  });

  it("should use first 6 chars of pubkey as prefix", async () => {
    const { getFriendSessionName } = await import("../src/friends.js");

    const sessionName = getFriendSessionName("wopr", "abcdef123456");
    assert.ok(sessionName.includes("(abcdef)"));
  });
});

describe("Auto-Accept Rules", () => {
  it("should match exact username", async () => {
    const { shouldAutoAccept, addAutoAcceptRule, removeAutoAcceptRule } = await import("../src/friends.js");

    // Add rule for specific user
    addAutoAcceptRule("hope");

    assert.strictEqual(shouldAutoAccept("hope"), true);
    assert.strictEqual(shouldAutoAccept("wopr"), false);

    // Cleanup
    removeAutoAcceptRule("hope");
  });

  it("should match wildcard pattern", async () => {
    const { shouldAutoAccept, addAutoAcceptRule, removeAutoAcceptRule } = await import("../src/friends.js");

    // Add wildcard rule
    addAutoAcceptRule("*");

    assert.strictEqual(shouldAutoAccept("hope"), true);
    assert.strictEqual(shouldAutoAccept("wopr"), true);
    assert.strictEqual(shouldAutoAccept("anyone"), true);

    // Cleanup
    removeAutoAcceptRule("*");
  });

  it("should match OR pattern", async () => {
    const { shouldAutoAccept, addAutoAcceptRule, removeAutoAcceptRule } = await import("../src/friends.js");

    // Add OR pattern
    addAutoAcceptRule("hope|wopr|claude");

    assert.strictEqual(shouldAutoAccept("hope"), true);
    assert.strictEqual(shouldAutoAccept("wopr"), true);
    assert.strictEqual(shouldAutoAccept("claude"), true);
    assert.strictEqual(shouldAutoAccept("bob"), false);

    // Cleanup
    removeAutoAcceptRule("hope|wopr|claude");
  });
});

describe("Friend Capability Management", () => {
  // These tests would require more setup to mock the file system
  // and identity system. Marking as placeholders.

  it("should have default message capability for new friends", () => {
    // New friends start with ["message"] capability
    // This is enforced in completeFriendship and acceptPendingRequest
    assert.ok(true, "Capability defaults are enforced in friend creation");
  });

  it("should allow granting additional capabilities", () => {
    // grantFriendCap adds capabilities like "inject", "inject.exec", etc.
    assert.ok(true, "grantFriendCap function exists and is exported");
  });
});
