/**
 * Unit tests for the P2P Security Integration module
 *
 * Tests capability mapping, trust levels, security config sync,
 * friend action validation, and security context retrieval.
 */

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert";
import { mkdirSync, rmSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import {
  FRIEND_CAP_TO_WOPR_CAPS,
  FRIEND_CAP_TO_TRUST_LEVEL,
  getHighestTrustLevel,
  getWoprCapabilities,
  loadSecurityConfig,
  saveSecurityConfig,
  syncFriendToSecurity,
  removeFriendFromSecurity,
  hasFriendCapability,
  getFriendSecurityContext,
  validateFriendAction,
} from "../src/security-integration.js";
import { initIdentity } from "../src/identity.js";
import type { Friend } from "../src/types.js";

const TEST_DATA_DIR = join(tmpdir(), "wopr-p2p-test-secint-" + process.pid);
const TEST_WOPR_HOME = join(tmpdir(), "wopr-secint-home-" + process.pid);

function useTestDirs() {
  mkdirSync(TEST_DATA_DIR, { recursive: true });
  mkdirSync(TEST_WOPR_HOME, { recursive: true });
  process.env.WOPR_P2P_DATA_DIR = TEST_DATA_DIR;
  process.env.WOPR_HOME = TEST_WOPR_HOME;
  return () => {
    delete process.env.WOPR_P2P_DATA_DIR;
    delete process.env.WOPR_HOME;
    rmSync(TEST_DATA_DIR, { recursive: true, force: true });
    rmSync(TEST_WOPR_HOME, { recursive: true, force: true });
  };
}

describe("Capability Mapping Constants", () => {
  describe("FRIEND_CAP_TO_WOPR_CAPS", () => {
    it("should map message to inject", () => {
      assert.deepStrictEqual(FRIEND_CAP_TO_WOPR_CAPS.message, ["inject"]);
    });

    it("should map inject to inject and inject.tools", () => {
      assert.deepStrictEqual(FRIEND_CAP_TO_WOPR_CAPS.inject, ["inject", "inject.tools"]);
    });
  });

  describe("FRIEND_CAP_TO_TRUST_LEVEL", () => {
    it("should map message to untrusted", () => {
      assert.strictEqual(FRIEND_CAP_TO_TRUST_LEVEL.message, "untrusted");
    });

    it("should map inject to untrusted", () => {
      assert.strictEqual(FRIEND_CAP_TO_TRUST_LEVEL.inject, "untrusted");
    });
  });
});

describe("Trust Level Calculation", () => {
  describe("getHighestTrustLevel", () => {
    it("should return untrusted for message cap", () => {
      assert.strictEqual(getHighestTrustLevel(["message"]), "untrusted");
    });

    it("should return untrusted for inject cap", () => {
      assert.strictEqual(getHighestTrustLevel(["inject"]), "untrusted");
    });

    it("should return untrusted for combined caps", () => {
      assert.strictEqual(getHighestTrustLevel(["message", "inject"]), "untrusted");
    });

    it("should return untrusted for empty caps", () => {
      assert.strictEqual(getHighestTrustLevel([]), "untrusted");
    });

    it("should return untrusted for unknown caps", () => {
      assert.strictEqual(getHighestTrustLevel(["unknown-cap"]), "untrusted");
    });
  });
});

describe("WOPR Capabilities", () => {
  describe("getWoprCapabilities", () => {
    it("should return inject for message cap", () => {
      const caps = getWoprCapabilities(["message"]);
      assert.deepStrictEqual(caps, ["inject"]);
    });

    it("should return inject and inject.tools for inject cap", () => {
      const caps = getWoprCapabilities(["inject"]);
      assert.ok(caps.includes("inject"));
      assert.ok(caps.includes("inject.tools"));
    });

    it("should deduplicate combined caps", () => {
      const caps = getWoprCapabilities(["message", "inject"]);
      // Both map to "inject", inject also adds "inject.tools"
      assert.ok(caps.includes("inject"));
      assert.ok(caps.includes("inject.tools"));
      assert.strictEqual(caps.filter(c => c === "inject").length, 1);
    });

    it("should return empty for unknown caps", () => {
      assert.deepStrictEqual(getWoprCapabilities(["unknown"]), []);
    });

    it("should return empty for empty input", () => {
      assert.deepStrictEqual(getWoprCapabilities([]), []);
    });
  });
});

describe("Security Config Persistence", () => {
  // NOTE: WOPR_HOME and SECURITY_CONFIG_FILE are constants computed at module
  // load time. We test save/load by round-tripping through the module's own
  // functions rather than controlling the file path directly.

  describe("saveSecurityConfig / loadSecurityConfig", () => {
    it("should round-trip save and load config", () => {
      const marker = `test-marker-${Date.now()}`;
      saveSecurityConfig({ enforcement: "warn", marker });

      const loaded = loadSecurityConfig();
      assert.ok(loaded);
      assert.strictEqual(loaded.enforcement, "warn");
      assert.strictEqual(loaded.marker, marker);
    });
  });
});

describe("Friend Security Sync", () => {
  let cleanup: (() => void) | undefined;

  beforeEach(() => {
    cleanup = useTestDirs();
  });

  afterEach(() => {
    if (cleanup) {
      cleanup();
      cleanup = undefined;
    }
  });

  const makeFriend = (overrides?: Partial<Friend>): Friend => ({
    name: "alice",
    publicKey: "alice-pub-key",
    encryptPub: "alice-enc-key",
    sessionName: "friend:p2p:alice(alice-)",
    addedAt: Date.now(),
    caps: ["message"],
    channel: "discord",
    ...overrides,
  });

  describe("syncFriendToSecurity", () => {
    it("should create config when none exists", () => {
      const friend = makeFriend();
      syncFriendToSecurity(friend);

      const config = loadSecurityConfig();
      assert.ok(config);
      assert.ok(config.sessions[friend.sessionName]);
      assert.ok(config.sources[`p2p:${friend.publicKey}`]);
    });

    it("should configure session with correct capabilities", () => {
      const friend = makeFriend({ caps: ["message"] });
      syncFriendToSecurity(friend);

      const config = loadSecurityConfig();
      const session = config.sessions[friend.sessionName];

      assert.deepStrictEqual(session.capabilities, ["inject"]);
      assert.deepStrictEqual(session.access, [`p2p:${friend.publicKey}`]);
      assert.deepStrictEqual(session.indexable, ["self"]);
    });

    it("should configure source with correct trust level", () => {
      const friend = makeFriend({ caps: ["inject"] });
      syncFriendToSecurity(friend);

      const config = loadSecurityConfig();
      const source = config.sources[`p2p:${friend.publicKey}`];

      assert.strictEqual(source.type, "p2p");
      assert.strictEqual(source.trust, "untrusted");
      assert.ok(source.capabilities.includes("inject"));
      assert.ok(source.capabilities.includes("inject.tools"));
    });

    it("should set rate limits based on trust level", () => {
      const friend = makeFriend({ caps: ["message"] });
      syncFriendToSecurity(friend);

      const config = loadSecurityConfig();
      const source = config.sources[`p2p:${friend.publicKey}`];

      // Untrusted gets 30/min, 300/hour
      assert.strictEqual(source.rateLimit.perMinute, 30);
      assert.strictEqual(source.rateLimit.perHour, 300);
    });

    it("should update existing config without losing other entries", () => {
      // Pre-populate config
      saveSecurityConfig({
        enforcement: "strict",
        sessions: { "existing-session": { access: ["local"] } },
        sources: { "existing-source": { type: "cli" } },
      });

      const friend = makeFriend();
      syncFriendToSecurity(friend);

      const config = loadSecurityConfig();
      assert.strictEqual(config.enforcement, "strict");
      assert.ok(config.sessions["existing-session"]);
      assert.ok(config.sources["existing-source"]);
      assert.ok(config.sessions[friend.sessionName]);
    });
  });

  describe("removeFriendFromSecurity", () => {
    it("should remove session and source config", () => {
      const friend = makeFriend();
      syncFriendToSecurity(friend);

      removeFriendFromSecurity(friend);

      const config = loadSecurityConfig();
      assert.strictEqual(config.sessions[friend.sessionName], undefined);
      assert.strictEqual(config.sources[`p2p:${friend.publicKey}`], undefined);
    });

    it("should be a no-op when no config exists", () => {
      const friend = makeFriend();
      // Should not throw
      removeFriendFromSecurity(friend);
    });

    it("should not affect other friends", () => {
      const alice = makeFriend({ name: "alice", publicKey: "alice-key", sessionName: "friend:p2p:alice(alice-)" });
      const bob = makeFriend({ name: "bob", publicKey: "bob-key", sessionName: "friend:p2p:bob(bob-ke)" });

      syncFriendToSecurity(alice);
      syncFriendToSecurity(bob);

      removeFriendFromSecurity(alice);

      const config = loadSecurityConfig();
      assert.strictEqual(config.sessions[alice.sessionName], undefined);
      assert.ok(config.sessions[bob.sessionName]);
    });
  });
});

describe("Friend Capability Checks", () => {
  let cleanup: (() => void) | undefined;

  beforeEach(() => {
    cleanup = useTestDirs();
    initIdentity();
  });

  afterEach(() => {
    if (cleanup) {
      cleanup();
      cleanup = undefined;
    }
  });

  // Helper to create a friend in state
  function createFriendInState(name: string, publicKey: string, caps: string[]): Friend {
    const friendsFile = join(TEST_DATA_DIR, "friends.json");

    let state = { friends: [] as Friend[], pendingIn: [], pendingOut: [], autoAccept: [] };
    if (existsSync(friendsFile)) {
      state = JSON.parse(readFileSync(friendsFile, "utf-8"));
    }

    const friend: Friend = {
      name,
      publicKey,
      encryptPub: "enc-" + publicKey,
      sessionName: `friend:p2p:${name}(${publicKey.slice(0, 6)})`,
      addedAt: Date.now(),
      caps,
      channel: "discord",
    };

    state.friends.push(friend);
    writeFileSync(friendsFile, JSON.stringify(state, null, 2), { mode: 0o600 });
    return friend;
  }

  describe("hasFriendCapability", () => {
    it("should return true when friend has capability", () => {
      createFriendInState("alice", "alice-key", ["message", "inject"]);
      assert.strictEqual(hasFriendCapability("alice-key", "message"), true);
      assert.strictEqual(hasFriendCapability("alice-key", "inject"), true);
    });

    it("should return false when friend lacks capability", () => {
      createFriendInState("bob", "bob-key", ["message"]);
      assert.strictEqual(hasFriendCapability("bob-key", "inject"), false);
    });

    it("should return false for unknown public key", () => {
      assert.strictEqual(hasFriendCapability("unknown-key", "message"), false);
    });
  });

  describe("getFriendSecurityContext", () => {
    it("should return context for known friend", () => {
      const friend = createFriendInState("charlie", "charlie-key", ["message"]);

      const ctx = getFriendSecurityContext("charlie-key");
      assert.ok(ctx);
      assert.strictEqual(ctx.trustLevel, "untrusted");
      assert.deepStrictEqual(ctx.capabilities, ["inject"]);
      assert.deepStrictEqual(ctx.allowedSessions, [friend.sessionName]);
    });

    it("should return null for unknown friend", () => {
      assert.strictEqual(getFriendSecurityContext("unknown-key"), null);
    });

    it("should reflect inject capabilities", () => {
      createFriendInState("dave", "dave-key", ["inject"]);

      const ctx = getFriendSecurityContext("dave-key");
      assert.ok(ctx);
      assert.ok(ctx.capabilities.includes("inject"));
      assert.ok(ctx.capabilities.includes("inject.tools"));
    });
  });

  describe("validateFriendAction", () => {
    it("should allow message action for friend with message cap", () => {
      const friend = createFriendInState("eve", "eve-key", ["message"]);

      const result = validateFriendAction("eve-key", "message");
      assert.strictEqual(result.allowed, true);
    });

    it("should allow inject action for friend with inject cap", () => {
      createFriendInState("frank", "frank-key", ["inject"]);

      const result = validateFriendAction("frank-key", "inject");
      assert.strictEqual(result.allowed, true);
    });

    it("should deny inject for message-only friend", () => {
      createFriendInState("grace", "grace-key", ["message"]);

      const result = validateFriendAction("grace-key", "inject");
      assert.strictEqual(result.allowed, false);
      assert.ok(result.reason?.includes("Missing capability"));
    });

    it("should deny unknown public key", () => {
      const result = validateFriendAction("unknown-key", "message");
      assert.strictEqual(result.allowed, false);
      assert.strictEqual(result.reason, "Not a friend");
    });

    it("should deny access to wrong session", () => {
      const friend = createFriendInState("heidi", "heidi-key", ["message"]);

      const result = validateFriendAction("heidi-key", "message", "wrong-session");
      assert.strictEqual(result.allowed, false);
      assert.ok(result.reason?.includes("Can only access session"));
    });

    it("should allow access to own session", () => {
      const friend = createFriendInState("ivan", "ivan-key", ["message"]);

      const result = validateFriendAction("ivan-key", "message", friend.sessionName);
      assert.strictEqual(result.allowed, true);
    });
  });
});
