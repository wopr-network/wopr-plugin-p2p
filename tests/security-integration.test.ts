/**
 * Unit tests for the P2P Security Integration module
 *
 * Tests capability mapping, trust levels, security config sync,
 * friend action validation, and security context retrieval.
 */

import { describe, it, beforeEach, afterEach, expect, vi } from "vitest";
import { mkdirSync, rmSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { initIdentity } from "../src/identity.js";
import {
  FRIEND_CAP_TO_TRUST_LEVEL,
  FRIEND_CAP_TO_WOPR_CAPS,
  getFriendSecurityContext,
  getHighestTrustLevel,
  getWoprCapabilities,
  hasFriendCapability,
  loadSecurityConfig,
  removeFriendFromSecurity,
  saveSecurityConfig,
  syncAllFriendsToSecurity,
  syncFriendToSecurity,
  updateFriendSecurityCaps,
  validateFriendAction,
} from "../src/security-integration.js";
import type { Friend } from "../src/types.js";

const TEST_DATA_DIR = join(tmpdir(), `wopr-p2p-test-secint-${process.pid}`);
const TEST_WOPR_HOME = join(tmpdir(), `wopr-secint-home-${process.pid}`);

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
      expect(FRIEND_CAP_TO_WOPR_CAPS.message).toEqual(["inject"]);
    });

    it("should map inject to inject and inject.tools", () => {
      expect(FRIEND_CAP_TO_WOPR_CAPS.inject).toEqual(["inject", "inject.tools"]);
    });
  });

  describe("FRIEND_CAP_TO_TRUST_LEVEL", () => {
    it("should map message to untrusted", () => {
      expect(FRIEND_CAP_TO_TRUST_LEVEL.message).toBe("untrusted");
    });

    it("should map inject to untrusted", () => {
      expect(FRIEND_CAP_TO_TRUST_LEVEL.inject).toBe("untrusted");
    });
  });
});

describe("Trust Level Calculation", () => {
  describe("getHighestTrustLevel", () => {
    it("should return untrusted for message cap", () => {
      expect(getHighestTrustLevel(["message"])).toBe("untrusted");
    });

    it("should return untrusted for inject cap", () => {
      expect(getHighestTrustLevel(["inject"])).toBe("untrusted");
    });

    it("should return untrusted for combined caps", () => {
      expect(getHighestTrustLevel(["message", "inject"])).toBe("untrusted");
    });

    it("should return untrusted for empty caps", () => {
      expect(getHighestTrustLevel([])).toBe("untrusted");
    });

    it("should return untrusted for unknown caps", () => {
      expect(getHighestTrustLevel(["unknown-cap"])).toBe("untrusted");
    });
  });
});

describe("WOPR Capabilities", () => {
  describe("getWoprCapabilities", () => {
    it("should return inject for message cap", () => {
      const caps = getWoprCapabilities(["message"]);
      expect(caps).toEqual(["inject"]);
    });

    it("should return inject and inject.tools for inject cap", () => {
      const caps = getWoprCapabilities(["inject"]);
      expect(caps.includes("inject")).toBeTruthy();
      expect(caps.includes("inject.tools")).toBeTruthy();
    });

    it("should deduplicate combined caps", () => {
      const caps = getWoprCapabilities(["message", "inject"]);
      // Both map to "inject", inject also adds "inject.tools"
      expect(caps.includes("inject")).toBeTruthy();
      expect(caps.includes("inject.tools")).toBeTruthy();
      expect(caps.filter(c => c === "inject").length).toBe(1);
    });

    it("should return empty for unknown caps", () => {
      expect(getWoprCapabilities(["unknown"])).toEqual([]);
    });

    it("should return empty for empty input", () => {
      expect(getWoprCapabilities([])).toEqual([]);
    });
  });
});

describe("Security Config Persistence", () => {
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

  describe("saveSecurityConfig / loadSecurityConfig", () => {
    it("should round-trip save and load config", () => {
      const marker = `test-marker-${Date.now()}`;
      saveSecurityConfig({ enforcement: "warn", marker });

      const loaded = loadSecurityConfig();
      expect(loaded).toBeTruthy();
      expect(loaded.enforcement).toBe("warn");
      expect(loaded.marker).toBe(marker);
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
      expect(config).toBeTruthy();
      expect(config.sessions[friend.sessionName]).toBeTruthy();
      expect(config.sources[`p2p:${friend.publicKey}`]).toBeTruthy();
    });

    it("should configure session with correct capabilities", () => {
      const friend = makeFriend({ caps: ["message"] });
      syncFriendToSecurity(friend);

      const config = loadSecurityConfig();
      const session = config.sessions[friend.sessionName];

      expect(session.capabilities).toEqual(["inject"]);
      expect(session.access).toEqual([`p2p:${friend.publicKey}`]);
      expect(session.indexable).toEqual(["self"]);
    });

    it("should configure source with correct trust level", () => {
      const friend = makeFriend({ caps: ["inject"] });
      syncFriendToSecurity(friend);

      const config = loadSecurityConfig();
      const source = config.sources[`p2p:${friend.publicKey}`];

      expect(source.type).toBe("p2p");
      expect(source.trust).toBe("untrusted");
      expect(source.capabilities.includes("inject")).toBeTruthy();
      expect(source.capabilities.includes("inject.tools")).toBeTruthy();
    });

    it("should set rate limits based on trust level", () => {
      const friend = makeFriend({ caps: ["message"] });
      syncFriendToSecurity(friend);

      const config = loadSecurityConfig();
      const source = config.sources[`p2p:${friend.publicKey}`];

      // Untrusted gets 30/min, 300/hour
      expect(source.rateLimit.perMinute).toBe(30);
      expect(source.rateLimit.perHour).toBe(300);
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
      expect(config.enforcement).toBe("strict");
      expect(config.sessions["existing-session"]).toBeTruthy();
      expect(config.sources["existing-source"]).toBeTruthy();
      expect(config.sessions[friend.sessionName]).toBeTruthy();
    });
  });

  describe("removeFriendFromSecurity", () => {
    it("should remove session and source config", () => {
      const friend = makeFriend();
      syncFriendToSecurity(friend);

      removeFriendFromSecurity(friend);

      const config = loadSecurityConfig();
      expect(config.sessions[friend.sessionName]).toBe(undefined);
      expect(config.sources[`p2p:${friend.publicKey}`]).toBe(undefined);
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
      expect(config.sessions[alice.sessionName]).toBe(undefined);
      expect(config.sessions[bob.sessionName]).toBeTruthy();
    });
  });
});

describe("Friend Capability Checks", () => {
  let cleanup: (() => void) | undefined;
  let secmod: any;
  let friendsmod: any;

  /** Add a friend directly into the in-memory friends module state */
  function createFriendInState(name: string, publicKey: string, caps: string[]): Friend {
    const sessionName = `friend:p2p:${name}(${publicKey.slice(0, 6)})`;
    const friend: Friend = {
      name,
      publicKey,
      encryptPub: "enc-" + publicKey,
      sessionName,
      addedAt: Date.now(),
      caps,
      channel: "discord",
    };
    // Use queueForApproval + acceptPendingRequest to populate in-memory state
    const mockRequest = {
      type: "FRIEND_REQUEST" as const,
      to: "me",
      from: name,
      pubkey: publicKey,
      encryptPub: "enc-" + publicKey,
      timestamp: Date.now(),
      sig: "mock-sig",
    };
    friendsmod.queueForApproval(mockRequest, "discord", "test-channel");
    const result = friendsmod.acceptPendingRequest(name);
    if (result) {
      // Override caps since acceptPendingRequest defaults to ["message"]
      if (caps.length !== 1 || caps[0] !== "message") {
        friendsmod.setFriendCaps(name, caps);
        // Update friend object caps to match
        friend.caps = caps;
      }
    }
    return friend;
  }

  beforeEach(async () => {
    cleanup = useTestDirs();
    vi.resetModules();
    const identmod = await import("../src/identity.js");
    identmod.initIdentity();
    friendsmod = await import("../src/friends.js");
    secmod = await import("../src/security-integration.js");
  });

  afterEach(() => {
    if (cleanup) {
      cleanup();
      cleanup = undefined;
    }
  });

  describe("hasFriendCapability", () => {
    it("should return true when friend has capability", () => {
      createFriendInState("alice", "alice-key", ["message", "inject"]);
      expect(secmod.hasFriendCapability("alice-key", "message")).toBe(true);
      expect(secmod.hasFriendCapability("alice-key", "inject")).toBe(true);
    });

    it("should return false when friend lacks capability", () => {
      createFriendInState("bob", "bob-key", ["message"]);
      expect(secmod.hasFriendCapability("bob-key", "inject")).toBe(false);
    });

    it("should return false for unknown public key", () => {
      expect(secmod.hasFriendCapability("unknown-key", "message")).toBe(false);
    });
  });

  describe("getFriendSecurityContext", () => {
    it("should return context for known friend", () => {
      const friend = createFriendInState("charlie", "charlie-key", ["message"]);

      const ctx = secmod.getFriendSecurityContext("charlie-key");
      expect(ctx).toBeTruthy();
      expect(ctx!.trustLevel).toBe("untrusted");
      expect(ctx!.capabilities).toEqual(["inject"]);
      expect(ctx!.allowedSessions).toEqual([friend.sessionName]);
    });

    it("should return null for unknown friend", () => {
      expect(secmod.getFriendSecurityContext("unknown-key")).toBe(null);
    });

    it("should reflect inject capabilities", () => {
      createFriendInState("dave", "dave-key", ["inject"]);

      const ctx = secmod.getFriendSecurityContext("dave-key");
      expect(ctx).toBeTruthy();
      expect(ctx!.capabilities.includes("inject")).toBeTruthy();
      expect(ctx!.capabilities.includes("inject.tools")).toBeTruthy();
    });
  });

  describe("validateFriendAction", () => {
    it("should allow message action for friend with message cap", () => {
      createFriendInState("eve", "eve-key", ["message"]);

      const result = secmod.validateFriendAction("eve-key", "message");
      expect(result.allowed).toBe(true);
    });

    it("should allow inject action for friend with inject cap", () => {
      createFriendInState("frank", "frank-key", ["inject"]);

      const result = secmod.validateFriendAction("frank-key", "inject");
      expect(result.allowed).toBe(true);
    });

    it("should deny inject for message-only friend", () => {
      createFriendInState("grace", "grace-key", ["message"]);

      const result = secmod.validateFriendAction("grace-key", "inject");
      expect(result.allowed).toBe(false);
      expect(result.reason?.includes("Missing capability")).toBeTruthy();
    });

    it("should deny unknown public key", () => {
      const result = secmod.validateFriendAction("unknown-key", "message");
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe("Not a friend");
    });

    it("should deny access to wrong session", () => {
      const _friend = createFriendInState("heidi", "heidi-key", ["message"]);

      const result = secmod.validateFriendAction("heidi-key", "message", "wrong-session");
      expect(result.allowed).toBe(false);
      expect(result.reason?.includes("Can only access session")).toBeTruthy();
    });

    it("should allow access to own session", () => {
      const friend = createFriendInState("ivan", "ivan-key", ["message"]);

      const result = secmod.validateFriendAction("ivan-key", "message", friend.sessionName);
      expect(result.allowed).toBe(true);
    });
  });

  describe("updateFriendSecurityCaps", () => {
    it("should update security config for existing friend", () => {
      const friend = createFriendInState("judy", "judy-key", ["message"]);
      secmod.syncFriendToSecurity(friend);

      // Upgrade capabilities
      secmod.updateFriendSecurityCaps("judy", ["message", "inject"]);

      const config = secmod.loadSecurityConfig();
      const source = config.sources[`p2p:judy-key`];
      expect(source.capabilities.includes("inject")).toBeTruthy();
      expect(source.capabilities.includes("inject.tools")).toBeTruthy();

      // Verify caps are updated in-memory
      const judyFriend = friendsmod.getFriend("judy");
      expect(judyFriend).toBeTruthy();
      expect(judyFriend.caps.includes("inject")).toBeTruthy();
    });

    it("should be a no-op for unknown friend", () => {
      // Should not throw
      secmod.updateFriendSecurityCaps("nonexistent", ["inject"]);
    });
  });

  describe("syncAllFriendsToSecurity", () => {
    it("should sync all friends to security config", () => {
      createFriendInState("kate", "kate-key", ["message"]);
      createFriendInState("leo", "leo-key", ["inject"]);

      secmod.syncAllFriendsToSecurity();

      const config = secmod.loadSecurityConfig();
      expect(config.sources["p2p:kate-key"]).toBeTruthy();
      expect(config.sources["p2p:leo-key"]).toBeTruthy();
    });

    it("should work with no friends", () => {
      // Should not throw when no friends exist
      secmod.syncAllFriendsToSecurity();
    });
  });
});
