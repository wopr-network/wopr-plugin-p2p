/**
 * Unit tests for the P2P Trust Management module
 *
 * Tests access grants, peer management, authorization checks,
 * key rotation processing, and expired key history cleanup.
 */

import { describe, it, beforeEach, afterEach, expect, vi } from "vitest";
import { mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import type { AccessGrant, Peer, KeyRotation } from "../src/types.js";

const TEST_DATA_DIR = join(tmpdir(), `wopr-p2p-test-trust-${process.pid}`);

function useTestDataDir() {
  mkdirSync(TEST_DATA_DIR, { recursive: true });
  process.env.WOPR_P2P_DATA_DIR = TEST_DATA_DIR;
  return () => {
    delete process.env.WOPR_P2P_DATA_DIR;
    rmSync(TEST_DATA_DIR, { recursive: true, force: true });
  };
}

// Helper: reset all module caches and re-import trust + identity
async function freshModules() {
  vi.resetModules();
  const trust = await import("../src/trust.js");
  const identity = await import("../src/identity.js");
  return { trust, identity };
}

describe("Access Grants", () => {
  let cleanup: (() => void) | undefined;
  let trust: any;

  beforeEach(async () => {
    cleanup = useTestDataDir();
    ({ trust } = await freshModules());
  });

  afterEach(() => {
    if (cleanup) {
      cleanup();
      cleanup = undefined;
    }
  });

  describe("getAccessGrants / saveAccessGrants", () => {
    it("should return empty array when no file exists", () => {
      expect(trust.getAccessGrants()).toEqual([]);
    });

    it("should round-trip save and load grants", () => {
      const grants: AccessGrant[] = [
        {
          id: "grant-1",
          peerKey: "key-1",
          sessions: ["session-a"],
          caps: ["message"],
          created: Date.now(),
        },
      ];

      trust.saveAccessGrants(grants);
      const loaded = trust.getAccessGrants();

      expect(loaded.length).toBe(1);
      expect(loaded[0].id).toBe("grant-1");
      expect(loaded[0].peerKey).toBe("key-1");
    });
  });

  describe("grantAccess", () => {
    it("should create a new grant", async () => {
      const { identity } = await freshModules();
      ({ trust } = await freshModules());
      identity.initIdentity();
      trust.addPeer("peer-key-1", ["s1"], ["message"]);
      const grant = trust.grantAccess("peer-key-1", ["session-1"], ["message"]);

      expect(grant.id.startsWith("grant-")).toBeTruthy();
      expect(grant.peerKey).toBe("peer-key-1");
      expect(grant.sessions).toEqual(["session-1"]);
      expect(grant.caps).toEqual(["message"]);
    });

    it("should merge sessions and caps for existing grant", () => {
      trust.grantAccess("peer-key-2", ["session-1"], ["message"]);
      const updated = trust.grantAccess("peer-key-2", ["session-2"], ["inject"]);

      expect(updated.sessions.includes("session-1")).toBeTruthy();
      expect(updated.sessions.includes("session-2")).toBeTruthy();
      expect(updated.caps.includes("message")).toBeTruthy();
      expect(updated.caps.includes("inject")).toBeTruthy();
    });

    it("should not duplicate sessions or caps", () => {
      trust.grantAccess("peer-key-3", ["s1"], ["message"]);
      const updated = trust.grantAccess("peer-key-3", ["s1"], ["message"]);

      expect(updated.sessions.filter((s: string) => s === "s1").length).toBe(1);
      expect(updated.caps.filter((c: string) => c === "message").length).toBe(1);
    });

    it("should store encryptPub when provided", () => {
      const grant = trust.grantAccess("peer-key-4", ["s1"], ["message"], "encrypt-pub");

      expect(grant.peerEncryptPub).toBe("encrypt-pub");
    });
  });
});

describe("Peer Management", () => {
  let cleanup: (() => void) | undefined;
  let trust: any;

  beforeEach(async () => {
    cleanup = useTestDataDir();
    ({ trust } = await freshModules());
  });

  afterEach(() => {
    if (cleanup) {
      cleanup();
      cleanup = undefined;
    }
  });

  describe("getPeers / savePeers", () => {
    it("should return empty array when no file exists", () => {
      expect(trust.getPeers()).toEqual([]);
    });

    it("should round-trip save and load peers", () => {
      const peers: Peer[] = [
        {
          id: "abcd1234",
          publicKey: "pub-key-1",
          sessions: ["s1"],
          caps: ["message"],
          added: Date.now(),
        },
      ];

      trust.savePeers(peers);
      const loaded = trust.getPeers();

      expect(loaded.length).toBe(1);
      expect(loaded[0].publicKey).toBe("pub-key-1");
    });
  });

  describe("addPeer", () => {
    it("should add a new peer", () => {
      const peer = trust.addPeer("new-pub-key", ["s1"], ["message"]);

      expect(peer.id).toBeTruthy();
      expect(peer.publicKey).toBe("new-pub-key");
      expect(peer.sessions).toEqual(["s1"]);
      expect(peer.caps).toEqual(["message"]);
    });

    it("should merge data for existing peer", () => {
      trust.addPeer("same-key", ["s1"], ["message"]);
      const updated = trust.addPeer("same-key", ["s2"], ["inject"]);

      expect(updated.sessions.includes("s1")).toBeTruthy();
      expect(updated.sessions.includes("s2")).toBeTruthy();
      expect(updated.caps.includes("message")).toBeTruthy();
      expect(updated.caps.includes("inject")).toBeTruthy();
    });

    it("should update encryptPub when provided", () => {
      trust.addPeer("ep-key", ["s1"], ["message"]);
      const updated = trust.addPeer("ep-key", ["s1"], ["message"], "new-encrypt");

      expect(updated.encryptPub).toBe("new-encrypt");
    });
  });

  describe("findPeer", () => {
    it("should find by public key", () => {
      trust.addPeer("find-by-key", ["s1"], ["message"]);
      const found = trust.findPeer("find-by-key");

      expect(found).toBeTruthy();
      expect(found!.publicKey).toBe("find-by-key");
    });

    it("should find by short ID", async () => {
      const { identity } = await freshModules();
      trust.addPeer("find-by-id-key", ["s1"], ["message"]);
      const id = identity.shortKey("find-by-id-key");
      const found = trust.findPeer(id);

      expect(found).toBeTruthy();
      expect(found!.publicKey).toBe("find-by-id-key");
    });

    it("should find by name (case insensitive)", () => {
      trust.addPeer("named-key", ["s1"], ["message"]);
      trust.namePeer("named-key", "Alice");

      const found = trust.findPeer("alice");
      expect(found).toBeTruthy();
      expect(found!.name).toBe("Alice");
    });

    it("should find by key history", () => {
      const peers: Peer[] = [{
        id: "current-id",
        publicKey: "current-key",
        sessions: ["s1"],
        caps: ["message"],
        added: Date.now(),
        keyHistory: [{
          publicKey: "old-key",
          encryptPub: "old-enc",
          validFrom: Date.now() - 100000,
          validUntil: Date.now() + 100000,
        }],
      }];
      trust.savePeers(peers);

      const found = trust.findPeer("old-key");
      expect(found).toBeTruthy();
      expect(found!.publicKey).toBe("current-key");
    });

    it("should return undefined for unknown peer", () => {
      expect(trust.findPeer("nonexistent")).toBe(undefined);
    });
  });

  describe("namePeer", () => {
    it("should set a peer name", () => {
      trust.addPeer("name-key", ["s1"], ["message"]);
      trust.namePeer("name-key", "Bob");

      const peer = trust.findPeer("name-key");
      expect(peer).toBeTruthy();
      expect(peer!.name).toBe("Bob");
    });

    it("should throw for unknown peer", () => {
      expect(() => trust.namePeer("unknown", "Name")).toThrow(/Peer not found/);
    });
  });

  describe("revokePeer", () => {
    it("should revoke an active grant", async () => {
      const { identity } = await freshModules();
      trust.grantAccess("revoke-key", ["s1"], ["message"]);

      trust.revokePeer(identity.shortKey("revoke-key"));

      const grants = trust.getAccessGrants();
      const grant = grants.find((g: AccessGrant) => g.peerKey === "revoke-key");
      expect(grant).toBeTruthy();
      expect(grant!.revoked).toBe(true);
    });

    it("should throw for unknown peer", () => {
      expect(() => trust.revokePeer("nonexistent")).toThrow(/No active grant found/);
    });

    it("should not revoke already revoked grant", async () => {
      const { identity } = await freshModules();
      trust.grantAccess("double-revoke-key", ["s1"], ["message"]);
      trust.revokePeer(identity.shortKey("double-revoke-key"));

      // Second revoke should throw because the grant is already revoked
      expect(() => trust.revokePeer(identity.shortKey("double-revoke-key"))).toThrow(/No active grant found/);
    });
  });
});

describe("Authorization", () => {
  let cleanup: (() => void) | undefined;
  let trust: any;
  let identity: any;

  beforeEach(async () => {
    cleanup = useTestDataDir();
    ({ trust, identity } = await freshModules());
  });

  afterEach(() => {
    if (cleanup) {
      cleanup();
      cleanup = undefined;
    }
  });

  describe("isAuthorized", () => {
    it("should authorize peer with matching session", () => {
      trust.grantAccess("auth-key", ["session-1"], ["message"]);
      expect(trust.isAuthorized("auth-key", "session-1")).toBe(true);
    });

    it("should authorize peer with wildcard session", () => {
      trust.grantAccess("wildcard-key", ["*"], ["message"]);
      expect(trust.isAuthorized("wildcard-key", "any-session")).toBe(true);
    });

    it("should authorize peer with inject capability", () => {
      trust.grantAccess("inject-key", ["s1"], ["inject"]);
      expect(trust.isAuthorized("inject-key", "s1")).toBe(true);
    });

    it("should deny peer with wrong session", () => {
      trust.grantAccess("wrong-session-key", ["session-1"], ["message"]);
      expect(trust.isAuthorized("wrong-session-key", "session-2")).toBe(false);
    });

    it("should deny peer with no matching capability", () => {
      // Grant with a non-message/inject capability
      const grants: AccessGrant[] = [{
        id: "g1",
        peerKey: "nocap-key",
        sessions: ["s1"],
        caps: ["other"],
        created: Date.now(),
      }];
      trust.saveAccessGrants(grants);

      expect(trust.isAuthorized("nocap-key", "s1")).toBe(false);
    });

    it("should deny revoked peer", () => {
      trust.grantAccess("revoked-key", ["s1"], ["message"]);
      trust.revokePeer(identity.shortKey("revoked-key"));

      expect(trust.isAuthorized("revoked-key", "s1")).toBe(false);
    });

    it("should deny unknown peer", () => {
      expect(trust.isAuthorized("unknown-key", "s1")).toBe(false);
    });

    it("should authorize old key in grace period via key history", () => {
      const grants: AccessGrant[] = [{
        id: "g-rotated",
        peerKey: "new-key",
        sessions: ["s1"],
        caps: ["message"],
        created: Date.now(),
        keyHistory: [{
          publicKey: "old-key",
          encryptPub: "old-enc",
          validFrom: Date.now() - 100000,
          validUntil: Date.now() + 100000, // Still valid
        }],
      }];
      trust.saveAccessGrants(grants);

      expect(trust.isAuthorized("old-key", "s1")).toBe(true);
    });

    it("should deny old key past grace period", () => {
      const grants: AccessGrant[] = [{
        id: "g-expired",
        peerKey: "new-key-2",
        sessions: ["s1"],
        caps: ["message"],
        created: Date.now(),
        keyHistory: [{
          publicKey: "expired-key",
          encryptPub: "old-enc",
          validFrom: Date.now() - 200000,
          validUntil: Date.now() - 100000, // Expired
        }],
      }];
      trust.saveAccessGrants(grants);

      expect(trust.isAuthorized("expired-key", "s1")).toBe(false);
    });
  });

  describe("getGrantForPeer", () => {
    it("should find grant by current key", () => {
      trust.grantAccess("grant-peer-key", ["s1"], ["message"]);
      const grant = trust.getGrantForPeer("grant-peer-key");

      expect(grant).toBeTruthy();
      expect(grant!.peerKey).toBe("grant-peer-key");
    });

    it("should find grant by historical key", () => {
      const grants: AccessGrant[] = [{
        id: "g-hist",
        peerKey: "current-key",
        sessions: ["s1"],
        caps: ["message"],
        created: Date.now(),
        keyHistory: [{
          publicKey: "historical-key",
          encryptPub: "enc",
          validFrom: Date.now() - 100000,
        }],
      }];
      trust.saveAccessGrants(grants);

      const grant = trust.getGrantForPeer("historical-key");
      expect(grant).toBeTruthy();
      expect(grant!.peerKey).toBe("current-key");
    });

    it("should skip revoked grants for current key", () => {
      trust.grantAccess("skip-revoked-key", ["s1"], ["message"]);
      trust.revokePeer(identity.shortKey("skip-revoked-key"));

      const grant = trust.getGrantForPeer("skip-revoked-key");
      expect(grant).toBe(undefined);
    });

    it("should return undefined for unknown peer", () => {
      expect(trust.getGrantForPeer("unknown")).toBe(undefined);
    });
  });
});

describe("Key Rotation Processing", () => {
  let cleanup: (() => void) | undefined;
  let trust: any;

  beforeEach(async () => {
    cleanup = useTestDataDir();
    ({ trust } = await freshModules());
  });

  afterEach(() => {
    if (cleanup) {
      cleanup();
      cleanup = undefined;
    }
  });

  describe("processPeerKeyRotation", () => {
    it("should update grant key after valid rotation", async () => {
      const { identity } = await freshModules();
      ({ trust } = await freshModules());

      identity.initIdentity();
      const ident = identity.initIdentity(true);

      // Set up grant and peer with old key
      trust.grantAccess(ident.publicKey, ["s1"], ["message"], ident.encryptPub);
      trust.addPeer(ident.publicKey, ["s1"], ["message"], ident.encryptPub);

      // Rotate
      const { rotation } = identity.rotateIdentity();

      const result = trust.processPeerKeyRotation(rotation);
      expect(result).toBe(true);

      // Grant should now have new key
      const grants = trust.getAccessGrants();
      const updatedGrant = grants.find((g: AccessGrant) => g.peerKey === rotation.newSignPub);
      expect(updatedGrant).toBeTruthy();
      expect(updatedGrant!.keyHistory).toBeTruthy();
      expect(updatedGrant!.keyHistory![0].publicKey).toBe(rotation.oldSignPub);
    });

    it("should return false for invalid rotation signature", () => {
      const fakeRotation: KeyRotation = {
        v: 1,
        type: "key-rotation",
        oldSignPub: "fake-old",
        newSignPub: "fake-new",
        newEncryptPub: "fake-enc",
        reason: "scheduled",
        effectiveAt: Date.now(),
        gracePeriodMs: 86400000,
        sig: "invalid-sig",
      };

      expect(trust.processPeerKeyRotation(fakeRotation)).toBe(false);
    });

    it("should return false when no matching grant or peer exists", async () => {
      const { identity } = await freshModules();
      ({ trust } = await freshModules());

      identity.initIdentity();
      const { rotation } = identity.rotateIdentity();

      // No grants or peers set up for the old key
      const result = trust.processPeerKeyRotation(rotation);
      expect(result).toBe(false);
    });
  });
});

describe("Key History Cleanup", () => {
  let cleanup: (() => void) | undefined;
  let trust: any;

  beforeEach(async () => {
    cleanup = useTestDataDir();
    ({ trust } = await freshModules());
  });

  afterEach(() => {
    if (cleanup) {
      cleanup();
      cleanup = undefined;
    }
  });

  describe("cleanupExpiredKeyHistory", () => {
    it("should remove expired key history entries", () => {
      const grants: AccessGrant[] = [{
        id: "g-cleanup",
        peerKey: "current",
        sessions: ["s1"],
        caps: ["message"],
        created: Date.now(),
        keyHistory: [
          {
            publicKey: "expired-key",
            encryptPub: "enc",
            validFrom: Date.now() - 200000,
            validUntil: Date.now() - 100000, // Expired
          },
          {
            publicKey: "valid-key",
            encryptPub: "enc",
            validFrom: Date.now() - 50000,
            validUntil: Date.now() + 100000, // Still valid
          },
        ],
      }];
      trust.saveAccessGrants(grants);

      const peers: Peer[] = [{
        id: "p-cleanup",
        publicKey: "current",
        sessions: ["s1"],
        caps: ["message"],
        added: Date.now(),
        keyHistory: [
          {
            publicKey: "expired-peer-key",
            encryptPub: "enc",
            validFrom: Date.now() - 200000,
            validUntil: Date.now() - 100000, // Expired
          },
        ],
      }];
      trust.savePeers(peers);

      trust.cleanupExpiredKeyHistory();

      const updatedGrants = trust.getAccessGrants();
      expect(updatedGrants[0].keyHistory?.length).toBe(1);
      expect(updatedGrants[0].keyHistory?.[0].publicKey).toBe("valid-key");

      const updatedPeers = trust.getPeers();
      expect(updatedPeers[0].keyHistory?.length).toBe(0);
    });

    it("should not modify grants/peers without key history", () => {
      const grants: AccessGrant[] = [{
        id: "g-no-hist",
        peerKey: "key",
        sessions: ["s1"],
        caps: ["message"],
        created: Date.now(),
      }];
      trust.saveAccessGrants(grants);

      trust.cleanupExpiredKeyHistory();

      const loaded = trust.getAccessGrants();
      expect(loaded.length).toBe(1);
      expect(loaded[0].keyHistory).toBe(undefined);
    });

    it("should keep entries without validUntil", () => {
      const grants: AccessGrant[] = [{
        id: "g-no-expiry",
        peerKey: "key",
        sessions: ["s1"],
        caps: ["message"],
        created: Date.now(),
        keyHistory: [{
          publicKey: "permanent-key",
          encryptPub: "enc",
          validFrom: Date.now() - 200000,
          // No validUntil - should be kept
        }],
      }];
      trust.saveAccessGrants(grants);

      trust.cleanupExpiredKeyHistory();

      const loaded = trust.getAccessGrants();
      expect(loaded[0].keyHistory?.length).toBe(1);
    });
  });

  describe("getAllPeerKeys", () => {
    it("should return current key when no history", () => {
      const keys = trust.getAllPeerKeys("solo-key");
      expect(keys).toEqual(["solo-key"]);
    });

    it("should include historical keys from grants", () => {
      const grants: AccessGrant[] = [{
        id: "g-keys",
        peerKey: "current-key",
        sessions: ["s1"],
        caps: ["message"],
        created: Date.now(),
        keyHistory: [
          { publicKey: "old-key-1", encryptPub: "enc", validFrom: Date.now() - 100000 },
          { publicKey: "old-key-2", encryptPub: "enc", validFrom: Date.now() - 200000 },
        ],
      }];
      trust.saveAccessGrants(grants);

      const keys = trust.getAllPeerKeys("current-key");
      expect(keys.includes("current-key")).toBeTruthy();
      expect(keys.includes("old-key-1")).toBeTruthy();
      expect(keys.includes("old-key-2")).toBeTruthy();
      expect(keys.length).toBe(3);
    });

    it("should include historical keys from peers", () => {
      const peers: Peer[] = [{
        id: "p-keys",
        publicKey: "current-peer-key",
        sessions: ["s1"],
        caps: ["message"],
        added: Date.now(),
        keyHistory: [
          { publicKey: "peer-old-key", encryptPub: "enc", validFrom: Date.now() - 100000 },
        ],
      }];
      trust.savePeers(peers);

      const keys = trust.getAllPeerKeys("current-peer-key");
      expect(keys.includes("current-peer-key")).toBeTruthy();
      expect(keys.includes("peer-old-key")).toBeTruthy();
    });

    it("should not duplicate keys", () => {
      const grants: AccessGrant[] = [{
        id: "g-dup",
        peerKey: "dup-key",
        sessions: ["s1"],
        caps: ["message"],
        created: Date.now(),
        keyHistory: [
          { publicKey: "shared-old-key", encryptPub: "enc", validFrom: Date.now() },
        ],
      }];
      trust.saveAccessGrants(grants);

      const peers: Peer[] = [{
        id: "p-dup",
        publicKey: "dup-key",
        sessions: ["s1"],
        caps: ["message"],
        added: Date.now(),
        keyHistory: [
          { publicKey: "shared-old-key", encryptPub: "enc", validFrom: Date.now() },
        ],
      }];
      trust.savePeers(peers);

      const keys = trust.getAllPeerKeys("dup-key");
      expect(keys.filter((k: string) => k === "shared-old-key").length).toBe(1);
    });
  });
});

describe("useInvite", () => {
  let cleanup: (() => void) | undefined;
  let trust: any;

  beforeEach(async () => {
    cleanup = useTestDataDir();
    ({ trust } = await freshModules());
  });

  afterEach(() => {
    if (cleanup) {
      cleanup();
      cleanup = undefined;
    }
  });

  it("should add a peer from a valid invite token", async () => {
    const { identity } = await freshModules();
    ({ trust } = await freshModules());
    const issuer = identity.initIdentity();
    const token = identity.createInviteToken("target-pubkey", ["session-1"]);

    const peer = trust.useInvite(token);

    expect(peer.id).toBeTruthy();
    expect(peer.publicKey).toBe(issuer.publicKey);
    expect(peer.caps).toEqual(["inject"]);
    expect(peer.sessions.includes("session-1")).toBeTruthy();
  });

  it("should merge sessions for existing peer", async () => {
    const { identity } = await freshModules();
    ({ trust } = await freshModules());
    identity.initIdentity();
    const token1 = identity.createInviteToken("target-pubkey", ["session-1"]);
    const token2 = identity.createInviteToken("target-pubkey", ["session-2"]);

    trust.useInvite(token1);
    const peer = trust.useInvite(token2);

    expect(peer.sessions.includes("session-1")).toBeTruthy();
    expect(peer.sessions.includes("session-2")).toBeTruthy();
  });

  it("should create identity if none exists when using invite", async () => {
    const { identity } = await freshModules();
    ({ trust } = await freshModules());
    // Create a separate identity to sign the token, then wipe it
    identity.initIdentity();
    const token = identity.createInviteToken("target-pubkey", ["session-1"]);

    // Force remove identity file to simulate no identity
    rmSync(join(TEST_DATA_DIR, "identity.json"), { force: true });

    const peer = trust.useInvite(token);
    expect(peer.publicKey).toBeTruthy();
  });

  it("should persist the added peer", async () => {
    const { identity } = await freshModules();
    ({ trust } = await freshModules());
    identity.initIdentity();
    const token = identity.createInviteToken("target-pubkey", ["session-1"]);

    trust.useInvite(token);

    const peers = trust.getPeers();
    expect(peers.length).toBe(1);
  });
});
