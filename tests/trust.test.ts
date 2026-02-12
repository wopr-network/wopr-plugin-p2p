/**
 * Unit tests for the P2P Trust Management module
 *
 * Tests access grants, peer management, authorization checks,
 * key rotation processing, and expired key history cleanup.
 */

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert";
import { mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import {
  getAccessGrants,
  saveAccessGrants,
  getPeers,
  savePeers,
  isAuthorized,
  getGrantForPeer,
  findPeer,
  revokePeer,
  namePeer,
  grantAccess,
  addPeer,
  processPeerKeyRotation,
  cleanupExpiredKeyHistory,
  getAllPeerKeys,
} from "../src/trust.js";
import { initIdentity, shortKey, verifyKeyRotation, rotateIdentity } from "../src/identity.js";
import type { AccessGrant, Peer, KeyRotation } from "../src/types.js";

const TEST_DATA_DIR = join(tmpdir(), "wopr-p2p-test-trust-" + process.pid);

function useTestDataDir() {
  mkdirSync(TEST_DATA_DIR, { recursive: true });
  process.env.WOPR_P2P_DATA_DIR = TEST_DATA_DIR;
  return () => {
    delete process.env.WOPR_P2P_DATA_DIR;
    rmSync(TEST_DATA_DIR, { recursive: true, force: true });
  };
}

describe("Access Grants", () => {
  let cleanup: (() => void) | undefined;

  beforeEach(() => {
    cleanup = useTestDataDir();
  });

  afterEach(() => {
    if (cleanup) {
      cleanup();
      cleanup = undefined;
    }
  });

  describe("getAccessGrants / saveAccessGrants", () => {
    it("should return empty array when no file exists", () => {
      assert.deepStrictEqual(getAccessGrants(), []);
    });

    it("should round-trip save and load grants", () => {
      const grants: AccessGrant[] = [{
        id: "grant-1",
        peerKey: "key-1",
        sessions: ["session-a"],
        caps: ["message"],
        created: Date.now(),
      }];

      saveAccessGrants(grants);
      const loaded = getAccessGrants();

      assert.strictEqual(loaded.length, 1);
      assert.strictEqual(loaded[0].id, "grant-1");
      assert.strictEqual(loaded[0].peerKey, "key-1");
    });
  });

  describe("grantAccess", () => {
    it("should create a new grant", () => {
      initIdentity();
      addPeer("peer-key-1", ["s1"], ["message"]);
      const grant = grantAccess("peer-key-1", ["session-1"], ["message"]);

      assert.ok(grant.id.startsWith("grant-"));
      assert.strictEqual(grant.peerKey, "peer-key-1");
      assert.deepStrictEqual(grant.sessions, ["session-1"]);
      assert.deepStrictEqual(grant.caps, ["message"]);
    });

    it("should merge sessions and caps for existing grant", () => {
      grantAccess("peer-key-2", ["session-1"], ["message"]);
      const updated = grantAccess("peer-key-2", ["session-2"], ["inject"]);

      assert.ok(updated.sessions.includes("session-1"));
      assert.ok(updated.sessions.includes("session-2"));
      assert.ok(updated.caps.includes("message"));
      assert.ok(updated.caps.includes("inject"));
    });

    it("should not duplicate sessions or caps", () => {
      grantAccess("peer-key-3", ["s1"], ["message"]);
      const updated = grantAccess("peer-key-3", ["s1"], ["message"]);

      assert.strictEqual(updated.sessions.filter(s => s === "s1").length, 1);
      assert.strictEqual(updated.caps.filter(c => c === "message").length, 1);
    });

    it("should store encryptPub when provided", () => {
      const grant = grantAccess("peer-key-4", ["s1"], ["message"], "encrypt-pub");

      assert.strictEqual(grant.peerEncryptPub, "encrypt-pub");
    });
  });
});

describe("Peer Management", () => {
  let cleanup: (() => void) | undefined;

  beforeEach(() => {
    cleanup = useTestDataDir();
  });

  afterEach(() => {
    if (cleanup) {
      cleanup();
      cleanup = undefined;
    }
  });

  describe("getPeers / savePeers", () => {
    it("should return empty array when no file exists", () => {
      assert.deepStrictEqual(getPeers(), []);
    });

    it("should round-trip save and load peers", () => {
      const peers: Peer[] = [{
        id: "abcd1234",
        publicKey: "pub-key-1",
        sessions: ["s1"],
        caps: ["message"],
        added: Date.now(),
      }];

      savePeers(peers);
      const loaded = getPeers();

      assert.strictEqual(loaded.length, 1);
      assert.strictEqual(loaded[0].publicKey, "pub-key-1");
    });
  });

  describe("addPeer", () => {
    it("should add a new peer", () => {
      const peer = addPeer("new-pub-key", ["s1"], ["message"]);

      assert.ok(peer.id);
      assert.strictEqual(peer.publicKey, "new-pub-key");
      assert.deepStrictEqual(peer.sessions, ["s1"]);
      assert.deepStrictEqual(peer.caps, ["message"]);
    });

    it("should merge data for existing peer", () => {
      addPeer("same-key", ["s1"], ["message"]);
      const updated = addPeer("same-key", ["s2"], ["inject"]);

      assert.ok(updated.sessions.includes("s1"));
      assert.ok(updated.sessions.includes("s2"));
      assert.ok(updated.caps.includes("message"));
      assert.ok(updated.caps.includes("inject"));
    });

    it("should update encryptPub when provided", () => {
      addPeer("ep-key", ["s1"], ["message"]);
      const updated = addPeer("ep-key", ["s1"], ["message"], "new-encrypt");

      assert.strictEqual(updated.encryptPub, "new-encrypt");
    });
  });

  describe("findPeer", () => {
    it("should find by public key", () => {
      addPeer("find-by-key", ["s1"], ["message"]);
      const found = findPeer("find-by-key");

      assert.ok(found);
      assert.strictEqual(found.publicKey, "find-by-key");
    });

    it("should find by short ID", () => {
      addPeer("find-by-id-key", ["s1"], ["message"]);
      const id = shortKey("find-by-id-key");
      const found = findPeer(id);

      assert.ok(found);
      assert.strictEqual(found.publicKey, "find-by-id-key");
    });

    it("should find by name (case insensitive)", () => {
      addPeer("named-key", ["s1"], ["message"]);
      namePeer("named-key", "Alice");

      const found = findPeer("alice");
      assert.ok(found);
      assert.strictEqual(found.name, "Alice");
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
      savePeers(peers);

      const found = findPeer("old-key");
      assert.ok(found);
      assert.strictEqual(found.publicKey, "current-key");
    });

    it("should return undefined for unknown peer", () => {
      assert.strictEqual(findPeer("nonexistent"), undefined);
    });
  });

  describe("namePeer", () => {
    it("should set a peer name", () => {
      addPeer("name-key", ["s1"], ["message"]);
      namePeer("name-key", "Bob");

      const peer = findPeer("name-key");
      assert.ok(peer);
      assert.strictEqual(peer.name, "Bob");
    });

    it("should throw for unknown peer", () => {
      assert.throws(() => namePeer("unknown", "Name"), /Peer not found/);
    });
  });

  describe("revokePeer", () => {
    it("should revoke an active grant", () => {
      grantAccess("revoke-key", ["s1"], ["message"]);

      revokePeer(shortKey("revoke-key"));

      const grants = getAccessGrants();
      const grant = grants.find(g => g.peerKey === "revoke-key");
      assert.ok(grant);
      assert.strictEqual(grant.revoked, true);
    });

    it("should throw for unknown peer", () => {
      assert.throws(() => revokePeer("nonexistent"), /No active grant found/);
    });

    it("should not revoke already revoked grant", () => {
      grantAccess("double-revoke-key", ["s1"], ["message"]);
      revokePeer(shortKey("double-revoke-key"));

      // Second revoke should throw because the grant is already revoked
      assert.throws(() => revokePeer(shortKey("double-revoke-key")), /No active grant found/);
    });
  });
});

describe("Authorization", () => {
  let cleanup: (() => void) | undefined;

  beforeEach(() => {
    cleanup = useTestDataDir();
  });

  afterEach(() => {
    if (cleanup) {
      cleanup();
      cleanup = undefined;
    }
  });

  describe("isAuthorized", () => {
    it("should authorize peer with matching session", () => {
      grantAccess("auth-key", ["session-1"], ["message"]);
      assert.strictEqual(isAuthorized("auth-key", "session-1"), true);
    });

    it("should authorize peer with wildcard session", () => {
      grantAccess("wildcard-key", ["*"], ["message"]);
      assert.strictEqual(isAuthorized("wildcard-key", "any-session"), true);
    });

    it("should authorize peer with inject capability", () => {
      grantAccess("inject-key", ["s1"], ["inject"]);
      assert.strictEqual(isAuthorized("inject-key", "s1"), true);
    });

    it("should deny peer with wrong session", () => {
      grantAccess("wrong-session-key", ["session-1"], ["message"]);
      assert.strictEqual(isAuthorized("wrong-session-key", "session-2"), false);
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
      saveAccessGrants(grants);

      assert.strictEqual(isAuthorized("nocap-key", "s1"), false);
    });

    it("should deny revoked peer", () => {
      grantAccess("revoked-key", ["s1"], ["message"]);
      revokePeer(shortKey("revoked-key"));

      assert.strictEqual(isAuthorized("revoked-key", "s1"), false);
    });

    it("should deny unknown peer", () => {
      assert.strictEqual(isAuthorized("unknown-key", "s1"), false);
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
      saveAccessGrants(grants);

      assert.strictEqual(isAuthorized("old-key", "s1"), true);
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
      saveAccessGrants(grants);

      assert.strictEqual(isAuthorized("expired-key", "s1"), false);
    });
  });

  describe("getGrantForPeer", () => {
    it("should find grant by current key", () => {
      grantAccess("grant-peer-key", ["s1"], ["message"]);
      const grant = getGrantForPeer("grant-peer-key");

      assert.ok(grant);
      assert.strictEqual(grant.peerKey, "grant-peer-key");
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
      saveAccessGrants(grants);

      const grant = getGrantForPeer("historical-key");
      assert.ok(grant);
      assert.strictEqual(grant.peerKey, "current-key");
    });

    it("should skip revoked grants for current key", () => {
      grantAccess("skip-revoked-key", ["s1"], ["message"]);
      revokePeer(shortKey("skip-revoked-key"));

      const grant = getGrantForPeer("skip-revoked-key");
      assert.strictEqual(grant, undefined);
    });

    it("should return undefined for unknown peer", () => {
      assert.strictEqual(getGrantForPeer("unknown"), undefined);
    });
  });
});

describe("Key Rotation Processing", () => {
  let cleanup: (() => void) | undefined;

  beforeEach(() => {
    cleanup = useTestDataDir();
  });

  afterEach(() => {
    if (cleanup) {
      cleanup();
      cleanup = undefined;
    }
  });

  describe("processPeerKeyRotation", () => {
    it("should update grant key after valid rotation", () => {
      initIdentity();
      const identity = initIdentity(true);

      // Set up grant and peer with old key
      grantAccess(identity.publicKey, ["s1"], ["message"], identity.encryptPub);
      addPeer(identity.publicKey, ["s1"], ["message"], identity.encryptPub);

      // Rotate
      const { rotation } = rotateIdentity();

      const result = processPeerKeyRotation(rotation);
      assert.strictEqual(result, true);

      // Grant should now have new key
      const grants = getAccessGrants();
      const updatedGrant = grants.find(g => g.peerKey === rotation.newSignPub);
      assert.ok(updatedGrant, "Grant should have new key");
      assert.ok(updatedGrant.keyHistory, "Should have key history");
      assert.strictEqual(updatedGrant.keyHistory[0].publicKey, rotation.oldSignPub);
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

      assert.strictEqual(processPeerKeyRotation(fakeRotation), false);
    });

    it("should return false when no matching grant or peer exists", () => {
      initIdentity();
      const { rotation } = rotateIdentity();

      // No grants or peers set up for the old key
      const result = processPeerKeyRotation(rotation);
      assert.strictEqual(result, false);
    });
  });
});

describe("Key History Cleanup", () => {
  let cleanup: (() => void) | undefined;

  beforeEach(() => {
    cleanup = useTestDataDir();
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
      saveAccessGrants(grants);

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
      savePeers(peers);

      cleanupExpiredKeyHistory();

      const updatedGrants = getAccessGrants();
      assert.strictEqual(updatedGrants[0].keyHistory?.length, 1);
      assert.strictEqual(updatedGrants[0].keyHistory?.[0].publicKey, "valid-key");

      const updatedPeers = getPeers();
      assert.strictEqual(updatedPeers[0].keyHistory?.length, 0);
    });

    it("should not modify grants/peers without key history", () => {
      const grants: AccessGrant[] = [{
        id: "g-no-hist",
        peerKey: "key",
        sessions: ["s1"],
        caps: ["message"],
        created: Date.now(),
      }];
      saveAccessGrants(grants);

      cleanupExpiredKeyHistory();

      const loaded = getAccessGrants();
      assert.strictEqual(loaded.length, 1);
      assert.strictEqual(loaded[0].keyHistory, undefined);
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
      saveAccessGrants(grants);

      cleanupExpiredKeyHistory();

      const loaded = getAccessGrants();
      assert.strictEqual(loaded[0].keyHistory?.length, 1);
    });
  });

  describe("getAllPeerKeys", () => {
    it("should return current key when no history", () => {
      const keys = getAllPeerKeys("solo-key");
      assert.deepStrictEqual(keys, ["solo-key"]);
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
      saveAccessGrants(grants);

      const keys = getAllPeerKeys("current-key");
      assert.ok(keys.includes("current-key"));
      assert.ok(keys.includes("old-key-1"));
      assert.ok(keys.includes("old-key-2"));
      assert.strictEqual(keys.length, 3);
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
      savePeers(peers);

      const keys = getAllPeerKeys("current-peer-key");
      assert.ok(keys.includes("current-peer-key"));
      assert.ok(keys.includes("peer-old-key"));
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
      saveAccessGrants(grants);

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
      savePeers(peers);

      const keys = getAllPeerKeys("dup-key");
      assert.strictEqual(keys.filter(k => k === "shared-old-key").length, 1);
    });
  });
});
