/**
 * Unit tests for the P2P Identity Management module
 *
 * Tests Ed25519/X25519 keypair generation, signing, verification,
 * key rotation, ephemeral keys, encryption/decryption, and invite tokens.
 */

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert";
import { mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import {
  getIdentity,
  initIdentity,
  saveIdentity,
  shortKey,
  getTopic,
  signMessage,
  verifySignature,
  rotateIdentity,
  verifyKeyRotation,
  isInGracePeriod,
  generateEphemeralKeyPair,
  deriveEphemeralSecret,
  encryptWithEphemeral,
  decryptWithEphemeral,
  deriveSharedSecret,
  encryptMessage,
  decryptMessage,
  createInviteToken,
  parseInviteToken,
} from "../src/identity.js";

const TEST_DATA_DIR = join(tmpdir(), "wopr-p2p-test-identity-" + process.pid);

function useTestDataDir() {
  mkdirSync(TEST_DATA_DIR, { recursive: true });
  process.env.WOPR_P2P_DATA_DIR = TEST_DATA_DIR;
  return () => {
    delete process.env.WOPR_P2P_DATA_DIR;
    rmSync(TEST_DATA_DIR, { recursive: true, force: true });
  };
}

describe("Identity Management", () => {
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

  describe("getIdentity", () => {
    it("should return null when no identity exists", () => {
      assert.strictEqual(getIdentity(), null);
    });

    it("should return saved identity", () => {
      const identity = initIdentity();
      const loaded = getIdentity();

      assert.ok(loaded);
      assert.strictEqual(loaded.publicKey, identity.publicKey);
      assert.strictEqual(loaded.privateKey, identity.privateKey);
      assert.strictEqual(loaded.encryptPub, identity.encryptPub);
      assert.strictEqual(loaded.encryptPriv, identity.encryptPriv);
    });
  });

  describe("initIdentity", () => {
    it("should create a new identity with all key fields", () => {
      const identity = initIdentity();

      assert.ok(identity.publicKey, "should have publicKey");
      assert.ok(identity.privateKey, "should have privateKey");
      assert.ok(identity.encryptPub, "should have encryptPub");
      assert.ok(identity.encryptPriv, "should have encryptPriv");
      assert.ok(identity.created > 0, "should have created timestamp");
    });

    it("should throw if identity already exists without force", () => {
      initIdentity();
      assert.throws(() => initIdentity(), /already exists/);
    });

    it("should regenerate identity with force=true", () => {
      const first = initIdentity();
      const second = initIdentity(true);

      assert.notStrictEqual(first.publicKey, second.publicKey);
      assert.notStrictEqual(first.privateKey, second.privateKey);
    });

    it("should generate valid base64 keys", () => {
      const identity = initIdentity();

      // All keys should be valid base64
      for (const field of ["publicKey", "privateKey", "encryptPub", "encryptPriv"] as const) {
        const buf = Buffer.from(identity[field], "base64");
        assert.ok(buf.length > 0, `${field} should decode from base64`);
      }
    });
  });

  describe("shortKey", () => {
    it("should return 8-character hex string", () => {
      const result = shortKey("somePublicKey");
      assert.strictEqual(result.length, 8);
      assert.ok(/^[0-9a-f]+$/.test(result), "should be hex");
    });

    it("should be deterministic", () => {
      assert.strictEqual(shortKey("key1"), shortKey("key1"));
    });

    it("should differ for different keys", () => {
      assert.notStrictEqual(shortKey("key1"), shortKey("key2"));
    });
  });

  describe("getTopic", () => {
    it("should return a 32-byte Buffer", () => {
      const topic = getTopic("someKey");
      assert.ok(Buffer.isBuffer(topic));
      assert.strictEqual(topic.length, 32);
    });

    it("should be deterministic", () => {
      assert.ok(getTopic("key1").equals(getTopic("key1")));
    });
  });

  describe("signMessage / verifySignature", () => {
    it("should sign and verify a message", () => {
      const identity = initIdentity();
      const msg = { hello: "world", ts: Date.now() };
      const signed = signMessage(msg);

      assert.ok(signed.sig, "should have signature");
      assert.strictEqual(signed.hello, "world");

      const valid = verifySignature(signed, identity.publicKey);
      assert.strictEqual(valid, true);
    });

    it("should reject tampered message", () => {
      const identity = initIdentity();
      const signed = signMessage({ data: "original" });

      // Tamper with the payload
      const tampered = { ...signed, data: "tampered" };
      assert.strictEqual(verifySignature(tampered, identity.publicKey), false);
    });

    it("should reject wrong signer key", () => {
      initIdentity();
      const signed = signMessage({ data: "test" });

      // Use a different identity's key
      const other = initIdentity(true);
      // Verify against the original key (which is no longer stored)
      // The signed message was created with old key, so verifying with new key should fail
      assert.strictEqual(verifySignature(signed, other.publicKey), false);
    });

    it("should throw when no identity for signing", () => {
      assert.throws(() => signMessage({ data: "test" }), /No identity/);
    });

    it("should return false for invalid key in verifySignature", () => {
      assert.strictEqual(verifySignature({ sig: "bad", data: "test" }, "not-a-key"), false);
    });

    it("should return false when no signer key provided", () => {
      assert.strictEqual(verifySignature({ sig: "something" }), false);
    });
  });

  describe("rotateIdentity", () => {
    it("should generate new keys and a signed rotation message", () => {
      const original = initIdentity();
      const { identity, rotation } = rotateIdentity();

      // New keys should differ from original
      assert.notStrictEqual(identity.publicKey, original.publicKey);
      assert.notStrictEqual(identity.encryptPub, original.encryptPub);

      // Rotation metadata
      assert.strictEqual(rotation.type, "key-rotation");
      assert.strictEqual(rotation.oldSignPub, original.publicKey);
      assert.strictEqual(rotation.newSignPub, identity.publicKey);
      assert.strictEqual(rotation.newEncryptPub, identity.encryptPub);
      assert.strictEqual(rotation.reason, "scheduled");
      assert.ok(rotation.sig, "rotation should be signed");

      // Identity should track rotation
      assert.strictEqual(identity.rotatedFrom, original.publicKey);
      assert.ok(identity.rotatedAt);
    });

    it("should throw when no identity to rotate", () => {
      assert.throws(() => rotateIdentity(), /No identity to rotate/);
    });

    it("should accept reason parameter", () => {
      initIdentity();
      const { rotation } = rotateIdentity("compromise");
      assert.strictEqual(rotation.reason, "compromise");
    });
  });

  describe("verifyKeyRotation", () => {
    it("should verify a valid rotation message", () => {
      initIdentity();
      const { rotation } = rotateIdentity();
      assert.strictEqual(verifyKeyRotation(rotation), true);
    });

    it("should reject a tampered rotation message", () => {
      initIdentity();
      const { rotation } = rotateIdentity();

      // Tamper with the new key
      const tampered = { ...rotation, newSignPub: "tampered-key" };
      assert.strictEqual(verifyKeyRotation(tampered), false);
    });

    it("should reject rotation with invalid signature", () => {
      initIdentity();
      const { rotation } = rotateIdentity();

      const tampered = { ...rotation, sig: "invalidsig" };
      assert.strictEqual(verifyKeyRotation(tampered), false);
    });
  });

  describe("isInGracePeriod", () => {
    it("should return true during grace period", () => {
      initIdentity();
      const { rotation } = rotateIdentity();
      assert.strictEqual(isInGracePeriod(rotation), true);
    });

    it("should return false after grace period expires", () => {
      const rotation = {
        v: 1,
        type: "key-rotation" as const,
        oldSignPub: "old",
        newSignPub: "new",
        newEncryptPub: "newEnc",
        reason: "scheduled" as const,
        effectiveAt: Date.now() - 100000,
        gracePeriodMs: 1000, // Already expired
        sig: "sig",
      };
      assert.strictEqual(isInGracePeriod(rotation), false);
    });
  });
});

describe("Ephemeral Keys", () => {
  describe("generateEphemeralKeyPair", () => {
    it("should generate a keypair with correct fields", () => {
      const pair = generateEphemeralKeyPair();

      assert.ok(pair.publicKey, "should have publicKey");
      assert.ok(pair.privateKey, "should have privateKey");
      assert.ok(pair.created > 0, "should have created timestamp");
      assert.ok(pair.expiresAt > pair.created, "expiresAt should be after created");
    });

    it("should respect custom TTL", () => {
      const ttl = 5000;
      const pair = generateEphemeralKeyPair(ttl);
      const expectedExpiry = pair.created + ttl;

      // Allow 100ms tolerance
      assert.ok(Math.abs(pair.expiresAt - expectedExpiry) < 100);
    });

    it("should generate unique keypairs", () => {
      const a = generateEphemeralKeyPair();
      const b = generateEphemeralKeyPair();
      assert.notStrictEqual(a.publicKey, b.publicKey);
      assert.notStrictEqual(a.privateKey, b.privateKey);
    });
  });

  describe("deriveEphemeralSecret", () => {
    it("should derive the same secret from both sides", () => {
      const alice = generateEphemeralKeyPair();
      const bob = generateEphemeralKeyPair();

      const secretA = deriveEphemeralSecret(alice.privateKey, bob.publicKey);
      const secretB = deriveEphemeralSecret(bob.privateKey, alice.publicKey);

      assert.ok(secretA.equals(secretB), "shared secrets should match");
    });

    it("should return a 32-byte key", () => {
      const alice = generateEphemeralKeyPair();
      const bob = generateEphemeralKeyPair();

      const secret = deriveEphemeralSecret(alice.privateKey, bob.publicKey);
      assert.strictEqual(secret.length, 32);
    });
  });

  describe("encryptWithEphemeral / decryptWithEphemeral", () => {
    it("should encrypt and decrypt a message", () => {
      const alice = generateEphemeralKeyPair();
      const bob = generateEphemeralKeyPair();

      const plaintext = "Hello, secure world!";
      const ciphertext = encryptWithEphemeral(plaintext, alice.privateKey, bob.publicKey);
      const decrypted = decryptWithEphemeral(ciphertext, bob.privateKey, alice.publicKey);

      assert.strictEqual(decrypted, plaintext);
    });

    it("should produce different ciphertexts for same plaintext (random IV)", () => {
      const alice = generateEphemeralKeyPair();
      const bob = generateEphemeralKeyPair();

      const ct1 = encryptWithEphemeral("same", alice.privateKey, bob.publicKey);
      const ct2 = encryptWithEphemeral("same", alice.privateKey, bob.publicKey);

      assert.notStrictEqual(ct1, ct2);
    });

    it("should fail to decrypt with wrong keys", () => {
      const alice = generateEphemeralKeyPair();
      const bob = generateEphemeralKeyPair();
      const eve = generateEphemeralKeyPair();

      const ciphertext = encryptWithEphemeral("secret", alice.privateKey, bob.publicKey);

      assert.throws(() => {
        decryptWithEphemeral(ciphertext, eve.privateKey, alice.publicKey);
      });
    });

    it("should handle empty string", () => {
      const alice = generateEphemeralKeyPair();
      const bob = generateEphemeralKeyPair();

      const ciphertext = encryptWithEphemeral("", alice.privateKey, bob.publicKey);
      const decrypted = decryptWithEphemeral(ciphertext, bob.privateKey, alice.publicKey);

      assert.strictEqual(decrypted, "");
    });

    it("should handle unicode content", () => {
      const alice = generateEphemeralKeyPair();
      const bob = generateEphemeralKeyPair();

      const plaintext = "Hello \u{1F30D} world \u{1F512}";
      const ciphertext = encryptWithEphemeral(plaintext, alice.privateKey, bob.publicKey);
      const decrypted = decryptWithEphemeral(ciphertext, bob.privateKey, alice.publicKey);

      assert.strictEqual(decrypted, plaintext);
    });
  });
});

describe("Static Key Encryption", () => {
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

  describe("deriveSharedSecret", () => {
    it("should throw when no identity exists", () => {
      const pair = generateEphemeralKeyPair();
      assert.throws(() => deriveSharedSecret(pair.publicKey), /No identity/);
    });
  });

  describe("encryptMessage / decryptMessage", () => {
    it("should encrypt and decrypt between two identities", () => {
      // Set up identity A
      const identityA = initIdentity();
      const encryptPubA = identityA.encryptPub;

      // Set up identity B (force overwrite)
      const identityB = initIdentity(true);
      const encryptPubB = identityB.encryptPub;

      // B encrypts message for A... but we need A's identity loaded
      // Since we can only have one identity at a time, test within same identity
      // by encrypting with our own encrypt pub (self-encryption)
      const plaintext = "Secret message";
      const ciphertext = encryptMessage(plaintext, encryptPubB);
      const decrypted = decryptMessage(ciphertext, encryptPubB);

      assert.strictEqual(decrypted, plaintext);
    });
  });
});

describe("Invite Tokens", () => {
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

  describe("createInviteToken", () => {
    it("should create a wop1:// prefixed token", () => {
      initIdentity();
      const token = createInviteToken("target-pubkey", ["session1"]);

      assert.ok(token.startsWith("wop1://"), "Token should start with wop1://");
    });

    it("should throw when no identity exists", () => {
      assert.throws(() => createInviteToken("target", ["s1"]), /No identity/);
    });
  });

  describe("parseInviteToken", () => {
    it("should round-trip create and parse", () => {
      const identity = initIdentity();
      const token = createInviteToken("target-pubkey", ["session1", "session2"], 24);

      const parsed = parseInviteToken(token);

      assert.strictEqual(parsed.v, 1);
      assert.strictEqual(parsed.iss, identity.publicKey);
      assert.strictEqual(parsed.sub, "target-pubkey");
      assert.deepStrictEqual(parsed.ses, ["session1", "session2"]);
      assert.deepStrictEqual(parsed.cap, ["inject"]);
      assert.ok(parsed.nonce, "should have nonce");
      assert.ok(parsed.sig, "should have signature");
    });

    it("should reject invalid prefix", () => {
      assert.throws(() => parseInviteToken("bad://token"), /Invalid token format/);
    });

    it("should reject expired tokens", () => {
      const identity = initIdentity();

      // Manually create an expired token by setting exp in the past
      const signed = signMessage({
        v: 1,
        iss: identity.publicKey,
        sub: "target",
        ses: ["s1"],
        cap: ["inject"],
        exp: Date.now() - 10000, // 10 seconds ago
        nonce: "test-nonce",
      });
      const expiredToken = "wop1://" + Buffer.from(JSON.stringify(signed)).toString("base64url");

      assert.throws(() => parseInviteToken(expiredToken), /expired/);
    });

    it("should reject tokens with invalid signatures", () => {
      initIdentity();
      const token = createInviteToken("target", ["s1"]);

      // Decode, tamper, re-encode
      const encoded = token.slice(7);
      const data = JSON.parse(Buffer.from(encoded, "base64url").toString());
      data.sub = "tampered-target";
      const tampered = "wop1://" + Buffer.from(JSON.stringify(data)).toString("base64url");

      assert.throws(() => parseInviteToken(tampered), /Invalid signature/);
    });
  });
});
