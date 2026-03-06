/**
 * Unit tests for the P2P Identity Management module
 *
 * Tests Ed25519/X25519 keypair generation, signing, verification,
 * key rotation, ephemeral keys, encryption/decryption, and invite tokens.
 */

import { describe, it, beforeEach, afterEach, expect, vi } from "vitest";
import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

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
  let getIdentity: any;
  let initIdentity: any;
  let signMessage: any;
  let verifySignature: any;
  let rotateIdentity: any;
  let verifyKeyRotation: any;
  let isInGracePeriod: any;

  beforeEach(async () => {
    cleanup = useTestDataDir();
    vi.resetModules();
    const mod = await import("../src/identity.js");
    getIdentity = mod.getIdentity;
    initIdentity = mod.initIdentity;
    signMessage = mod.signMessage;
    verifySignature = mod.verifySignature;
    rotateIdentity = mod.rotateIdentity;
    verifyKeyRotation = mod.verifyKeyRotation;
    isInGracePeriod = mod.isInGracePeriod;
  });

  afterEach(() => {
    if (cleanup) {
      cleanup();
      cleanup = undefined;
    }
  });

  describe("getIdentity", () => {
    it("should return null when no identity exists", () => {
      expect(getIdentity()).toBe(null);
    });

    it("should return saved identity", () => {
      const identity = initIdentity();
      const loaded = getIdentity();

      expect(loaded).toBeTruthy();
      expect(loaded!.publicKey).toBe(identity.publicKey);
      expect(loaded!.privateKey).toBe(identity.privateKey);
      expect(loaded!.encryptPub).toBe(identity.encryptPub);
      expect(loaded!.encryptPriv).toBe(identity.encryptPriv);
    });
  });

  describe("initIdentity", () => {
    it("should create a new identity with all key fields", () => {
      const identity = initIdentity();

      expect(identity.publicKey).toBeTruthy();
      expect(identity.privateKey).toBeTruthy();
      expect(identity.encryptPub).toBeTruthy();
      expect(identity.encryptPriv).toBeTruthy();
      expect(identity.created > 0).toBeTruthy();
    });

    it("should throw if identity already exists without force", () => {
      initIdentity();
      expect(() => initIdentity()).toThrow(/already exists/);
    });

    it("should regenerate identity with force=true", () => {
      const first = initIdentity();
      const second = initIdentity(true);

      expect(first.publicKey).not.toBe(second.publicKey);
      expect(first.privateKey).not.toBe(second.privateKey);
    });

    it("should generate valid base64 keys", () => {
      const identity = initIdentity();

      // All keys should be valid base64
      for (const field of ["publicKey", "privateKey", "encryptPub", "encryptPriv"] as const) {
        const buf = Buffer.from(identity[field], "base64");
        expect(buf.length > 0).toBeTruthy();
      }
    });
  });

  describe("signMessage / verifySignature", () => {
    it("should sign and verify a message", () => {
      const identity = initIdentity();
      const msg = { hello: "world", ts: Date.now() };
      const signed = signMessage(msg);

      expect(signed.sig).toBeTruthy();
      expect(signed.hello).toBe("world");

      const valid = verifySignature(signed, identity.publicKey);
      expect(valid).toBe(true);
    });

    it("should reject tampered message", () => {
      const identity = initIdentity();
      const signed = signMessage({ data: "original" });

      // Tamper with the payload
      const tampered = { ...signed, data: "tampered" };
      expect(verifySignature(tampered, identity.publicKey)).toBe(false);
    });

    it("should reject wrong signer key", () => {
      initIdentity();
      const signed = signMessage({ data: "test" });

      // Use a different identity's key
      const other = initIdentity(true);
      // Verify against the original key (which is no longer stored)
      // The signed message was created with old key, so verifying with new key should fail
      expect(verifySignature(signed, other.publicKey)).toBe(false);
    });

    it("should throw when no identity for signing", () => {
      expect(() => signMessage({ data: "test" })).toThrow(/No identity/);
    });

    it("should return false for invalid key in verifySignature", () => {
      expect(verifySignature({ sig: "bad", data: "test" }, "not-a-key")).toBe(false);
    });

    it("should return false when no signer key provided", () => {
      expect(verifySignature({ sig: "something" })).toBe(false);
    });
  });

  describe("rotateIdentity", () => {
    it("should generate new keys and a signed rotation message", () => {
      const original = initIdentity();
      const { identity, rotation } = rotateIdentity();

      // New keys should differ from original
      expect(identity.publicKey).not.toBe(original.publicKey);
      expect(identity.encryptPub).not.toBe(original.encryptPub);

      // Rotation metadata
      expect(rotation.type).toBe("key-rotation");
      expect(rotation.oldSignPub).toBe(original.publicKey);
      expect(rotation.newSignPub).toBe(identity.publicKey);
      expect(rotation.newEncryptPub).toBe(identity.encryptPub);
      expect(rotation.reason).toBe("scheduled");
      expect(rotation.sig).toBeTruthy();

      // Identity should track rotation
      expect(identity.rotatedFrom).toBe(original.publicKey);
      expect(identity.rotatedAt).toBeTruthy();
    });

    it("should throw when no identity to rotate", () => {
      expect(() => rotateIdentity()).toThrow(/No identity to rotate/);
    });

    it("should accept reason parameter", () => {
      initIdentity();
      const { rotation } = rotateIdentity("compromise");
      expect(rotation.reason).toBe("compromise");
    });
  });

  describe("verifyKeyRotation", () => {
    it("should verify a valid rotation message", () => {
      initIdentity();
      const { rotation } = rotateIdentity();
      expect(verifyKeyRotation(rotation)).toBe(true);
    });

    it("should reject a tampered rotation message", () => {
      initIdentity();
      const { rotation } = rotateIdentity();

      // Tamper with the new key
      const tampered = { ...rotation, newSignPub: "tampered-key" };
      expect(verifyKeyRotation(tampered)).toBe(false);
    });

    it("should reject rotation with invalid signature", () => {
      initIdentity();
      const { rotation } = rotateIdentity();

      const tampered = { ...rotation, sig: "invalidsig" };
      expect(verifyKeyRotation(tampered)).toBe(false);
    });
  });

  describe("isInGracePeriod", () => {
    it("should return true during grace period", () => {
      initIdentity();
      const { rotation } = rotateIdentity();
      expect(isInGracePeriod(rotation)).toBe(true);
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
      expect(isInGracePeriod(rotation)).toBe(false);
    });
  });
});

describe("shortKey / getTopic", () => {
  let shortKey: any;
  let getTopic: any;

  beforeEach(async () => {
    vi.resetModules();
    const mod = await import("../src/identity.js");
    shortKey = mod.shortKey;
    getTopic = mod.getTopic;
  });

  describe("shortKey", () => {
    it("should return 8-character hex string", () => {
      const result = shortKey("somePublicKey");
      expect(result.length).toBe(8);
      expect(/^[0-9a-f]+$/.test(result)).toBeTruthy();
    });

    it("should be deterministic", () => {
      expect(shortKey("key1")).toBe(shortKey("key1"));
    });

    it("should differ for different keys", () => {
      expect(shortKey("key1")).not.toBe(shortKey("key2"));
    });
  });

  describe("getTopic", () => {
    it("should return a 32-byte Buffer", () => {
      const topic = getTopic("someKey");
      expect(Buffer.isBuffer(topic)).toBeTruthy();
      expect(topic.length).toBe(32);
    });

    it("should be deterministic", () => {
      expect(getTopic("key1").equals(getTopic("key1"))).toBeTruthy();
    });
  });
});

describe("Ephemeral Keys", () => {
  let generateEphemeralKeyPair: any;
  let deriveEphemeralSecret: any;
  let encryptWithEphemeral: any;
  let decryptWithEphemeral: any;

  beforeEach(async () => {
    vi.resetModules();
    const mod = await import("../src/identity.js");
    generateEphemeralKeyPair = mod.generateEphemeralKeyPair;
    deriveEphemeralSecret = mod.deriveEphemeralSecret;
    encryptWithEphemeral = mod.encryptWithEphemeral;
    decryptWithEphemeral = mod.decryptWithEphemeral;
  });

  describe("generateEphemeralKeyPair", () => {
    it("should generate a keypair with correct fields", () => {
      const pair = generateEphemeralKeyPair();

      expect(pair.publicKey).toBeTruthy();
      expect(pair.privateKey).toBeTruthy();
      expect(pair.created > 0).toBeTruthy();
      expect(pair.expiresAt > pair.created).toBeTruthy();
    });

    it("should respect custom TTL", () => {
      const ttl = 5000;
      const pair = generateEphemeralKeyPair(ttl);
      const expectedExpiry = pair.created + ttl;

      // Allow 100ms tolerance
      expect(Math.abs(pair.expiresAt - expectedExpiry) < 100).toBeTruthy();
    });

    it("should generate unique keypairs", () => {
      const a = generateEphemeralKeyPair();
      const b = generateEphemeralKeyPair();
      expect(a.publicKey).not.toBe(b.publicKey);
      expect(a.privateKey).not.toBe(b.privateKey);
    });
  });

  describe("deriveEphemeralSecret", () => {
    it("should derive the same secret from both sides", () => {
      const alice = generateEphemeralKeyPair();
      const bob = generateEphemeralKeyPair();

      const secretA = deriveEphemeralSecret(alice.privateKey, bob.publicKey);
      const secretB = deriveEphemeralSecret(bob.privateKey, alice.publicKey);

      expect(secretA.equals(secretB)).toBeTruthy();
    });

    it("should return a 32-byte key", () => {
      const alice = generateEphemeralKeyPair();
      const bob = generateEphemeralKeyPair();

      const secret = deriveEphemeralSecret(alice.privateKey, bob.publicKey);
      expect(secret.length).toBe(32);
    });
  });

  describe("encryptWithEphemeral / decryptWithEphemeral", () => {
    it("should encrypt and decrypt a message", () => {
      const alice = generateEphemeralKeyPair();
      const bob = generateEphemeralKeyPair();

      const plaintext = "Hello, secure world!";
      const ciphertext = encryptWithEphemeral(plaintext, alice.privateKey, bob.publicKey);
      const decrypted = decryptWithEphemeral(ciphertext, bob.privateKey, alice.publicKey);

      expect(decrypted).toBe(plaintext);
    });

    it("should produce different ciphertexts for same plaintext (random IV)", () => {
      const alice = generateEphemeralKeyPair();
      const bob = generateEphemeralKeyPair();

      const ct1 = encryptWithEphemeral("same", alice.privateKey, bob.publicKey);
      const ct2 = encryptWithEphemeral("same", alice.privateKey, bob.publicKey);

      expect(ct1).not.toBe(ct2);
    });

    it("should fail to decrypt with wrong keys", () => {
      const alice = generateEphemeralKeyPair();
      const bob = generateEphemeralKeyPair();
      const eve = generateEphemeralKeyPair();

      const ciphertext = encryptWithEphemeral("secret", alice.privateKey, bob.publicKey);

      expect(() => {
        decryptWithEphemeral(ciphertext, eve.privateKey, alice.publicKey);
      }).toThrow();
    });

    it("should handle empty string", () => {
      const alice = generateEphemeralKeyPair();
      const bob = generateEphemeralKeyPair();

      const ciphertext = encryptWithEphemeral("", alice.privateKey, bob.publicKey);
      const decrypted = decryptWithEphemeral(ciphertext, bob.privateKey, alice.publicKey);

      expect(decrypted).toBe("");
    });

    it("should handle unicode content", () => {
      const alice = generateEphemeralKeyPair();
      const bob = generateEphemeralKeyPair();

      const plaintext = "Hello \u{1F30D} world \u{1F512}";
      const ciphertext = encryptWithEphemeral(plaintext, alice.privateKey, bob.publicKey);
      const decrypted = decryptWithEphemeral(ciphertext, bob.privateKey, alice.publicKey);

      expect(decrypted).toBe(plaintext);
    });
  });
});

describe("Static Key Encryption", () => {
  let cleanup: (() => void) | undefined;
  let generateEphemeralKeyPair: any;
  let deriveSharedSecret: any;
  let initIdentity: any;
  let encryptMessage: any;
  let decryptMessage: any;

  beforeEach(async () => {
    cleanup = useTestDataDir();
    vi.resetModules();
    const mod = await import("../src/identity.js");
    generateEphemeralKeyPair = mod.generateEphemeralKeyPair;
    deriveSharedSecret = mod.deriveSharedSecret;
    initIdentity = mod.initIdentity;
    encryptMessage = mod.encryptMessage;
    decryptMessage = mod.decryptMessage;
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
      expect(() => deriveSharedSecret(pair.publicKey)).toThrow(/No identity/);
    });
  });

  describe("encryptMessage / decryptMessage", () => {
    it("should encrypt and decrypt between two identities", () => {
      // Set up identity A
      const identityA = initIdentity();
      const _encryptPubA = identityA.encryptPub;

      // Set up identity B (force overwrite)
      const identityB = initIdentity(true);
      const encryptPubB = identityB.encryptPub;

      // B encrypts message for A... but we need A's identity loaded
      // Since we can only have one identity at a time, test within same identity
      // by encrypting with our own encrypt pub (self-encryption)
      const plaintext = "Secret message";
      const ciphertext = encryptMessage(plaintext, encryptPubB);
      const decrypted = decryptMessage(ciphertext, encryptPubB);

      expect(decrypted).toBe(plaintext);
    });
  });
});

describe("Invite Tokens", () => {
  let cleanup: (() => void) | undefined;
  let initIdentity: any;
  let signMessage: any;
  let createInviteToken: any;
  let parseInviteToken: any;

  beforeEach(async () => {
    cleanup = useTestDataDir();
    vi.resetModules();
    const mod = await import("../src/identity.js");
    initIdentity = mod.initIdentity;
    signMessage = mod.signMessage;
    createInviteToken = mod.createInviteToken;
    parseInviteToken = mod.parseInviteToken;
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

      expect(token.startsWith("wop1://")).toBeTruthy();
    });

    it("should throw when no identity exists", () => {
      expect(() => createInviteToken("target", ["s1"])).toThrow(/No identity/);
    });
  });

  describe("parseInviteToken", () => {
    it("should round-trip create and parse", () => {
      const identity = initIdentity();
      const token = createInviteToken("target-pubkey", ["session1", "session2"], 24);

      const parsed = parseInviteToken(token);

      expect(parsed.v).toBe(1);
      expect(parsed.iss).toBe(identity.publicKey);
      expect(parsed.sub).toBe("target-pubkey");
      expect(parsed.ses).toEqual(["session1", "session2"]);
      expect(parsed.cap).toEqual(["inject"]);
      expect(parsed.nonce).toBeTruthy();
      expect(parsed.sig).toBeTruthy();
    });

    it("should reject invalid prefix", () => {
      expect(() => parseInviteToken("bad://token")).toThrow(/Invalid token format/);
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
      const expiredToken = `wop1://${Buffer.from(JSON.stringify(signed)).toString("base64url")}`;

      expect(() => parseInviteToken(expiredToken)).toThrow(/expired/);
    });

    it("should reject tokens with invalid signatures", () => {
      initIdentity();
      const token = createInviteToken("target", ["s1"]);

      // Decode, tamper, re-encode
      const encoded = token.slice(7);
      const data = JSON.parse(Buffer.from(encoded, "base64url").toString());
      data.sub = "tampered-target";
      const tampered = `wop1://${Buffer.from(JSON.stringify(data)).toString("base64url")}`;

      expect(() => parseInviteToken(tampered)).toThrow(/Invalid signature/);
    });
  });
});
