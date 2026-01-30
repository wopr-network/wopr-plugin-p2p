/**
 * P2P Identity Management
 *
 * Handles Ed25519/X25519 keypairs, signing, encryption, and invite tokens.
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync } from "fs";
import {
  createHash,
  generateKeyPairSync,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
  randomBytes,
  diffieHellman,
  createCipheriv,
  createDecipheriv,
} from "crypto";
import { homedir } from "os";
import { join } from "path";
import type { Identity, InviteToken, EphemeralKeyPair, KeyRotation } from "./types.js";

// Data directory for P2P plugin
const P2P_DATA_DIR = join(homedir(), ".wopr", "p2p");
const IDENTITY_FILE = join(P2P_DATA_DIR, "identity.json");

function ensureDataDir(): void {
  if (!existsSync(P2P_DATA_DIR)) {
    mkdirSync(P2P_DATA_DIR, { recursive: true, mode: 0o700 });
  }
}

export function getIdentity(): Identity | null {
  if (!existsSync(IDENTITY_FILE)) return null;
  return JSON.parse(readFileSync(IDENTITY_FILE, "utf-8"));
}

export function saveIdentity(identity: Identity): void {
  ensureDataDir();
  writeFileSync(IDENTITY_FILE, JSON.stringify(identity, null, 2), { mode: 0o600 });
}

export function shortKey(publicKey: string): string {
  return createHash("sha256").update(publicKey).digest("hex").slice(0, 8);
}

export function getTopic(publicKey: string): Buffer {
  return createHash("sha256").update(publicKey).digest();
}

export function initIdentity(force = false): Identity {
  const existing = getIdentity();
  if (existing && !force) {
    throw new Error("Identity already exists. Use force to regenerate.");
  }

  // Ed25519 for signing
  const { publicKey, privateKey } = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "der" },
  });

  // X25519 for encryption
  const { publicKey: encPub, privateKey: encPriv } = generateKeyPairSync("x25519", {
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "der" },
  });

  const identity: Identity = {
    publicKey: publicKey.toString("base64"),
    privateKey: privateKey.toString("base64"),
    encryptPub: encPub.toString("base64"),
    encryptPriv: encPriv.toString("base64"),
    created: Date.now(),
  };

  saveIdentity(identity);
  return identity;
}

/**
 * Rotate identity keys. The old key signs the rotation message,
 * proving continuity to peers.
 */
export function rotateIdentity(reason: "scheduled" | "compromise" | "upgrade" = "scheduled"): {
  identity: Identity;
  rotation: KeyRotation;
} {
  const existing = getIdentity();
  if (!existing) {
    throw new Error("No identity to rotate");
  }

  // Generate new Ed25519 keypair
  const { publicKey, privateKey } = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "der" },
  });

  // Generate new X25519 keypair
  const { publicKey: encPub, privateKey: encPriv } = generateKeyPairSync("x25519", {
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "der" },
  });

  const newPubKey = publicKey.toString("base64");
  const newEncPub = encPub.toString("base64");

  // Create key rotation message, signed with OLD key
  const rotationData: Omit<KeyRotation, "sig"> = {
    v: 1,
    type: "key-rotation",
    oldSignPub: existing.publicKey,
    newSignPub: newPubKey,
    newEncryptPub: newEncPub,
    reason,
    effectiveAt: Date.now(),
    gracePeriodMs: 24 * 3600000, // 24 hours grace period (reduced from 7 days for security)
  };

  // Sign with OLD private key to prove continuity
  const oldPrivKey = createPrivateKey({
    key: Buffer.from(existing.privateKey, "base64"),
    format: "der",
    type: "pkcs8",
  });
  const signature = sign(null, Buffer.from(JSON.stringify(rotationData)), oldPrivKey);
  const rotation: KeyRotation = { ...rotationData, sig: signature.toString("base64") };

  // Create new identity
  const identity: Identity = {
    publicKey: newPubKey,
    privateKey: privateKey.toString("base64"),
    encryptPub: newEncPub,
    encryptPriv: encPriv.toString("base64"),
    created: Date.now(),
    rotatedFrom: existing.publicKey,
    rotatedAt: Date.now(),
  };

  saveIdentity(identity);
  return { identity, rotation };
}

/**
 * Verify a key rotation message.
 */
export function verifyKeyRotation(rotation: KeyRotation): boolean {
  const { sig, ...payload } = rotation;

  try {
    const oldPubKey = createPublicKey({
      key: Buffer.from(rotation.oldSignPub, "base64"),
      format: "der",
      type: "spki",
    });
    return verify(null, Buffer.from(JSON.stringify(payload)), oldPubKey, Buffer.from(sig, "base64"));
  } catch {
    return false;
  }
}

/**
 * Check if a key rotation is still in grace period.
 */
export function isInGracePeriod(rotation: KeyRotation): boolean {
  const now = Date.now();
  return now < rotation.effectiveAt + rotation.gracePeriodMs;
}

export function signMessage<T extends object>(msg: T): T & { sig: string } {
  const identity = getIdentity();
  if (!identity) throw new Error("No identity");

  const payload = JSON.stringify(msg);
  const privateKey = createPrivateKey({
    key: Buffer.from(identity.privateKey, "base64"),
    format: "der",
    type: "pkcs8",
  });
  const signature = sign(null, Buffer.from(payload), privateKey);

  return { ...msg, sig: signature.toString("base64") };
}

export function verifySignature(msg: { sig: string; from?: string; iss?: string }, signerKey?: string): boolean {
  const { sig, ...payload } = msg;
  const key = signerKey || (msg as any).from || (msg as any).iss;
  if (!key) return false;

  try {
    const publicKey = createPublicKey({
      key: Buffer.from(key, "base64"),
      format: "der",
      type: "spki",
    });
    return verify(null, Buffer.from(JSON.stringify(payload)), publicKey, Buffer.from(sig, "base64"));
  } catch {
    return false;
  }
}

// ============================================
// Ephemeral Keys for Forward Secrecy
// ============================================

/**
 * Generate an ephemeral X25519 keypair for forward secrecy.
 */
export function generateEphemeralKeyPair(ttlMs = 3600000): EphemeralKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("x25519", {
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "der" },
  });

  return {
    publicKey: publicKey.toString("base64"),
    privateKey: privateKey.toString("base64"),
    created: Date.now(),
    expiresAt: Date.now() + ttlMs,
  };
}

/**
 * Derive a shared secret using ephemeral keys (forward secrecy).
 */
export function deriveEphemeralSecret(ephemeralPriv: string, theirEphemeralPub: string): Buffer {
  const myPrivKey = createPrivateKey({
    key: Buffer.from(ephemeralPriv, "base64"),
    format: "der",
    type: "pkcs8",
  });

  const theirPubKey = createPublicKey({
    key: Buffer.from(theirEphemeralPub, "base64"),
    format: "der",
    type: "spki",
  });

  const secret = diffieHellman({ privateKey: myPrivKey, publicKey: theirPubKey });
  return createHash("sha256").update(secret).digest();
}

/**
 * Encrypt using ephemeral keys for forward secrecy.
 */
export function encryptWithEphemeral(plaintext: string, ephemeralPriv: string, theirEphemeralPub: string): string {
  const key = deriveEphemeralSecret(ephemeralPriv, theirEphemeralPub);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);

  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return Buffer.concat([iv, authTag, encrypted]).toString("base64");
}

/**
 * Decrypt using ephemeral keys for forward secrecy.
 */
export function decryptWithEphemeral(ciphertext: string, ephemeralPriv: string, theirEphemeralPub: string): string {
  const key = deriveEphemeralSecret(ephemeralPriv, theirEphemeralPub);
  const data = Buffer.from(ciphertext, "base64");

  const iv = data.subarray(0, 12);
  const authTag = data.subarray(12, 28);
  const encrypted = data.subarray(28);

  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(authTag);

  return decipher.update(encrypted) + decipher.final("utf8");
}

// ============================================
// Legacy Static Key Encryption
// ============================================

/**
 * Derive shared secret from static keys (no forward secrecy).
 */
export function deriveSharedSecret(theirEncryptPub: string): Buffer {
  const identity = getIdentity();
  if (!identity) throw new Error("No identity");

  const myPrivKey = createPrivateKey({
    key: Buffer.from(identity.encryptPriv, "base64"),
    format: "der",
    type: "pkcs8",
  });

  const theirPubKey = createPublicKey({
    key: Buffer.from(theirEncryptPub, "base64"),
    format: "der",
    type: "spki",
  });

  const secret = diffieHellman({ privateKey: myPrivKey, publicKey: theirPubKey });
  return createHash("sha256").update(secret).digest();
}

/**
 * Encrypt using static keys (AES-256-GCM).
 */
export function encryptMessage(plaintext: string, theirEncryptPub: string): string {
  const key = deriveSharedSecret(theirEncryptPub);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);

  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return Buffer.concat([iv, authTag, encrypted]).toString("base64");
}

/**
 * Decrypt using static keys (AES-256-GCM).
 */
export function decryptMessage(ciphertext: string, theirEncryptPub: string): string {
  const key = deriveSharedSecret(theirEncryptPub);
  const data = Buffer.from(ciphertext, "base64");

  const iv = data.subarray(0, 12);
  const authTag = data.subarray(12, 28);
  const encrypted = data.subarray(28);

  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(authTag);

  return decipher.update(encrypted) + decipher.final("utf8");
}

// ============================================
// Invite Tokens
// ============================================

export function createInviteToken(forPubkey: string, sessions: string[], expireHours = 168): string {
  const identity = getIdentity();
  if (!identity) throw new Error("No identity");

  const token: Omit<InviteToken, "sig"> = {
    v: 1,
    iss: identity.publicKey,
    sub: forPubkey,
    ses: sessions,
    cap: ["inject"],
    exp: Date.now() + expireHours * 3600000,
    nonce: randomBytes(16).toString("hex"),
  };

  const signed = signMessage(token);
  return "wop1://" + Buffer.from(JSON.stringify(signed)).toString("base64url");
}

export function parseInviteToken(tokenStr: string): InviteToken {
  if (!tokenStr.startsWith("wop1://")) {
    throw new Error("Invalid token format");
  }

  const encoded = tokenStr.slice(7);
  const token: InviteToken = JSON.parse(Buffer.from(encoded, "base64url").toString());

  if (Date.now() > token.exp) {
    throw new Error("Token expired");
  }

  if (!verifySignature(token, token.iss)) {
    throw new Error("Invalid signature");
  }

  return token;
}
