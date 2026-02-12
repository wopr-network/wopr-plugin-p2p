/**
 * P2P Trust Management
 *
 * Handles access grants, peer management, and key rotation.
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync } from "fs";
import { homedir } from "os";
import { join } from "path";
import type { AccessGrant, Peer, KeyRotation, KeyHistory } from "./types.js";
import { getIdentity, initIdentity, shortKey, parseInviteToken, verifyKeyRotation } from "./identity.js";

// Data directory for P2P plugin (overridable via WOPR_P2P_DATA_DIR for testing)
function getP2PDataDir(): string {
  return process.env.WOPR_P2P_DATA_DIR
    ?? (existsSync("/data") ? "/data/p2p" : join(homedir(), ".wopr", "p2p"));
}

function getAccessFile(): string {
  return join(getP2PDataDir(), "access.json");
}

function getPeersFile(): string {
  return join(getP2PDataDir(), "peers.json");
}

function ensureDataDir(): void {
  const dir = getP2PDataDir();
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
}

export function getAccessGrants(): AccessGrant[] {
  const file = getAccessFile();
  if (!existsSync(file)) return [];
  return JSON.parse(readFileSync(file, "utf-8"));
}

export function saveAccessGrants(grants: AccessGrant[]): void {
  ensureDataDir();
  writeFileSync(getAccessFile(), JSON.stringify(grants, null, 2), { mode: 0o600 });
}

export function getPeers(): Peer[] {
  const file = getPeersFile();
  if (!existsSync(file)) return [];
  return JSON.parse(readFileSync(file, "utf-8"));
}

export function savePeers(peers: Peer[]): void {
  ensureDataDir();
  writeFileSync(getPeersFile(), JSON.stringify(peers, null, 2), { mode: 0o600 });
}

/**
 * Check if a sender is authorized for a session.
 */
export function isAuthorized(senderKey: string, session: string): boolean {
  const grants = getAccessGrants();

  // Check current key - accept either "inject" or "message" capability
  const hasMessageCap = (caps: string[]) => caps.includes("inject") || caps.includes("message");

  let grant = grants.find(g =>
    !g.revoked &&
    g.peerKey === senderKey &&
    (g.sessions.includes("*") || g.sessions.includes(session)) &&
    hasMessageCap(g.caps)
  );

  if (grant) return true;

  // Check key history (for rotated keys in grace period)
  for (const g of grants) {
    if (g.revoked || !g.keyHistory) continue;
    if (!g.sessions.includes("*") && !g.sessions.includes(session)) continue;
    if (!hasMessageCap(g.caps)) continue;

    for (const history of g.keyHistory) {
      if (history.publicKey === senderKey) {
        if (history.validUntil && Date.now() < history.validUntil) {
          return true;
        }
      }
    }
  }

  return false;
}

/**
 * Get grant for peer, including by historical keys.
 */
export function getGrantForPeer(peerKey: string): AccessGrant | undefined {
  const grants = getAccessGrants();

  let grant = grants.find(g => !g.revoked && g.peerKey === peerKey);
  if (grant) return grant;

  // Check key history
  for (const g of grants) {
    if (g.revoked || !g.keyHistory) continue;
    for (const history of g.keyHistory) {
      if (history.publicKey === peerKey) {
        return g;
      }
    }
  }

  return undefined;
}

/**
 * Find peer by ID, name, or public key.
 */
export function findPeer(idOrName: string): Peer | undefined {
  const peers = getPeers();

  let peer = peers.find(p =>
    p.id === idOrName ||
    p.name?.toLowerCase() === idOrName.toLowerCase() ||
    p.publicKey === idOrName
  );

  if (peer) return peer;

  // Search key history
  for (const p of peers) {
    if (!p.keyHistory) continue;
    for (const history of p.keyHistory) {
      if (history.publicKey === idOrName) {
        return p;
      }
    }
  }

  return undefined;
}

export function useInvite(tokenStr: string): Peer {
  const token = parseInviteToken(tokenStr);

  let identity = getIdentity();
  if (!identity) {
    identity = initIdentity();
  }

  const peers = getPeers();
  const peerShort = shortKey(token.iss);

  const existing = peers.find(p => p.publicKey === token.iss);
  if (existing) {
    existing.sessions = Array.from(new Set([...existing.sessions, ...token.ses]));
    existing.caps = Array.from(new Set([...existing.caps, ...token.cap]));
    savePeers(peers);
    return existing;
  }

  const peer: Peer = {
    id: peerShort,
    publicKey: token.iss,
    sessions: token.ses,
    caps: token.cap,
    added: Date.now(),
  };

  peers.push(peer);
  savePeers(peers);
  return peer;
}

export function revokePeer(idOrName: string): void {
  const grants = getAccessGrants();
  const idx = grants.findIndex(g =>
    !g.revoked && (
      shortKey(g.peerKey) === idOrName ||
      g.peerName?.toLowerCase() === idOrName.toLowerCase() ||
      g.id === idOrName
    )
  );

  if (idx === -1) {
    throw new Error(`No active grant found for "${idOrName}"`);
  }

  grants[idx].revoked = true;
  saveAccessGrants(grants);
}

export function namePeer(idOrKey: string, name: string): void {
  const peers = getPeers();
  const peer = peers.find(p => p.id === idOrKey || p.publicKey === idOrKey);

  if (!peer) {
    throw new Error(`Peer not found: ${idOrKey}`);
  }

  peer.name = name;
  savePeers(peers);
}

export function grantAccess(peerKey: string, sessions: string[], caps: string[], encryptPub?: string): AccessGrant {
  const grants = getAccessGrants();

  // Resolve short ID to full public key if needed
  let resolvedKey = peerKey;
  const peer = findPeer(peerKey);
  if (peer) {
    resolvedKey = peer.publicKey;
    if (!encryptPub && peer.encryptPub) {
      encryptPub = peer.encryptPub;
    }
  }

  // Find existing grant by resolved key
  const existing = grants.find(g => g.peerKey === resolvedKey && !g.revoked);
  if (existing) {
    existing.sessions = Array.from(new Set([...existing.sessions, ...sessions]));
    existing.caps = Array.from(new Set([...existing.caps, ...caps]));
    if (encryptPub) existing.peerEncryptPub = encryptPub;
    saveAccessGrants(grants);
    return existing;
  }

  const grant: AccessGrant = {
    id: `grant-${Date.now()}`,
    peerKey: resolvedKey,
    peerEncryptPub: encryptPub,
    sessions,
    caps,
    created: Date.now(),
  };

  grants.push(grant);
  saveAccessGrants(grants);
  return grant;
}

export function addPeer(publicKey: string, sessions: string[], caps: string[], encryptPub?: string): Peer {
  const peers = getPeers();
  const peerShort = shortKey(publicKey);

  const existing = peers.find(p => p.publicKey === publicKey);
  if (existing) {
    existing.sessions = Array.from(new Set([...existing.sessions, ...sessions]));
    existing.caps = Array.from(new Set([...existing.caps, ...caps]));
    if (encryptPub) existing.encryptPub = encryptPub;
    savePeers(peers);
    return existing;
  }

  const peer: Peer = {
    id: peerShort,
    publicKey,
    encryptPub,
    sessions,
    caps,
    added: Date.now(),
  };

  peers.push(peer);
  savePeers(peers);
  return peer;
}

/**
 * Process a key rotation message from a peer.
 */
export function processPeerKeyRotation(rotation: KeyRotation): boolean {
  if (!verifyKeyRotation(rotation)) {
    return false;
  }

  const grants = getAccessGrants();
  const peers = getPeers();

  // Find grant by old key
  const grantIdx = grants.findIndex(g => g.peerKey === rotation.oldSignPub && !g.revoked);
  if (grantIdx !== -1) {
    const grant = grants[grantIdx];

    const historyEntry: KeyHistory = {
      publicKey: grant.peerKey,
      encryptPub: grant.peerEncryptPub || "",
      validFrom: grant.created,
      validUntil: rotation.effectiveAt + rotation.gracePeriodMs,
      rotationReason: rotation.reason,
    };

    if (!grant.keyHistory) grant.keyHistory = [];
    grant.keyHistory.push(historyEntry);

    grant.peerKey = rotation.newSignPub;
    grant.peerEncryptPub = rotation.newEncryptPub;

    saveAccessGrants(grants);
  }

  // Find peer by old key
  const peerIdx = peers.findIndex(p => p.publicKey === rotation.oldSignPub);
  if (peerIdx !== -1) {
    const peer = peers[peerIdx];

    const historyEntry: KeyHistory = {
      publicKey: peer.publicKey,
      encryptPub: peer.encryptPub || "",
      validFrom: peer.added,
      validUntil: rotation.effectiveAt + rotation.gracePeriodMs,
      rotationReason: rotation.reason,
    };

    if (!peer.keyHistory) peer.keyHistory = [];
    peer.keyHistory.push(historyEntry);

    peer.publicKey = rotation.newSignPub;
    peer.encryptPub = rotation.newEncryptPub;
    peer.id = shortKey(rotation.newSignPub);

    savePeers(peers);
  }

  return grantIdx !== -1 || peerIdx !== -1;
}

/**
 * Clean up expired key history entries.
 */
export function cleanupExpiredKeyHistory(): void {
  const now = Date.now();
  const grants = getAccessGrants();
  const peers = getPeers();
  let modified = false;

  for (const grant of grants) {
    if (!grant.keyHistory) continue;
    const before = grant.keyHistory.length;
    grant.keyHistory = grant.keyHistory.filter(h => !h.validUntil || h.validUntil > now);
    if (grant.keyHistory.length !== before) modified = true;
  }

  for (const peer of peers) {
    if (!peer.keyHistory) continue;
    const before = peer.keyHistory.length;
    peer.keyHistory = peer.keyHistory.filter(h => !h.validUntil || h.validUntil > now);
    if (peer.keyHistory.length !== before) modified = true;
  }

  if (modified) {
    saveAccessGrants(grants);
    savePeers(peers);
  }
}

/**
 * Get all known keys for a peer.
 */
export function getAllPeerKeys(peerKey: string): string[] {
  const keys: string[] = [peerKey];

  const grants = getAccessGrants();
  for (const grant of grants) {
    if (grant.peerKey === peerKey && grant.keyHistory) {
      for (const h of grant.keyHistory) {
        if (!keys.includes(h.publicKey)) {
          keys.push(h.publicKey);
        }
      }
    }
  }

  const peers = getPeers();
  for (const peer of peers) {
    if (peer.publicKey === peerKey && peer.keyHistory) {
      for (const h of peer.keyHistory) {
        if (!keys.includes(h.publicKey)) {
          keys.push(h.publicKey);
        }
      }
    }
  }

  return keys;
}
