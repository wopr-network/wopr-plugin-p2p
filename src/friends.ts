/**
 * P2P Friend Management
 *
 * Handles the friending protocol: creating/accepting friend requests,
 * managing friendships, and session creation for friends.
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync } from "fs";
import { homedir } from "os";
import { join } from "path";
import {
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from "crypto";
import type {
  FriendRequest,
  FriendAccept,
  PendingFriendRequest,
  OutgoingFriendRequest,
  Friend,
  FriendsState,
  AutoAcceptRule,
} from "./types.js";
import { getIdentity, shortKey } from "./identity.js";
import { grantAccess, addPeer } from "./trust.js";
import { syncFriendToSecurity, removeFriendFromSecurity } from "./security-integration.js";

// Data directory for P2P plugin
const P2P_DATA_DIR = existsSync("/data") ? "/data/p2p" : join(homedir(), ".wopr", "p2p");
const FRIENDS_FILE = join(P2P_DATA_DIR, "friends.json");

// Request expiry time (5 minutes)
const REQUEST_EXPIRY_MS = 5 * 60 * 1000;

function ensureDataDir(): void {
  if (!existsSync(P2P_DATA_DIR)) {
    mkdirSync(P2P_DATA_DIR, { recursive: true, mode: 0o700 });
  }
}

function loadFriendsState(): FriendsState {
  if (!existsSync(FRIENDS_FILE)) {
    return { friends: [], pendingIn: [], pendingOut: [], autoAccept: [] };
  }
  return JSON.parse(readFileSync(FRIENDS_FILE, "utf-8"));
}

function saveFriendsState(state: FriendsState): void {
  ensureDataDir();
  writeFileSync(FRIENDS_FILE, JSON.stringify(state, null, 2), { mode: 0o600 });
}

/**
 * Generate deterministic session name for a friend
 */
export function getFriendSessionName(name: string, pubkey: string): string {
  const prefix = pubkey.slice(0, 6);
  return `friend:p2p:${name}(${prefix})`;
}

/**
 * Serialize a friend request for signing (excludes sig field)
 */
function serializeForSigning(obj: Omit<FriendRequest, "sig"> | Omit<FriendAccept, "sig">): string {
  return JSON.stringify(obj);
}

/**
 * Create a signed friend request
 */
export function createFriendRequest(
  to: string,
  from: string
): FriendRequest {
  const identity = getIdentity();
  if (!identity) throw new Error("No P2P identity initialized");

  const payload: Omit<FriendRequest, "sig"> = {
    type: "FRIEND_REQUEST",
    to,
    from,
    pubkey: identity.publicKey,
    encryptPub: identity.encryptPub,
    timestamp: Date.now(),
  };

  const privateKey = createPrivateKey({
    key: Buffer.from(identity.privateKey, "base64"),
    format: "der",
    type: "pkcs8",
  });

  const signature = sign(null, Buffer.from(serializeForSigning(payload)), privateKey);

  return {
    ...payload,
    sig: signature.toString("base64"),
  };
}

/**
 * Create a signed friend accept
 */
export function createFriendAccept(
  request: FriendRequest,
  from: string
): FriendAccept {
  const identity = getIdentity();
  if (!identity) throw new Error("No P2P identity initialized");

  const payload: Omit<FriendAccept, "sig"> = {
    type: "FRIEND_ACCEPT",
    to: request.from,  // Accept goes back to the requester
    from,
    pubkey: identity.publicKey,
    encryptPub: identity.encryptPub,
    requestSig: request.sig,  // Proves what we're accepting
    timestamp: Date.now(),
  };

  const privateKey = createPrivateKey({
    key: Buffer.from(identity.privateKey, "base64"),
    format: "der",
    type: "pkcs8",
  });

  const signature = sign(null, Buffer.from(serializeForSigning(payload)), privateKey);

  return {
    ...payload,
    sig: signature.toString("base64"),
  };
}

/**
 * Verify a friend request signature
 */
export function verifyFriendRequest(request: FriendRequest): boolean {
  try {
    const { sig, ...payload } = request;

    // Check timestamp (reject requests older than 5 minutes)
    if (Date.now() - request.timestamp > REQUEST_EXPIRY_MS) {
      return false;
    }

    const publicKey = createPublicKey({
      key: Buffer.from(request.pubkey, "base64"),
      format: "der",
      type: "spki",
    });

    return verify(null, Buffer.from(serializeForSigning(payload)), publicKey, Buffer.from(sig, "base64"));
  } catch {
    return false;
  }
}

/**
 * Verify a friend accept signature
 */
export function verifyFriendAccept(accept: FriendAccept): boolean {
  try {
    const { sig, ...payload } = accept;

    // Check timestamp
    if (Date.now() - accept.timestamp > REQUEST_EXPIRY_MS) {
      return false;
    }

    const publicKey = createPublicKey({
      key: Buffer.from(accept.pubkey, "base64"),
      format: "der",
      type: "spki",
    });

    return verify(null, Buffer.from(serializeForSigning(payload)), publicKey, Buffer.from(sig, "base64"));
  } catch {
    return false;
  }
}

/**
 * Format a friend request for posting to a channel
 */
export function formatFriendRequest(request: FriendRequest): string {
  return `FRIEND_REQUEST | to:${request.to} | from:${request.from} | pubkey:${request.pubkey} | encryptPub:${request.encryptPub} | ts:${request.timestamp} | sig:${request.sig}`;
}

/**
 * Format a friend accept for posting to a channel
 */
export function formatFriendAccept(accept: FriendAccept): string {
  return `FRIEND_ACCEPT | to:${accept.to} | from:${accept.from} | pubkey:${accept.pubkey} | encryptPub:${accept.encryptPub} | requestSig:${accept.requestSig} | ts:${accept.timestamp} | sig:${accept.sig}`;
}

/**
 * Parse a friend request from channel message
 */
export function parseFriendRequest(content: string): FriendRequest | null {
  const match = content.match(/^FRIEND_REQUEST \| to:(\S+) \| from:(\S+) \| pubkey:(\S+) \| encryptPub:(\S+) \| ts:(\d+) \| sig:(\S+)$/);
  if (!match) return null;

  return {
    type: "FRIEND_REQUEST",
    to: match[1],
    from: match[2],
    pubkey: match[3],
    encryptPub: match[4],
    timestamp: parseInt(match[5], 10),
    sig: match[6],
  };
}

/**
 * Parse a friend accept from channel message
 */
export function parseFriendAccept(content: string): FriendAccept | null {
  const match = content.match(/^FRIEND_ACCEPT \| to:(\S+) \| from:(\S+) \| pubkey:(\S+) \| encryptPub:(\S+) \| requestSig:(\S+) \| ts:(\d+) \| sig:(\S+)$/);
  if (!match) return null;

  return {
    type: "FRIEND_ACCEPT",
    to: match[1],
    from: match[2],
    pubkey: match[3],
    encryptPub: match[4],
    requestSig: match[5],
    timestamp: parseInt(match[6], 10),
    sig: match[7],
  };
}

/**
 * Store an outgoing friend request
 */
export function storePendingRequest(
  request: FriendRequest,
  channel: string,
  channelId: string
): void {
  const state = loadFriendsState();

  // Remove any existing request to the same target
  state.pendingOut = state.pendingOut.filter(p => p.request.to !== request.to);

  state.pendingOut.push({
    request,
    sentAt: Date.now(),
    channel,
    channelId,
  });

  saveFriendsState(state);
}

/**
 * Store an incoming friend request for approval
 */
export function queueForApproval(
  request: FriendRequest,
  channel: string,
  channelId: string
): void {
  const state = loadFriendsState();

  // Remove any existing request from the same sender
  state.pendingIn = state.pendingIn.filter(p => p.request.from !== request.from);

  state.pendingIn.push({
    request,
    receivedAt: Date.now(),
    channel,
    channelId,
  });

  saveFriendsState(state);
}

/**
 * Check if we should auto-accept a friend request
 */
export function shouldAutoAccept(from: string): boolean {
  const state = loadFriendsState();

  for (const rule of state.autoAccept) {
    // Exact match
    if (rule.pattern === from) return true;

    // Wildcard match
    if (rule.pattern === "*") return true;

    // Simple glob (pattern|pattern)
    if (rule.pattern.includes("|")) {
      const patterns = rule.pattern.split("|");
      if (patterns.includes(from)) return true;
    }
  }

  return false;
}

/**
 * Get our pending outgoing request to a specific target
 */
export function getPendingOutgoing(to: string): OutgoingFriendRequest | undefined {
  const state = loadFriendsState();
  return state.pendingOut.find(p => p.request.to === to);
}

/**
 * Get a pending incoming request from a specific sender
 */
export function getPendingIncoming(from: string): PendingFriendRequest | undefined {
  const state = loadFriendsState();
  return state.pendingIn.find(p => p.request.from === from);
}

/**
 * Complete a friendship after receiving an accept
 */
export function completeFriendship(accept: FriendAccept, channel: string): Friend {
  const state = loadFriendsState();

  // Remove from pending outgoing
  const pendingIdx = state.pendingOut.findIndex(p => p.request.to === accept.from);
  if (pendingIdx !== -1) {
    state.pendingOut.splice(pendingIdx, 1);
  }

  // Check if already friends
  const existing = state.friends.find(f => f.publicKey === accept.pubkey);
  if (existing) {
    saveFriendsState(state);
    return existing;
  }

  // Compute session name
  const sessionName = getFriendSessionName(accept.from, accept.pubkey);

  // Create friend entry
  const friend: Friend = {
    name: accept.from,
    publicKey: accept.pubkey,
    encryptPub: accept.encryptPub,
    sessionName,
    addedAt: Date.now(),
    caps: ["message"],  // Default: message only, inject must be explicitly granted
    channel,
  };

  state.friends.push(friend);
  saveFriendsState(state);

  // Also add to P2P trust system
  addPeer(accept.pubkey, [sessionName], ["message"], accept.encryptPub);
  grantAccess(accept.pubkey, [sessionName], ["message"], accept.encryptPub);

  // Sync to WOPR security model
  try {
    syncFriendToSecurity(friend);
  } catch {
    // Security sync is optional - may not have WOPR security module
  }

  return friend;
}

/**
 * Accept a pending friend request
 */
export function acceptPendingRequest(from: string): { friend: Friend; request: FriendRequest } | null {
  const state = loadFriendsState();

  const pendingIdx = state.pendingIn.findIndex(p => p.request.from.toLowerCase() === from.toLowerCase());
  if (pendingIdx === -1) return null;

  const pending = state.pendingIn[pendingIdx];
  const request = pending.request;

  // Compute session name
  const sessionName = getFriendSessionName(request.from, request.pubkey);

  // Create friend entry
  const friend: Friend = {
    name: request.from,
    publicKey: request.pubkey,
    encryptPub: request.encryptPub,
    sessionName,
    addedAt: Date.now(),
    caps: ["message"],
    channel: pending.channel,
  };

  // Remove from pending
  state.pendingIn.splice(pendingIdx, 1);

  // Check if already friends
  const existingIdx = state.friends.findIndex(f => f.publicKey === request.pubkey);
  if (existingIdx === -1) {
    state.friends.push(friend);
  }

  saveFriendsState(state);

  // Add to P2P trust system
  addPeer(request.pubkey, [sessionName], ["message"], request.encryptPub);
  grantAccess(request.pubkey, [sessionName], ["message"], request.encryptPub);

  return { friend, request };
}

/**
 * Get all friends
 */
export function getFriends(): Friend[] {
  return loadFriendsState().friends;
}

/**
 * Get a friend by name or pubkey
 */
export function getFriend(nameOrKey: string): Friend | undefined {
  const state = loadFriendsState();
  return state.friends.find(
    f => f.name.toLowerCase() === nameOrKey.toLowerCase() ||
         f.publicKey === nameOrKey ||
         shortKey(f.publicKey) === nameOrKey
  );
}

/**
 * Remove a friend
 */
export function removeFriend(nameOrKey: string): boolean {
  const state = loadFriendsState();
  const idx = state.friends.findIndex(
    f => f.name.toLowerCase() === nameOrKey.toLowerCase() ||
         f.publicKey === nameOrKey
  );

  if (idx === -1) return false;

  const friend = state.friends[idx];
  state.friends.splice(idx, 1);
  saveFriendsState(state);

  // Remove from WOPR security model
  try {
    removeFriendFromSecurity(friend);
  } catch {
    // Security sync is optional
  }

  return true;
}

/**
 * Grant additional capabilities to a friend
 */
export function grantFriendCap(nameOrKey: string, cap: string): boolean {
  const state = loadFriendsState();
  const friend = state.friends.find(
    f => f.name.toLowerCase() === nameOrKey.toLowerCase() ||
         f.publicKey === nameOrKey
  );

  if (!friend) return false;

  if (!friend.caps.includes(cap)) {
    friend.caps.push(cap);
    saveFriendsState(state);

    // Update P2P trust system
    grantAccess(friend.publicKey, [friend.sessionName], friend.caps, friend.encryptPub);

    // Sync to WOPR security model
    try {
      syncFriendToSecurity(friend);
    } catch {
      // Security sync is optional
    }
  }

  return true;
}

/**
 * Revoke a capability from a friend
 */
export function revokeFriendCap(nameOrKey: string, cap: string): boolean {
  const state = loadFriendsState();
  const friend = state.friends.find(
    f => f.name.toLowerCase() === nameOrKey.toLowerCase() ||
         f.publicKey === nameOrKey
  );

  if (!friend) return false;

  const idx = friend.caps.indexOf(cap);
  if (idx !== -1) {
    friend.caps.splice(idx, 1);
    saveFriendsState(state);

    // Update P2P trust system
    grantAccess(friend.publicKey, [friend.sessionName], friend.caps, friend.encryptPub);

    // Sync to WOPR security model
    try {
      syncFriendToSecurity(friend);
    } catch {
      // Security sync is optional
    }
  }

  return true;
}

/**
 * Add an auto-accept rule
 */
export function addAutoAcceptRule(pattern: string): void {
  const state = loadFriendsState();

  // Check if already exists
  if (state.autoAccept.some(r => r.pattern === pattern)) return;

  state.autoAccept.push({
    pattern,
    addedAt: Date.now(),
  });

  saveFriendsState(state);
}

/**
 * Remove an auto-accept rule
 */
export function removeAutoAcceptRule(pattern: string): boolean {
  const state = loadFriendsState();
  const idx = state.autoAccept.findIndex(r => r.pattern === pattern);

  if (idx === -1) return false;

  state.autoAccept.splice(idx, 1);
  saveFriendsState(state);
  return true;
}

/**
 * Get auto-accept rules
 */
export function getAutoAcceptRules(): AutoAcceptRule[] {
  return loadFriendsState().autoAccept;
}

/**
 * Get pending incoming requests
 */
export function getPendingIncomingRequests(): PendingFriendRequest[] {
  return loadFriendsState().pendingIn;
}

/**
 * Get a pending incoming request by its signature
 */
export function getPendingIncomingBySignature(sig: string): PendingFriendRequest | undefined {
  const state = loadFriendsState();
  return state.pendingIn.find(p => p.request.sig === sig);
}

/**
 * Deny/remove a pending incoming friend request
 */
export function denyPendingRequest(fromOrSig: string): boolean {
  const state = loadFriendsState();
  const idx = state.pendingIn.findIndex(p =>
    p.request.from.toLowerCase() === fromOrSig.toLowerCase() ||
    p.request.sig === fromOrSig
  );

  if (idx === -1) return false;

  state.pendingIn.splice(idx, 1);
  saveFriendsState(state);
  return true;
}

/**
 * Get pending outgoing requests
 */
export function getPendingOutgoingRequests(): OutgoingFriendRequest[] {
  return loadFriendsState().pendingOut;
}

/**
 * Clean up expired pending requests
 */
export function cleanupExpiredRequests(): void {
  const state = loadFriendsState();
  const now = Date.now();

  const originalInCount = state.pendingIn.length;
  const originalOutCount = state.pendingOut.length;

  // Remove requests older than 24 hours
  const maxAge = 24 * 60 * 60 * 1000;
  state.pendingIn = state.pendingIn.filter(p => now - p.receivedAt < maxAge);
  state.pendingOut = state.pendingOut.filter(p => now - p.sentAt < maxAge);

  if (state.pendingIn.length !== originalInCount || state.pendingOut.length !== originalOutCount) {
    saveFriendsState(state);
  }
}
