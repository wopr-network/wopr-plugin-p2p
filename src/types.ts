/**
 * P2P Plugin Types
 *
 * Shared plugin types are imported from @wopr-network/plugin-types.
 * P2P-specific types are defined here.
 */

import type { A2AToolDefinition } from "@wopr-network/plugin-types";

// Re-export shared types used by other files in this plugin
export type {
  WOPRPlugin,
  WOPRPluginContext,
  PluginCommand,
  ChannelRef,
  A2AToolResult,
  A2AToolDefinition,
  A2AServerConfig,
  PluginInjectOptions,
} from "@wopr-network/plugin-types";

// ============================================
// Minimal Storage API types (from wopr core)
// ============================================

export interface Repository<T extends Record<string, unknown>> {
  insert(data: Partial<T>): Promise<T>;
  insertMany(data: Partial<T>[]): Promise<T[]>;
  findById(id: unknown): Promise<T | null>;
  findFirst(filter: Record<string, unknown>): Promise<T | null>;
  findMany(filter?: Record<string, unknown>): Promise<T[]>;
  update(id: unknown, data: Partial<T>): Promise<T>;
  updateMany(filter: Record<string, unknown>, data: Partial<T>): Promise<number>;
  delete(id: unknown): Promise<boolean>;
  deleteMany(filter: Record<string, unknown>): Promise<number>;
  count(filter?: Record<string, unknown>): Promise<number>;
  exists(id: unknown): Promise<boolean>;
}

export interface StorageApi {
  readonly driver: "sqlite" | "postgres";
  register(schema: PluginSchemaDefinition): Promise<void>;
  getRepository<T extends Record<string, unknown>>(namespace: string, tableName: string): Repository<T>;
  isRegistered(namespace: string): boolean;
  getVersion(namespace: string): Promise<number>;
  raw(sql: string, params?: unknown[]): Promise<unknown[]>;
  transaction<R>(fn: (storage: StorageApi) => Promise<R>): Promise<R>;
}

export interface PluginSchemaDefinition {
  namespace: string;
  version: number;
  tables: Record<string, { schema: any; primaryKey: string; indexes?: Array<{ fields: string[]; unique?: boolean }> }>;
  migrate?: (fromVersion: number, toVersion: number, storage: StorageApi) => Promise<void>;
}

// Extend WOPRPluginContext with storage property
declare module "@wopr-network/plugin-types" {
  interface WOPRPluginContext {
    storage?: StorageApi;
  }
}

// Exit codes
export const EXIT_OK = 0;
export const EXIT_OFFLINE = 1;
export const EXIT_REJECTED = 2;
export const EXIT_INVALID = 3;
export const EXIT_RATE_LIMITED = 4;
export const EXIT_VERSION_MISMATCH = 5;
export const EXIT_PEER_OFFLINE = 6;
export const EXIT_UNAUTHORIZED = 7;

// Protocol version
export const PROTOCOL_VERSION = 2;
export const MIN_PROTOCOL_VERSION = 1;

export interface Identity {
  publicKey: string;
  privateKey: string;
  encryptPub: string;
  encryptPriv: string;
  created: number;
  rotatedFrom?: string;
  rotatedAt?: number;
}

export interface KeyRotation {
  v: number;
  type: "key-rotation";
  oldSignPub: string;
  newSignPub: string;
  newEncryptPub: string;
  reason: "scheduled" | "compromise" | "upgrade";
  effectiveAt: number;
  gracePeriodMs: number;
  sig: string;
}

export interface KeyHistory {
  publicKey: string;
  encryptPub: string;
  validFrom: number;
  validUntil?: number;
  rotationReason?: string;
}

export interface AccessGrant {
  id: string;
  peerKey: string;
  peerName?: string;
  peerEncryptPub?: string;
  sessions: string[];
  caps: string[];
  created: number;
  revoked?: boolean;
  keyHistory?: KeyHistory[];
}

export interface Peer {
  id: string;
  publicKey: string;
  encryptPub?: string;
  name?: string;
  sessions: string[];
  caps: string[];
  added: number;
  keyHistory?: KeyHistory[];
}

export interface InviteToken {
  v: number;
  iss: string;
  sub: string;
  ses: string[];
  cap: string[];
  exp: number;
  nonce: string;
  sig: string;
}

export type P2PMessageType =
  | "hello"
  | "hello-ack"
  | "log"       // Mailbox: just log to session history
  | "inject"   // Invoke AI: process and return response
  | "response" // AI response to an inject request
  | "ack"
  | "reject"
  | "claim"
  | "key-rotation";

export interface P2PMessage {
  v: number;
  type: P2PMessageType;
  from: string;
  encryptPub?: string;
  ephemeralPub?: string;
  session?: string;
  payload?: string;
  token?: string;
  reason?: string;
  requestId?: string;  // For inject/response correlation
  nonce: string;
  ts: number;
  sig: string;
  versions?: number[];
  version?: number;
  keyRotation?: KeyRotation;
}

export interface EphemeralKeyPair {
  publicKey: string;
  privateKey: string;
  created: number;
  expiresAt: number;
}

export interface RateLimitConfig {
  maxPerMinute: number;
  maxPerHour: number;
  banDurationMs: number;
}

export interface RateLimitState {
  minute: number[];
  hour: number[];
  banned?: number;
}

export interface RateLimits {
  [peerKey: string]: {
    [action: string]: RateLimitState;
  };
}

export interface ReplayState {
  nonces: Set<string>;
  timestamps: number[];
}

export interface Profile {
  id: string;
  publicKey: string;
  encryptPub: string;
  content: any;
  topics: string[];
  updated: number;
  sig: string;
}

export type DiscoveryMessageType =
  | "announce"
  | "withdraw"
  | "profile-request"
  | "profile-response"
  | "connect-request"
  | "connect-response";

export interface DiscoveryMessage {
  v: number;
  type: DiscoveryMessageType;
  from: string;
  encryptPub?: string;
  topic?: string;
  profile?: Profile;
  accepted?: boolean;
  sessions?: string[];
  reason?: string;
  nonce: string;
  ts: number;
  sig: string;
}

export interface TopicState {
  topic: string;
  joined: number;
  peers: Map<string, Profile>;
}

// Context passed to A2A tool handlers by WOPR core
// Extended from shared A2AToolDefinition to include P2P-specific context parameter
export interface A2AToolContext {
  sessionName: string;  // The WOPR session calling this tool
}

/**
 * P2P-specific A2A tool definition that extends the shared type
 * with an optional context parameter for session tracking.
 */
export type P2PToolDefinition = Omit<A2AToolDefinition, "handler"> & {
  handler: (args: Record<string, unknown>, context?: A2AToolContext) => Promise<import("@wopr-network/plugin-types").A2AToolResult>;
};

// P2P Extension API - exposed to other plugins via ctx.getExtension("p2p")
export interface P2PExtension {
  // Identity
  getIdentity(): { publicKey: string; shortId: string; encryptPub: string } | null;
  shortKey(key: string): string;

  // Peers
  getPeers(): Peer[];
  findPeer(keyOrName: string): Peer | undefined;
  namePeer(key: string, name: string): boolean;
  revokePeer(key: string): boolean;

  // Messaging
  injectPeer(peerKey: string, session: string, message: string): Promise<SendResult>;

  // Discovery
  joinTopic(topic: string): Promise<void>;
  leaveTopic(topic: string): Promise<void>;
  getTopics(): string[];
  getDiscoveredPeers(topic?: string): DiscoveredPeer[];
  requestConnection(peerId: string): Promise<ConnectionResult>;
}

// P2P Send/Claim Results
export interface SendResult {
  code: number;
  message?: string;
  response?: string;  // AI response for inject mode
}

export interface ClaimResult {
  code: number;
  peerKey?: string;
  sessions?: string[];
  caps?: string[];
  message?: string;
}

// Discovery Types
export interface DiscoveredPeer {
  id: string;
  publicKey: string;
  encryptPub?: string;
  content?: Record<string, unknown>;
  topics?: string[];
  updated?: number;
  connected?: boolean;
  grantedSessions?: string[];
}

export interface DiscoveryProfile {
  id: string;
  publicKey: string;
  encryptPub: string;
  content: Record<string, unknown>;
  topics: string[];
  updated: number;
}

export interface ConnectionResult {
  accept: boolean;
  code?: number;
  sessions?: string[];
  message?: string;
  reason?: string;
}

// ============================================================================
// Friend Protocol Types
// ============================================================================

/**
 * Friend request message - posted to public channel (Discord, Slack, etc.)
 * All security comes from the cryptographic signature, not channel access control.
 */
export interface FriendRequest {
  type: "FRIEND_REQUEST";
  to: string;           // Channel username of target (e.g., Discord username)
  from: string;         // Channel username of sender
  pubkey: string;       // Ed25519 public key (base64)
  encryptPub: string;   // X25519 encryption key (base64)
  timestamp: number;    // Milliseconds since epoch
  sig: string;          // Ed25519 signature over all fields
}

/**
 * Friend accept message - posted to channel in response to request
 */
export interface FriendAccept {
  type: "FRIEND_ACCEPT";
  to: string;           // Original requester's channel username
  from: string;         // Accepting agent's channel username
  pubkey: string;       // Ed25519 public key (base64)
  encryptPub: string;   // X25519 encryption key (base64)
  requestSig: string;   // Signature from original request (proves what we're accepting)
  timestamp: number;
  sig: string;          // Ed25519 signature over all fields
}

/**
 * Pending friend request waiting for approval
 */
export interface PendingFriendRequest {
  request: FriendRequest;
  receivedAt: number;
  channel: string;      // Channel type where received (discord, slack, etc.)
  channelId: string;    // Specific channel ID
}

/**
 * Outgoing friend request awaiting acceptance
 */
export interface OutgoingFriendRequest {
  request: FriendRequest;
  sentAt: number;
  channel: string;
  channelId: string;
}

/**
 * Established friendship
 */
export interface Friend {
  name: string;                 // Their channel username
  publicKey: string;            // Ed25519 pubkey
  encryptPub: string;           // X25519 pubkey
  sessionName: string;          // Dedicated session name for them
  addedAt: number;
  caps: string[];               // Capabilities granted (starts with ["message"])
  channel: string;              // Channel type where friended
}

/**
 * Friend grant - upgrade friend capabilities
 */
export interface FriendGrant {
  pubkey: string;
  caps: string[];           // What they can do
  sessions: string[];       // Which sessions they can access
  rateLimit?: {
    messagesPerMinute: number;
    injectsPerMinute?: number;
  };
}

/**
 * Auto-accept rule
 */
export interface AutoAcceptRule {
  pattern: string;        // Glob pattern or exact match
  addedAt: number;
}

/**
 * Friends state (persisted)
 */
export interface FriendsState {
  friends: Friend[];
  pendingIn: PendingFriendRequest[];
  pendingOut: OutgoingFriendRequest[];
  autoAccept: AutoAcceptRule[];
}
