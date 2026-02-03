/**
 * P2P Plugin Types
 */

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

// A2A Tool Types
export interface A2AToolResult {
  content: Array<{
    type: "text" | "image" | "resource";
    text?: string;
    data?: string;
    mimeType?: string;
  }>;
  isError?: boolean;
}

// Context passed to A2A tool handlers by WOPR core
export interface A2AToolContext {
  sessionName: string;  // The WOPR session calling this tool
}

export interface A2AToolDefinition {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  handler: (args: Record<string, unknown>, context?: A2AToolContext) => Promise<A2AToolResult>;
}

export interface A2AServerConfig {
  name: string;
  version?: string;
  tools: A2AToolDefinition[];
}

// Channel reference for message logging
export interface ChannelRef {
  type: string;
  id: string;
}

// Security source for injection (matches WOPR's InjectionSource)
export interface InjectionSource {
  type: "cli" | "daemon" | "plugin" | "cron" | "p2p" | "p2p.discovery" | "api" | "gateway";
  trustLevel: "owner" | "trusted" | "semi-trusted" | "untrusted";
  identity?: {
    publicKey?: string;
    pluginName?: string;
    apiKeyId?: string;
    gatewaySession?: string;
  };
  grantedCapabilities?: string[];
  grantId?: string;
}

// Options for plugin inject
export interface PluginInjectOptions {
  from?: string;
  channel?: ChannelRef;
  stream?: boolean;
  /** Security source for proper sandboxing of untrusted peers */
  source?: InjectionSource;
}

// WOPR Plugin Types
export interface WOPRPluginContext {
  log: { info: (msg: string) => void; error: (msg: string) => void; warn: (msg: string) => void };
  registerA2AServer: (config: A2AServerConfig) => void;
  getPluginDir: () => string;
  getConfig: () => Record<string, unknown>;
  getMainConfig: (key?: string) => Record<string, unknown> | undefined;

  // Session injection methods - critical for receiving P2P messages
  inject?: (session: string, message: string, options?: PluginInjectOptions) => Promise<string>;
  logMessage?: (session: string, message: string, options?: { from?: string; channel?: ChannelRef }) => void;
  getSessions?: () => string[];
  cancelInject?: (session: string) => void;

  registerUiComponent?: (component: {
    id: string;
    title: string;
    moduleUrl: string;
    slot: string;
    description: string;
  }) => void;
  registerWebUiExtension?: (extension: {
    id: string;
    title: string;
    url: string;
    description: string;
    category: string;
  }) => void;
  // Plugin extensions - expose APIs to other plugins
  registerExtension?: (name: string, extension: unknown) => void;
  unregisterExtension?: (name: string) => void;
  getExtension?: <T = unknown>(name: string) => T | undefined;
}

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

export interface PluginCommand {
  name: string;
  description: string;
  usage?: string;
  handler: (ctx: WOPRPluginContext, args: string[]) => Promise<void>;
}

export interface WOPRPlugin {
  name: string;
  version: string;
  description: string;
  commands?: PluginCommand[];
  init(ctx: WOPRPluginContext): Promise<void>;
  shutdown(): Promise<void>;
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
