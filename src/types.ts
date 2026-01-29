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
  | "inject"
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

export interface A2AToolDefinition {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  handler: (args: Record<string, unknown>) => Promise<A2AToolResult>;
}

export interface A2AServerConfig {
  name: string;
  version?: string;
  tools: A2AToolDefinition[];
}

// WOPR Plugin Types
export interface WOPRPluginContext {
  log: { info: (msg: string) => void; error: (msg: string) => void; warn: (msg: string) => void };
  registerA2AServer: (config: A2AServerConfig) => void;
  getPluginDir: () => string;
  getConfig: () => Record<string, unknown>;
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
}

export interface WOPRPlugin {
  name: string;
  version: string;
  description: string;
  init(ctx: WOPRPluginContext): Promise<void>;
  shutdown(): Promise<void>;
}

// P2P Send/Claim Results
export interface SendResult {
  code: number;
  message?: string;
}

export interface ClaimResult {
  code: number;
  peerKey?: string;
  sessions?: string[];
  caps?: string[];
  message?: string;
}
