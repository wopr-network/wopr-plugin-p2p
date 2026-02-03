/**
 * WOPR Plugin: P2P Networking
 *
 * Provides P2P networking with Hyperswarm, identity management, trust,
 * and A2A tools for agent-to-agent communication.
 *
 * Install: wopr plugin install wopr-plugin-p2p
 */

import winston from "winston";
import http from "http";
import { createReadStream, existsSync } from "fs";
import { extname, join } from "path";
import type Hyperswarm from "hyperswarm";
import type {
  WOPRPlugin,
  WOPRPluginContext,
  A2AToolDefinition,
  A2AServerConfig,
  A2AToolResult,
  A2AToolContext,
} from "./types.js";
import { EXIT_OK } from "./types.js";
import {
  getIdentity,
  initIdentity,
  shortKey,
  createInviteToken,
  rotateIdentity,
} from "./identity.js";
import {
  getPeers,
  getAccessGrants,
  findPeer,
  namePeer,
  revokePeer,
  addPeer,
  grantAccess,
  isAuthorized,
} from "./trust.js";
import { sendP2PInject, sendP2PLog, claimToken, createP2PListener, sendKeyRotation, setP2PLogger } from "./p2p.js";
import {
  initDiscovery,
  joinTopic,
  leaveTopic,
  getTopics,
  getDiscoveredPeers,
  requestConnection,
  getProfile,
  updateProfile,
  shutdownDiscovery,
  notifyGrantUpdate,
} from "./discovery.js";
import { setP2PConfig } from "./config.js";
import { registerChannelHooks, registerAutoAcceptCommands, registerP2PSlashCommands } from "./channel-hooks.js";
import {
  cleanupExpiredRequests,
  acceptPendingRequest,
  createFriendAccept,
  completeFriendship,
  formatFriendAccept,
  getPendingIncomingBySignature,
  denyPendingRequest,
} from "./friends.js";
import { friendCommand } from "./cli-commands.js";
import { syncAllFriendsToSecurity, getFriendSecurityContext } from "./security-integration.js";

// Setup winston logger
const logger = winston.createLogger({
  level: "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: "wopr-plugin-p2p" },
  transports: [new winston.transports.Console({ level: "warn" })],
});

// Plugin state
let ctx: WOPRPluginContext | null = null;
let p2pListener: Hyperswarm | null = null;
let uiServer: http.Server | null = null;

// Track sessions currently being P2P injected into
// This prevents recursive inject loops (A injects to B, B tries to inject back to A)
const sessionsBeingInjected: Set<string> = new Set();

// Content types for UI server
const CONTENT_TYPES: Record<string, string> = {
  ".js": "application/javascript",
  ".css": "text/css",
  ".html": "text/html",
};

/**
 * Start HTTP server to serve UI component
 */
function startUIServer(port: number, pluginDir: string): http.Server {
  const server = http.createServer((req, res) => {
    const url = req.url === "/" ? "/ui.js" : req.url || "/ui.js";
    const filePath = join(pluginDir, url);
    const ext = extname(filePath).toLowerCase();

    res.setHeader("Content-Type", CONTENT_TYPES[ext] || "application/octet-stream");
    res.setHeader("Access-Control-Allow-Origin", "*");

    if (existsSync(filePath)) {
      const stream = createReadStream(filePath);
      stream.pipe(res);
      stream.on("error", () => {
        res.statusCode = 404;
        res.end("Not found");
      });
    } else {
      res.statusCode = 404;
      res.end("Not found");
    }
  });

  server.listen(port, "127.0.0.1", () => {
    logger.info(`P2P UI available at http://127.0.0.1:${port}`);
  });

  return server;
}

/**
 * Create A2A tool result
 */
function toolResult(text: string, isError = false): A2AToolResult {
  return {
    content: [{ type: "text", text }],
    isError,
  };
}

/**
 * A2A Tools for P2P operations
 */
const p2pTools: A2AToolDefinition[] = [
  // Identity Tools
  {
    name: "p2p_get_identity",
    description: "Get your P2P identity (public key, short ID). Creates one if none exists.",
    inputSchema: {
      type: "object",
      properties: {},
    },
    handler: async () => {
      let identity = getIdentity();
      if (!identity) {
        identity = initIdentity();
        logger.info("[p2p] Created new identity");
      }
      return toolResult(
        JSON.stringify({
          shortId: shortKey(identity.publicKey),
          publicKey: identity.publicKey,
          encryptPub: identity.encryptPub,
          created: new Date(identity.created).toISOString(),
        })
      );
    },
  },
  {
    name: "p2p_rotate_keys",
    description: "Rotate your P2P identity keys. Use for security or scheduled rotation.",
    inputSchema: {
      type: "object",
      properties: {
        reason: {
          type: "string",
          enum: ["scheduled", "compromise", "upgrade"],
          description: "Reason for key rotation",
        },
        notifyPeers: {
          type: "boolean",
          description: "Whether to notify connected peers of the rotation",
        },
      },
    },
    handler: async (args) => {
      const reason = (args.reason as "scheduled" | "compromise" | "upgrade") || "scheduled";
      const notifyPeers = args.notifyPeers !== false;

      try {
        const { identity, rotation } = rotateIdentity(reason);

        if (notifyPeers) {
          const peers = getPeers();
          for (const peer of peers) {
            try {
              await sendKeyRotation(peer.publicKey, rotation);
              logger.info(`[p2p] Notified ${peer.id} of key rotation`);
            } catch (err) {
              logger.warn(`[p2p] Failed to notify ${peer.id}: ${err}`);
            }
          }
        }

        return toolResult(
          JSON.stringify({
            success: true,
            newShortId: shortKey(identity.publicKey),
            reason,
            peersNotified: notifyPeers ? getPeers().length : 0,
          })
        );
      } catch (err) {
        return toolResult(`Key rotation failed: ${err}`, true);
      }
    },
  },

  // Peer Management Tools
  {
    name: "p2p_list_peers",
    description: "List all known P2P peers with their access permissions.",
    inputSchema: {
      type: "object",
      properties: {},
    },
    handler: async () => {
      const peers = getPeers();
      return toolResult(
        JSON.stringify({
          count: peers.length,
          peers: peers.map((p) => ({
            id: p.id,
            name: p.name,
            publicKey: p.publicKey.slice(0, 20) + "...",
            sessions: p.sessions,
            caps: p.caps,
            added: new Date(p.added).toISOString(),
          })),
        })
      );
    },
  },
  {
    name: "p2p_name_peer",
    description: "Give a friendly name to a peer for easier reference.",
    inputSchema: {
      type: "object",
      properties: {
        peerId: { type: "string", description: "Peer ID or public key" },
        name: { type: "string", description: "Friendly name for the peer" },
      },
      required: ["peerId", "name"],
    },
    handler: async (args) => {
      try {
        namePeer(args.peerId as string, args.name as string);
        return toolResult(`Peer ${args.peerId} named "${args.name}"`);
      } catch (err) {
        return toolResult(`Failed to name peer: ${err}`, true);
      }
    },
  },
  {
    name: "p2p_revoke_peer",
    description: "Revoke access for a peer. They will no longer be able to send messages.",
    inputSchema: {
      type: "object",
      properties: {
        peerId: { type: "string", description: "Peer ID, name, or public key" },
      },
      required: ["peerId"],
    },
    handler: async (args) => {
      try {
        revokePeer(args.peerId as string);
        return toolResult(`Access revoked for peer ${args.peerId}`);
      } catch (err) {
        return toolResult(`Failed to revoke peer: ${err}`, true);
      }
    },
  },

  // Invite/Token Tools
  {
    name: "p2p_create_invite",
    description: "Create an invite token for another peer to claim. They need your public key first.",
    inputSchema: {
      type: "object",
      properties: {
        forPubkey: { type: "string", description: "Public key of the peer to invite" },
        sessions: {
          type: "array",
          items: { type: "string" },
          description: "Sessions to grant access to (use ['*'] for all)",
        },
        expireHours: {
          type: "number",
          description: "Hours until token expires (default: 168 = 1 week)",
        },
      },
      required: ["forPubkey", "sessions"],
    },
    handler: async (args) => {
      try {
        const token = createInviteToken(
          args.forPubkey as string,
          args.sessions as string[],
          (args.expireHours as number) || 168
        );
        return toolResult(
          JSON.stringify({
            token,
            forPeer: shortKey(args.forPubkey as string),
            sessions: args.sessions,
            expiresIn: `${(args.expireHours as number) || 168} hours`,
          })
        );
      } catch (err) {
        return toolResult(`Failed to create invite: ${err}`, true);
      }
    },
  },
  {
    name: "p2p_claim_invite",
    description: "Claim an invite token from another peer. They must be online.",
    inputSchema: {
      type: "object",
      properties: {
        token: { type: "string", description: "Invite token (wop1://...)" },
        timeoutMs: { type: "number", description: "Timeout in milliseconds (default: 10000)" },
      },
      required: ["token"],
    },
    handler: async (args) => {
      const result = await claimToken(args.token as string, (args.timeoutMs as number) || 10000);

      if (result.code === EXIT_OK) {
        return toolResult(
          JSON.stringify({
            success: true,
            peerKey: result.peerKey ? shortKey(result.peerKey) : undefined,
            sessions: result.sessions,
            caps: result.caps,
          })
        );
      } else {
        return toolResult(`Claim failed: ${result.message}`, true);
      }
    },
  },

  // Messaging Tools
  {
    name: "p2p_log_message",
    description: "Log a message to a peer's session (mailbox style). Message is stored in their session history for later viewing. Does NOT invoke the AI - just delivers the message. Use p2p_inject_message if you need an AI response.",
    inputSchema: {
      type: "object",
      properties: {
        peer: { type: "string", description: "Peer ID, name, or public key" },
        session: { type: "string", description: "Session to log message to" },
        message: { type: "string", description: "Message content" },
        timeoutMs: { type: "number", description: "Timeout in milliseconds (default: 10000)" },
      },
      required: ["peer", "session", "message"],
    },
    handler: async (args) => {
      const result = await sendP2PLog(
        args.peer as string,
        args.session as string,
        args.message as string,
        (args.timeoutMs as number) || 10000
      );

      if (result.code === EXIT_OK) {
        return toolResult(
          JSON.stringify({
            success: true,
            mode: "log",
            peer: args.peer,
            session: args.session,
          })
        );
      } else {
        return toolResult(`Log failed: ${result.message}`, true);
      }
    },
  },
  {
    name: "p2p_inject_message",
    description: "Inject a message into a peer's session and get the AI's response back. This invokes the peer's AI which processes the message and generates a response. Use for questions or tasks that need a reply. Use p2p_log_message for fire-and-forget notifications. NOTE: Cannot be used while processing an incoming P2P inject - just respond with text instead.",
    inputSchema: {
      type: "object",
      properties: {
        peer: { type: "string", description: "Peer ID, name, or public key" },
        session: { type: "string", description: "Session to inject into" },
        message: { type: "string", description: "Message content" },
        timeoutMs: { type: "number", description: "Timeout in milliseconds (default: 60000 for AI processing)" },
      },
      required: ["peer", "session", "message"],
    },
    handler: async (args, context?: A2AToolContext) => {
      // CRITICAL: Block recursive P2P inject loops
      // If this session is currently being P2P injected into, the AI should NOT
      // call p2p_inject_message - it should just respond with text, which will
      // be returned to the caller automatically via the inject response channel.
      if (context?.sessionName && sessionsBeingInjected.has(context.sessionName)) {
        logger.warn(`[p2p] BLOCKED: Session ${context.sessionName} tried to call p2p_inject_message while being P2P injected into`);
        return toolResult(
          `BLOCKED: You are currently responding to a P2P inject. ` +
          `Do NOT use p2p_inject_message to reply - just respond with text. ` +
          `Your text response will be automatically returned to the caller.`,
          true
        );
      }

      const result = await sendP2PInject(
        args.peer as string,
        args.session as string,
        args.message as string,
        (args.timeoutMs as number) || 60000  // Longer timeout for AI processing
      );

      if (result.code === EXIT_OK) {
        return toolResult(
          JSON.stringify({
            success: true,
            mode: "inject",
            peer: args.peer,
            session: args.session,
            response: result.response,  // AI's response
          })
        );
      } else {
        return toolResult(`Inject failed: ${result.message}`, true);
      }
    },
  },
  // Status Tools
  {
    name: "p2p_status",
    description: "Get P2P network status including identity, peers, and listener state.",
    inputSchema: {
      type: "object",
      properties: {},
    },
    handler: async () => {
      const identity = getIdentity();
      const peers = getPeers();
      const grants = getAccessGrants();

      return toolResult(
        JSON.stringify({
          identity: identity
            ? {
                shortId: shortKey(identity.publicKey),
                publicKey: identity.publicKey.slice(0, 30) + "...",
                created: new Date(identity.created).toISOString(),
              }
            : null,
          listening: p2pListener !== null,
          peers: {
            count: peers.length,
            names: peers.filter((p) => p.name).map((p) => p.name),
          },
          grants: {
            total: grants.length,
            active: grants.filter((g) => !g.revoked).length,
            revoked: grants.filter((g) => g.revoked).length,
          },
        })
      );
    },
  },

  // Grant Access Tools
  {
    name: "p2p_grant_access",
    description: "Manually grant a peer access to specific sessions without using tokens. Updates existing peer record if found.",
    inputSchema: {
      type: "object",
      properties: {
        peerKey: { type: "string", description: "Peer ID, name, or public key" },
        sessions: {
          type: "array",
          items: { type: "string" },
          description: "Sessions to grant access to",
        },
        caps: {
          type: "array",
          items: { type: "string" },
          description: "Capabilities to grant (default: ['inject'])",
        },
      },
      required: ["peerKey", "sessions"],
    },
    handler: async (args) => {
      try {
        let peerKey = args.peerKey as string;
        const sessions = args.sessions as string[];

        // Resolve short ID or name to full public key
        const existingPeer = findPeer(peerKey);
        if (existingPeer) {
          peerKey = existingPeer.publicKey;
          logger.info(`[p2p] Resolved peer ${args.peerKey} to ${shortKey(peerKey)}`);
        }

        const grant = grantAccess(
          peerKey,
          sessions,
          (args.caps as string[]) || ["inject"]
        );

        // Also update the peer record
        addPeer(peerKey, sessions, (args.caps as string[]) || ["inject"]);

        // Notify the peer of the updated grant if they're connected
        const notified = notifyGrantUpdate(peerKey, grant.sessions);

        return toolResult(
          JSON.stringify({
            success: true,
            grantId: grant.id,
            peer: shortKey(peerKey),
            sessions: grant.sessions,
            caps: grant.caps,
            notified, // Whether the peer was notified in real-time
          })
        );
      } catch (err) {
        return toolResult(`Failed to grant access: ${err}`, true);
      }
    },
  },
  {
    name: "p2p_list_grants",
    description: "List all access grants (who can send to which sessions).",
    inputSchema: {
      type: "object",
      properties: {
        includeRevoked: { type: "boolean", description: "Include revoked grants" },
      },
    },
    handler: async (args) => {
      const grants = getAccessGrants();
      const filtered = args.includeRevoked
        ? grants
        : grants.filter((g) => !g.revoked);

      return toolResult(
        JSON.stringify({
          count: filtered.length,
          grants: filtered.map((g) => ({
            id: g.id,
            peer: shortKey(g.peerKey),
            name: g.peerName,
            sessions: g.sessions,
            caps: g.caps,
            revoked: g.revoked || false,
            created: new Date(g.created).toISOString(),
          })),
        })
      );
    },
  },

  // Discovery Tools
  {
    name: "p2p_join_topic",
    description: "Join a discovery topic to find other peers. Peers in the same topic can discover each other.",
    inputSchema: {
      type: "object",
      properties: {
        topic: { type: "string", description: "Topic name to join" },
      },
      required: ["topic"],
    },
    handler: async (args) => {
      try {
        await joinTopic(args.topic as string);
        return toolResult(
          JSON.stringify({
            success: true,
            topic: args.topic,
            activeTopics: getTopics(),
          })
        );
      } catch (err) {
        return toolResult(`Failed to join topic: ${err}`, true);
      }
    },
  },
  {
    name: "p2p_leave_topic",
    description: "Leave a discovery topic.",
    inputSchema: {
      type: "object",
      properties: {
        topic: { type: "string", description: "Topic name to leave" },
      },
      required: ["topic"],
    },
    handler: async (args) => {
      try {
        await leaveTopic(args.topic as string);
        return toolResult(
          JSON.stringify({
            success: true,
            topic: args.topic,
            activeTopics: getTopics(),
          })
        );
      } catch (err) {
        return toolResult(`Failed to leave topic: ${err}`, true);
      }
    },
  },
  {
    name: "p2p_list_topics",
    description: "List all discovery topics you've joined.",
    inputSchema: {
      type: "object",
      properties: {},
    },
    handler: async () => {
      const topics = getTopics();
      return toolResult(
        JSON.stringify({
          count: topics.length,
          topics,
        })
      );
    },
  },
  {
    name: "p2p_discover_peers",
    description: "List peers discovered through topic-based discovery.",
    inputSchema: {
      type: "object",
      properties: {
        topic: { type: "string", description: "Filter by topic (optional)" },
      },
    },
    handler: async (args) => {
      const peers = getDiscoveredPeers(args.topic as string | undefined);
      return toolResult(
        JSON.stringify({
          count: peers.length,
          peers: peers.map((p) => ({
            id: p.id,
            publicKey: p.publicKey.slice(0, 20) + "...",
            topics: p.topics,
            content: p.content,
            connected: p.connected || false,
          })),
        })
      );
    },
  },
  {
    name: "p2p_connect_peer",
    description: "Request connection with a discovered peer. They will decide whether to accept.",
    inputSchema: {
      type: "object",
      properties: {
        peerId: { type: "string", description: "Peer ID or public key" },
      },
      required: ["peerId"],
    },
    handler: async (args) => {
      try {
        const result = await requestConnection(args.peerId as string);
        if (result.accept) {
          return toolResult(
            JSON.stringify({
              success: true,
              connected: true,
              sessions: result.sessions,
            })
          );
        } else {
          return toolResult(`Connection rejected: ${result.message || result.reason}`, true);
        }
      } catch (err) {
        return toolResult(`Connection failed: ${err}`, true);
      }
    },
  },
  {
    name: "p2p_get_profile",
    description: "Get your discovery profile.",
    inputSchema: {
      type: "object",
      properties: {},
    },
    handler: async () => {
      const profile = getProfile();
      if (!profile) {
        return toolResult("Discovery not initialized", true);
      }
      return toolResult(
        JSON.stringify({
          id: profile.id,
          publicKey: profile.publicKey.slice(0, 20) + "...",
          topics: profile.topics,
          content: profile.content,
          updated: new Date(profile.updated).toISOString(),
        })
      );
    },
  },
  {
    name: "p2p_set_profile",
    description: "Update your discovery profile content. This is broadcast to peers.",
    inputSchema: {
      type: "object",
      properties: {
        content: {
          type: "object",
          description: "Profile content (name, about, capabilities, etc.)",
        },
      },
      required: ["content"],
    },
    handler: async (args) => {
      try {
        const profile = updateProfile(args.content as Record<string, unknown>);
        if (!profile) {
          return toolResult("Discovery not initialized", true);
        }
        return toolResult(
          JSON.stringify({
            success: true,
            id: profile.id,
            content: profile.content,
            updated: new Date(profile.updated).toISOString(),
          })
        );
      } catch (err) {
        return toolResult(`Failed to update profile: ${err}`, true);
      }
    },
  },
];

/**
 * Plugin export
 */
const plugin: WOPRPlugin = {
  name: "p2p",
  version: "1.0.0",
  description: "P2P networking with Hyperswarm, identity, trust, and A2A tools",

  // CLI commands
  commands: [friendCommand],

  async init(pluginContext: WOPRPluginContext) {
    ctx = pluginContext;
    ctx.log.info("Initializing P2P plugin...");

    // Set up P2P module logger for debugging
    setP2PLogger((msg) => ctx?.log.info(`[p2p] ${msg}`));

    // Configure bootstrap nodes if specified in config
    const pluginConfig = ctx.getConfig();
    ctx.log.info(`P2P plugin config received: ${JSON.stringify(pluginConfig)}`);
    if (pluginConfig.bootstrap) {
      const bootstrapNodes = Array.isArray(pluginConfig.bootstrap)
        ? pluginConfig.bootstrap
        : [pluginConfig.bootstrap];
      setP2PConfig({ bootstrap: bootstrapNodes as string[] });
      ctx.log.info(`P2P bootstrap configured: ${bootstrapNodes.join(", ")}`);
    } else {
      ctx.log.warn("No bootstrap config found in plugin config");
    }

    // Ensure identity exists
    let identity = getIdentity();
    if (!identity) {
      identity = initIdentity();
      ctx.log.info(`P2P identity created: ${shortKey(identity.publicKey)}`);
    } else {
      ctx.log.info(`P2P identity: ${shortKey(identity.publicKey)}`);
    }

    // Start P2P listener with log and inject handlers
    p2pListener = createP2PListener({
      // Log handler - mailbox style, just stores message in session history
      onLogMessage: (session, message, peerKey) => {
        const peerId = peerKey ? shortKey(peerKey) : "unknown";
        ctx?.log.info(`P2P log message: ${peerId} -> ${session}`);
        ctx?.log.info(`P2P message content: ${message.slice(0, 200)}...`);

        // Log the message to the session (makes it visible in history)
        if (ctx?.logMessage) {
          ctx.logMessage(session, message, {
            from: `p2p:${peerId}`,
            channel: { type: "p2p", id: peerKey || "unknown" },
          });
          ctx?.log.info(`[p2p] Message logged to session ${session}`);
        } else {
          ctx?.log.warn(`[p2p] No logMessage method - message not logged to session`);
        }
      },

      // Inject handler - invokes AI and returns response
      onInjectMessage: async (session, message, peerKey) => {
        const peerId = peerKey ? shortKey(peerKey) : "unknown";
        ctx?.log.info(`P2P inject message: ${peerId} -> ${session}`);
        ctx?.log.info(`P2P message content: ${message.slice(0, 200)}...`);

        // Get the friend's security context for proper trust level
        const friendSecurity = peerKey ? getFriendSecurityContext(peerKey) : null;
        const trustLevel = (friendSecurity?.trustLevel || "untrusted") as
          "untrusted" | "semi-trusted" | "trusted" | "owner";
        ctx?.log.info(`[p2p] Peer ${peerId} trust level: ${trustLevel} (sandboxed: ${trustLevel === "untrusted" || trustLevel === "semi-trusted"})`);

        // Invoke the AI and get response
        if (ctx?.inject) {
          try {
            ctx?.log.info(`[p2p] Calling ctx.inject for session ${session}...`);

            // Track this session as being P2P injected into
            // This prevents the AI from calling p2p_inject_message while processing
            sessionsBeingInjected.add(session);
            ctx?.log.info(`[p2p] Session ${session} marked as being-injected (blocks p2p_inject_message)`);

            const startTime = Date.now();
            try {
              // Create security source with proper trust level for sandboxing
              // Trust levels: untrusted/semi-trusted -> sandboxed, trusted/owner -> not sandboxed
              const source = {
                type: "p2p" as const,
                trustLevel,
                identity: { publicKey: peerKey || peerId },
                grantedCapabilities: friendSecurity?.capabilities,
              };

              const response = await ctx.inject(session, message, {
                from: `p2p:${peerKey || peerId}`,
                channel: { type: "p2p", id: peerKey || "unknown" },
                source, // Pass the security source with friend's trust level
              });
              const elapsed = Date.now() - startTime;
              ctx?.log.info(`[p2p] AI response generated (${response.length} chars) in ${elapsed}ms`);
              return response;
            } finally {
              // Always clear the tracking, even on error
              sessionsBeingInjected.delete(session);
              ctx?.log.info(`[p2p] Session ${session} cleared from being-injected tracking`);
            }
          } catch (err) {
            ctx?.log.error(`[p2p] Inject failed: ${err}`);
            return `Error: Failed to process message - ${err}`;
          }
        } else {
          ctx?.log.warn(`[p2p] No inject method - cannot invoke AI`);
          return "Error: AI injection not available";
        }
      },

      // Logging output
      onLog: (msg) => ctx?.log.info(`[p2p] ${msg}`),
    });

    if (p2pListener) {
      ctx.log.info("P2P listener started");
    }

    // Initialize discovery system
    try {
      await initDiscovery(
        async (peerProfile, topic) => {
          ctx?.log.info(`Discovery connection request from ${peerProfile.id} in ${topic}`);

          // Check if this peer has ANY valid grant (session filtering happens when messaging)
          const grants = getAccessGrants();
          const grant = grants.find(g => g.peerKey === peerProfile.publicKey && !g.revoked);

          if (grant) {
            ctx?.log.info(`[security] Peer ${peerProfile.id} has valid grant - accepting connection`);
            return {
              accept: true,
              sessions: grant.sessions,
            };
          }

          // SECURITY: Do NOT auto-accept discovered peers that haven't been granted access
          // They must be explicitly granted access via p2p_grant_access
          ctx?.log.warn(
            `[security] Discovered peer ${peerProfile.id} requires explicit grant. ` +
            `Use p2p_grant_access to authorize.`
          );
          return {
            accept: false,
            sessions: [],
            reason: `Peer not authorized. Use p2p_grant_access to authorize peer ${peerProfile.id}.`,
          };
        },
        (msg) => ctx?.log.info(`[discovery] ${msg}`)
      );
      ctx.log.info("Discovery system initialized");
    } catch (err) {
      ctx.log.warn(`Failed to initialize discovery: ${err}`);
    }

    // Register A2A tools
    const a2aConfig: A2AServerConfig = {
      name: "p2p",
      version: "1.0.0",
      tools: p2pTools,
    };

    if (ctx.registerA2AServer) {
      ctx.registerA2AServer(a2aConfig);
      ctx.log.info(`Registered ${p2pTools.length} P2P A2A tools`);
    }

    // Register P2P extension for other plugins to use
    if (ctx.registerExtension) {
      ctx.registerExtension("p2p", {
        // Identity
        getIdentity: () => {
          const id = getIdentity();
          return id ? { publicKey: id.publicKey, shortId: shortKey(id.publicKey), encryptPub: id.encryptPub } : null;
        },
        shortKey,

        // Peers
        getPeers,
        findPeer,
        namePeer,
        revokePeer,

        // Messaging
        injectPeer: async (peerKey: string, session: string, message: string) => {
          return sendP2PInject(peerKey, session, message);
        },

        // Discovery
        joinTopic,
        leaveTopic,
        getTopics,
        getDiscoveredPeers,
        requestConnection,

        // Friend request handling (for Discord button integration)
        acceptFriendRequest: async (from: string, pubkey: string, encryptPub: string, signature: string, channelId: string) => {
          // Find the pending request by signature
          const pending = getPendingIncomingBySignature(signature);
          if (!pending) {
            // Check if we can find it by username
            const result = acceptPendingRequest(from);
            if (!result) {
              throw new Error(`No pending friend request from @${from}`);
            }
            // Complete the accept using the original request
            const config = ctx?.getConfig() as { botUsername?: string } | undefined;
            const myUsername = config?.botUsername || "unknown";
            const accept = createFriendAccept(result.request, myUsername);
            return {
              friend: result.friend,
              acceptMessage: formatFriendAccept(accept),
            };
          }

          // Accept the pending request
          const result = acceptPendingRequest(from);
          if (!result) {
            throw new Error(`Failed to accept friend request from @${from}`);
          }

          // Get our bot username for the accept message
          const config2 = ctx?.getConfig() as { botUsername?: string } | undefined;
          const myUsername = config2?.botUsername || "unknown";
          const accept = createFriendAccept(result.request, myUsername);

          ctx?.log.info(`[p2p] Friend request from @${from} accepted via button`);

          return {
            friend: result.friend,
            acceptMessage: formatFriendAccept(accept),
          };
        },

        denyFriendRequest: async (from: string, signature: string) => {
          // Try to find and remove by username or signature
          const removed = denyPendingRequest(from) || denyPendingRequest(signature);

          if (!removed) {
            throw new Error(`No pending friend request from @${from}`);
          }

          ctx?.log.info(`[p2p] Friend request from @${from} denied via button`);
        },
      });
      ctx.log.info("Registered P2P extension for inter-plugin use");
    }

    // Register friend protocol channel hooks
    // This adds /friend, /accept, /friends, /unfriend, /grant commands to all channel providers
    try {
      registerChannelHooks(ctx as any);
      registerAutoAcceptCommands(ctx as any);
      ctx.log.info("Registered friend protocol channel hooks");
    } catch (err) {
      ctx.log.warn(`Failed to register channel hooks: ${err}`);
    }

    // Register P2P slash commands with Discord
    // This merges with existing Discord commands so /friend, /accept, etc. show up
    try {
      // Get Discord config from main config or environment
      const mainDiscordConfig = ctx.getMainConfig?.("discord") as { token?: string; clientId?: string; guildId?: string } | undefined;
      const discordToken = mainDiscordConfig?.token || process.env.DISCORD_TOKEN;
      const discordClientId = mainDiscordConfig?.clientId || process.env.DISCORD_CLIENT_ID;
      const discordGuildId = mainDiscordConfig?.guildId || process.env.DISCORD_GUILD_ID;

      if (discordToken && discordClientId) {
        await registerP2PSlashCommands(
          discordToken,
          discordClientId,
          discordGuildId,
          ctx.log
        );
      } else {
        ctx.log.info("[p2p] Discord config not available - P2P slash commands not registered");
      }
    } catch (err) {
      ctx.log.warn(`[p2p] Failed to register P2P slash commands: ${err}`);
    }

    // Clean up expired friend requests on startup
    cleanupExpiredRequests();

    // Sync all existing friends to WOPR security model
    try {
      syncAllFriendsToSecurity();
      ctx.log.info("Synced friends to WOPR security model");
    } catch (err) {
      ctx.log.warn(`Failed to sync friends to security model: ${err}`);
    }

    // Start UI server
    const config = ctx.getConfig();
    const uiPort = (config.uiPort as number) || 7334;

    try {
      uiServer = startUIServer(uiPort, ctx.getPluginDir());

      // Register UI component
      if (ctx.registerUiComponent) {
        ctx.registerUiComponent({
          id: "p2p-panel",
          title: "P2P Network",
          moduleUrl: `http://127.0.0.1:${uiPort}/ui.js`,
          slot: "settings",
          description: "Manage P2P peers and invites",
        });
        ctx.log.info("Registered P2P UI component");
      }

      // Register as web extension
      if (ctx.registerWebUiExtension) {
        ctx.registerWebUiExtension({
          id: "p2p",
          title: "P2P Network",
          url: `http://127.0.0.1:${uiPort}`,
          description: "P2P peer management",
          category: "network",
        });
      }
    } catch (err) {
      ctx.log.warn(`Failed to start UI server: ${err}`);
    }

    ctx.log.info("P2P plugin initialized");
  },

  async shutdown() {
    logger.info("[p2p] Shutting down...");

    // Unregister P2P extension
    if (ctx?.unregisterExtension) {
      ctx.unregisterExtension("p2p");
      logger.info("[p2p] P2P extension unregistered");
    }

    // Shutdown discovery
    try {
      await shutdownDiscovery();
      logger.info("[p2p] Discovery shutdown complete");
    } catch (err) {
      logger.warn(`[p2p] Discovery shutdown error: ${err}`);
    }

    if (p2pListener) {
      await p2pListener.destroy();
      p2pListener = null;
    }

    if (uiServer) {
      await new Promise<void>((resolve) => uiServer!.close(() => resolve()));
      uiServer = null;
    }

    ctx = null;
    logger.info("[p2p] Shutdown complete");
  },
};

export default plugin;

// Re-export core modules for programmatic use
export * from "./identity.js";
export * from "./trust.js";
export * from "./p2p.js";
export * from "./discovery.js";
export * from "./config.js";
export * from "./types.js";
export * from "./friends.js";
export * from "./channel-hooks.js";
export * from "./cli-commands.js";
export * from "./security-integration.js";
