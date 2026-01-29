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
} from "./trust.js";
import { sendP2PInject, claimToken, createP2PListener, sendKeyRotation } from "./p2p.js";
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
} from "./discovery.js";

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
    name: "p2p_send_message",
    description: "Send an encrypted message to a peer. They must be online and you must have access.",
    inputSchema: {
      type: "object",
      properties: {
        peer: { type: "string", description: "Peer ID, name, or public key" },
        session: { type: "string", description: "Session to inject into" },
        message: { type: "string", description: "Message content" },
        timeoutMs: { type: "number", description: "Timeout in milliseconds (default: 10000)" },
      },
      required: ["peer", "session", "message"],
    },
    handler: async (args) => {
      const result = await sendP2PInject(
        args.peer as string,
        args.session as string,
        args.message as string,
        (args.timeoutMs as number) || 10000
      );

      if (result.code === EXIT_OK) {
        return toolResult(
          JSON.stringify({
            success: true,
            peer: args.peer,
            session: args.session,
          })
        );
      } else {
        return toolResult(`Send failed: ${result.message}`, true);
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
    description: "Manually grant a peer access to specific sessions without using tokens.",
    inputSchema: {
      type: "object",
      properties: {
        peerKey: { type: "string", description: "Public key of the peer" },
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
        const grant = grantAccess(
          args.peerKey as string,
          args.sessions as string[],
          (args.caps as string[]) || ["inject"]
        );
        return toolResult(
          JSON.stringify({
            success: true,
            grantId: grant.id,
            peer: shortKey(args.peerKey as string),
            sessions: grant.sessions,
            caps: grant.caps,
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

  async init(pluginContext: WOPRPluginContext) {
    ctx = pluginContext;
    ctx.log.info("Initializing P2P plugin...");

    // Ensure identity exists
    let identity = getIdentity();
    if (!identity) {
      identity = initIdentity();
      ctx.log.info(`P2P identity created: ${shortKey(identity.publicKey)}`);
    } else {
      ctx.log.info(`P2P identity: ${shortKey(identity.publicKey)}`);
    }

    // Start P2P listener
    p2pListener = createP2PListener(
      async (session, message, peerKey) => {
        ctx?.log.info(`P2P inject: ${peerKey ? shortKey(peerKey) : "unknown"} -> ${session}`);
        // TODO: Forward to WOPR session injection system
      },
      (msg) => ctx?.log.info(`[p2p] ${msg}`)
    );

    if (p2pListener) {
      ctx.log.info("P2P listener started");
    }

    // Initialize discovery system
    try {
      await initDiscovery(
        async (peerProfile, topic) => {
          ctx?.log.info(`Discovery connection request from ${peerProfile.id} in ${topic}`);
          // Auto-accept connections from discovered peers
          return {
            accept: true,
            sessions: ["*"],
            reason: `Discovered in topic: ${topic}`,
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
      });
      ctx.log.info("Registered P2P extension for inter-plugin use");
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
export * from "./types.js";
