/**
 * P2P Discovery Module
 *
 * Topic-based peer discovery using Hyperswarm DHT.
 * Peers can join topics to find each other without prior knowledge.
 */

import Hyperswarm from "hyperswarm";
import { createHash } from "crypto";
import { getIdentity, shortKey } from "./identity.js";
import { addPeer, grantAccess } from "./trust.js";
import type { DiscoveredPeer, DiscoveryProfile, ConnectionResult } from "./types.js";
import { EXIT_OK, EXIT_PEER_OFFLINE, EXIT_UNAUTHORIZED } from "./types.js";

// Discovery state
let discoverySwarm: Hyperswarm | null = null;
let myProfile: DiscoveryProfile | null = null;
const activeTopics: Map<string, Buffer> = new Map();
const discoveredPeers: Map<string, DiscoveredPeer> = new Map();
let connectionHandler: ((peer: DiscoveryProfile, topic: string) => Promise<ConnectionResult>) | null = null;
let logFn: ((msg: string) => void) | null = null;

/**
 * Hash a topic name to a 32-byte key for DHT
 */
function hashTopic(topic: string): Buffer {
  return createHash("sha256").update(`wopr:discovery:${topic}`).digest();
}

/**
 * Initialize discovery system
 */
export async function initDiscovery(
  onConnectionRequest: (peer: DiscoveryProfile, topic: string) => Promise<ConnectionResult>,
  logger?: (msg: string) => void
): Promise<void> {
  if (discoverySwarm) {
    await shutdownDiscovery();
  }

  connectionHandler = onConnectionRequest;
  logFn = logger || console.log;

  const identity = getIdentity();
  if (!identity) {
    throw new Error("Identity required for discovery");
  }

  // Initialize profile
  myProfile = {
    id: shortKey(identity.publicKey),
    publicKey: identity.publicKey,
    encryptPub: identity.encryptPub,
    content: {},
    topics: [],
    updated: Date.now(),
  };

  // Create discovery swarm
  discoverySwarm = new Hyperswarm();

  discoverySwarm.on("connection", async (socket, peerInfo) => {
    const remotePubkey = peerInfo.publicKey?.toString("hex");
    logFn?.(`Discovery connection from ${remotePubkey ? shortKey(remotePubkey) : "unknown"}`);

    // Exchange profiles
    socket.write(JSON.stringify({
      type: "profile",
      profile: myProfile,
    }));

    socket.on("data", async (data: Buffer) => {
      try {
        const msg = JSON.parse(data.toString());

        if (msg.type === "profile" && msg.profile) {
          const peer = msg.profile as DiscoveryProfile;
          discoveredPeers.set(peer.publicKey, peer);
          logFn?.(`Discovered peer: ${peer.id}`);
        } else if (msg.type === "connect_request" && msg.topic) {
          // Handle connection request
          if (connectionHandler && myProfile) {
            const result = await connectionHandler(msg.profile, msg.topic);
            socket.write(JSON.stringify({
              type: "connect_response",
              ...result,
            }));

            if (result.accept && msg.profile) {
              // Grant access
              grantAccess(msg.profile.publicKey, result.sessions || ["*"], ["inject"], msg.profile.encryptPub);
              addPeer(msg.profile.publicKey, result.sessions || ["*"], ["inject"], msg.profile.encryptPub);
              logFn?.(`Granted access to ${msg.profile.id}`);
            }
          }
        } else if (msg.type === "connect_response") {
          // Handle connection response (stored for later retrieval)
          if (msg.accept && remotePubkey) {
            const peer = discoveredPeers.get(remotePubkey);
            if (peer) {
              peer.connected = true;
              peer.grantedSessions = msg.sessions;
            }
          }
        }
      } catch (err) {
        logFn?.(`Discovery message error: ${err}`);
      }
    });

    socket.on("error", (err: Error) => {
      logFn?.(`Discovery socket error: ${err.message}`);
    });
  });

  logFn?.("Discovery initialized");
}

/**
 * Join a discovery topic
 */
export async function joinTopic(topic: string): Promise<void> {
  if (!discoverySwarm) {
    throw new Error("Discovery not initialized");
  }

  if (activeTopics.has(topic)) {
    return; // Already in topic
  }

  const topicHash = hashTopic(topic);
  activeTopics.set(topic, topicHash);

  if (myProfile) {
    myProfile.topics = Array.from(activeTopics.keys());
    myProfile.updated = Date.now();
  }

  discoverySwarm.join(topicHash, { server: true, client: true });
  logFn?.(`Joined topic: ${topic}`);
}

/**
 * Leave a discovery topic
 */
export async function leaveTopic(topic: string): Promise<void> {
  if (!discoverySwarm) {
    return;
  }

  const topicHash = activeTopics.get(topic);
  if (!topicHash) {
    return; // Not in topic
  }

  activeTopics.delete(topic);

  if (myProfile) {
    myProfile.topics = Array.from(activeTopics.keys());
    myProfile.updated = Date.now();
  }

  await discoverySwarm.leave(topicHash);
  logFn?.(`Left topic: ${topic}`);
}

/**
 * Get list of active topics
 */
export function getTopics(): string[] {
  return Array.from(activeTopics.keys());
}

/**
 * Get discovered peers, optionally filtered by topic
 */
export function getDiscoveredPeers(topic?: string): DiscoveredPeer[] {
  const peers = Array.from(discoveredPeers.values());

  if (topic) {
    return peers.filter(p => p.topics?.includes(topic));
  }

  return peers;
}

/**
 * Request connection with a discovered peer
 */
export async function requestConnection(peerId: string): Promise<ConnectionResult> {
  if (!discoverySwarm || !myProfile) {
    return { accept: false, code: EXIT_PEER_OFFLINE, message: "Discovery not initialized" };
  }

  // Find peer
  let peer: DiscoveredPeer | undefined;
  for (const p of discoveredPeers.values()) {
    if (p.id === peerId || p.publicKey === peerId) {
      peer = p;
      break;
    }
  }

  if (!peer) {
    return { accept: false, code: EXIT_PEER_OFFLINE, message: "Peer not found" };
  }

  // Find a common topic
  const commonTopic = peer.topics?.find(t => activeTopics.has(t));
  if (!commonTopic) {
    return { accept: false, code: EXIT_UNAUTHORIZED, message: "No common topic with peer" };
  }

  // Send connection request via the swarm
  // This is simplified - in production you'd track the specific connection
  return new Promise((resolve) => {
    const timeout = setTimeout(() => {
      resolve({ accept: false, code: EXIT_PEER_OFFLINE, message: "Connection timeout" });
    }, 10000);

    // Check if peer accepted (simplified - relies on connect_response handler)
    const checkInterval = setInterval(() => {
      const updatedPeer = discoveredPeers.get(peer!.publicKey);
      if (updatedPeer?.connected) {
        clearTimeout(timeout);
        clearInterval(checkInterval);
        resolve({
          accept: true,
          code: EXIT_OK,
          sessions: updatedPeer.grantedSessions || ["*"],
        });
      }
    }, 500);
  });
}

/**
 * Get current profile
 */
export function getProfile(): DiscoveryProfile | null {
  return myProfile;
}

/**
 * Update profile content
 */
export function updateProfile(content: Record<string, unknown>): DiscoveryProfile | null {
  if (!myProfile) {
    return null;
  }

  myProfile.content = { ...myProfile.content, ...content };
  myProfile.updated = Date.now();

  // Broadcast updated profile to all connections
  if (discoverySwarm) {
    for (const conn of discoverySwarm.connections) {
      try {
        conn.write(JSON.stringify({
          type: "profile",
          profile: myProfile,
        }));
      } catch {
        // Ignore write errors
      }
    }
  }

  return myProfile;
}

/**
 * Shutdown discovery system
 */
export async function shutdownDiscovery(): Promise<void> {
  if (discoverySwarm) {
    // Leave all topics
    for (const [topic, hash] of activeTopics) {
      try {
        await discoverySwarm.leave(hash);
      } catch {
        // Ignore errors during shutdown
      }
    }

    await discoverySwarm.destroy();
    discoverySwarm = null;
  }

  activeTopics.clear();
  discoveredPeers.clear();
  myProfile = null;
  connectionHandler = null;
  logFn = null;
}
