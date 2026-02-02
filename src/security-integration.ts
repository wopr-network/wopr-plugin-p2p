/**
 * Security Integration Module
 *
 * Bridges P2P friend capabilities with WOPR's security model.
 * Maps friend caps (message, inject, inject.exec, etc.) to WOPR security capabilities.
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync } from "fs";
import { homedir } from "os";
import { join } from "path";
import type { Friend } from "./types.js";
import { getFriends, getFriend } from "./friends.js";

// WOPR home directory
const WOPR_HOME = process.env.WOPR_HOME || join(homedir(), "wopr");
const SECURITY_CONFIG_FILE = join(WOPR_HOME, "security.json");

/**
 * Mapping from friend capabilities to WOPR security capabilities.
 *
 * Friend caps are simpler (user-facing), WOPR caps are granular (system-level).
 */
export const FRIEND_CAP_TO_WOPR_CAPS: Record<string, string[]> = {
  // message - fire and forget, no AI response
  message: ["inject"],

  // inject - can invoke AI and get response
  inject: ["inject", "inject.tools"],

  // inject.exec - can run shell commands
  "inject.exec": ["inject", "inject.tools", "inject.exec"],

  // inject.spawn - can create new sessions
  "inject.spawn": ["inject", "inject.tools", "session.spawn"],

  // inject.network - can make network requests
  "inject.network": ["inject", "inject.tools", "inject.network"],

  // admin - full access
  admin: [
    "inject",
    "inject.tools",
    "inject.exec",
    "inject.network",
    "session.spawn",
    "session.history",
    "cross.inject",
    "cross.read",
    "config.read",
    "cron.manage",
    "event.emit",
    "a2a.call",
    "memory.read",
    "memory.write",
  ],
};

/**
 * Trust level mapping for friends.
 * Friends start as untrusted but can be elevated.
 */
export const FRIEND_CAP_TO_TRUST_LEVEL: Record<string, string> = {
  message: "untrusted",     // Fire-and-forget only
  inject: "semi-trusted",   // Can invoke AI
  "inject.exec": "trusted", // Can run commands
  "inject.spawn": "trusted",
  "inject.network": "semi-trusted",
  admin: "owner",           // Full access
};

/**
 * Load WOPR security configuration.
 */
export function loadSecurityConfig(): any {
  if (!existsSync(SECURITY_CONFIG_FILE)) {
    return null;
  }
  try {
    return JSON.parse(readFileSync(SECURITY_CONFIG_FILE, "utf-8"));
  } catch {
    return null;
  }
}

/**
 * Save WOPR security configuration.
 */
export function saveSecurityConfig(config: any): void {
  const dir = WOPR_HOME;
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
  writeFileSync(SECURITY_CONFIG_FILE, JSON.stringify(config, null, 2));
}

/**
 * Get the highest trust level from a list of friend capabilities.
 */
export function getHighestTrustLevel(caps: string[]): string {
  const trustOrder = ["untrusted", "semi-trusted", "trusted", "owner"];
  let highest = "untrusted";

  for (const cap of caps) {
    const level = FRIEND_CAP_TO_TRUST_LEVEL[cap] || "untrusted";
    if (trustOrder.indexOf(level) > trustOrder.indexOf(highest)) {
      highest = level;
    }
  }

  return highest;
}

/**
 * Get all WOPR capabilities granted by a list of friend capabilities.
 */
export function getWoprCapabilities(friendCaps: string[]): string[] {
  const woprCaps = new Set<string>();

  for (const cap of friendCaps) {
    const mapped = FRIEND_CAP_TO_WOPR_CAPS[cap];
    if (mapped) {
      for (const c of mapped) {
        woprCaps.add(c);
      }
    }
  }

  return Array.from(woprCaps);
}

/**
 * Sync a friend's capabilities to WOPR security configuration.
 *
 * This updates the security.json to grant the friend access
 * to their dedicated session with the appropriate capabilities.
 */
export function syncFriendToSecurity(friend: Friend): void {
  let config = loadSecurityConfig();

  if (!config) {
    // Create default config if none exists
    config = {
      enforcement: "warn",
      defaults: {},
      trustLevels: {},
      sessions: {},
      sources: {},
    };
  }

  // Ensure sessions config exists
  if (!config.sessions) {
    config.sessions = {};
  }

  // Ensure sources config exists
  if (!config.sources) {
    config.sources = {};
  }

  // Get WOPR capabilities from friend caps
  const woprCaps = getWoprCapabilities(friend.caps);
  const trustLevel = getHighestTrustLevel(friend.caps);

  // Create access pattern for this friend's P2P identity
  const accessPattern = `p2p:${friend.publicKey}`;

  // Configure the friend's dedicated session
  config.sessions[friend.sessionName] = {
    access: [accessPattern],
    capabilities: woprCaps,
    description: `Dedicated session for friend @${friend.name}`,
  };

  // Configure the P2P source
  config.sources[accessPattern] = {
    type: "p2p",
    trust: trustLevel,
    capabilities: woprCaps,
    sessions: [friend.sessionName],
    rateLimit: {
      perMinute: trustLevel === "owner" ? 1000 : trustLevel === "trusted" ? 100 : 30,
      perHour: trustLevel === "owner" ? 10000 : trustLevel === "trusted" ? 1000 : 300,
    },
  };

  saveSecurityConfig(config);
}

/**
 * Remove a friend's access from WOPR security configuration.
 */
export function removeFriendFromSecurity(friend: Friend): void {
  const config = loadSecurityConfig();
  if (!config) return;

  // Remove session config
  if (config.sessions && config.sessions[friend.sessionName]) {
    delete config.sessions[friend.sessionName];
  }

  // Remove source config
  const accessPattern = `p2p:${friend.publicKey}`;
  if (config.sources && config.sources[accessPattern]) {
    delete config.sources[accessPattern];
  }

  saveSecurityConfig(config);
}

/**
 * Update a friend's capabilities in WOPR security configuration.
 */
export function updateFriendSecurityCaps(friendName: string, newCaps: string[]): void {
  const friend = getFriend(friendName);
  if (!friend) return;

  // Update the friend object and sync to security
  friend.caps = newCaps;
  syncFriendToSecurity(friend);
}

/**
 * Sync all friends to WOPR security configuration.
 * Call this on plugin startup.
 */
export function syncAllFriendsToSecurity(): void {
  const friends = getFriends();
  for (const friend of friends) {
    syncFriendToSecurity(friend);
  }
}

/**
 * Check if a P2P peer has a specific capability.
 */
export function hasFriendCapability(publicKey: string, capability: string): boolean {
  const friends = getFriends();
  const friend = friends.find(f => f.publicKey === publicKey);

  if (!friend) return false;

  // Check direct capability match
  if (friend.caps.includes(capability)) return true;

  // Check if admin (has all capabilities)
  if (friend.caps.includes("admin")) return true;

  return false;
}

/**
 * Get the security context for a friend.
 */
export function getFriendSecurityContext(publicKey: string): {
  trustLevel: string;
  capabilities: string[];
  allowedSessions: string[];
} | null {
  const friends = getFriends();
  const friend = friends.find(f => f.publicKey === publicKey);

  if (!friend) return null;

  return {
    trustLevel: getHighestTrustLevel(friend.caps),
    capabilities: getWoprCapabilities(friend.caps),
    allowedSessions: [friend.sessionName],
  };
}

/**
 * Validate that a friend can perform an action.
 */
export function validateFriendAction(
  publicKey: string,
  action: "message" | "inject" | "exec" | "spawn",
  targetSession?: string
): { allowed: boolean; reason?: string } {
  const friends = getFriends();
  const friend = friends.find(f => f.publicKey === publicKey);

  if (!friend) {
    return { allowed: false, reason: "Not a friend" };
  }

  // Check session access
  if (targetSession && targetSession !== friend.sessionName) {
    return { allowed: false, reason: `Can only access session: ${friend.sessionName}` };
  }

  // Map action to required capability
  const actionToCap: Record<string, string> = {
    message: "message",
    inject: "inject",
    exec: "inject.exec",
    spawn: "inject.spawn",
  };

  const requiredCap = actionToCap[action];
  if (!requiredCap) {
    return { allowed: false, reason: `Unknown action: ${action}` };
  }

  // Check capability
  if (friend.caps.includes(requiredCap) || friend.caps.includes("admin")) {
    return { allowed: true };
  }

  return {
    allowed: false,
    reason: `Missing capability: ${requiredCap}. Current caps: ${friend.caps.join(", ")}`,
  };
}
