/**
 * Security Integration Module
 *
 * Bridges P2P friend capabilities with WOPR's security model.
 * P2P peers can only have "message" or "inject" - both sandboxed, both untrusted.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { homedir } from "os";
import { join } from "path";
import { getFriend, getFriends, setFriendCaps } from "./friends.js";
import type { Friend } from "./types.js";

// WOPR home directory — computed lazily so tests can override WOPR_HOME
function getWoprHome(): string {
	return process.env.WOPR_HOME || join(homedir(), "wopr");
}
function getSecurityConfigFile(): string {
	return join(getWoprHome(), "security.json");
}

/**
 * Mapping from friend capabilities to WOPR security capabilities.
 *
 * SIMPLE: Friends can either send messages or invoke AI. That's it.
 * The SANDBOX controls what tools/commands are available, not capabilities.
 */
export const FRIEND_CAP_TO_WOPR_CAPS: Record<string, string[]> = {
	// message - fire and forget, no AI response (just logs to conversation)
	message: ["inject"],

	// inject - can invoke AI and get response (AI runs in sandbox)
	inject: ["inject", "inject.tools"],
};

/**
 * Trust level mapping for friends.
 *
 * SECURITY: ALL P2P peers are untrusted and sandboxed. Period.
 * The sandbox controls what's allowed, not trust levels.
 */
export const FRIEND_CAP_TO_TRUST_LEVEL: Record<string, string> = {
	message: "untrusted", // Sandboxed, no workspace
	inject: "untrusted", // Sandboxed, no workspace
};

/**
 * Load WOPR security configuration.
 */
export function loadSecurityConfig(): any {
	const configFile = getSecurityConfigFile();
	if (!existsSync(configFile)) {
		return null;
	}
	try {
		return JSON.parse(readFileSync(configFile, "utf-8"));
	} catch {
		return null;
	}
}

/**
 * Save WOPR security configuration.
 */
export function saveSecurityConfig(config: any): void {
	const dir = getWoprHome();
	if (!existsSync(dir)) {
		mkdirSync(dir, { recursive: true });
	}
	writeFileSync(getSecurityConfigFile(), JSON.stringify(config, null, 2));
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
	// P2P sessions always default to indexable: ["self"] - can only search own transcripts
	// Even admin friends need explicit grants to see other sessions' transcripts
	config.sessions[friend.sessionName] = {
		access: [accessPattern],
		capabilities: woprCaps,
		indexable: ["self"],
		description: `Dedicated session for friend @${friend.name}`,
	};

	// Configure the P2P source
	config.sources[accessPattern] = {
		type: "p2p",
		trust: trustLevel,
		capabilities: woprCaps,
		sessions: [friend.sessionName],
		rateLimit: {
			perMinute:
				trustLevel === "owner" ? 1000 : trustLevel === "trusted" ? 100 : 30,
			perHour:
				trustLevel === "owner" ? 10000 : trustLevel === "trusted" ? 1000 : 300,
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
export function updateFriendSecurityCaps(
	friendName: string,
	newCaps: string[],
): void {
	const friend = getFriend(friendName);
	if (!friend) return;

	// Persist updated caps to disk, then sync to security
	setFriendCaps(friendName, newCaps);
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
export function hasFriendCapability(
	publicKey: string,
	capability: string,
): boolean {
	const friends = getFriends();
	const friend = friends.find((f) => f.publicKey === publicKey);

	if (!friend) return false;

	// Check direct capability match - only "message" or "inject" are valid
	return friend.caps.includes(capability);
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
	const friend = friends.find((f) => f.publicKey === publicKey);

	if (!friend) return null;

	return {
		trustLevel: getHighestTrustLevel(friend.caps),
		capabilities: getWoprCapabilities(friend.caps),
		allowedSessions: [friend.sessionName],
	};
}

/**
 * Validate that a friend can perform an action.
 *
 * SIMPLE: Friends can either send messages or invoke AI. That's it.
 */
export function validateFriendAction(
	publicKey: string,
	action: "message" | "inject",
	targetSession?: string,
): { allowed: boolean; reason?: string } {
	const friends = getFriends();
	const friend = friends.find((f) => f.publicKey === publicKey);

	if (!friend) {
		return { allowed: false, reason: "Not a friend" };
	}

	// Check session access
	if (targetSession && targetSession !== friend.sessionName) {
		return {
			allowed: false,
			reason: `Can only access session: ${friend.sessionName}`,
		};
	}

	// Check capability - just message or inject
	if (friend.caps.includes(action)) {
		return { allowed: true };
	}

	return {
		allowed: false,
		reason: `Missing capability: ${action}. Current caps: ${friend.caps.join(", ")}`,
	};
}
