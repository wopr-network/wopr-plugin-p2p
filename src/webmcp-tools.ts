/**
 * WebMCP response builders for P2P plugin.
 *
 * Builds JSON responses for the three WebMCP endpoints:
 * - /api/webmcp/status  — node identity, peers, grants, topics
 * - /api/webmcp/peers   — peer list with truncated public keys
 * - /api/webmcp/stats   — network statistics with formatted values
 *
 * Security: public keys are safe to expose. Private keys, encryptPriv,
 * and encryptPub are NEVER included in any response.
 */

import { getDiscoveredPeers, getTopics } from "./discovery.js";
import { getIdentity, shortKey } from "./identity.js";
import { getP2PStats } from "./stats.js";
import { getAccessGrants, getPeers } from "./trust.js";

/**
 * Format bytes into a human-readable string.
 */
export function formatBytes(bytes: number): string {
	if (bytes < 1024) return `${bytes} B`;
	if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
	return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/**
 * Format milliseconds into a human-readable uptime string.
 */
export function formatUptime(ms: number): string {
	const seconds = Math.floor(ms / 1000);
	if (seconds < 60) return `${seconds}s`;

	const minutes = Math.floor(seconds / 60);
	const remSeconds = seconds % 60;
	if (minutes < 60) return `${minutes}m ${remSeconds}s`;

	const hours = Math.floor(minutes / 60);
	const remMinutes = minutes % 60;
	if (hours < 24) return `${hours}h ${remMinutes}m`;

	const days = Math.floor(hours / 24);
	const remHours = hours % 24;
	return `${days}d ${remHours}h`;
}

/**
 * Build the response for GET /api/webmcp/status
 */
export function buildP2pStatusResponse(): Record<string, unknown> {
	const identity = getIdentity();
	const peers = getPeers();
	const grants = getAccessGrants();
	const topics = getTopics();

	return {
		node: identity
			? {
					shortId: shortKey(identity.publicKey),
					publicKey: identity.publicKey,
					created: new Date(identity.created).toISOString(),
				}
			: null,
		peers: {
			count: peers.length,
		},
		grants: {
			total: grants.length,
			active: grants.filter((g) => !g.revoked).length,
			revoked: grants.filter((g) => g.revoked).length,
		},
		topics,
	};
}

/**
 * Build the response for GET /api/webmcp/peers
 */
export function buildListPeersResponse(): Record<string, unknown> {
	const peers = getPeers();
	const discovered = getDiscoveredPeers();
	const discoveredMap = new Map(discovered.map((d) => [d.publicKey, d]));

	return {
		count: peers.length,
		peers: peers.map((p) => ({
			id: p.id,
			name: p.name,
			publicKey: `${p.publicKey.slice(0, 20)}...`,
			sessions: p.sessions,
			caps: p.caps,
			added: new Date(p.added).toISOString(),
			connected: discoveredMap.get(p.publicKey)?.connected ?? false,
		})),
	};
}

/**
 * Build the response for GET /api/webmcp/stats
 */
export function buildP2pStatsResponse(): Record<string, unknown> {
	const stats = getP2PStats();
	const uptimeMs = Date.now() - stats.startedAt;

	return {
		messagesRelayed: stats.messagesRelayed,
		connectionsTotal: stats.connectionsTotal,
		uptime: formatUptime(uptimeMs),
		startedAt: new Date(stats.startedAt).toISOString(),
	};
}
