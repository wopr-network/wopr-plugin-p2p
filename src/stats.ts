/**
 * In-memory P2P statistics collector.
 *
 * Tracks messages relayed, connections, and bandwidth for WebMCP reporting.
 */

export interface P2PStats {
	messagesRelayed: number;
	connectionsTotal: number;
	startedAt: number;
}

let stats: P2PStats = {
	messagesRelayed: 0,
	connectionsTotal: 0,
	startedAt: Date.now(),
};

export function getP2PStats(): Readonly<P2PStats> {
	return { ...stats };
}

export function incrementStat(
	key: keyof Omit<P2PStats, "startedAt">,
	amount = 1,
): void {
	stats[key] += amount;
}

export function resetStats(): void {
	stats = {
		messagesRelayed: 0,
		connectionsTotal: 0,
		startedAt: Date.now(),
	};
}
