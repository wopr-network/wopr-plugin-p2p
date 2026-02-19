/**
 * Unit tests for the P2P Stats module
 */

import { describe, it, beforeEach } from "node:test";
import assert from "node:assert";

import { getP2PStats, incrementStat, resetStats } from "../src/stats.js";

describe("P2P Stats", () => {
	beforeEach(() => {
		resetStats();
	});

	it("should return zeros after reset", () => {
		const stats = getP2PStats();
		assert.strictEqual(stats.messagesRelayed, 0);
		assert.strictEqual(stats.messagesSent, 0);
		assert.strictEqual(stats.connectionsTotal, 0);
		assert.strictEqual(stats.bytesReceived, 0);
		assert.strictEqual(stats.bytesSent, 0);
		assert.ok(stats.startedAt > 0);
	});

	it("should increment a stat by 1 by default", () => {
		incrementStat("messagesRelayed");
		const stats = getP2PStats();
		assert.strictEqual(stats.messagesRelayed, 1);
	});

	it("should increment a stat by a custom amount", () => {
		incrementStat("bytesReceived", 1024);
		const stats = getP2PStats();
		assert.strictEqual(stats.bytesReceived, 1024);
	});

	it("should increment multiple stats independently", () => {
		incrementStat("messagesRelayed", 5);
		incrementStat("connectionsTotal", 3);
		incrementStat("bytesSent", 2048);

		const stats = getP2PStats();
		assert.strictEqual(stats.messagesRelayed, 5);
		assert.strictEqual(stats.connectionsTotal, 3);
		assert.strictEqual(stats.bytesSent, 2048);
		assert.strictEqual(stats.messagesSent, 0);
	});

	it("should reset all stats to zero", () => {
		incrementStat("messagesRelayed", 10);
		incrementStat("connectionsTotal", 5);
		incrementStat("bytesReceived", 4096);

		resetStats();

		const stats = getP2PStats();
		assert.strictEqual(stats.messagesRelayed, 0);
		assert.strictEqual(stats.connectionsTotal, 0);
		assert.strictEqual(stats.bytesReceived, 0);
	});

	it("should return a copy (not a reference)", () => {
		const stats1 = getP2PStats();
		incrementStat("messagesRelayed");
		const stats2 = getP2PStats();

		assert.strictEqual(stats1.messagesRelayed, 0);
		assert.strictEqual(stats2.messagesRelayed, 1);
	});

	it("should update startedAt on reset", () => {
		const before = getP2PStats().startedAt;
		// Small delay to ensure different timestamp
		const start = Date.now();
		while (Date.now() - start < 5) {
			// busy wait
		}
		resetStats();
		const after = getP2PStats().startedAt;
		assert.ok(after >= before);
	});
});
