/**
 * Unit tests for the P2P Stats module
 */

import { describe, it, beforeEach, expect } from "vitest";

import { getP2PStats, incrementStat, resetStats } from "../src/stats.js";

describe("P2P Stats", () => {
  beforeEach(() => {
    resetStats();
  });

	it("should return zeros after reset", () => {
		const stats = getP2PStats();
		expect(stats.messagesRelayed).toBe(0);
		expect(stats.connectionsTotal).toBe(0);
		expect(stats.startedAt > 0).toBeTruthy();
	});

	it("should increment a stat by 1 by default", () => {
		incrementStat("messagesRelayed");
		const stats = getP2PStats();
		expect(stats.messagesRelayed).toBe(1);
	});

  it("should increment multiple stats independently", () => {
    incrementStat("messagesRelayed", 5);
    incrementStat("connectionsTotal", 3);

		const stats = getP2PStats();
		expect(stats.messagesRelayed).toBe(5);
		expect(stats.connectionsTotal).toBe(3);
	});

  it("should reset all stats to zero", () => {
    incrementStat("messagesRelayed", 10);
    incrementStat("connectionsTotal", 5);

    resetStats();

		const stats = getP2PStats();
		expect(stats.messagesRelayed).toBe(0);
		expect(stats.connectionsTotal).toBe(0);
	});

  it("should return a copy (not a reference)", () => {
    const stats1 = getP2PStats();
    incrementStat("messagesRelayed");
    const stats2 = getP2PStats();

		expect(stats1.messagesRelayed).toBe(0);
		expect(stats2.messagesRelayed).toBe(1);
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
		expect(after >= before).toBeTruthy();
	});
});
