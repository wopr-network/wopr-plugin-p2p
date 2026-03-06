/**
 * Unit tests for the WebMCP response builders
 */

import { describe, it, beforeEach, expect } from "vitest";

import {
  buildListPeersResponse,
  buildP2pStatsResponse,
  buildP2pStatusResponse,
  formatBytes,
  formatUptime,
} from "../src/webmcp-tools.js";
import { incrementStat, resetStats } from "../src/stats.js";

describe("WebMCP Tools", () => {
  beforeEach(() => {
    resetStats();
  });

	describe("formatBytes", () => {
		it("should format bytes", () => {
			expect(formatBytes(0)).toBe("0 B");
			expect(formatBytes(512)).toBe("512 B");
			expect(formatBytes(1023)).toBe("1023 B");
		});

		it("should format kilobytes", () => {
			expect(formatBytes(1024)).toBe("1.0 KB");
			expect(formatBytes(2048)).toBe("2.0 KB");
			expect(formatBytes(1536)).toBe("1.5 KB");
		});

		it("should format megabytes", () => {
			expect(formatBytes(1024 * 1024)).toBe("1.0 MB");
			expect(formatBytes(5 * 1024 * 1024)).toBe("5.0 MB");
		});
	});

	describe("formatUptime", () => {
		it("should format seconds", () => {
			expect(formatUptime(0)).toBe("0s");
			expect(formatUptime(5000)).toBe("5s");
			expect(formatUptime(59000)).toBe("59s");
		});

		it("should format minutes and seconds", () => {
			expect(formatUptime(60000)).toBe("1m 0s");
			expect(formatUptime(90000)).toBe("1m 30s");
			expect(formatUptime(3599000)).toBe("59m 59s");
		});

		it("should format hours and minutes", () => {
			expect(formatUptime(3600000)).toBe("1h 0m");
			expect(formatUptime(7200000)).toBe("2h 0m");
			expect(formatUptime(5400000)).toBe("1h 30m");
		});

		it("should format days and hours", () => {
			expect(formatUptime(86400000)).toBe("1d 0h");
			expect(formatUptime(90000000)).toBe("1d 1h");
			expect(formatUptime(172800000)).toBe("2d 0h");
		});
	});

	describe("buildP2pStatusResponse", () => {
		it("should return null node when no identity", () => {
			const response = buildP2pStatusResponse();
			expect(response.node).toBe(null);
			expect(response.peers !== undefined).toBeTruthy();
			expect(response.grants !== undefined).toBeTruthy();
			expect(Array.isArray(response.topics)).toBeTruthy();
		});

		it("should not contain private keys", () => {
			const response = buildP2pStatusResponse();
			const json = JSON.stringify(response);
			expect(!json.includes("privateKey")).toBeTruthy();
			expect(!json.includes("encryptPriv")).toBeTruthy();
			expect(!json.includes("encryptPub")).toBeTruthy();
		});
	});

	describe("buildListPeersResponse", () => {
		it("should return correct shape", () => {
			const response = buildListPeersResponse();
			expect(typeof response.count).toBe("number");
			expect(Array.isArray(response.peers)).toBeTruthy();
		});

		it("should not contain private keys", () => {
			const response = buildListPeersResponse();
			const json = JSON.stringify(response);
			expect(!json.includes("privateKey")).toBeTruthy();
			expect(!json.includes("encryptPriv")).toBeTruthy();
		});
	});

	describe("buildP2pStatsResponse", () => {
		it("should return correct shape with defaults", () => {
			const response = buildP2pStatsResponse();
			expect(response.messagesRelayed).toBe(0);
			expect(response.connectionsTotal).toBe(0);
			expect(typeof response.uptime).toBe("string");
			expect(typeof response.startedAt).toBe("string");
		});

    it("should reflect incremented stats", () => {
      incrementStat("messagesRelayed", 42);
      incrementStat("connectionsTotal", 3);

			const response = buildP2pStatsResponse();
			expect(response.messagesRelayed).toBe(42);
			expect(response.connectionsTotal).toBe(3);
		});

		it("should not contain private keys", () => {
			const response = buildP2pStatsResponse();
			const json = JSON.stringify(response);
			expect(!json.includes("privateKey")).toBeTruthy();
			expect(!json.includes("encryptPriv")).toBeTruthy();
			expect(!json.includes("encryptPub")).toBeTruthy();
		});
	});
});
