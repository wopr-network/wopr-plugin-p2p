/**
 * Unit tests for the WebMCP response builders
 */

import { describe, it, beforeEach } from "node:test";
import assert from "node:assert";

import {
	formatBytes,
	formatUptime,
	buildP2pStatusResponse,
	buildListPeersResponse,
	buildP2pStatsResponse,
} from "../src/webmcp-tools.js";
import { resetStats, incrementStat } from "../src/stats.js";

describe("WebMCP Tools", () => {
	beforeEach(() => {
		resetStats();
	});

	describe("formatBytes", () => {
		it("should format bytes", () => {
			assert.strictEqual(formatBytes(0), "0 B");
			assert.strictEqual(formatBytes(512), "512 B");
			assert.strictEqual(formatBytes(1023), "1023 B");
		});

		it("should format kilobytes", () => {
			assert.strictEqual(formatBytes(1024), "1.0 KB");
			assert.strictEqual(formatBytes(2048), "2.0 KB");
			assert.strictEqual(formatBytes(1536), "1.5 KB");
		});

		it("should format megabytes", () => {
			assert.strictEqual(formatBytes(1024 * 1024), "1.0 MB");
			assert.strictEqual(formatBytes(5 * 1024 * 1024), "5.0 MB");
		});
	});

	describe("formatUptime", () => {
		it("should format seconds", () => {
			assert.strictEqual(formatUptime(0), "0s");
			assert.strictEqual(formatUptime(5000), "5s");
			assert.strictEqual(formatUptime(59000), "59s");
		});

		it("should format minutes and seconds", () => {
			assert.strictEqual(formatUptime(60000), "1m 0s");
			assert.strictEqual(formatUptime(90000), "1m 30s");
			assert.strictEqual(formatUptime(3599000), "59m 59s");
		});

		it("should format hours and minutes", () => {
			assert.strictEqual(formatUptime(3600000), "1h 0m");
			assert.strictEqual(formatUptime(7200000), "2h 0m");
			assert.strictEqual(formatUptime(5400000), "1h 30m");
		});

		it("should format days and hours", () => {
			assert.strictEqual(formatUptime(86400000), "1d 0h");
			assert.strictEqual(formatUptime(90000000), "1d 1h");
			assert.strictEqual(formatUptime(172800000), "2d 0h");
		});
	});

	describe("buildP2pStatusResponse", () => {
		it("should return null node when no identity", () => {
			const response = buildP2pStatusResponse();
			assert.strictEqual(response.node, null);
			assert.ok(response.peers !== undefined);
			assert.ok(response.grants !== undefined);
			assert.ok(Array.isArray(response.topics));
		});

		it("should not contain private keys", () => {
			const response = buildP2pStatusResponse();
			const json = JSON.stringify(response);
			assert.ok(!json.includes("privateKey"));
			assert.ok(!json.includes("encryptPriv"));
			assert.ok(!json.includes("encryptPub"));
		});
	});

	describe("buildListPeersResponse", () => {
		it("should return correct shape", () => {
			const response = buildListPeersResponse();
			assert.strictEqual(typeof response.count, "number");
			assert.ok(Array.isArray(response.peers));
		});

		it("should not contain private keys", () => {
			const response = buildListPeersResponse();
			const json = JSON.stringify(response);
			assert.ok(!json.includes("privateKey"));
			assert.ok(!json.includes("encryptPriv"));
		});
	});

	describe("buildP2pStatsResponse", () => {
		it("should return correct shape with defaults", () => {
			const response = buildP2pStatsResponse();
			assert.strictEqual(response.messagesRelayed, 0);
			assert.strictEqual(response.connectionsTotal, 0);
			assert.ok(typeof response.uptime === "string");
			assert.ok(typeof response.startedAt === "string");
		});

		it("should reflect incremented stats", () => {
			incrementStat("messagesRelayed", 42);
			incrementStat("connectionsTotal", 3);

			const response = buildP2pStatsResponse();
			assert.strictEqual(response.messagesRelayed, 42);
			assert.strictEqual(response.connectionsTotal, 3);
		});

		it("should not contain private keys", () => {
			const response = buildP2pStatsResponse();
			const json = JSON.stringify(response);
			assert.ok(!json.includes("privateKey"));
			assert.ok(!json.includes("encryptPriv"));
			assert.ok(!json.includes("encryptPub"));
		});
	});
});
