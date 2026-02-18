/**
 * Tests for path traversal protection in the P2P UI server (WOP-619)
 *
 * The startUIServer() function was vulnerable to path traversal because
 * it passed req.url directly to path.join() without sanitization.
 * These tests verify the fix is in place.
 */
import { describe, it, afterEach, beforeEach } from "node:test";
import assert from "node:assert";
import http from "node:http";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { _startUIServer as startUIServer } from "../src/index.js";

// Simple HTTP fetch helper
function fetchUrl(url: string): Promise<{ status: number; body: string }> {
	return new Promise((resolve, reject) => {
		http
			.get(url, (res) => {
				let data = "";
				res.on("data", (chunk) => (data += chunk));
				res.on("end", () => resolve({ status: res.statusCode!, body: data }));
			})
			.on("error", reject);
	});
}

describe("UI Server Path Traversal Protection (WOP-619)", () => {
	let server: http.Server | null = null;
	let port: number;
	let pluginDir: string;
	const testId = `wopr-p2p-uitest-${process.pid}`;

	beforeEach(async () => {
		pluginDir = join(tmpdir(), testId);
		mkdirSync(pluginDir, { recursive: true });

		// Create some test files
		writeFileSync(join(pluginDir, "ui.js"), `console.log("p2p ui");`);
		writeFileSync(join(pluginDir, "style.css"), `body { color: red; }`);
		writeFileSync(join(pluginDir, "index.html"), `<html><body>P2P</body></html>`);
		writeFileSync(join(pluginDir, "secret.json"), `{"token":"super-secret"}`);
		writeFileSync(join(pluginDir, "malware.exe"), `MZ-binary`);

		// Start server on an ephemeral port (0 = OS assigns) and wait for listen
		server = startUIServer(0, pluginDir);
		await new Promise<void>((resolve) => server!.once("listening", resolve));
		const addr = server.address() as { port: number };
		port = addr.port;
	});

	afterEach(async () => {
		if (server) {
			await new Promise<void>((resolve) => server!.close(() => resolve()));
			server = null;
		}
		rmSync(pluginDir, { recursive: true, force: true });
	});

	it("should serve ui.js from plugin directory on GET /", async () => {
		const res = await fetchUrl(`http://127.0.0.1:${port}/`);
		assert.strictEqual(res.status, 200);
		assert.ok(res.body.includes("p2p ui"));
	});

	it("should serve ui.js from plugin directory on GET /ui.js", async () => {
		const res = await fetchUrl(`http://127.0.0.1:${port}/ui.js`);
		assert.strictEqual(res.status, 200);
		assert.ok(res.body.includes("p2p ui"));
	});

	it("should serve .css files from plugin directory", async () => {
		const res = await fetchUrl(`http://127.0.0.1:${port}/style.css`);
		assert.strictEqual(res.status, 200);
		assert.ok(res.body.includes("color: red"));
	});

	it("should serve .html files from plugin directory", async () => {
		const res = await fetchUrl(`http://127.0.0.1:${port}/index.html`);
		assert.strictEqual(res.status, 200);
		assert.ok(res.body.includes("P2P"));
	});

	it("should return 404 for non-existent allowed file", async () => {
		const res = await fetchUrl(`http://127.0.0.1:${port}/nonexistent.js`);
		assert.strictEqual(res.status, 404);
	});

	it("should block ../ traversal (GET /../../etc/passwd)", async () => {
		const res = await fetchUrl(
			`http://127.0.0.1:${port}/../../etc/passwd`,
		);
		assert.strictEqual(res.status, 403);
	});

	it("should block URL-encoded traversal (GET /%2e%2e/%2e%2e/etc/passwd)", async () => {
		const res = await fetchUrl(
			`http://127.0.0.1:${port}/%2e%2e/%2e%2e/etc/passwd`,
		);
		assert.strictEqual(res.status, 403);
	});

	it("should block traversal with query string (GET /../../../etc/passwd?foo=bar)", async () => {
		const res = await fetchUrl(
			`http://127.0.0.1:${port}/../../../etc/passwd?foo=bar`,
		);
		assert.strictEqual(res.status, 403);
	});

	it("should block non-allowlisted extension .json (403 Forbidden)", async () => {
		const res = await fetchUrl(`http://127.0.0.1:${port}/secret.json`);
		assert.strictEqual(res.status, 403);
	});

	it("should block non-allowlisted extension .exe (403 Forbidden)", async () => {
		const res = await fetchUrl(`http://127.0.0.1:${port}/malware.exe`);
		assert.strictEqual(res.status, 403);
	});

	it("should block absolute path injection (GET //etc/passwd)", async () => {
		// Double-slash may be treated as /etc/passwd — must not serve it
		const res = await fetchUrl(`http://127.0.0.1:${port}//etc/passwd`);
		// Either 403 (traversal blocked) or 404 (file not in dir) is acceptable
		assert.ok(
			res.status === 403 || res.status === 404,
			`Expected 403 or 404, got ${res.status}`,
		);
	});
});
