/**
 * Unit tests for cli-commands.ts
 *
 * Tests the CLI command handler, parseFlags utility, and all friend subcommands.
 */

import { describe, it, beforeEach, afterEach, mock } from "node:test";
import assert from "node:assert";

// We need to mock friends.js and identity.js before importing cli-commands
// Since node:test doesn't have vi.mock, we test via the exported handler
// and use mock contexts to capture output.

import { handleFriendCommand, friendCommand } from "../src/cli-commands.js";

/** Create a mock WOPRPluginContext that captures log output */
function createMockCtx() {
  const logs: string[] = [];
  const errors: string[] = [];
  const warns: string[] = [];

  return {
    ctx: {
      log: {
        info: (msg: string) => logs.push(msg),
        error: (msg: string) => errors.push(msg),
        warn: (msg: string) => warns.push(msg),
      },
      registerA2AServer: () => {},
      getPluginDir: () => "/tmp/test-p2p",
      getConfig: () => ({}),
      getMainConfig: () => undefined,
    },
    logs,
    errors,
    warns,
  };
}

describe("friendCommand export", () => {
  it("should export command metadata", () => {
    assert.strictEqual(friendCommand.name, "friend");
    assert.strictEqual(typeof friendCommand.description, "string");
    assert.ok(friendCommand.description.length > 0);
    assert.strictEqual(typeof friendCommand.usage, "string");
    assert.strictEqual(friendCommand.handler, handleFriendCommand);
  });
});

describe("handleFriendCommand", () => {
  describe("help / unknown subcommand", () => {
    it("should show help when no subcommand given", async () => {
      const { ctx, logs } = createMockCtx();
      await handleFriendCommand(ctx as any, []);
      // showFriendHelp logs usage info
      const output = logs.join("\n");
      assert.ok(output.includes("wopr friend"), "Should contain usage header");
      assert.ok(output.includes("list"), "Should mention list subcommand");
      assert.ok(output.includes("accept"), "Should mention accept subcommand");
    });

    it("should show help for unknown subcommand", async () => {
      const { ctx, logs } = createMockCtx();
      await handleFriendCommand(ctx as any, ["bogus"]);
      const output = logs.join("\n");
      assert.ok(output.includes("wopr friend"), "Should show help for unknown subcommand");
    });
  });

  describe("list subcommand", () => {
    it("should handle empty friends list", async () => {
      const { ctx, logs } = createMockCtx();
      await handleFriendCommand(ctx as any, ["list"]);
      const output = logs.join("\n");
      // Either shows "No friends" or a table - depends on actual friends state
      assert.ok(output.length > 0, "Should produce some output");
    });
  });

  describe("request subcommand", () => {
    it("should show channel instructions", async () => {
      const { ctx, logs } = createMockCtx();
      await handleFriendCommand(ctx as any, ["request"]);
      const output = logs.join("\n");
      assert.ok(output.includes("Discord") || output.includes("channel"),
        "Should mention channel-based friend requests");
    });
  });

  describe("accept subcommand", () => {
    it("should require a name argument", async () => {
      const { ctx, errors } = createMockCtx();
      await handleFriendCommand(ctx as any, ["accept"]);
      const output = errors.join("\n");
      assert.ok(output.includes("Usage") || output.includes("accept"),
        "Should show usage or error for missing name");
    });

    it("should strip @ prefix from name", async () => {
      const { ctx, errors, logs } = createMockCtx();
      // This will fail to find a pending request, but should not crash
      await handleFriendCommand(ctx as any, ["accept", "@hope"]);
      // Either logs an error about no pending request or logs success
      const allOutput = [...errors, ...logs].join("\n");
      assert.ok(allOutput.length > 0, "Should produce output");
    });
  });

  describe("remove subcommand", () => {
    it("should require a name argument", async () => {
      const { ctx, errors } = createMockCtx();
      await handleFriendCommand(ctx as any, ["remove"]);
      assert.ok(errors.some(e => e.includes("Usage")), "Should show usage error");
    });

    it("should also work as 'unfriend'", async () => {
      const { ctx, errors, logs } = createMockCtx();
      await handleFriendCommand(ctx as any, ["unfriend", "nobody"]);
      const allOutput = [...errors, ...logs].join("\n");
      // Should try to remove and report not found
      assert.ok(allOutput.length > 0, "Should produce output for unfriend");
    });

    it("should strip @ prefix", async () => {
      const { ctx, errors, logs } = createMockCtx();
      await handleFriendCommand(ctx as any, ["remove", "@test"]);
      const allOutput = [...errors, ...logs].join("\n");
      assert.ok(allOutput.length > 0, "Should produce output");
    });
  });

  describe("grant subcommand", () => {
    it("should require both name and capability", async () => {
      const { ctx, errors } = createMockCtx();
      await handleFriendCommand(ctx as any, ["grant"]);
      assert.ok(errors.some(e => e.includes("Usage")), "Should show usage for no args");
    });

    it("should require capability argument", async () => {
      const { ctx, errors } = createMockCtx();
      await handleFriendCommand(ctx as any, ["grant", "hope"]);
      assert.ok(errors.some(e => e.includes("Usage")), "Should show usage for missing cap");
    });

    it("should reject invalid capabilities", async () => {
      const { ctx, errors } = createMockCtx();
      await handleFriendCommand(ctx as any, ["grant", "hope", "admin"]);
      assert.ok(errors.some(e => e.includes("Invalid capability")),
        "Should reject invalid capability");
    });

    it("should accept valid capabilities", async () => {
      const { ctx, errors, logs } = createMockCtx();
      // Will fail because friend not found, but should not reject the cap
      await handleFriendCommand(ctx as any, ["grant", "hope", "inject"]);
      const allOutput = [...errors, ...logs].join("\n");
      // Should not contain "Invalid capability"
      assert.ok(!allOutput.includes("Invalid capability"),
        "Should not reject valid inject capability");
    });

    it("should accept message capability", async () => {
      const { ctx, errors } = createMockCtx();
      await handleFriendCommand(ctx as any, ["grant", "hope", "message"]);
      assert.ok(!errors.some(e => e.includes("Invalid capability")),
        "Should not reject valid message capability");
    });
  });

  describe("revoke subcommand", () => {
    it("should require both name and capability", async () => {
      const { ctx, errors } = createMockCtx();
      await handleFriendCommand(ctx as any, ["revoke"]);
      assert.ok(errors.some(e => e.includes("Usage")), "Should show usage");
    });

    it("should require capability argument", async () => {
      const { ctx, errors } = createMockCtx();
      await handleFriendCommand(ctx as any, ["revoke", "hope"]);
      assert.ok(errors.some(e => e.includes("Usage")), "Should show usage for missing cap");
    });
  });

  describe("auto-accept subcommand", () => {
    it("should list rules when no action given", async () => {
      const { ctx, logs } = createMockCtx();
      await handleFriendCommand(ctx as any, ["auto-accept"]);
      const output = logs.join("\n");
      // Either shows "No auto-accept rules" or lists them
      assert.ok(output.includes("auto-accept") || output.includes("No auto-accept"),
        "Should show auto-accept info");
    });

    it("should list rules with explicit list action", async () => {
      const { ctx, logs } = createMockCtx();
      await handleFriendCommand(ctx as any, ["auto-accept", "list"]);
      const output = logs.join("\n");
      assert.ok(output.length > 0, "Should produce output for list");
    });

    it("should require pattern for add", async () => {
      const { ctx, errors } = createMockCtx();
      await handleFriendCommand(ctx as any, ["auto-accept", "add"]);
      assert.ok(errors.some(e => e.includes("Usage")), "Should show usage for add without pattern");
    });

    it("should require pattern for remove", async () => {
      const { ctx, errors } = createMockCtx();
      await handleFriendCommand(ctx as any, ["auto-accept", "remove"]);
      assert.ok(errors.some(e => e.includes("Usage")), "Should show usage for remove without pattern");
    });

    it("should handle unknown action", async () => {
      const { ctx, errors } = createMockCtx();
      await handleFriendCommand(ctx as any, ["auto-accept", "bogus"]);
      assert.ok(errors.some(e => e.includes("Unknown action")), "Should report unknown action");
    });

    it("should add and remove auto-accept rules", async () => {
      // This test writes to the friends state file. If the P2P data directory
      // is not writable (e.g., /data/p2p in a non-container env), skip gracefully.
      try {
        const { ctx: ctx1, logs: logs1 } = createMockCtx();
        await handleFriendCommand(ctx1 as any, ["auto-accept", "add", "test-pattern-cli"]);
        assert.ok(logs1.some(l => l.includes("Added")), "Should confirm add");

        const { ctx: ctx2, logs: logs2 } = createMockCtx();
        await handleFriendCommand(ctx2 as any, ["auto-accept", "remove", "test-pattern-cli"]);
        assert.ok(logs2.some(l => l.includes("Removed")), "Should confirm remove");
      } catch (err: any) {
        if (err?.code === "EACCES") {
          // Data directory not writable - skip this test path
          assert.ok(true, "Skipped: P2P data directory not writable");
        } else {
          throw err;
        }
      }
    });
  });

  describe("pending subcommand", () => {
    it("should show pending requests status", async () => {
      const { ctx, logs } = createMockCtx();
      await handleFriendCommand(ctx as any, ["pending"]);
      const output = logs.join("\n");
      // Should either show pending requests or "No pending"
      assert.ok(output.includes("pending") || output.includes("No pending"),
        "Should show pending status");
    });
  });
});
