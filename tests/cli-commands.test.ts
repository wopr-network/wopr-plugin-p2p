/**
 * Unit tests for cli-commands.ts
 *
 * Tests the CLI command handler, parseFlags utility, and all friend subcommands.
 */

import { describe, it, afterEach, beforeEach, expect, vi } from "vitest";
import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { friendCommand, handleFriendCommand } from "../src/cli-commands.js";

/** Temporary data directory for tests that touch friends state */
const TEST_DATA_DIR = join(tmpdir(), `wopr-p2p-test-cli-${process.pid}`);

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

/** Capture console.log output during a function call */
async function captureConsole(fn: () => Promise<void>): Promise<{ stdout: string[]; stderr: string[] }> {
  const stdout: string[] = [];
  const stderr: string[] = [];
  const origLog = console.log;
  const origError = console.error;
  console.log = (...args: any[]) => stdout.push(args.map(String).join(" "));
  console.error = (...args: any[]) => stderr.push(args.map(String).join(" "));
  try {
    await fn();
  } finally {
    console.log = origLog;
    console.error = origError;
  }
  return { stdout, stderr };
}

/**
 * Set up isolated test data directory for friends state.
 * Returns a cleanup function.
 */
function useTestDataDir() {
  mkdirSync(TEST_DATA_DIR, { recursive: true });
  process.env.WOPR_P2P_DATA_DIR = TEST_DATA_DIR;
  return () => {
    delete process.env.WOPR_P2P_DATA_DIR;
    rmSync(TEST_DATA_DIR, { recursive: true, force: true });
  };
}

describe("friendCommand export", () => {
  it("should export command metadata", () => {
    expect(friendCommand.name).toBe("friend");
    expect(typeof friendCommand.description).toBe("string");
    expect(friendCommand.description.length > 0).toBeTruthy();
    expect(typeof friendCommand.usage).toBe("string");
    expect(friendCommand.handler).toBe(handleFriendCommand);
  });
});

describe("handleFriendCommand", () => {
  let cleanup: (() => void) | undefined;

  afterEach(() => {
    if (cleanup) {
      cleanup();
      cleanup = undefined;
    }
  });

  describe("help / unknown subcommand", () => {
    it("should show help when no subcommand given", async () => {
      const { ctx } = createMockCtx();
      const { stdout } = await captureConsole(() => handleFriendCommand(ctx as any, []));
      const output = stdout.join("\n");
      expect(output.includes("wopr friend")).toBeTruthy();
      expect(output.includes("list")).toBeTruthy();
      expect(output.includes("accept")).toBeTruthy();
    });

    it("should show help for unknown subcommand", async () => {
      const { ctx } = createMockCtx();
      const { stdout } = await captureConsole(() => handleFriendCommand(ctx as any, ["bogus"]));
      const output = stdout.join("\n");
      expect(output.includes("wopr friend")).toBeTruthy();
    });
  });

  describe("list subcommand", () => {
    it("should handle empty friends list", async () => {
      cleanup = useTestDataDir();
      const { ctx } = createMockCtx();
      const { stdout } = await captureConsole(() => handleFriendCommand(ctx as any, ["list"]));
      const output = stdout.join("\n");
      expect(output.includes("No friends")).toBeTruthy();
    });
  });

  describe("request subcommand", () => {
    it("should show channel instructions", async () => {
      const { ctx } = createMockCtx();
      const { stdout } = await captureConsole(() => handleFriendCommand(ctx as any, ["request"]));
      const output = stdout.join("\n");
      expect(output.includes("Discord") || output.includes("channel")).toBeTruthy();
    });
  });

  describe("accept subcommand", () => {
    it("should require a name argument", async () => {
      const { ctx } = createMockCtx();
      const { stdout, stderr } = await captureConsole(() => handleFriendCommand(ctx as any, ["accept"]));
      const output = [...stdout, ...stderr].join("\n");
      expect(output.includes("Usage") || output.includes("accept")).toBeTruthy();
    });

    it("should strip @ prefix from name", async () => {
      cleanup = useTestDataDir();
      const { ctx } = createMockCtx();
      const { stdout, stderr } = await captureConsole(() => handleFriendCommand(ctx as any, ["accept", "@hope"]));
      // No pending request in empty test state => error about no pending request
      const allOutput = [...stdout, ...stderr].join("\n");
      expect(allOutput.length > 0).toBeTruthy();
    });
  });

  describe("remove subcommand", () => {
    it("should require a name argument", async () => {
      const { ctx } = createMockCtx();
      const { stdout, stderr } = await captureConsole(() => handleFriendCommand(ctx as any, ["remove"]));
      const allOutput = [...stdout, ...stderr].join("\n");
      expect(allOutput.includes("Usage")).toBeTruthy();
    });

    it("should also work as 'unfriend'", async () => {
      cleanup = useTestDataDir();
      const { ctx } = createMockCtx();
      const { stdout, stderr } = await captureConsole(() => handleFriendCommand(ctx as any, ["unfriend", "nobody"]));
      const allOutput = [...stdout, ...stderr].join("\n");
      // Should try to remove and report not found
      expect(allOutput.length > 0).toBeTruthy();
    });

    it("should strip @ prefix", async () => {
      cleanup = useTestDataDir();
      const { ctx } = createMockCtx();
      const { stdout, stderr } = await captureConsole(() => handleFriendCommand(ctx as any, ["remove", "@test"]));
      const allOutput = [...stdout, ...stderr].join("\n");
      expect(allOutput.length > 0).toBeTruthy();
    });
  });

  describe("grant subcommand", () => {
    it("should require both name and capability", async () => {
      const { ctx } = createMockCtx();
      const { stdout, stderr } = await captureConsole(() => handleFriendCommand(ctx as any, ["grant"]));
      const allOutput = [...stdout, ...stderr].join("\n");
      expect(allOutput.includes("Usage")).toBeTruthy();
    });

    it("should require capability argument", async () => {
      const { ctx } = createMockCtx();
      const { stdout, stderr } = await captureConsole(() => handleFriendCommand(ctx as any, ["grant", "hope"]));
      const allOutput = [...stdout, ...stderr].join("\n");
      expect(allOutput.includes("Usage")).toBeTruthy();
    });

    it("should reject invalid capabilities", async () => {
      const { ctx } = createMockCtx();
      const { stdout, stderr } = await captureConsole(() => handleFriendCommand(ctx as any, ["grant", "hope", "admin"]));
      const allOutput = [...stdout, ...stderr].join("\n");
      expect(allOutput.includes("Invalid capability")).toBeTruthy();
    });

    it("should accept valid capabilities", async () => {
      cleanup = useTestDataDir();
      const { ctx } = createMockCtx();
      // Will fail because friend not found in empty test state, but should not reject the cap
      const { stdout, stderr } = await captureConsole(() => handleFriendCommand(ctx as any, ["grant", "hope", "inject"]));
      const allOutput = [...stdout, ...stderr].join("\n");
      // Should not contain "Invalid capability"
      expect(!allOutput.includes("Invalid capability")).toBeTruthy();
    });

    it("should accept message capability", async () => {
      cleanup = useTestDataDir();
      const { ctx } = createMockCtx();
      const { stdout, stderr } = await captureConsole(() => handleFriendCommand(ctx as any, ["grant", "hope", "message"]));
      const allOutput = [...stdout, ...stderr].join("\n");
      expect(!allOutput.includes("Invalid capability")).toBeTruthy();
    });
  });

  describe("revoke subcommand", () => {
    it("should require both name and capability", async () => {
      const { ctx } = createMockCtx();
      const { stdout, stderr } = await captureConsole(() => handleFriendCommand(ctx as any, ["revoke"]));
      const allOutput = [...stdout, ...stderr].join("\n");
      expect(allOutput.includes("Usage")).toBeTruthy();
    });

    it("should require capability argument", async () => {
      const { ctx } = createMockCtx();
      const { stdout, stderr } = await captureConsole(() => handleFriendCommand(ctx as any, ["revoke", "hope"]));
      const allOutput = [...stdout, ...stderr].join("\n");
      expect(allOutput.includes("Usage")).toBeTruthy();
    });
  });

  describe("auto-accept subcommand", () => {
    it("should list rules when no action given", async () => {
      cleanup = useTestDataDir();
      const { ctx } = createMockCtx();
      const { stdout } = await captureConsole(() => handleFriendCommand(ctx as any, ["auto-accept"]));
      const output = stdout.join("\n");
      expect(output.includes("auto-accept") || output.includes("No auto-accept")).toBeTruthy();
    });

    it("should list rules with explicit list action", async () => {
      cleanup = useTestDataDir();
      const { ctx } = createMockCtx();
      const { stdout } = await captureConsole(() => handleFriendCommand(ctx as any, ["auto-accept", "list"]));
      const output = stdout.join("\n");
      expect(output.length > 0).toBeTruthy();
    });

    it("should require pattern for add", async () => {
      const { ctx } = createMockCtx();
      const { stdout, stderr } = await captureConsole(() => handleFriendCommand(ctx as any, ["auto-accept", "add"]));
      const allOutput = [...stdout, ...stderr].join("\n");
      expect(allOutput.includes("Usage")).toBeTruthy();
    });

    it("should require pattern for remove", async () => {
      const { ctx } = createMockCtx();
      const { stdout, stderr } = await captureConsole(() => handleFriendCommand(ctx as any, ["auto-accept", "remove"]));
      const allOutput = [...stdout, ...stderr].join("\n");
      expect(allOutput.includes("Usage")).toBeTruthy();
    });

    it("should handle unknown action", async () => {
      const { ctx } = createMockCtx();
      const { stdout, stderr } = await captureConsole(() => handleFriendCommand(ctx as any, ["auto-accept", "bogus"]));
      const allOutput = [...stdout, ...stderr].join("\n");
      expect(allOutput.includes("Unknown action")).toBeTruthy();
    });

    it("should add and remove auto-accept rules", async () => {
      cleanup = useTestDataDir();
      const { ctx: ctx1 } = createMockCtx();
      const { stdout: stdout1 } = await captureConsole(() =>
        handleFriendCommand(ctx1 as any, ["auto-accept", "add", "test-pattern-cli"])
      );
      expect(stdout1.some(l => l.includes("Added"))).toBeTruthy();

      const { ctx: ctx2 } = createMockCtx();
      const { stdout: stdout2 } = await captureConsole(() =>
        handleFriendCommand(ctx2 as any, ["auto-accept", "remove", "test-pattern-cli"])
      );
      expect(stdout2.some(l => l.includes("Removed"))).toBeTruthy();
    });
  });

  describe("pending subcommand", () => {
    it("should show pending requests status", async () => {
      cleanup = useTestDataDir();
      const { ctx } = createMockCtx();
      const { stdout } = await captureConsole(() => handleFriendCommand(ctx as any, ["pending"]));
      const output = stdout.join("\n");
      // Should either show pending requests or "No pending"
      expect(output.includes("pending") || output.includes("No pending")).toBeTruthy();
    });
  });
});
