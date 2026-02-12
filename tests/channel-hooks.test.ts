/**
 * Unit tests for the P2P Channel Hooks module (WOP-100)
 *
 * Tests command registration, message parser registration, and
 * auto-accept command handling with mock channel providers.
 */

import { describe, it } from "node:test";
import assert from "node:assert";

import { registerChannelHooks, registerAutoAcceptCommands } from "../src/channel-hooks.js";

// Helper: create a mock plugin context
function createMockCtx(opts?: { channels?: any[]; noChannelProviders?: boolean }) {
  const registeredCommands: any[] = [];
  const registeredParsers: any[] = [];
  const logMessages: string[] = [];

  const mockChannel = {
    id: "test-channel",
    registerCommand: (cmd: any) => registeredCommands.push(cmd),
    addMessageParser: (parser: any) => registeredParsers.push(parser),
  };

  const ctx: any = {
    log: {
      info: (msg: string) => logMessages.push(msg),
      warn: (msg: string) => logMessages.push(`WARN: ${msg}`),
      error: (msg: string) => logMessages.push(`ERROR: ${msg}`),
    },
  };

  if (!opts?.noChannelProviders) {
    ctx.getChannelProviders = () => opts?.channels ?? [mockChannel];
  }

  return { ctx, registeredCommands, registeredParsers, logMessages, mockChannel };
}

describe("registerChannelHooks", () => {
  it("should log and return when no getChannelProviders method exists", () => {
    const { ctx, logMessages, registeredCommands } = createMockCtx({ noChannelProviders: true });

    registerChannelHooks(ctx);

    assert.ok(logMessages.some(m => m.includes("No channel provider support")));
    assert.strictEqual(registeredCommands.length, 0);
  });

  it("should log and return when channel providers list is empty", () => {
    const { ctx, logMessages, registeredCommands } = createMockCtx({ channels: [] });

    registerChannelHooks(ctx);

    assert.ok(logMessages.some(m => m.includes("No channel providers registered")));
    assert.strictEqual(registeredCommands.length, 0);
  });

  it("should register 5 commands on each channel provider", () => {
    const { ctx, registeredCommands } = createMockCtx();

    registerChannelHooks(ctx);

    // friend, accept, friends, unfriend, grant
    assert.strictEqual(registeredCommands.length, 5);
  });

  it("should register 2 message parsers on each channel provider", () => {
    const { ctx, registeredParsers } = createMockCtx();

    registerChannelHooks(ctx);

    // FRIEND_REQUEST parser, FRIEND_ACCEPT parser
    assert.strictEqual(registeredParsers.length, 2);
  });

  it("should register friend command with correct name", () => {
    const { ctx, registeredCommands } = createMockCtx();

    registerChannelHooks(ctx);

    const friendCmd = registeredCommands.find((c: any) => c.name === "friend");
    assert.ok(friendCmd, "friend command should be registered");
    assert.ok(friendCmd.description.length > 0);
  });

  it("should register accept command", () => {
    const { ctx, registeredCommands } = createMockCtx();

    registerChannelHooks(ctx);

    assert.ok(registeredCommands.find((c: any) => c.name === "accept"));
  });

  it("should register friends command", () => {
    const { ctx, registeredCommands } = createMockCtx();

    registerChannelHooks(ctx);

    assert.ok(registeredCommands.find((c: any) => c.name === "friends"));
  });

  it("should register unfriend command", () => {
    const { ctx, registeredCommands } = createMockCtx();

    registerChannelHooks(ctx);

    assert.ok(registeredCommands.find((c: any) => c.name === "unfriend"));
  });

  it("should register grant command", () => {
    const { ctx, registeredCommands } = createMockCtx();

    registerChannelHooks(ctx);

    assert.ok(registeredCommands.find((c: any) => c.name === "grant"));
  });

  it("should register p2p-friend-request parser", () => {
    const { ctx, registeredParsers } = createMockCtx();

    registerChannelHooks(ctx);

    const parser = registeredParsers.find((p: any) => p.id === "p2p-friend-request");
    assert.ok(parser, "friend request parser should be registered");
    assert.ok(parser.pattern instanceof RegExp);
  });

  it("should register p2p-friend-accept parser", () => {
    const { ctx, registeredParsers } = createMockCtx();

    registerChannelHooks(ctx);

    const parser = registeredParsers.find((p: any) => p.id === "p2p-friend-accept");
    assert.ok(parser, "friend accept parser should be registered");
    assert.ok(parser.pattern instanceof RegExp);
  });

  it("should register on multiple channel providers", () => {
    const commands1: any[] = [];
    const commands2: any[] = [];

    const channels = [
      {
        id: "discord",
        registerCommand: (cmd: any) => commands1.push(cmd),
        addMessageParser: () => {},
      },
      {
        id: "slack",
        registerCommand: (cmd: any) => commands2.push(cmd),
        addMessageParser: () => {},
      },
    ];

    const { ctx, logMessages } = createMockCtx({ channels });

    registerChannelHooks(ctx);

    assert.strictEqual(commands1.length, 5);
    assert.strictEqual(commands2.length, 5);
    assert.ok(logMessages.some(m => m.includes("2 channel(s)")));
  });

  it("should match FRIEND_REQUEST pattern correctly", () => {
    const { ctx, registeredParsers } = createMockCtx();

    registerChannelHooks(ctx);

    const parser = registeredParsers.find((p: any) => p.id === "p2p-friend-request");
    const pattern = parser.pattern as RegExp;

    assert.ok(pattern.test("FRIEND_REQUEST | to:hope | from:wopr"));
    assert.ok(!pattern.test("FRIEND_ACCEPT | to:hope | from:wopr"));
    assert.ok(!pattern.test("Hello world"));
  });

  it("should match FRIEND_ACCEPT pattern correctly", () => {
    const { ctx, registeredParsers } = createMockCtx();

    registerChannelHooks(ctx);

    const parser = registeredParsers.find((p: any) => p.id === "p2p-friend-accept");
    const pattern = parser.pattern as RegExp;

    assert.ok(pattern.test("FRIEND_ACCEPT | to:wopr | from:hope"));
    assert.ok(!pattern.test("FRIEND_REQUEST | to:hope | from:wopr"));
    assert.ok(!pattern.test("Hello world"));
  });
});

describe("registerAutoAcceptCommands", () => {
  it("should return when no getChannelProviders method exists", () => {
    const { ctx, registeredCommands } = createMockCtx({ noChannelProviders: true });

    registerAutoAcceptCommands(ctx);

    assert.strictEqual(registeredCommands.length, 0);
  });

  it("should register auto-accept command on each channel", () => {
    const { ctx, registeredCommands } = createMockCtx();

    registerAutoAcceptCommands(ctx);

    const autoAcceptCmd = registeredCommands.find((c: any) => c.name === "auto-accept");
    assert.ok(autoAcceptCmd, "auto-accept command should be registered");
    assert.ok(autoAcceptCmd.description.includes("auto-accept"));
  });

  it("should register auto-accept on multiple channels", () => {
    const commands1: any[] = [];
    const commands2: any[] = [];

    const channels = [
      { id: "ch1", registerCommand: (cmd: any) => commands1.push(cmd), addMessageParser: () => {} },
      { id: "ch2", registerCommand: (cmd: any) => commands2.push(cmd), addMessageParser: () => {} },
    ];

    const { ctx } = createMockCtx({ channels });

    registerAutoAcceptCommands(ctx);

    assert.strictEqual(commands1.length, 1);
    assert.strictEqual(commands2.length, 1);
    assert.strictEqual(commands1[0].name, "auto-accept");
    assert.strictEqual(commands2[0].name, "auto-accept");
  });
});
