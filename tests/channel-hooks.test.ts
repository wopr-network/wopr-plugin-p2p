/**
 * Unit tests for the P2P Channel Hooks module (WOP-100)
 *
 * Tests command registration, message parser registration, and
 * auto-accept command handling with mock channel providers.
 */

import { describe, it, expect } from "vitest";

import { registerAutoAcceptCommands, registerChannelHooks } from "../src/channel-hooks.js";

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

    expect(logMessages.some(m => m.includes("No channel provider support"))).toBeTruthy();
    expect(registeredCommands.length).toBe(0);
  });

  it("should log and return when channel providers list is empty", () => {
    const { ctx, logMessages, registeredCommands } = createMockCtx({ channels: [] });

    registerChannelHooks(ctx);

    expect(logMessages.some(m => m.includes("No channel providers registered"))).toBeTruthy();
    expect(registeredCommands.length).toBe(0);
  });

  it("should register 5 commands on each channel provider", () => {
    const { ctx, registeredCommands } = createMockCtx();

    registerChannelHooks(ctx);

    // friend, accept, friends, unfriend, grant
    expect(registeredCommands.length).toBe(5);
  });

  it("should register 2 message parsers on each channel provider", () => {
    const { ctx, registeredParsers } = createMockCtx();

    registerChannelHooks(ctx);

    // FRIEND_REQUEST parser, FRIEND_ACCEPT parser
    expect(registeredParsers.length).toBe(2);
  });

  it("should register friend command with correct name", () => {
    const { ctx, registeredCommands } = createMockCtx();

    registerChannelHooks(ctx);

    const friendCmd = registeredCommands.find((c: any) => c.name === "friend");
    expect(friendCmd).toBeTruthy();
    expect(friendCmd.description.length > 0).toBeTruthy();
  });

  it("should register accept command", () => {
    const { ctx, registeredCommands } = createMockCtx();

    registerChannelHooks(ctx);

    expect(registeredCommands.find((c: any) => c.name === "accept")).toBeTruthy();
  });

  it("should register friends command", () => {
    const { ctx, registeredCommands } = createMockCtx();

    registerChannelHooks(ctx);

    expect(registeredCommands.find((c: any) => c.name === "friends")).toBeTruthy();
  });

  it("should register unfriend command", () => {
    const { ctx, registeredCommands } = createMockCtx();

    registerChannelHooks(ctx);

    expect(registeredCommands.find((c: any) => c.name === "unfriend")).toBeTruthy();
  });

  it("should register grant command", () => {
    const { ctx, registeredCommands } = createMockCtx();

    registerChannelHooks(ctx);

    expect(registeredCommands.find((c: any) => c.name === "grant")).toBeTruthy();
  });

  it("should register p2p-friend-request parser", () => {
    const { ctx, registeredParsers } = createMockCtx();

    registerChannelHooks(ctx);

    const parser = registeredParsers.find((p: any) => p.id === "p2p-friend-request");
    expect(parser).toBeTruthy();
    expect(parser.pattern instanceof RegExp).toBeTruthy();
  });

  it("should register p2p-friend-accept parser", () => {
    const { ctx, registeredParsers } = createMockCtx();

    registerChannelHooks(ctx);

    const parser = registeredParsers.find((p: any) => p.id === "p2p-friend-accept");
    expect(parser).toBeTruthy();
    expect(parser.pattern instanceof RegExp).toBeTruthy();
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

    expect(commands1.length).toBe(5);
    expect(commands2.length).toBe(5);
    expect(logMessages.some(m => m.includes("2 channel(s)"))).toBeTruthy();
  });

  it("should match FRIEND_REQUEST pattern correctly", () => {
    const { ctx, registeredParsers } = createMockCtx();

    registerChannelHooks(ctx);

    const parser = registeredParsers.find((p: any) => p.id === "p2p-friend-request");
    const pattern = parser.pattern as RegExp;

    expect(pattern.test("FRIEND_REQUEST | to:hope | from:wopr")).toBeTruthy();
    expect(!pattern.test("FRIEND_ACCEPT | to:hope | from:wopr")).toBeTruthy();
    expect(!pattern.test("Hello world")).toBeTruthy();
  });

  it("should match FRIEND_ACCEPT pattern correctly", () => {
    const { ctx, registeredParsers } = createMockCtx();

    registerChannelHooks(ctx);

    const parser = registeredParsers.find((p: any) => p.id === "p2p-friend-accept");
    const pattern = parser.pattern as RegExp;

    expect(pattern.test("FRIEND_ACCEPT | to:wopr | from:hope")).toBeTruthy();
    expect(!pattern.test("FRIEND_REQUEST | to:hope | from:wopr")).toBeTruthy();
    expect(!pattern.test("Hello world")).toBeTruthy();
  });
});

describe("registerAutoAcceptCommands", () => {
  it("should return when no getChannelProviders method exists", () => {
    const { ctx, registeredCommands } = createMockCtx({ noChannelProviders: true });

    registerAutoAcceptCommands(ctx);

    expect(registeredCommands.length).toBe(0);
  });

  it("should register auto-accept command on each channel", () => {
    const { ctx, registeredCommands } = createMockCtx();

    registerAutoAcceptCommands(ctx);

    const autoAcceptCmd = registeredCommands.find((c: any) => c.name === "auto-accept");
    expect(autoAcceptCmd).toBeTruthy();
    expect(autoAcceptCmd.description.includes("auto-accept")).toBeTruthy();
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

    expect(commands1.length).toBe(1);
    expect(commands2.length).toBe(1);
    expect(commands1[0].name).toBe("auto-accept");
    expect(commands2[0].name).toBe("auto-accept");
  });
});
