/**
 * Unit tests for the P2P Channel Hooks module (WOP-100)
 *
 * Tests command registration, message parser registration, and
 * auto-accept command handling with mock channel providers.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

import { registerAutoAcceptCommands, registerChannelHooks } from "../src/channel-hooks.js";

// Module mocks for handler-level tests
vi.mock("../src/friends.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("../src/friends.js")>();
  return {
    ...original,
    acceptPendingRequest: vi.fn(),
    addAutoAcceptRule: vi.fn(),
    completeFriendship: vi.fn(),
    createFriendAccept: vi.fn((_req: any, _username: string) => ({ from: _req?.from ?? "alice", to: _username })),
    createFriendRequest: vi.fn(),
    denyPendingRequest: vi.fn(),
    formatFriendAccept: vi.fn(() => "FRIEND_ACCEPT accepted"),
    formatFriendRequest: vi.fn(),
    getAutoAcceptRules: vi.fn(() => []),
    getFriend: vi.fn(),
    getFriends: vi.fn(() => []),
    getPendingIncomingRequests: vi.fn(() => []),
    getPendingOutgoing: vi.fn(),
    grantFriendCap: vi.fn(),
    parseFriendAccept: vi.fn(),
    parseFriendRequest: vi.fn(),
    queueForApproval: vi.fn(),
    removeAutoAcceptRule: vi.fn(),
    removeFriend: vi.fn(),
    shouldAutoAccept: vi.fn(() => false),
    storePendingRequest: vi.fn(),
    verifyFriendAccept: vi.fn(() => true),
    verifyFriendRequest: vi.fn(() => true),
  };
});

vi.mock("../src/security-integration.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("../src/security-integration.js")>();
  return {
    ...original,
    syncFriendToSecurity: vi.fn(),
  };
});

vi.mock("../src/identity.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("../src/identity.js")>();
  return {
    ...original,
    getIdentity: vi.fn(),
    shortKey: vi.fn((k: string) => k.substring(0, 8)),
  };
});

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

// ---------------------------------------------------------------------------
// FRIEND_REQUEST handler — notification dispatch and callback tests
// ---------------------------------------------------------------------------

describe("FRIEND_REQUEST handler — notification dispatch", () => {
  let friendsMod: typeof import("../src/friends.js");
  let secMod: typeof import("../src/security-integration.js");

  beforeEach(async () => {
    friendsMod = await import("../src/friends.js");
    secMod = await import("../src/security-integration.js");
    vi.clearAllMocks();

    vi.mocked(friendsMod.parseFriendRequest).mockReturnValue({
      type: "FRIEND_REQUEST",
      to: "wopr",
      from: "alice",
      pubkey: "pub-alice",
      encryptPub: "enc-alice",
      sig: "sig-alice",
    } as any);
    vi.mocked(friendsMod.verifyFriendRequest).mockReturnValue(true);
    vi.mocked(friendsMod.shouldAutoAccept).mockReturnValue(false);
  });

  function makeMsgCtx(channelType = "discord", channel = "general") {
    return {
      content: "FRIEND_REQUEST | to:wopr | from:alice | ...",
      channelType,
      channel,
      getBotUsername: () => "wopr",
      reply: vi.fn(),
    };
  }

  /** Build a channel provider that supports sendNotification and captures registered parsers. */
  function makeProvider(id: string, parsers?: any[]) {
    return {
      id,
      registerCommand: vi.fn(),
      addMessageParser: vi.fn((p: any) => parsers?.push(p)),
      sendNotification: vi.fn().mockResolvedValue(undefined),
    };
  }

  /** Find the FRIEND_REQUEST parser registered on a provider. */
  function getFriendRequestParser(provider: ReturnType<typeof makeProvider>) {
    const calls = vi.mocked(provider.addMessageParser).mock.calls;
    const call = calls.find(([p]) => p.id === "p2p-friend-request");
    return call?.[0];
  }

  it("sends notification only to the source channel provider", async () => {
    const sourceProvider = makeProvider("discord");
    const otherProvider = makeProvider("slack");

    const { ctx } = createMockCtx({ channels: [sourceProvider, otherProvider] });
    registerChannelHooks(ctx);

    const parser = getFriendRequestParser(sourceProvider);
    await parser.handler(makeMsgCtx("discord", "general"));

    expect(sourceProvider.sendNotification).toHaveBeenCalledTimes(1);
    expect(sourceProvider.sendNotification).toHaveBeenCalledWith(
      "general",
      expect.objectContaining({ type: "friend-request", from: "alice" }),
      expect.objectContaining({ onAccept: expect.any(Function), onDeny: expect.any(Function) }),
    );
    expect(otherProvider.sendNotification).not.toHaveBeenCalled();
  });

  it("skips sendNotification when auto-accept is active", async () => {
    vi.mocked(friendsMod.shouldAutoAccept).mockReturnValue(true);

    const provider = makeProvider("discord");
    const { ctx } = createMockCtx({ channels: [provider] });
    registerChannelHooks(ctx);

    const parser = getFriendRequestParser(provider);
    await parser.handler(makeMsgCtx("discord", "general"));

    expect(provider.sendNotification).not.toHaveBeenCalled();
  });

  it("onAccept calls acceptPendingRequest, syncFriendToSecurity, and reply", async () => {
    const mockFriend = { name: "alice", publicKey: "pub-alice", encryptPub: "enc-alice" } as any;
    vi.mocked(friendsMod.acceptPendingRequest).mockReturnValue({
      friend: mockFriend,
      request: { from: "alice", pubkey: "pub-alice", encryptPub: "enc-alice" } as any,
    });

    const provider = makeProvider("discord");
    const msgCtx = makeMsgCtx("discord", "general");
    const { ctx } = createMockCtx({ channels: [provider] });
    registerChannelHooks(ctx);

    const parser = getFriendRequestParser(provider);
    await parser.handler(msgCtx);

    const [, , callbacks] = vi.mocked(provider.sendNotification).mock.calls[0];
    await callbacks.onAccept();

    expect(friendsMod.acceptPendingRequest).toHaveBeenCalledWith("alice");
    expect(secMod.syncFriendToSecurity).toHaveBeenCalledWith(mockFriend);
    expect(msgCtx.reply).toHaveBeenCalledWith(expect.stringContaining("FRIEND_ACCEPT"));
  });

  it("onDeny calls denyPendingRequest", async () => {
    const provider = makeProvider("discord");
    const msgCtx = makeMsgCtx("discord", "general");
    const { ctx } = createMockCtx({ channels: [provider] });
    registerChannelHooks(ctx);

    const parser = getFriendRequestParser(provider);
    await parser.handler(msgCtx);

    const [, , callbacks] = vi.mocked(provider.sendNotification).mock.calls[0];
    await callbacks.onDeny();

    expect(friendsMod.denyPendingRequest).toHaveBeenCalledWith("alice");
  });

  it("logs warning when provider.sendNotification throws without propagating", async () => {
    const provider = makeProvider("discord");
    vi.mocked(provider.sendNotification).mockRejectedValue(new Error("send failed"));

    const { ctx, logMessages } = createMockCtx({ channels: [provider] });
    registerChannelHooks(ctx);

    const parser = getFriendRequestParser(provider);
    await expect(parser.handler(makeMsgCtx("discord", "general"))).resolves.not.toThrow();
    expect(logMessages.some((m) => m.includes("WARN") && m.includes("send failed"))).toBeTruthy();
  });
});
