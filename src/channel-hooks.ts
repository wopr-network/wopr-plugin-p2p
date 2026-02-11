/**
 * P2P Channel Hooks
 *
 * Registers friend commands and message parsers with all channel providers
 * (Discord, Slack, Telegram, etc.).
 *
 * This allows the friending protocol to work across any messaging channel.
 */

import type { WOPRPluginContext } from "./types.js";
import {
	createFriendRequest,
	createFriendAccept,
	formatFriendRequest,
	formatFriendAccept,
	parseFriendRequest,
	parseFriendAccept,
	verifyFriendRequest,
	verifyFriendAccept,
	storePendingRequest,
	queueForApproval,
	shouldAutoAccept,
	getPendingOutgoing,
	completeFriendship,
	acceptPendingRequest,
	getFriends,
	getFriend,
	removeFriend,
	grantFriendCap,
	getPendingIncomingRequests,
	getAutoAcceptRules,
	addAutoAcceptRule,
	removeAutoAcceptRule,
} from "./friends.js";
import { getIdentity, shortKey } from "./identity.js";

// Discord extension interface for sending owner notifications
interface DiscordExtension {
	sendFriendRequestNotification: (
		requestFrom: string,
		pubkey: string,
		encryptPub: string,
		channelId: string,
		channelName: string,
		signature: string,
	) => Promise<boolean>;
	getBotUsername: () => string;
}

// Extended plugin context with channel providers
interface ExtendedPluginContext extends WOPRPluginContext {
	getChannelProviders?: () => Array<{
		id: string;
		registerCommand: (cmd: {
			name: string;
			description: string;
			handler: (ctx: {
				channel: string;
				channelType: string;
				sender: string;
				args: string[];
				reply: (msg: string) => Promise<void>;
				getBotUsername: () => string;
			}) => Promise<void>;
		}) => void;
		addMessageParser: (parser: {
			id: string;
			pattern: RegExp | ((msg: string) => boolean);
			handler: (ctx: {
				channel: string;
				channelType: string;
				sender: string;
				content: string;
				reply: (msg: string) => Promise<void>;
				getBotUsername: () => string;
			}) => Promise<void>;
		}) => void;
	}>;
	getExtension?: <T>(name: string) => T | undefined;
}

/**
 * P2P slash command definitions (plain objects, no discord.js dependency).
 * Used by registerP2PSlashCommands() to build Discord SlashCommandBuilder instances at runtime.
 */
const p2pCommandDefs = [
	{
		name: "friend",
		description: "Send a friend request to another agent",
		options: [
			{
				name: "username",
				description: "Username of the agent to friend (e.g., @hope)",
				required: true,
			},
		],
	},
	{
		name: "accept",
		description: "Accept a pending friend request",
		options: [
			{
				name: "from",
				description: "Username of the requester (leave empty to list pending)",
				required: false,
			},
		],
	},
	{
		name: "friends",
		description: "List all friends and their status",
		options: [],
	},
	{
		name: "unfriend",
		description: "Remove a friend",
		options: [
			{
				name: "name",
				description: "Name of the friend to remove",
				required: true,
			},
		],
	},
	{
		name: "grant",
		description: "Grant capabilities to a friend",
		options: [
			{ name: "friend", description: "Name of the friend", required: true },
			{
				name: "capability",
				description: "Capability to grant",
				required: true,
				choices: [
					{ name: "inject - Can invoke AI (sandboxed)", value: "inject" },
				],
			},
		],
	},
];

/**
 * Register P2P slash commands with Discord (merge mode - doesn't replace existing commands).
 * Dynamically imports discord.js so it is not required at module load time.
 */
export async function registerP2PSlashCommands(
	token: string,
	clientId: string,
	guildId?: string,
	log?: { info: (...args: any[]) => void; error: (...args: any[]) => void },
): Promise<void> {
	const logger = log || console;

	// Dynamic import — discord.js is an optional peer dependency.
	// Use a variable so TypeScript does not resolve the module at compile time.
	let SlashCommandBuilder: any;
	let REST: any;
	let Routes: any;
	try {
		const mod = "discord.js";
		const discordjs = await import(/* webpackIgnore: true */ mod);
		SlashCommandBuilder = discordjs.SlashCommandBuilder;
		REST = discordjs.REST;
		Routes = discordjs.Routes;
	} catch {
		logger.info(
			"[p2p] discord.js not available — skipping slash command registration",
		);
		return;
	}

	// Build SlashCommandBuilder instances from plain definitions
	const p2pCommands = p2pCommandDefs.map((def) => {
		const builder = new SlashCommandBuilder()
			.setName(def.name)
			.setDescription(def.description);
		for (const opt of def.options) {
			builder.addStringOption((o: any) => {
				o.setName(opt.name)
					.setDescription(opt.description)
					.setRequired(opt.required ?? false);
				if (opt.choices) {
					o.addChoices(...opt.choices);
				}
				return o;
			});
		}
		return builder;
	});

	const rest = new REST({ version: "10" }).setToken(token);

	try {
		logger.info("[p2p] Registering P2P slash commands (merge mode)...");

		// Get our command names for filtering
		const p2pCommandNames = new Set(p2pCommands.map((cmd: any) => cmd.name));

		if (guildId) {
			// Fetch existing guild commands
			const existingCommands = (await rest.get(
				Routes.applicationGuildCommands(clientId, guildId),
			)) as any[];

			// Filter out our P2P commands from existing (in case of re-registration)
			const otherCommands = existingCommands.filter(
				(cmd: any) => !p2pCommandNames.has(cmd.name),
			);

			// Merge: keep other commands + add our P2P commands
			const mergedCommands = [
				...otherCommands,
				...p2pCommands.map((cmd: any) => cmd.toJSON()),
			];

			await rest.put(Routes.applicationGuildCommands(clientId, guildId), {
				body: mergedCommands,
			});
			logger.info(
				`[p2p] Registered ${p2pCommands.length} P2P commands (merged with ${otherCommands.length} existing) to guild ${guildId}`,
			);
		} else {
			// Fetch existing global commands
			const existingCommands = (await rest.get(
				Routes.applicationCommands(clientId),
			)) as any[];

			// Filter out our P2P commands from existing
			const otherCommands = existingCommands.filter(
				(cmd: any) => !p2pCommandNames.has(cmd.name),
			);

			// Merge: keep other commands + add our P2P commands
			const mergedCommands = [
				...otherCommands,
				...p2pCommands.map((cmd: any) => cmd.toJSON()),
			];

			await rest.put(Routes.applicationCommands(clientId), {
				body: mergedCommands,
			});
			logger.info(
				`[p2p] Registered ${p2pCommands.length} P2P global commands (merged with ${otherCommands.length} existing)`,
			);
		}
	} catch (error) {
		logger.error({
			msg: "[p2p] Failed to register P2P slash commands",
			error: String(error),
		});
	}
}

/**
 * Register friend protocol commands and parsers with all channel providers
 */
export function registerChannelHooks(ctx: ExtendedPluginContext): void {
	// Check if channel providers are available
	if (!ctx.getChannelProviders) {
		ctx.log.info(
			"[p2p] No channel provider support - friend commands not available",
		);
		return;
	}

	const channels = ctx.getChannelProviders();
	if (channels.length === 0) {
		ctx.log.info(
			"[p2p] No channel providers registered yet - will retry on demand",
		);
		return;
	}

	ctx.log.info(
		`[p2p] Registering friend commands on ${channels.length} channel(s)`,
	);

	for (const channel of channels) {
		registerFriendCommand(channel, ctx);
		registerAcceptCommand(channel, ctx);
		registerFriendsCommand(channel, ctx);
		registerUnfriendCommand(channel, ctx);
		registerGrantCommand(channel, ctx);
		registerFriendRequestParser(channel, ctx);
		registerFriendAcceptParser(channel, ctx);
	}
}

/**
 * Register /friend command
 */
function registerFriendCommand(
	channel: ReturnType<
		NonNullable<ExtendedPluginContext["getChannelProviders"]>
	>[0],
	ctx: ExtendedPluginContext,
): void {
	channel.registerCommand({
		name: "friend",
		description: "Send a friend request to another agent",
		async handler(cmdCtx) {
			const target = cmdCtx.args[0];
			if (!target) {
				await cmdCtx.reply("Usage: /friend @username");
				return;
			}

			// Clean up @ prefix if present
			const cleanTarget = target.startsWith("@") ? target.slice(1) : target;

			const identity = getIdentity();
			if (!identity) {
				await cmdCtx.reply(
					"Error: No P2P identity initialized. Run `wopr p2p init` first.",
				);
				return;
			}

			// Create signed friend request
			const request = createFriendRequest(cleanTarget, cmdCtx.getBotUsername());

			// Store as pending outgoing
			storePendingRequest(request, cmdCtx.channelType, cmdCtx.channel);

			// Post to channel
			await cmdCtx.reply(formatFriendRequest(request));

			ctx.log.info(
				`[p2p] Friend request sent to ${cleanTarget} on ${cmdCtx.channelType}`,
			);
		},
	});
}

/**
 * Register /accept command
 */
function registerAcceptCommand(
	channel: ReturnType<
		NonNullable<ExtendedPluginContext["getChannelProviders"]>
	>[0],
	ctx: ExtendedPluginContext,
): void {
	channel.registerCommand({
		name: "accept",
		description: "Accept a pending friend request",
		async handler(cmdCtx) {
			const from = cmdCtx.args[0];
			if (!from) {
				// List pending requests
				const pending = getPendingIncomingRequests();
				if (pending.length === 0) {
					await cmdCtx.reply("No pending friend requests.");
					return;
				}

				const list = pending
					.map((p) => `- @${p.request.from} (${shortKey(p.request.pubkey)})`)
					.join("\n");
				await cmdCtx.reply(
					`Pending friend requests:\n${list}\n\nUse /accept @username to accept.`,
				);
				return;
			}

			// Clean up @ prefix
			const cleanFrom = from.startsWith("@") ? from.slice(1) : from;

			const result = acceptPendingRequest(cleanFrom);
			if (!result) {
				await cmdCtx.reply(`No pending friend request from @${cleanFrom}`);
				return;
			}

			// Create the accept message with the original request and our username
			const accept = createFriendAccept(
				result.request,
				cmdCtx.getBotUsername(),
			);

			// Post accept to channel
			await cmdCtx.reply(formatFriendAccept(accept));

			ctx.log.info(`[p2p] Accepted friend request from ${cleanFrom}`);
		},
	});
}

/**
 * Register /friends command
 */
function registerFriendsCommand(
	channel: ReturnType<
		NonNullable<ExtendedPluginContext["getChannelProviders"]>
	>[0],
	ctx: ExtendedPluginContext,
): void {
	channel.registerCommand({
		name: "friends",
		description: "List your friends",
		async handler(cmdCtx) {
			const friends = getFriends();
			if (friends.length === 0) {
				await cmdCtx.reply(
					"No friends yet. Use /friend @username to send a friend request.",
				);
				return;
			}

			const list = friends
				.map((f) => {
					const caps = f.caps.join(", ");
					return `- @${f.name} (${shortKey(f.publicKey)}) - caps: [${caps}] - session: ${f.sessionName}`;
				})
				.join("\n");

			await cmdCtx.reply(`Friends:\n${list}`);
		},
	});
}

/**
 * Register /unfriend command
 */
function registerUnfriendCommand(
	channel: ReturnType<
		NonNullable<ExtendedPluginContext["getChannelProviders"]>
	>[0],
	ctx: ExtendedPluginContext,
): void {
	channel.registerCommand({
		name: "unfriend",
		description: "Remove a friend",
		async handler(cmdCtx) {
			const target = cmdCtx.args[0];
			if (!target) {
				await cmdCtx.reply("Usage: /unfriend @username");
				return;
			}

			const cleanTarget = target.startsWith("@") ? target.slice(1) : target;

			if (removeFriend(cleanTarget)) {
				await cmdCtx.reply(`Removed @${cleanTarget} from friends.`);
				ctx.log.info(`[p2p] Removed friend: ${cleanTarget}`);
			} else {
				await cmdCtx.reply(`@${cleanTarget} is not in your friends list.`);
			}
		},
	});
}

/**
 * Register /grant command for granting capabilities to friends
 */
function registerGrantCommand(
	channel: ReturnType<
		NonNullable<ExtendedPluginContext["getChannelProviders"]>
	>[0],
	ctx: ExtendedPluginContext,
): void {
	channel.registerCommand({
		name: "grant",
		description: "Grant capabilities to a friend",
		async handler(cmdCtx) {
			const target = cmdCtx.args[0];
			const cap = cmdCtx.args[1];

			if (!target || !cap) {
				await cmdCtx.reply("Usage: /grant @username inject");
				return;
			}

			const cleanTarget = target.startsWith("@") ? target.slice(1) : target;

			const validCaps = ["message", "inject"];
			if (!validCaps.includes(cap)) {
				await cmdCtx.reply(
					`Invalid capability: ${cap}\nValid: ${validCaps.join(", ")}`,
				);
				return;
			}

			if (grantFriendCap(cleanTarget, cap)) {
				const friend = getFriend(cleanTarget);
				await cmdCtx.reply(
					`Granted ${cap} to @${cleanTarget}. Caps: [${friend?.caps.join(", ")}]`,
				);
				ctx.log.info(`[p2p] Granted ${cap} to ${cleanTarget}`);
			} else {
				await cmdCtx.reply(`@${cleanTarget} is not in your friends list.`);
			}
		},
	});
}

/**
 * Register message parser for FRIEND_REQUEST
 */
function registerFriendRequestParser(
	channel: ReturnType<
		NonNullable<ExtendedPluginContext["getChannelProviders"]>
	>[0],
	ctx: ExtendedPluginContext,
): void {
	channel.addMessageParser({
		id: "p2p-friend-request",
		pattern: /^FRIEND_REQUEST \|/,
		async handler(msgCtx) {
			const request = parseFriendRequest(msgCtx.content);
			if (!request) return;

			// Check if this is addressed to us
			const myUsername = msgCtx.getBotUsername();
			// Strip @ prefix from both for comparison
			const targetName = request.to.startsWith("@")
				? request.to.slice(1)
				: request.to;
			if (targetName.toLowerCase() !== myUsername.toLowerCase()) {
				return; // Not for us
			}

			ctx.log.info(`[p2p] Received friend request from @${request.from}`);

			// Verify signature
			if (!verifyFriendRequest(request)) {
				ctx.log.warn(
					`[p2p] Invalid signature on friend request from @${request.from}`,
				);
				return;
			}

			// Check auto-accept
			if (shouldAutoAccept(request.from)) {
				ctx.log.info(
					`[p2p] Auto-accepting friend request from @${request.from}`,
				);

				// Create and send accept
				const accept = createFriendAccept(request, myUsername);

				// Complete friendship on our side
				completeFriendship(
					{
						...accept,
						pubkey: request.pubkey,
						encryptPub: request.encryptPub,
					} as any,
					msgCtx.channelType,
				);

				await msgCtx.reply(formatFriendAccept(accept));
			} else {
				// Queue for manual approval
				queueForApproval(request, msgCtx.channelType, msgCtx.channel);

				// Try to send owner notification with buttons (Discord only)
				if (msgCtx.channelType === "discord" && ctx.getExtension) {
					const discordExt = ctx.getExtension<DiscordExtension>("discord");
					if (discordExt) {
						const channelName = msgCtx.channel; // Channel ID for Discord
						await discordExt.sendFriendRequestNotification(
							request.from,
							request.pubkey,
							request.encryptPub,
							msgCtx.channel,
							channelName,
							request.sig,
						);
						ctx.log.info(
							`[p2p] Sent owner notification for friend request from @${request.from}`,
						);
					}
				}

				await msgCtx.reply(
					`Friend request from @${request.from} - waiting for approval. Use /accept @${request.from} to accept.`,
				);
			}
		},
	});
}

/**
 * Register message parser for FRIEND_ACCEPT
 */
function registerFriendAcceptParser(
	channel: ReturnType<
		NonNullable<ExtendedPluginContext["getChannelProviders"]>
	>[0],
	ctx: ExtendedPluginContext,
): void {
	channel.addMessageParser({
		id: "p2p-friend-accept",
		pattern: /^FRIEND_ACCEPT \|/,
		async handler(msgCtx) {
			const accept = parseFriendAccept(msgCtx.content);
			if (!accept) return;

			// Check if this is addressed to us
			const myUsername = msgCtx.getBotUsername();
			if (accept.to.toLowerCase() !== myUsername.toLowerCase()) {
				return; // Not for us
			}

			ctx.log.info(`[p2p] Received friend accept from @${accept.from}`);

			// Verify signature
			if (!verifyFriendAccept(accept)) {
				ctx.log.warn(
					`[p2p] Invalid signature on friend accept from @${accept.from}`,
				);
				return;
			}

			// Check that we have a pending outgoing request with matching signature
			const pending = getPendingOutgoing(accept.from);
			if (!pending) {
				ctx.log.warn(
					`[p2p] Received accept but no pending request to @${accept.from}`,
				);
				return;
			}

			// Verify the requestSig matches our original request
			if (accept.requestSig !== pending.request.sig) {
				ctx.log.warn(
					`[p2p] Accept requestSig doesn't match our original request`,
				);
				return;
			}

			// Complete the friendship
			const friend = completeFriendship(accept, msgCtx.channelType);

			await msgCtx.reply(
				`Friendship established with @${accept.from}! Session: ${friend.sessionName}`,
			);
			ctx.log.info(`[p2p] Friendship completed with @${accept.from}`);
		},
	});
}

/**
 * Setup auto-accept configuration commands
 */
export function registerAutoAcceptCommands(ctx: ExtendedPluginContext): void {
	if (!ctx.getChannelProviders) return;

	const channels = ctx.getChannelProviders();

	for (const channel of channels) {
		channel.registerCommand({
			name: "auto-accept",
			description: "Manage auto-accept rules for friend requests",
			async handler(cmdCtx) {
				const action = cmdCtx.args[0];
				const pattern = cmdCtx.args[1];

				if (!action || action === "list") {
					const rules = getAutoAcceptRules();
					if (rules.length === 0) {
						await cmdCtx.reply("No auto-accept rules configured.");
					} else {
						const list = rules.map((r) => `- "${r.pattern}"`).join("\n");
						await cmdCtx.reply(`Auto-accept rules:\n${list}`);
					}
					return;
				}

				if (action === "add" && pattern) {
					addAutoAcceptRule(pattern);
					await cmdCtx.reply(`Added auto-accept rule: "${pattern}"`);
					return;
				}

				if (action === "remove" && pattern) {
					if (removeAutoAcceptRule(pattern)) {
						await cmdCtx.reply(`Removed auto-accept rule: "${pattern}"`);
					} else {
						await cmdCtx.reply(`Rule not found: "${pattern}"`);
					}
					return;
				}

				await cmdCtx.reply(
					"Usage: /auto-accept [list|add|remove] [pattern]\nExamples:\n  /auto-accept list\n  /auto-accept add *\n  /auto-accept add hope|wopr\n  /auto-accept remove *",
				);
			},
		});
	}
}
