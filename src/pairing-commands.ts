/**
 * Pairing Channel Commands
 *
 * Registers cross-channel pairing commands on all channel providers.
 * These commands work identically on Discord, Slack, Telegram, etc.
 *
 * Commands:
 * - !pair generate <name> [trustLevel] -- Generate a pairing code (owner only)
 * - !pair verify <code>               -- Verify a pairing code (any user)
 * - !pair list                         -- List all paired identities (owner only)
 * - !pair revoke <name>                -- Revoke a user's identity (owner only)
 * - !pair whois                        -- Show your own paired identity
 * - !pair codes                        -- List pending pairing codes (owner only)
 */

import type {
	ChannelCommand,
	ChannelCommandContext,
	ChannelProvider,
	PluginLogger,
} from "@wopr-network/plugin-types";
import {
	findIdentityBySender,
	generatePairingCode,
	getIdentityByName,
	listIdentities,
	listPendingCodes,
	removeIdentity,
	resolveTrustLevel,
	verifyPairingCode,
} from "./pairing.js";
import type { TrustLevel } from "./pairing-types.js";

const VALID_TRUST_LEVELS: TrustLevel[] = [
	"owner",
	"trusted",
	"semi-trusted",
	"untrusted",
];

let log: PluginLogger | null = null;

export function setPairingCommandsLogger(logger: PluginLogger): void {
	log = logger;
}

async function isOwner(ctx: ChannelCommandContext): Promise<boolean> {
	return (await resolveTrustLevel(ctx.channelType, ctx.sender)) === "owner";
}

/**
 * The main !pair command handler
 */
async function handlePairCommand(ctx: ChannelCommandContext): Promise<void> {
	const subcommand = ctx.args[0]?.toLowerCase();

	switch (subcommand) {
		case "generate":
			await handleGenerate(ctx);
			break;
		case "verify":
			await handleVerify(ctx);
			break;
		case "list":
			await handleList(ctx);
			break;
		case "revoke":
			await handleRevoke(ctx);
			break;
		case "whois":
			await handleWhois(ctx);
			break;
		case "codes":
			await handleCodes(ctx);
			break;
		default:
			await ctx.reply(
				"Usage: !pair <generate|verify|list|revoke|whois|codes>\n" +
					"  generate <name> [trust] - Generate a pairing code\n" +
					"  verify <code>           - Verify a pairing code\n" +
					"  list                    - List paired identities\n" +
					"  revoke <name>           - Revoke an identity\n" +
					"  whois                   - Show your identity\n" +
					"  codes                   - List pending codes",
			);
	}
}

async function handleGenerate(ctx: ChannelCommandContext): Promise<void> {
	if (!(await isOwner(ctx))) {
		await ctx.reply(
			"Permission denied. Only owners can generate pairing codes.",
		);
		return;
	}

	const name = ctx.args[1];
	if (!name) {
		await ctx.reply(
			"Usage: !pair generate <name> [trustLevel]\nTrust levels: owner, trusted, semi-trusted, untrusted",
		);
		return;
	}

	const trustLevel = (ctx.args[2] as TrustLevel) || "semi-trusted";
	if (!VALID_TRUST_LEVELS.includes(trustLevel)) {
		await ctx.reply(
			`Invalid trust level: ${ctx.args[2]}\nValid levels: ${VALID_TRUST_LEVELS.join(", ")}`,
		);
		return;
	}

	try {
		const code = await generatePairingCode(name, trustLevel);
		const expiresIn = Math.round((code.expiresAt - Date.now()) / 1000 / 60);
		await ctx.reply(
			`Pairing code for "${name}" (trust: ${trustLevel}):\n` +
				`Code: **${code.code}**\n` +
				`Expires in ${expiresIn} minutes.\n` +
				`User should run: !pair verify ${code.code}`,
		);
	} catch (err: unknown) {
		const error = err as Error;
		await ctx.reply(`Error: ${error.message}`);
	}
}

async function handleVerify(ctx: ChannelCommandContext): Promise<void> {
	const code = ctx.args[1];
	if (!code) {
		await ctx.reply("Usage: !pair verify <code>");
		return;
	}

	const result = await verifyPairingCode(code, ctx.channelType, ctx.sender);
	if (!result) {
		await ctx.reply("Invalid or expired pairing code.");
		return;
	}

	const linkedChannels = result.identity.links
		.map((l) => l.channelType)
		.join(", ");
	await ctx.reply(
		`Paired successfully as "${result.identity.name}" (trust: ${result.trustLevel}).\n` +
			`Linked channels: ${linkedChannels}`,
	);
}

async function handleList(ctx: ChannelCommandContext): Promise<void> {
	if (!(await isOwner(ctx))) {
		await ctx.reply("Permission denied. Only owners can list identities.");
		return;
	}

	const identities = await listIdentities();
	if (identities.length === 0) {
		await ctx.reply("No paired identities.");
		return;
	}

	const lines = identities.map((id) => {
		const links = id.links
			.map((l) => `${l.channelType}:${l.senderId}`)
			.join(", ");
		return `- **${id.name}** (trust: ${id.trustLevel}) [${links || "no links"}]`;
	});

	await ctx.reply(
		`Paired identities (${identities.length}):\n${lines.join("\n")}`,
	);
}

async function handleRevoke(ctx: ChannelCommandContext): Promise<void> {
	if (!(await isOwner(ctx))) {
		await ctx.reply("Permission denied. Only owners can revoke identities.");
		return;
	}

	const name = ctx.args[1];
	if (!name) {
		await ctx.reply("Usage: !pair revoke <name>");
		return;
	}

	const identity = await getIdentityByName(name);
	if (!identity) {
		await ctx.reply(`Identity not found: ${name}`);
		return;
	}

	await removeIdentity(identity.id);
	await ctx.reply(`Revoked identity "${name}" and all linked platforms.`);
}

async function handleWhois(ctx: ChannelCommandContext): Promise<void> {
	const identity = await findIdentityBySender(ctx.channelType, ctx.sender);
	if (!identity) {
		await ctx.reply(
			"You are not paired. Ask an admin to generate a pairing code for you.",
		);
		return;
	}

	const links = identity.links
		.map((l) => `  - ${l.channelType}: ${l.senderId}`)
		.join("\n");
	await ctx.reply(
		`Identity: **${identity.name}**\n` +
			`Trust: ${identity.trustLevel}\n` +
			`Linked channels:\n${links}`,
	);
}

async function handleCodes(ctx: ChannelCommandContext): Promise<void> {
	if (!(await isOwner(ctx))) {
		await ctx.reply("Permission denied. Only owners can list pairing codes.");
		return;
	}

	const codes = await listPendingCodes();
	if (codes.length === 0) {
		await ctx.reply("No pending pairing codes.");
		return;
	}

	const lines = codes.map((c) => {
		const expiresIn = Math.round((c.expiresAt - Date.now()) / 1000 / 60);
		return `- **${c.code}** (trust: ${c.trustLevel}) expires in ${expiresIn}m`;
	});

	await ctx.reply(
		`Pending pairing codes (${codes.length}):\n${lines.join("\n")}`,
	);
}

// ============================================================================
// Registration
// ============================================================================

/**
 * The pair channel command definition
 */
export const pairCommand: ChannelCommand = {
	name: "pair",
	description:
		"Cross-channel identity pairing (generate, verify, list, revoke, whois, codes)",
	handler: handlePairCommand,
};

/**
 * Register pairing commands on a single channel provider
 */
export function registerPairingCommands(provider: ChannelProvider): void {
	provider.registerCommand(pairCommand);
	log?.info(
		`[pairing] Registered !pair command on channel provider: ${provider.id}`,
	);
}

/**
 * Unregister pairing commands from a channel provider
 */
export function unregisterPairingCommands(provider: ChannelProvider): void {
	provider.unregisterCommand("pair");
}

/**
 * Register pairing commands on all currently registered channel providers
 */
export function registerPairingOnAllProviders(
	providers: ChannelProvider[],
): void {
	for (const provider of providers) {
		registerPairingCommands(provider);
	}
}
