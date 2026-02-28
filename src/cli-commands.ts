/**
 * P2P Plugin CLI Commands
 *
 * Provides CLI commands for friend management:
 *   wopr friend list
 *   wopr friend request <pubkey> [--name <name>]
 *   wopr friend accept <name-or-pubkey>
 *   wopr friend remove <name>
 *   wopr friend grant <name> <cap>
 *   wopr friend revoke <name> <cap>
 *   wopr friend auto-accept [list|add|remove] [pattern]
 */

import type { WOPRPluginContext } from "@wopr-network/plugin-types";
import {
	acceptPendingRequest,
	addAutoAcceptRule,
	getAutoAcceptRules,
	getFriend,
	getFriends,
	getPendingIncomingRequests,
	getPendingOutgoingRequests,
	grantFriendCap,
	removeAutoAcceptRule,
	removeFriend,
	revokeFriendCap,
} from "./friends.js";
import { shortKey } from "./identity.js";

// Parse flags from args
function _parseFlags(args: string[]): {
	flags: Record<string, string | boolean>;
	positional: string[];
} {
  const flags: Record<string, string | boolean> = {};
  const positional: string[] = [];

  for (let i = 0; i < args.length; i++) {
    if (args[i].startsWith("--")) {
      const key = args[i].slice(2);
      if (i + 1 < args.length && !args[i + 1].startsWith("--")) {
        flags[key] = args[++i];
      } else {
        flags[key] = true;
      }
    } else {
      positional.push(args[i]);
    }
  }

  return { flags, positional };
}

/**
 * Handle the `wopr friend` command
 */
export async function handleFriendCommand(ctx: WOPRPluginContext, args: string[]): Promise<void> {
  const subcommand = args[0];
  const subArgs = args.slice(1);

  switch (subcommand) {
    case "list":
      await handleFriendList(ctx);
      break;

    case "request":
      await handleFriendRequest(ctx, subArgs);
      break;

    case "accept":
      await handleFriendAccept(ctx, subArgs);
      break;

    case "pending":
      await handleFriendPending(ctx);
      break;

    case "remove":
    case "unfriend":
      await handleFriendRemove(ctx, subArgs);
      break;

    case "grant":
      await handleFriendGrant(ctx, subArgs);
      break;

    case "revoke":
      await handleFriendRevoke(ctx, subArgs);
      break;

    case "auto-accept":
      await handleAutoAccept(ctx, subArgs);
      break;

    default:
      showFriendHelp(ctx);
  }
}

function showFriendHelp(_ctx: WOPRPluginContext): void {
	console.log(`
wopr friend - Manage P2P friends

async function handleFriendList(_ctx: WOPRPluginContext): Promise<void> {
  const friends = getFriends();

  if (friends.length === 0) {
    return;
  }

  for (const f of friends) {
    const _name = f.name.padEnd(17);
    const _pubkey = shortKey(f.publicKey).padEnd(10);
    const _caps = f.caps.join(",").padEnd(17);
  }
}

async function handleFriendList(_ctx: WOPRPluginContext): Promise<void> {
	const friends = getFriends();

async function handleFriendAccept(_ctx: WOPRPluginContext, args: string[]): Promise<void> {
  if (!args[0]) {
    console.error("Usage: wopr friend accept <name>");
    return;
  }

  const from = args[0].startsWith("@") ? args[0].slice(1) : args[0];

  const result = acceptPendingRequest(from);
  if (!result) {
    console.error(`No pending friend request from "${from}"`);
    return;
  }
}

async function handleFriendRequest(
	_ctx: WOPRPluginContext,
	_args: string[],
): Promise<void> {
	// Note: Friend requests are primarily sent via Discord/Slack channels
	// The CLI can display how to do it
	console.log(`
To send a friend request, use the /friend command in a channel:

  if (incoming.length === 0 && outgoing.length === 0) {
    return;
  }

  if (incoming.length > 0) {
    for (const p of incoming) {
      const _age = Math.round((Date.now() - p.receivedAt) / 60000);
    }
  }

  if (outgoing.length > 0) {
    for (const p of outgoing) {
      const _age = Math.round((Date.now() - p.sentAt) / 60000);
    }
  }
}

async function handleFriendAccept(
	_ctx: WOPRPluginContext,
	args: string[],
): Promise<void> {
	if (!args[0]) {
		console.error("Usage: wopr friend accept <name>");
		return;
	}

  const name = args[0].startsWith("@") ? args[0].slice(1) : args[0];

  if (removeFriend(name)) {
  } else {
    console.error(`Friend not found: ${name}`);
  }
}

async function handleFriendPending(_ctx: WOPRPluginContext): Promise<void> {
	const incoming = getPendingIncomingRequests();
	const outgoing = getPendingOutgoingRequests();

  const name = args[0].startsWith("@") ? args[0].slice(1) : args[0];
  const cap = args[1];

  const validCaps = ["message", "inject"];
  if (!validCaps.includes(cap)) {
    console.error(`Invalid capability: ${cap}`);
    return;
  }

  if (grantFriendCap(name, cap)) {
    const _friend = getFriend(name);
  } else {
    console.error(`Friend not found: ${name}`);
  }
}

async function handleFriendRemove(
	_ctx: WOPRPluginContext,
	args: string[],
): Promise<void> {
	if (!args[0]) {
		console.error("Usage: wopr friend remove <name>");
		return;
	}

  const name = args[0].startsWith("@") ? args[0].slice(1) : args[0];
  const cap = args[1];

  if (revokeFriendCap(name, cap)) {
    const _friend = getFriend(name);
  } else {
    console.error(`Friend not found or cap not granted: ${name}`);
  }
}

async function handleFriendGrant(
	_ctx: WOPRPluginContext,
	args: string[],
): Promise<void> {
	if (args.length < 2) {
		console.error("Usage: wopr friend grant <name> <capability>");
		console.log("Capabilities: message, inject");
		return;
	}

  if (!action || action === "list") {
    const rules = getAutoAcceptRules();
    if (rules.length === 0) {
    } else {
      for (const r of rules) {
        const _added = new Date(r.addedAt).toLocaleDateString();
      }
    }
    return;
  }

  if (action === "add") {
    if (!pattern) {
      console.error("Usage: wopr friend auto-accept add <pattern>");
      return;
    }

    addAutoAcceptRule(pattern);
    return;
  }

async function handleFriendRevoke(
	_ctx: WOPRPluginContext,
	args: string[],
): Promise<void> {
	if (args.length < 2) {
		console.error("Usage: wopr friend revoke <name> <capability>");
		return;
	}

    if (removeAutoAcceptRule(pattern)) {
    } else {
      console.error(`Rule not found: "${pattern}"`);
    }
    return;
  }

	if (revokeFriendCap(name, cap)) {
		const friend = getFriend(name);
		console.log(`Revoked ${cap} from ${name}`);
		console.log(`Current caps: ${friend?.caps.join(", ")}`);
	} else {
		console.error(`Friend not found or cap not granted: ${name}`);
	}
}

async function handleAutoAccept(
	_ctx: WOPRPluginContext,
	args: string[],
): Promise<void> {
	const action = args[0];
	const pattern = args[1];

	if (!action || action === "list") {
		const rules = getAutoAcceptRules();
		if (rules.length === 0) {
			console.log("No auto-accept rules configured.");
			console.log("Add with: wopr friend auto-accept add <pattern>");
		} else {
			console.log("Auto-accept rules:");
			for (const r of rules) {
				const added = new Date(r.addedAt).toLocaleDateString();
				console.log(`  "${r.pattern}" (added ${added})`);
			}
		}
		return;
	}

	if (action === "add") {
		if (!pattern) {
			console.error("Usage: wopr friend auto-accept add <pattern>");
			console.log("Examples:");
			console.log('  wopr friend auto-accept add "*"       # Accept all');
			console.log('  wopr friend auto-accept add "hope"    # Accept from hope');
			console.log(
				'  wopr friend auto-accept add "hope|wopr"  # Accept from hope or wopr',
			);
			return;
		}

		addAutoAcceptRule(pattern);
		console.log(`Added auto-accept rule: "${pattern}"`);
		return;
	}

	if (action === "remove") {
		if (!pattern) {
			console.error("Usage: wopr friend auto-accept remove <pattern>");
			return;
		}

		if (removeAutoAcceptRule(pattern)) {
			console.log(`Removed auto-accept rule: "${pattern}"`);
		} else {
			console.error(`Rule not found: "${pattern}"`);
		}
		return;
	}

	console.error(`Unknown action: ${action}`);
	console.log("Usage: wopr friend auto-accept [list|add|remove] [pattern]");
}

/**
 * Plugin command definition for export
 */
export const friendCommand = {
  name: "friend",
  description: "Manage P2P friends",
  usage: "wopr friend [list|pending|accept|remove|grant|revoke|auto-accept] [args]",
  handler: handleFriendCommand,
};
