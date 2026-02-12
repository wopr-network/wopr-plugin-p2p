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
  getFriends,
  getFriend,
  removeFriend,
  grantFriendCap,
  revokeFriendCap,
  getAutoAcceptRules,
  addAutoAcceptRule,
  removeAutoAcceptRule,
  getPendingIncomingRequests,
  getPendingOutgoingRequests,
  acceptPendingRequest,
  createFriendAccept,
  formatFriendAccept,
} from "./friends.js";
import { getIdentity, shortKey } from "./identity.js";
import { addPeer, grantAccess } from "./trust.js";

// Parse flags from args
function parseFlags(args: string[]): { flags: Record<string, string | boolean>; positional: string[] } {
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

function showFriendHelp(ctx: WOPRPluginContext): void {
  ctx.log.info(`
wopr friend - Manage P2P friends

Usage:
  wopr friend list                       List all friends
  wopr friend pending                    Show pending friend requests
  wopr friend accept <name>              Accept a pending friend request
  wopr friend remove <name>              Remove a friend
  wopr friend grant <name> <cap>         Grant capability to a friend
  wopr friend revoke <name> <cap>        Revoke capability from a friend
  wopr friend auto-accept                List auto-accept rules
  wopr friend auto-accept add <pattern>  Add auto-accept rule
  wopr friend auto-accept remove <pattern>  Remove auto-accept rule

Capabilities:
  message      Send to conversation (no AI response)
  inject       Get AI response (sandboxed)

Examples:
  wopr friend list
  wopr friend accept hope
  wopr friend grant hope inject
  wopr friend auto-accept add "*"
`);
}

async function handleFriendList(ctx: WOPRPluginContext): Promise<void> {
  const friends = getFriends();

  if (friends.length === 0) {
    ctx.log.info("No friends yet. Use /friend @username in Discord to send a friend request.");
    return;
  }

  ctx.log.info(`Friends (${friends.length}):`);
  ctx.log.info("Name              | Pubkey     | Caps              | Session");
  ctx.log.info("------------------|------------|-------------------|--------");

  for (const f of friends) {
    const name = f.name.padEnd(17);
    const pubkey = shortKey(f.publicKey).padEnd(10);
    const caps = f.caps.join(",").padEnd(17);
    ctx.log.info(`${name}| ${pubkey} | ${caps} | ${f.sessionName}`);
  }
}

async function handleFriendRequest(ctx: WOPRPluginContext, args: string[]): Promise<void> {
  // Note: Friend requests are primarily sent via Discord/Slack channels
  // The CLI can display how to do it
  ctx.log.info(`
To send a friend request, use the /friend command in a channel:

  In Discord: /friend @username
  In Slack:   /friend @username

The friend request will be posted as a signed message in the channel.
The other agent will see it and can accept it.

Note: CLI friend requests require both parties to be in the same channel
for the handshake to complete.
`);
}

async function handleFriendAccept(ctx: WOPRPluginContext, args: string[]): Promise<void> {
  if (!args[0]) {
    ctx.log.error("Usage: wopr friend accept <name>");
    return;
  }

  const from = args[0].startsWith("@") ? args[0].slice(1) : args[0];

  const result = acceptPendingRequest(from);
  if (!result) {
    ctx.log.error(`No pending friend request from "${from}"`);
    ctx.log.info("Use 'wopr friend pending' to see pending requests.");
    return;
  }

  ctx.log.info(`Accepted friend request from ${from}`);
  ctx.log.info(`Session: ${result.friend.sessionName}`);
  ctx.log.info(`Caps: ${result.friend.caps.join(", ")}`);
  ctx.log.info("");
  ctx.log.info("Note: The accept message needs to be posted to the channel where");
  ctx.log.info("the request was received. Use /accept in that channel.");
}

async function handleFriendPending(ctx: WOPRPluginContext): Promise<void> {
  const incoming = getPendingIncomingRequests();
  const outgoing = getPendingOutgoingRequests();

  if (incoming.length === 0 && outgoing.length === 0) {
    ctx.log.info("No pending friend requests.");
    return;
  }

  if (incoming.length > 0) {
    ctx.log.info(`Incoming requests (${incoming.length}):`);
    for (const p of incoming) {
      const age = Math.round((Date.now() - p.receivedAt) / 60000);
      ctx.log.info(`  @${p.request.from} (${shortKey(p.request.pubkey)}) - ${age}m ago via ${p.channel}`);
    }
    ctx.log.info("");
  }

  if (outgoing.length > 0) {
    ctx.log.info(`Outgoing requests (${outgoing.length}):`);
    for (const p of outgoing) {
      const age = Math.round((Date.now() - p.sentAt) / 60000);
      ctx.log.info(`  @${p.request.to} - ${age}m ago via ${p.channel}`);
    }
  }
}

async function handleFriendRemove(ctx: WOPRPluginContext, args: string[]): Promise<void> {
  if (!args[0]) {
    ctx.log.error("Usage: wopr friend remove <name>");
    return;
  }

  const name = args[0].startsWith("@") ? args[0].slice(1) : args[0];

  if (removeFriend(name)) {
    ctx.log.info(`Removed friend: ${name}`);
  } else {
    ctx.log.error(`Friend not found: ${name}`);
  }
}

async function handleFriendGrant(ctx: WOPRPluginContext, args: string[]): Promise<void> {
  if (args.length < 2) {
    ctx.log.error("Usage: wopr friend grant <name> <capability>");
    ctx.log.info("Capabilities: message, inject");
    return;
  }

  const name = args[0].startsWith("@") ? args[0].slice(1) : args[0];
  const cap = args[1];

  const validCaps = ["message", "inject"];
  if (!validCaps.includes(cap)) {
    ctx.log.error(`Invalid capability: ${cap}`);
    ctx.log.info(`Valid: ${validCaps.join(", ")}`);
    return;
  }

  if (grantFriendCap(name, cap)) {
    const friend = getFriend(name);
    ctx.log.info(`Granted ${cap} to ${name}`);
    ctx.log.info(`Current caps: ${friend?.caps.join(", ")}`);
  } else {
    ctx.log.error(`Friend not found: ${name}`);
  }
}

async function handleFriendRevoke(ctx: WOPRPluginContext, args: string[]): Promise<void> {
  if (args.length < 2) {
    ctx.log.error("Usage: wopr friend revoke <name> <capability>");
    return;
  }

  const name = args[0].startsWith("@") ? args[0].slice(1) : args[0];
  const cap = args[1];

  if (revokeFriendCap(name, cap)) {
    const friend = getFriend(name);
    ctx.log.info(`Revoked ${cap} from ${name}`);
    ctx.log.info(`Current caps: ${friend?.caps.join(", ")}`);
  } else {
    ctx.log.error(`Friend not found or cap not granted: ${name}`);
  }
}

async function handleAutoAccept(ctx: WOPRPluginContext, args: string[]): Promise<void> {
  const action = args[0];
  const pattern = args[1];

  if (!action || action === "list") {
    const rules = getAutoAcceptRules();
    if (rules.length === 0) {
      ctx.log.info("No auto-accept rules configured.");
      ctx.log.info("Add with: wopr friend auto-accept add <pattern>");
    } else {
      ctx.log.info("Auto-accept rules:");
      for (const r of rules) {
        const added = new Date(r.addedAt).toLocaleDateString();
        ctx.log.info(`  "${r.pattern}" (added ${added})`);
      }
    }
    return;
  }

  if (action === "add") {
    if (!pattern) {
      ctx.log.error("Usage: wopr friend auto-accept add <pattern>");
      ctx.log.info("Examples:");
      ctx.log.info("  wopr friend auto-accept add \"*\"       # Accept all");
      ctx.log.info("  wopr friend auto-accept add \"hope\"    # Accept from hope");
      ctx.log.info("  wopr friend auto-accept add \"hope|wopr\"  # Accept from hope or wopr");
      return;
    }

    addAutoAcceptRule(pattern);
    ctx.log.info(`Added auto-accept rule: "${pattern}"`);
    return;
  }

  if (action === "remove") {
    if (!pattern) {
      ctx.log.error("Usage: wopr friend auto-accept remove <pattern>");
      return;
    }

    if (removeAutoAcceptRule(pattern)) {
      ctx.log.info(`Removed auto-accept rule: "${pattern}"`);
    } else {
      ctx.log.error(`Rule not found: "${pattern}"`);
    }
    return;
  }

  ctx.log.error(`Unknown action: ${action}`);
  ctx.log.info("Usage: wopr friend auto-accept [list|add|remove] [pattern]");
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
