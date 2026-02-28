/**
 * Pairing A2A tools - expose pairing operations as A2A tools
 * so agents can manage identities and pairing codes programmatically.
 */

import type { A2AServerConfig, A2AToolResult } from "@wopr-network/plugin-types";
import {
  findIdentityBySender,
  generatePairingCode,
  getIdentityByName,
  linkPlatform,
  listIdentities,
  listPendingCodes,
  removeIdentity,
  resolveTrustLevel,
  revokePairingCode,
  setIdentityTrustLevel,
  unlinkPlatform,
  verifyPairingCode,
} from "./pairing.js";
import type { TrustLevel } from "./pairing-types.js";

const VALID_TRUST_LEVELS: TrustLevel[] = ["owner", "trusted", "semi-trusted", "untrusted"];

function textResult(text: string): A2AToolResult {
  return { content: [{ type: "text", text }] };
}

export function buildPairingA2ATools(): A2AServerConfig {
  return {
    name: "pairing",
    version: "1.0.0",
    tools: [
      {
        name: "pairing.generateCode",
        description:
          "Generate a pairing code for a user. Creates the identity if it doesn't exist. The user verifies this code from any channel to link their platform account.",
        inputSchema: {
          type: "object",
          properties: {
            name: {
              type: "string",
              description: "Human-readable name for the identity",
            },
            trustLevel: {
              type: "string",
              enum: VALID_TRUST_LEVELS,
              description: "Trust level to assign (default: semi-trusted)",
            },
            expiryMinutes: {
              type: "number",
              description: "Minutes until code expires (default: 15)",
            },
          },
          required: ["name"],
        },
        async handler(args: Record<string, unknown>): Promise<A2AToolResult> {
          const name = args.name as string;
          const trustLevel = (args.trustLevel as TrustLevel) || "semi-trusted";
          const expiryMs = ((args.expiryMinutes as number) || 15) * 60 * 1000;

          if (!VALID_TRUST_LEVELS.includes(trustLevel)) {
            return textResult(`Error: Invalid trust level: ${trustLevel}`);
          }

          try {
            const code = await generatePairingCode(name, trustLevel, expiryMs);
            return textResult(
              JSON.stringify({
                code: code.code,
                identityId: code.identityId,
                trustLevel: code.trustLevel,
                expiresAt: new Date(code.expiresAt).toISOString(),
                instruction: `User should run: !pair verify ${code.code}`,
              }),
            );
          } catch (err: unknown) {
            return textResult(`Error: ${(err as Error).message}`);
          }
        },
      },
      {
        name: "pairing.verifyCode",
        description: "Verify a pairing code and link a platform sender to the identity.",
        inputSchema: {
          type: "object",
          properties: {
            code: {
              type: "string",
              description: "The 6-character pairing code",
            },
            channelType: {
              type: "string",
              description: "Channel type (e.g., discord, telegram, slack)",
            },
            senderId: {
              type: "string",
              description: "Platform-specific sender ID",
            },
          },
          required: ["code", "channelType", "senderId"],
        },
        async handler(args: Record<string, unknown>): Promise<A2AToolResult> {
          const result = await verifyPairingCode(
            args.code as string,
            args.channelType as string,
            args.senderId as string,
          );
          if (!result) {
            return textResult("Error: Invalid or expired pairing code.");
          }
          return textResult(
            JSON.stringify({
              identity: result.identity.name,
              trustLevel: result.trustLevel,
              linkedChannels: result.identity.links.map((l) => l.channelType),
            }),
          );
        },
      },
      {
        name: "pairing.listIdentities",
        description: "List all paired identities with their linked platforms.",
        inputSchema: { type: "object", properties: {} },
        async handler(): Promise<A2AToolResult> {
          const identities = await listIdentities();
          return textResult(
            JSON.stringify({
              count: identities.length,
              identities: identities.map((id) => ({
                id: id.id,
                name: id.name,
                trustLevel: id.trustLevel,
                links: id.links.map((l) => ({
                  channelType: l.channelType,
                  senderId: l.senderId,
                })),
              })),
            }),
          );
        },
      },
      {
        name: "pairing.resolveTrust",
        description: "Resolve the trust level for a platform sender. Returns 'untrusted' if not paired.",
        inputSchema: {
          type: "object",
          properties: {
            channelType: {
              type: "string",
              description: "Channel type (e.g., discord, telegram)",
            },
            senderId: {
              type: "string",
              description: "Platform-specific sender ID",
            },
          },
          required: ["channelType", "senderId"],
        },
        async handler(args: Record<string, unknown>): Promise<A2AToolResult> {
          const trustLevel = await resolveTrustLevel(args.channelType as string, args.senderId as string);
          const identity = await findIdentityBySender(args.channelType as string, args.senderId as string);
          return textResult(
            JSON.stringify({
              trustLevel,
              identity: identity ? { id: identity.id, name: identity.name } : null,
            }),
          );
        },
      },
      {
        name: "pairing.removeIdentity",
        description: "Remove an identity and all its platform links.",
        inputSchema: {
          type: "object",
          properties: {
            name: { type: "string", description: "Identity name to remove" },
          },
          required: ["name"],
        },
        async handler(args: Record<string, unknown>): Promise<A2AToolResult> {
          const identity = await getIdentityByName(args.name as string);
          if (!identity) {
            return textResult(`Error: Identity not found: ${args.name}`);
          }
          await removeIdentity(identity.id);
          return textResult(`Removed identity "${args.name}" and all linked platforms.`);
        },
      },
      {
        name: "pairing.setTrust",
        description: "Update the trust level for an existing identity.",
        inputSchema: {
          type: "object",
          properties: {
            name: { type: "string", description: "Identity name" },
            trustLevel: {
              type: "string",
              enum: VALID_TRUST_LEVELS,
              description: "New trust level",
            },
          },
          required: ["name", "trustLevel"],
        },
        async handler(args: Record<string, unknown>): Promise<A2AToolResult> {
          const identity = await getIdentityByName(args.name as string);
          if (!identity) {
            return textResult(`Error: Identity not found: ${args.name}`);
          }
          const trustLevel = args.trustLevel as TrustLevel;
          if (!VALID_TRUST_LEVELS.includes(trustLevel)) {
            return textResult(`Error: Invalid trust level: ${trustLevel}`);
          }
          const updated = await setIdentityTrustLevel(identity.id, trustLevel);
          return textResult(
            JSON.stringify({
              name: updated.name,
              trustLevel: updated.trustLevel,
            }),
          );
        },
      },
      {
        name: "pairing.linkPlatform",
        description: "Manually link a platform sender to an existing identity (bypasses pairing code).",
        inputSchema: {
          type: "object",
          properties: {
            identityName: {
              type: "string",
              description: "Identity name to link to",
            },
            channelType: {
              type: "string",
              description: "Channel type (e.g., discord, telegram)",
            },
            senderId: {
              type: "string",
              description: "Platform-specific sender ID",
            },
          },
          required: ["identityName", "channelType", "senderId"],
        },
        async handler(args: Record<string, unknown>): Promise<A2AToolResult> {
          const identity = await getIdentityByName(args.identityName as string);
          if (!identity) {
            return textResult(`Error: Identity not found: ${args.identityName}`);
          }
          try {
            const updated = await linkPlatform(identity.id, args.channelType as string, args.senderId as string);
            return textResult(
              JSON.stringify({
                identity: updated.name,
                links: updated.links.map((l) => ({
                  channelType: l.channelType,
                  senderId: l.senderId,
                })),
              }),
            );
          } catch (err: unknown) {
            return textResult(`Error: ${(err as Error).message}`);
          }
        },
      },
      {
        name: "pairing.unlinkPlatform",
        description: "Unlink a platform from an identity.",
        inputSchema: {
          type: "object",
          properties: {
            identityName: { type: "string", description: "Identity name" },
            channelType: {
              type: "string",
              description: "Channel type to unlink",
            },
          },
          required: ["identityName", "channelType"],
        },
        async handler(args: Record<string, unknown>): Promise<A2AToolResult> {
          const identity = await getIdentityByName(args.identityName as string);
          if (!identity) {
            return textResult(`Error: Identity not found: ${args.identityName}`);
          }
          const removed = await unlinkPlatform(identity.id, args.channelType as string);
          if (!removed) {
            return textResult(`Error: No ${args.channelType} link found for "${args.identityName}"`);
          }
          return textResult(`Unlinked ${args.channelType} from "${args.identityName}"`);
        },
      },
      {
        name: "pairing.listCodes",
        description: "List all pending (non-expired) pairing codes.",
        inputSchema: { type: "object", properties: {} },
        async handler(): Promise<A2AToolResult> {
          const codes = await listPendingCodes();
          return textResult(
            JSON.stringify({
              count: codes.length,
              codes: codes.map((c) => ({
                code: c.code,
                trustLevel: c.trustLevel,
                expiresAt: new Date(c.expiresAt).toISOString(),
              })),
            }),
          );
        },
      },
      {
        name: "pairing.revokeCode",
        description: "Revoke a pending pairing code.",
        inputSchema: {
          type: "object",
          properties: {
            code: { type: "string", description: "The pairing code to revoke" },
          },
          required: ["code"],
        },
        async handler(args: Record<string, unknown>): Promise<A2AToolResult> {
          const revoked = await revokePairingCode(args.code as string);
          if (!revoked) {
            return textResult(`Error: Code not found: ${args.code}`);
          }
          return textResult(`Revoked pairing code: ${args.code}`);
        },
      },
    ],
  };
}
