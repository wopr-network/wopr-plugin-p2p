/**
 * Pairing storage schema - SQLite tables for identities and pairing codes
 */

import type { PluginSchema } from "@wopr-network/plugin-types";
import { z } from "zod";

const trustLevelEnum = z.enum([
	"owner",
	"trusted",
	"semi-trusted",
	"untrusted",
]);

// ---------- pairing_identities table ----------
export const pairingIdentitySchema = z.object({
	id: z.string(),
	name: z.string(),
	trustLevel: trustLevelEnum,
	links: z.string(), // JSON-serialized PlatformLink[]
	createdAt: z.number(),
	updatedAt: z.number(),
});
export type PairingIdentityRecord = z.infer<typeof pairingIdentitySchema>;

// ---------- pairing_codes table ----------
export const pairingCodeSchema = z.object({
	code: z.string(),
	identityId: z.string(),
	trustLevel: trustLevelEnum,
	createdAt: z.number(),
	expiresAt: z.number(),
});
export type PairingCodeRecord = z.infer<typeof pairingCodeSchema>;

// ---------- PluginSchema ----------
export const pairingPluginSchema: PluginSchema = {
	namespace: "pairing",
	version: 1,
	tables: {
		identities: {
			schema: pairingIdentitySchema,
			primaryKey: "id",
			indexes: [
				{ fields: ["name"], unique: true },
				{ fields: ["trustLevel"] },
				{ fields: ["createdAt"] },
			],
		},
		codes: {
			schema: pairingCodeSchema,
			primaryKey: "code",
			indexes: [{ fields: ["identityId"] }, { fields: ["expiresAt"] }],
		},
	},
};
