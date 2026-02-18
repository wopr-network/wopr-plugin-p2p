import { z } from "zod";

// ============================================
// Zod Schemas for each table
// ============================================

export const P2PIdentitySchema = z.object({
	id: z.string(), // Always "default" (single row)
	publicKey: z.string(),
	privateKey: z.string(),
	encryptPub: z.string(),
	encryptPriv: z.string(),
	created: z.number(),
	rotatedFrom: z.string().optional(),
	rotatedAt: z.number().optional(),
});

export const P2PPeerSchema = z.object({
	id: z.string(), // shortKey hash
	publicKey: z.string(),
	encryptPub: z.string().optional(),
	name: z.string().optional(),
	sessions: z.array(z.string()), // JSON array stored as TEXT
	caps: z.array(z.string()), // JSON array stored as TEXT
	added: z.number(),
	keyHistory: z
		.array(
			z.object({
				// JSON array stored as TEXT
				publicKey: z.string(),
				encryptPub: z.string(),
				validFrom: z.number(),
				validUntil: z.number().optional(),
				rotationReason: z.string().optional(),
			}),
		)
		.optional(),
});

export const P2PAccessGrantSchema = z.object({
	id: z.string(), // "grant-{timestamp}"
	peerKey: z.string(),
	peerName: z.string().optional(),
	peerEncryptPub: z.string().optional(),
	sessions: z.array(z.string()),
	caps: z.array(z.string()),
	created: z.number(),
	revoked: z.number().optional(), // SQLite stores boolean as 0/1, use number
	keyHistory: z
		.array(
			z.object({
				publicKey: z.string(),
				encryptPub: z.string(),
				validFrom: z.number(),
				validUntil: z.number().optional(),
				rotationReason: z.string().optional(),
			}),
		)
		.optional(),
});

export const P2PFriendSchema = z.object({
	id: z.string(), // Generated: shortKey(publicKey)
	name: z.string(),
	publicKey: z.string(),
	encryptPub: z.string(),
	sessionName: z.string(),
	addedAt: z.number(),
	caps: z.array(z.string()),
	channel: z.string(),
});

export const P2PPendingRequestSchema = z.object({
	id: z.string(), // Generated UUID or sig hash
	direction: z.string(), // "in" or "out"
	requestJson: z.string(), // Serialized FriendRequest JSON
	timestamp: z.number(), // receivedAt (in) or sentAt (out)
	channel: z.string(),
	channelId: z.string(),
});

export const P2PAutoAcceptSchema = z.object({
	id: z.string(), // The pattern itself (unique)
	pattern: z.string(),
	addedAt: z.number(),
});

// ============================================
// PluginSchema registration
// ============================================

export const p2pPluginSchema = {
	namespace: "p2p",
	version: 1,
	tables: {
		identity: {
			schema: P2PIdentitySchema,
			primaryKey: "id",
		},
		peers: {
			schema: P2PPeerSchema,
			primaryKey: "id",
			indexes: [{ fields: ["publicKey"], unique: true }],
		},
		access_grants: {
			schema: P2PAccessGrantSchema,
			primaryKey: "id",
			indexes: [{ fields: ["peerKey"] }, { fields: ["revoked"] }],
		},
		friends: {
			schema: P2PFriendSchema,
			primaryKey: "id",
			indexes: [{ fields: ["publicKey"], unique: true }, { fields: ["name"] }],
		},
		pending_requests: {
			schema: P2PPendingRequestSchema,
			primaryKey: "id",
			indexes: [{ fields: ["direction"] }],
		},
		auto_accept: {
			schema: P2PAutoAcceptSchema,
			primaryKey: "id",
			indexes: [{ fields: ["pattern"], unique: true }],
		},
	},
	// Migration callback for v0 -> v1 (reads JSON, inserts into SQL)
	// This is called by core's storage.register() when version changes
	// Not needed for initial install (no existing version), but useful for
	// upgrades. The actual migration logic is in migrateJsonToSql().
};

// Type aliases for repository records
export type P2PIdentityRow = z.infer<typeof P2PIdentitySchema>;
export type P2PPeerRow = z.infer<typeof P2PPeerSchema>;
export type P2PAccessGrantRow = z.infer<typeof P2PAccessGrantSchema>;
export type P2PFriendRow = z.infer<typeof P2PFriendSchema>;
export type P2PPendingRequestRow = z.infer<typeof P2PPendingRequestSchema>;
export type P2PAutoAcceptRow = z.infer<typeof P2PAutoAcceptSchema>;
