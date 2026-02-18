/**
 * Cross-Channel DM Pairing - Unified Identity System
 *
 * Links platform-specific sender IDs (Discord user ID, Telegram user ID, etc.)
 * to a single WOPR identity. Users pair via a short-lived pairing code that
 * can be generated from any channel and verified from any other channel.
 *
 * Flow:
 * 1. Owner generates a pairing code for a user: `!pair generate <name> [trustLevel]`
 * 2. User sends the code from any channel: `!pair verify <code>`
 * 3. System links that channel's sender ID to the WOPR identity
 * 4. Trust level is applied consistently across all linked channels
 */

import { randomBytes } from "node:crypto";
import type { PluginLogger } from "@wopr-network/plugin-types";
import { getPairingStore } from "./pairing-store.js";
import type { PairingCode, TrustLevel, WoprIdentity } from "./pairing-types.js";

// Re-export initPairing for plugin startup
export { initPairing } from "./pairing-store.js";

// ============================================================================
// Module-level logger (set during plugin init)
// ============================================================================

let log: PluginLogger | null = null;

export function setPairingLogger(logger: PluginLogger): void {
	log = logger;
}

// ============================================================================
// Constants
// ============================================================================

const PAIRING_CODE_LENGTH = 6;
const PAIRING_CODE_EXPIRY_MS = 15 * 60 * 1000; // 15 minutes
const PAIRING_CODE_CHARSET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // No 0/O/1/I confusion

// ============================================================================
// Pairing Code Generation
// ============================================================================

/**
 * Generate a cryptographically random pairing code using rejection sampling
 * to eliminate modulo bias.
 */
function generateCode(): string {
	const charsetLen = PAIRING_CODE_CHARSET.length;
	const limit = 256 - (256 % charsetLen);
	let code = "";
	while (code.length < PAIRING_CODE_LENGTH) {
		const bytes = randomBytes(PAIRING_CODE_LENGTH - code.length);
		for (const byte of bytes) {
			if (byte < limit && code.length < PAIRING_CODE_LENGTH) {
				code += PAIRING_CODE_CHARSET[byte % charsetLen];
			}
		}
	}
	return code;
}

/**
 * Generate a unique identity ID
 */
function generateId(): string {
	return randomBytes(16).toString("hex");
}

// ============================================================================
// Identity Management
// ============================================================================

/**
 * Create a new WOPR identity
 */
export async function createIdentity(
	name: string,
	trustLevel: TrustLevel = "semi-trusted",
): Promise<WoprIdentity> {
	const store = getPairingStore();

	const existing = await store.getIdentityByName(name);
	if (existing) {
		throw new Error(`Identity with name "${name}" already exists`);
	}

	const identity: WoprIdentity = {
		id: generateId(),
		name,
		trustLevel,
		links: [],
		createdAt: Date.now(),
		updatedAt: Date.now(),
	};

	await store.createIdentity(identity);

	log?.info(`[pairing] Created identity: ${name} (trust: ${trustLevel})`);
	return identity;
}

/**
 * Get an identity by ID
 */
export async function getIdentity(id: string): Promise<WoprIdentity | null> {
	const store = getPairingStore();
	return store.getIdentity(id);
}

/**
 * Get an identity by name
 */
export async function getIdentityByName(
	name: string,
): Promise<WoprIdentity | null> {
	const store = getPairingStore();
	return store.getIdentityByName(name);
}

/**
 * Find the identity linked to a specific platform sender
 */
export async function findIdentityBySender(
	channelType: string,
	senderId: string,
): Promise<WoprIdentity | null> {
	const store = getPairingStore();
	return store.findIdentityBySender(channelType, senderId);
}

/**
 * Get all identities
 */
export async function listIdentities(): Promise<WoprIdentity[]> {
	const store = getPairingStore();
	return store.listIdentities();
}

/**
 * Update an identity's trust level
 */
export async function setIdentityTrustLevel(
	id: string,
	trustLevel: TrustLevel,
): Promise<WoprIdentity> {
	const store = getPairingStore();
	const identity = await store.getIdentity(id);
	if (!identity) {
		throw new Error(`Identity not found: ${id}`);
	}

	const updated = await store.updateIdentity(id, { trustLevel });

	log?.info(`[pairing] Updated trust level for ${updated.name}: ${trustLevel}`);
	return updated;
}

/**
 * Remove an identity and all its links
 */
export async function removeIdentity(id: string): Promise<boolean> {
	const store = getPairingStore();
	const identity = await store.getIdentity(id);
	if (!identity) return false;

	await store.removeIdentity(id);
	log?.info(`[pairing] Removed identity: ${identity.name}`);
	return true;
}

// ============================================================================
// Platform Linking
// ============================================================================

/**
 * Link a platform sender to an identity
 */
export async function linkPlatform(
	identityId: string,
	channelType: string,
	senderId: string,
): Promise<WoprIdentity> {
	const store = getPairingStore();
	const identity = await store.getIdentity(identityId);
	if (!identity) {
		throw new Error(`Identity not found: ${identityId}`);
	}

	const existing = await store.findIdentityBySender(channelType, senderId);
	if (existing && existing.id !== identityId) {
		throw new Error(
			`Sender ${channelType}:${senderId} is already linked to identity "${existing.name}"`,
		);
	}

	const existingLink = identity.links.find(
		(l) => l.channelType === channelType,
	);
	const updatedLinks = [...identity.links];

	if (existingLink) {
		const idx = updatedLinks.findIndex((l) => l.channelType === channelType);
		updatedLinks[idx] = { channelType, senderId, linkedAt: Date.now() };
	} else {
		updatedLinks.push({ channelType, senderId, linkedAt: Date.now() });
	}

	const updated = await store.updateIdentity(identityId, {
		links: updatedLinks,
	});

	log?.info(
		`[pairing] Linked ${channelType}:${senderId} to identity ${updated.name}`,
	);
	return updated;
}

/**
 * Unlink a platform from an identity
 */
export async function unlinkPlatform(
	identityId: string,
	channelType: string,
): Promise<boolean> {
	const store = getPairingStore();
	const identity = await store.getIdentity(identityId);
	if (!identity) return false;

	const idx = identity.links.findIndex((l) => l.channelType === channelType);
	if (idx === -1) return false;

	const updatedLinks = identity.links.filter(
		(l) => l.channelType !== channelType,
	);
	await store.updateIdentity(identityId, { links: updatedLinks });

	log?.info(`[pairing] Unlinked ${channelType} from identity ${identity.name}`);
	return true;
}

// ============================================================================
// Pairing Code Flow
// ============================================================================

/**
 * Generate a pairing code for an identity.
 * If the identity does not exist yet, creates it.
 */
export async function generatePairingCode(
	name: string,
	trustLevel: TrustLevel = "semi-trusted",
	expiryMs: number = PAIRING_CODE_EXPIRY_MS,
): Promise<PairingCode> {
	const store = getPairingStore();

	let identity = await store.getIdentityByName(name);
	if (!identity) {
		identity = {
			id: generateId(),
			name,
			trustLevel,
			links: [],
			createdAt: Date.now(),
			updatedAt: Date.now(),
		};
		await store.createIdentity(identity);
	}

	await store.deleteCodesByIdentityId(identity.id);

	const code: PairingCode = {
		code: generateCode(),
		identityId: identity.id,
		trustLevel,
		createdAt: Date.now(),
		expiresAt: Date.now() + expiryMs,
	};

	await store.createCode(code);

	log?.info(
		`[pairing] Generated pairing code for ${name} (expires in ${expiryMs / 1000}s)`,
	);
	return code;
}

/**
 * Verify a pairing code and link the sender to the identity.
 * Returns the identity on success, or null if the code is invalid/expired.
 */
export async function verifyPairingCode(
	code: string,
	channelType: string,
	senderId: string,
): Promise<{ identity: WoprIdentity; trustLevel: TrustLevel } | null> {
	const store = getPairingStore();

	await store.cleanExpiredCodes();

	const codeUpper = code.toUpperCase();
	const pairingCode = await store.getCode(codeUpper);
	if (!pairingCode) {
		return null;
	}

	const identity = await store.getIdentity(pairingCode.identityId);
	if (!identity) {
		await store.revokeCode(codeUpper);
		return null;
	}

	const existingIdentity = await store.findIdentityBySender(
		channelType,
		senderId,
	);
	if (existingIdentity && existingIdentity.id !== identity.id) {
		log?.warn(
			`[pairing] Sender ${channelType}:${senderId} already linked to "${existingIdentity.name}", cannot pair to "${identity.name}"`,
		);
		return null;
	}

	const existingLink = identity.links.find(
		(l) => l.channelType === channelType,
	);
	const updatedLinks = [...identity.links];

	if (existingLink) {
		const idx = updatedLinks.findIndex((l) => l.channelType === channelType);
		updatedLinks[idx] = { channelType, senderId, linkedAt: Date.now() };
	} else {
		updatedLinks.push({ channelType, senderId, linkedAt: Date.now() });
	}

	const updated = await store.updateIdentity(identity.id, {
		trustLevel: pairingCode.trustLevel,
		links: updatedLinks,
	});

	await store.revokeCode(codeUpper);

	log?.info(
		`[pairing] Verified pairing code: ${channelType}:${senderId} -> ${updated.name} (${pairingCode.trustLevel})`,
	);
	return { identity: updated, trustLevel: pairingCode.trustLevel };
}

/**
 * Get all pending pairing codes (for admin listing)
 */
export async function listPendingCodes(): Promise<PairingCode[]> {
	const store = getPairingStore();
	return store.listPendingCodes();
}

/**
 * Revoke a pending pairing code
 */
export async function revokePairingCode(code: string): Promise<boolean> {
	const store = getPairingStore();
	return store.revokeCode(code.toUpperCase());
}

// ============================================================================
// Trust Level Resolution
// ============================================================================

/**
 * Resolve the trust level for a sender on a given channel.
 * Returns the trust level from their paired identity, or "untrusted" if not paired.
 */
export async function resolveTrustLevel(
	channelType: string,
	senderId: string,
): Promise<TrustLevel> {
	const identity = await findIdentityBySender(channelType, senderId);
	return identity?.trustLevel ?? "untrusted";
}

// ============================================================================
// Exports for testing
// ============================================================================

export const _testing = {
	PAIRING_CODE_LENGTH,
	PAIRING_CODE_EXPIRY_MS,
	PAIRING_CODE_CHARSET,
	generateCode,
	generateId,
};
