/**
 * Pairing plugin types.
 */

/**
 * Trust level hierarchy (highest to lowest).
 * Matches WOPR core security/types.ts TrustLevel.
 */
export type TrustLevel = "owner" | "trusted" | "semi-trusted" | "untrusted";

/**
 * A platform-specific identity link (e.g., Discord user ID, Telegram user ID)
 */
export interface PlatformLink {
	/** Channel type (e.g., "discord", "telegram", "slack") */
	channelType: string;
	/** Platform-specific sender ID */
	senderId: string;
	/** When this link was created */
	linkedAt: number;
}

/**
 * A unified WOPR identity that can span multiple channels
 */
export interface WoprIdentity {
	/** Unique identity ID */
	id: string;
	/** Human-readable name */
	name: string;
	/** Trust level for this identity */
	trustLevel: TrustLevel;
	/** Platform links - one per channel type */
	links: PlatformLink[];
	/** When this identity was created */
	createdAt: number;
	/** When this identity was last updated */
	updatedAt: number;
}

/**
 * A pending pairing code waiting to be verified
 */
export interface PairingCode {
	/** The short code (e.g., "A1B2C3") */
	code: string;
	/** Identity ID this code pairs to */
	identityId: string;
	/** Trust level to assign on successful pairing */
	trustLevel: TrustLevel;
	/** When this code was created */
	createdAt: number;
	/** When this code expires */
	expiresAt: number;
}
