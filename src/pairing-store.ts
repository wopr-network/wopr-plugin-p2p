/**
 * Pairing store - SQL-based storage for identities and pairing codes.
 *
 * Uses the WOPR plugin StorageApi for persistence.
 */

import type { Repository, StorageApi } from "@wopr-network/plugin-types";
import type {
	PairingCodeRecord,
	PairingIdentityRecord,
} from "./pairing-schema.js";
import { pairingPluginSchema } from "./pairing-schema.js";
import type {
	PairingCode,
	PlatformLink,
	TrustLevel,
	WoprIdentity,
} from "./pairing-types.js";

let identitiesRepo: Repository<PairingIdentityRecord> | null = null;
let codesRepo: Repository<PairingCodeRecord> | null = null;

/**
 * Pairing store - CRUD operations for identities and codes
 */
export class PairingStore {
	constructor(
		private readonly identities: Repository<PairingIdentityRecord>,
		private readonly codes: Repository<PairingCodeRecord>,
	) {}

	// ==================== Identity Operations ====================

	async createIdentity(identity: WoprIdentity): Promise<WoprIdentity> {
		const record: PairingIdentityRecord = {
			id: identity.id,
			name: identity.name,
			trustLevel: identity.trustLevel,
			links: JSON.stringify(identity.links),
			createdAt: identity.createdAt,
			updatedAt: identity.updatedAt,
		};
		const saved = await this.identities.insert(record);
		return this.recordToIdentity(saved);
	}

	async getIdentity(id: string): Promise<WoprIdentity | null> {
		const record = await this.identities.findById(id);
		return record ? this.recordToIdentity(record) : null;
	}

	async getIdentityByName(name: string): Promise<WoprIdentity | null> {
		const record = await this.identities.findFirst({ name });
		return record ? this.recordToIdentity(record) : null;
	}

	/**
	 * Find identity by platform sender using raw SQL with json_each()
	 */
	async findIdentityBySender(
		channelType: string,
		senderId: string,
	): Promise<WoprIdentity | null> {
		const sql = `
      SELECT i.*
      FROM pairing_identities i,
           json_each(i.links) AS link
      WHERE json_extract(link.value, '$.channelType') = ?
        AND json_extract(link.value, '$.senderId') = ?
      LIMIT 1
    `;
		const results = await this.identities.raw(sql, [channelType, senderId]);
		if (results.length === 0) return null;
		return this.recordToIdentity(results[0] as PairingIdentityRecord);
	}

	async listIdentities(): Promise<WoprIdentity[]> {
		const records = await this.identities.findMany();
		return records.map((r) => this.recordToIdentity(r));
	}

	async updateIdentity(
		id: string,
		updates: Partial<WoprIdentity>,
	): Promise<WoprIdentity> {
		const record: Partial<PairingIdentityRecord> = {
			updatedAt: Date.now(),
		};
		if (updates.name !== undefined) record.name = updates.name;
		if (updates.trustLevel !== undefined)
			record.trustLevel = updates.trustLevel;
		if (updates.links !== undefined)
			record.links = JSON.stringify(updates.links);

		const updated = await this.identities.update(id, record);
		return this.recordToIdentity(updated);
	}

	async removeIdentity(id: string): Promise<boolean> {
		await this.codes.deleteMany({ identityId: id });
		return this.identities.delete(id);
	}

	// ==================== Pairing Code Operations ====================

	async createCode(code: PairingCode): Promise<PairingCode> {
		const record: PairingCodeRecord = {
			code: code.code,
			identityId: code.identityId,
			trustLevel: code.trustLevel,
			createdAt: code.createdAt,
			expiresAt: code.expiresAt,
		};
		await this.codes.insert(record);
		return code;
	}

	async getCode(code: string): Promise<PairingCode | null> {
		const record = await this.codes.findById(code);
		return record ? this.recordToCode(record) : null;
	}

	async listPendingCodes(): Promise<PairingCode[]> {
		const now = Date.now();
		const records = await this.codes.findMany({ expiresAt: { $gt: now } });
		return records.map((r) => this.recordToCode(r));
	}

	async revokeCode(code: string): Promise<boolean> {
		return this.codes.delete(code);
	}

	async deleteCodesByIdentityId(identityId: string): Promise<number> {
		return this.codes.deleteMany({ identityId });
	}

	async cleanExpiredCodes(): Promise<number> {
		const now = Date.now();
		return this.codes.deleteMany({ expiresAt: { $lte: now } });
	}

	// ==================== Helpers ====================

	private recordToIdentity(record: PairingIdentityRecord): WoprIdentity {
		return {
			id: record.id,
			name: record.name,
			trustLevel: record.trustLevel as TrustLevel,
			links: JSON.parse(record.links) as PlatformLink[],
			createdAt: record.createdAt,
			updatedAt: record.updatedAt,
		};
	}

	private recordToCode(record: PairingCodeRecord): PairingCode {
		return {
			code: record.code,
			identityId: record.identityId,
			trustLevel: record.trustLevel as TrustLevel,
			createdAt: record.createdAt,
			expiresAt: record.expiresAt,
		};
	}
}

/**
 * Initialize the pairing storage schema.
 * Called during plugin init.
 */
export async function initPairing(storage: StorageApi): Promise<void> {
	await storage.register(pairingPluginSchema);
	identitiesRepo = storage.getRepository<PairingIdentityRecord>(
		"pairing",
		"identities",
	);
	codesRepo = storage.getRepository<PairingCodeRecord>("pairing", "codes");
}

/**
 * Get a PairingStore instance. Must call initPairing() first.
 */
export function getPairingStore(): PairingStore {
	if (!identitiesRepo || !codesRepo) {
		throw new Error(
			"Pairing storage not initialized - call initPairing() first",
		);
	}
	return new PairingStore(identitiesRepo, codesRepo);
}

/**
 * Reset initialization state (for testing)
 */
export function resetPairingStoreState(): void {
	identitiesRepo = null;
	codesRepo = null;
}
