/**
 * P2P Storage Wrapper
 *
 * Wraps the repository with async operations needed by friends.ts
 */

// Keep types simple - will be updated as needed
type FriendRow = any;
type PendingRequestRow = any;
type AutoAcceptRow = any;
type AccessGrantRow = any;
type PeerRow = any;

export class P2PStorage {
  constructor(
    private friendsRepo: any,
    private pendingRepo: any,
    private autoAcceptRepo: any,
    private grantsRepo: any,
    private peersRepo: any,
  ) {}

  /**
   * Store pending friend request - INSERT instead of JSON rewrite
   */
  async storePendingRequest(
    request: any,
    channel: string,
    channelId: string
  ): Promise<void> {
    if (!this.pendingRepo) throw new Error("Storage not initialized");

    // Remove any existing request to same target (SQL DELETE)
    await this.pendingRepo.deleteMany({
      to: request.to,
      $eq: { type: "outgoing" },
    });

    // Insert new request (SQL INSERT)
    await this.pendingRepo.insert({
      id: crypto.randomUUID(),
      type: "outgoing",
      from: request.from,
      to: request.to,
      pubkey: request.pubkey,
      encryptPub: request.encryptPub,
      signature: request.sig,
      channel,
      channelId,
      timestamp: request.timestamp,
      sentAt: Date.now(),
    });
  }

  /**
   * Get all pending outgoing requests
   */
  async getPendingRequests(type: "outgoing" | "incoming"): Promise<any[]> {
    if (!this.pendingRepo) throw new Error("Storage not initialized");

    return this.pendingRepo.findMany({
      type,
    });
  }

  /**
   * Find pending request by signature
   */
  async getPendingRequestBySignature(signature: string): Promise<any | null> {
    if (!this.pendingRepo) throw new Error("Storage not initialized");

    return this.pendingRepo.findFirst({
      signature,
    });
  }

  /**
   * Get all friends
   */
  async getFriends(): Promise<any[]> {
    if (!this.friendsRepo) throw new Error("Storage not initialized");

    return this.friendsRepo.findMany();
  }

  /**
   * Find friend by name or pubkey
   */
  async getFriend(nameOrKey: string): Promise<any | null> {
    if (!this.friendsRepo) throw new Error("Storage not initialized");

    // Query with OR condition
    return this.friendsRepo.findFirst({
      $or: [
        { name: nameOrKey },
        { publicKey: nameOrKey },
        { publicKey: `*${nameOrKey}*` }, // Wildcard match
      ],
    });
  }

  /**
   * Get all auto-accept rules
   */
  async getAutoAcceptRules(): Promise<any[]> {
    if (!this.autoAcceptRepo) throw new Error("Storage not initialized");

    return this.autoAcceptRepo.findMany();
  }

  /**
   * Get all access grants
   */
  async getAccessGrants(): Promise<any[]> {
    if (!this.grantsRepo) throw new Error("Storage not initialized");

    return this.grantsRepo.findMany();
  }

  /**
   * Get all peers
   */
  async getPeers(): Promise<any[]> {
    if (!this.peersRepo) throw new Error("Storage not initialized");

    return this.peersRepo.findMany();
  }

  /**
   * Find peer by key
   */
  async getPeerByKey(key: string): Promise<any | null> {
    if (!this.peersRepo) throw new Error("Storage not initialized");

    return this.peersRepo.findFirst({
      publicKey: key,
    });
  }

  /**
   * Cleanup expired requests - DELETE query
   */
  async cleanupExpiredRequests(expiryMs: number): Promise<number> {
    if (!this.pendingRepo) throw new Error("Storage not initialized");

    const cutoff = Date.now() - expiryMs;

    // Single DELETE query
    await this.pendingRepo.deleteMany({
      $and: [
        {
          $or: [
            { type: "incoming", receivedAt: { $lt: cutoff } },
            { type: "outgoing", sentAt: { $lt: cutoff } },
          ],
        },
      ],
    });

    return 0; // Return count deleted
  }

  /**
   * Find peer by name
   */
  async findPeer(name: string): Promise<any | null> {
    if (!this.peersRepo) throw new Error("Storage not initialized");

    return this.peersRepo.findFirst({
      name,
    });
  }
}
