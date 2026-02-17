import { existsSync, readFileSync, renameSync } from "fs";
import { homedir } from "os";
import { join } from "path";
import type { StorageApi } from "./types.js";
import { shortKey } from "./identity.js";
import type {
  P2PIdentityRow,
  P2PPeerRow,
  P2PAccessGrantRow,
  P2PFriendRow,
  P2PPendingRequestRow,
  P2PAutoAcceptRow,
} from "./storage-schema.js";

// Resolve data directory (same logic as trust.ts/friends.ts)
function getDataDir(): string {
  return existsSync("/data") ? "/data/p2p" : join(homedir(), ".wopr", "p2p");
}

/**
 * Migrate all JSON files to SQL via the Storage API.
 * Called once during plugin init when storage is available but tables are empty.
 */
export async function migrateJsonToSql(storage: StorageApi, log: (msg: string) => void): Promise<void> {
  const dataDir = getDataDir();
  let migrated = 0;

  // 1. Migrate identity.json
  const identityFile = join(dataDir, "identity.json");
  if (existsSync(identityFile)) {
    try {
      const identity = JSON.parse(readFileSync(identityFile, "utf-8"));
      const repo = storage.getRepository<P2PIdentityRow>("p2p", "identity");
      const existing = await repo.findById("default");
      if (!existing) {
        await repo.insert({
          id: "default",
          publicKey: identity.publicKey,
          privateKey: identity.privateKey,
          encryptPub: identity.encryptPub,
          encryptPriv: identity.encryptPriv,
          created: identity.created,
          rotatedFrom: identity.rotatedFrom,
          rotatedAt: identity.rotatedAt,
        });
        log(`Migrated identity.json`);
        migrated++;
      }
      renameSync(identityFile, identityFile + ".backup");
    } catch (err) {
      log(`Failed to migrate identity.json: ${err}`);
    }
  }

  // 2. Migrate peers.json
  const peersFile = join(dataDir, "peers.json");
  if (existsSync(peersFile)) {
    try {
      const peers = JSON.parse(readFileSync(peersFile, "utf-8")) as any[];
      const repo = storage.getRepository<P2PPeerRow>("p2p", "peers");
      for (const peer of peers) {
        const existing = await repo.findFirst({ publicKey: peer.publicKey });
        if (!existing) {
          await repo.insert({
            id: peer.id,
            publicKey: peer.publicKey,
            encryptPub: peer.encryptPub,
            name: peer.name,
            sessions: peer.sessions,
            caps: peer.caps,
            added: peer.added,
            keyHistory: peer.keyHistory,
          });
        }
      }
      log(`Migrated ${peers.length} peers from peers.json`);
      migrated++;
      renameSync(peersFile, peersFile + ".backup");
    } catch (err) {
      log(`Failed to migrate peers.json: ${err}`);
    }
  }

  // 3. Migrate access.json
  const accessFile = join(dataDir, "access.json");
  if (existsSync(accessFile)) {
    try {
      const grants = JSON.parse(readFileSync(accessFile, "utf-8")) as any[];
      const repo = storage.getRepository<P2PAccessGrantRow>("p2p", "access_grants");
      for (const grant of grants) {
        const existing = await repo.findById(grant.id);
        if (!existing) {
          await repo.insert({
            id: grant.id,
            peerKey: grant.peerKey,
            peerName: grant.peerName,
            peerEncryptPub: grant.peerEncryptPub,
            sessions: grant.sessions,
            caps: grant.caps,
            created: grant.created,
            revoked: grant.revoked ? 1 : undefined,
            keyHistory: grant.keyHistory,
          });
        }
      }
      log(`Migrated ${grants.length} access grants from access.json`);
      migrated++;
      renameSync(accessFile, accessFile + ".backup");
    } catch (err) {
      log(`Failed to migrate access.json: ${err}`);
    }
  }

  // 4. Migrate friends.json (4 arrays -> 3 tables)
  const friendsFile = join(dataDir, "friends.json");
  if (existsSync(friendsFile)) {
    try {
      const state = JSON.parse(readFileSync(friendsFile, "utf-8"));

      // 4a. Friends
      const friendsRepo = storage.getRepository<P2PFriendRow>("p2p", "friends");
      for (const friend of (state.friends || [])) {
        const existing = await friendsRepo.findFirst({ publicKey: friend.publicKey });
        if (!existing) {
          await friendsRepo.insert({
            id: shortKey(friend.publicKey),
            name: friend.name,
            publicKey: friend.publicKey,
            encryptPub: friend.encryptPub,
            sessionName: friend.sessionName,
            addedAt: friend.addedAt,
            caps: friend.caps,
            channel: friend.channel,
          });
        }
      }

      // 4b. Pending requests (incoming + outgoing merged into one table)
      const pendingRepo = storage.getRepository<P2PPendingRequestRow>("p2p", "pending_requests");
      for (const pending of (state.pendingIn || [])) {
        await pendingRepo.insert({
          id: `in-${pending.request.sig.slice(0, 16)}`,
          direction: "in",
          requestJson: JSON.stringify(pending.request),
          timestamp: pending.receivedAt,
          channel: pending.channel,
          channelId: pending.channelId,
        });
      }
      for (const pending of (state.pendingOut || [])) {
        await pendingRepo.insert({
          id: `out-${pending.request.sig.slice(0, 16)}`,
          direction: "out",
          requestJson: JSON.stringify(pending.request),
          timestamp: pending.sentAt,
          channel: pending.channel,
          channelId: pending.channelId,
        });
      }

      // 4c. Auto-accept rules
      const autoAcceptRepo = storage.getRepository<P2PAutoAcceptRow>("p2p", "auto_accept");
      for (const rule of (state.autoAccept || [])) {
        const existing = await autoAcceptRepo.findFirst({ pattern: rule.pattern });
        if (!existing) {
          await autoAcceptRepo.insert({
            id: rule.pattern,
            pattern: rule.pattern,
            addedAt: rule.addedAt,
          });
        }
      }

      const total = (state.friends?.length || 0) + (state.pendingIn?.length || 0) +
        (state.pendingOut?.length || 0) + (state.autoAccept?.length || 0);
      log(`Migrated ${total} records from friends.json`);
      migrated++;
      renameSync(friendsFile, friendsFile + ".backup");
    } catch (err) {
      log(`Failed to migrate friends.json: ${err}`);
    }
  }

  if (migrated > 0) {
    log(`Migration complete: ${migrated} JSON files migrated to SQL`);
  } else {
    log(`No JSON files to migrate (fresh install or already migrated)`);
  }
}
