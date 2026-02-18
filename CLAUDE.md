# wopr-plugin-p2p

P2P networking plugin for WOPR — bot-to-bot communication via Hyperswarm DHT with identity management and A2A tools.

## Commands

```bash
npm run build     # tsc
npm run check     # biome check + tsc --noEmit (run before committing)
npm run format    # biome format --write src/
npm test          # vitest run
```

## Architecture

```
src/
  index.ts              # Plugin entry
  p2p.ts                # Core Hyperswarm connection management
  identity.ts           # Cryptographic identity (keypair generation, signing)
  discovery.ts          # Peer discovery via DHT
  friends.ts            # Trusted peer list (allowlist)
  trust.ts              # Trust level management
  rate-limit.ts         # Per-peer rate limiting
  security-integration.ts  # Integration with WOPR security layer
  channel-hooks.ts      # Channel-level hooks for P2P message routing
  cli-commands.ts       # CLI commands (pair, unpair, list-peers)
  config.ts             # Plugin config schema
  hyperswarm.d.ts       # Type declarations for Hyperswarm (no official types)
  types.ts              # Plugin-local types
```

## Key Details

- **Framework**: Hyperswarm (`hyperswarm` npm package) — NAT-traversing P2P networking
- Each WOPR instance has a cryptographic identity (Ed25519 keypair) managed by `identity.ts`
- Peers must be mutually added to friends list before communication (`friends.ts`)
- `trust.ts` manages trust levels — affects what A2A tools peers can invoke
- `rate-limit.ts` prevents peer abuse — always respected, do not bypass
- **Gotcha**: Hyperswarm has no TypeScript types — `hyperswarm.d.ts` is a hand-written declaration file. Keep it updated when the Hyperswarm API changes.
- **Gotcha**: DHT bootstrap nodes must be reachable for peer discovery. Offline = no discovery.

## Plugin Contract

Imports only from `@wopr-network/plugin-types`. Never import from `@wopr-network/wopr` core.

## Issue Tracking

All issues in **Linear** (team: WOPR). Issue descriptions start with `**Repo:** wopr-network/wopr-plugin-p2p`.
