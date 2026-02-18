# wopr-plugin-p2p-storage

P2P networking plugin with distributed storage — adds shared storage layer on top of Hyperswarm.

## Commands

```bash
npm run build     # tsc
npm run check     # biome check + tsc --noEmit (run before committing)
npm run format    # biome format --write src/
npm test          # vitest run
```

## Architecture (additions over wopr-plugin-p2p)

```
src/
  schema.ts          # Shared data schema for distributed storage
  storage-wrapper.ts # Wraps Hypercore/Hyperbee for distributed key-value storage
  # ... all other files same as wopr-plugin-p2p
```

## Key Details

- Extends `wopr-plugin-p2p` with distributed key-value storage using Hyperbee
- `schema.ts` defines what gets stored and how — changes here are breaking if peers have old data
- `storage-wrapper.ts` provides a consistent API over the Hyperbee layer
- **Gotcha**: Schema changes require migration or version-gated reads. Never change schema without handling old data.
- See `wopr-plugin-p2p/CLAUDE.md` for the core P2P architecture

## Plugin Contract

Imports only from `@wopr-network/plugin-types`. Never import from `@wopr-network/wopr` core.

## Issue Tracking

All issues in **Linear** (team: WOPR). Issue descriptions start with `**Repo:** wopr-network/wopr-plugin-p2p-storage`.
