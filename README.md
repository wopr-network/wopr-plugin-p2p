# WOPR P2P Management Plugin

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![WOPR](https://img.shields.io/badge/WOPR-Plugin-blue)](https://github.com/TSavo/wopr)

P2P network management plugin for [WOPR](https://github.com/TSavo/wopr). Provides UI for managing peers, invites, and access control.

> Part of the [WOPR](https://github.com/TSavo/wopr) ecosystem - Self-sovereign AI session management over P2P.

## Features

- **Peer Management**: View connected peers and their shared sessions
- **Invite Creation**: Generate invites for new peers with session access control
- **Invite Claiming**: Accept invites from other WOPR nodes
- **Access Control**: Revoke peer access to sessions
- **Web UI**: Settings panel integrated into WOPR's web interface

## Installation

```bash
wopr plugin install github:TSavo/wopr-plugin-p2p
wopr plugin enable p2p
```

## CLI Commands

```bash
# Show P2P network status
wopr p2p status

# Add a friend (creates invite)
wopr p2p friend add <peer-pubkey> [session...] [--token <token>]
```

## Web UI

The plugin adds a "P2P Network" section to the WOPR settings page where you can:
- View your identity (short ID and public key)
- See all connected peers
- Create invites for new peers
- Claim invites from other nodes
- Manage session sharing

## Configuration

The plugin stores configuration under `plugins.data.p2p`:

```json
{
  "uiPort": 7334
}
```

## Architecture

This plugin works alongside WOPR's core P2P functionality:
- Core provides the P2P networking layer (Hyperswarm, encryption, protocol)
- This plugin provides the management UI and convenience commands
- Uses the plugin context API to access identity and peers

## Security

This plugin implements several security hardening measures:

- **Auto-accept disabled**: Discovered peers must be explicitly granted access
- **Reduced key rotation grace**: 24 hours (reduced from 7 days)
- **Payload size limits**: 1MB max to prevent memory exhaustion
- **Rate limiting**: Per-peer limits to prevent abuse
- **Forward secrecy**: Ephemeral keys for each session

See [SECURITY.md](./SECURITY.md) for complete security documentation.

For WOPR's overall security model (trust levels, capabilities, sandboxing), see the [WOPR Security Documentation](https://github.com/TSavo/wopr/docs/SECURITY.md).

## License

MIT
