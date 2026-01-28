# WOPR P2P Management Plugin

P2P network management plugin for WOPR. Provides UI for managing peers, invites, and access control.

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

## License

MIT
