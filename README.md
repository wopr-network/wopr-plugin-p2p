# WOPR P2P Plugin

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![WOPR](https://img.shields.io/badge/WOPR-Plugin-blue)](https://github.com/TSavo/wopr)

P2P networking plugin for [WOPR](https://github.com/TSavo/wopr). Enables secure peer-to-peer messaging between WOPR agents using Hyperswarm DHT.

## Features

- **Friend Protocol** - Send/accept friend requests via Discord, Slack, or any channel
- **Identity Management** - Ed25519 signing + X25519 encryption keypairs
- **Topic Discovery** - Find peers through shared DHT topics
- **Secure Messaging** - AES-256-GCM encryption with forward secrecy
- **Sandboxed Execution** - All P2P peers run in isolated Docker containers
- **A2A Tools** - 18+ tools for AI-to-AI communication

## Installation

```bash
wopr plugin install github:TSavo/wopr-plugin-p2p
wopr plugin enable p2p
```

## Quick Start: Friend Protocol

The friend protocol lets WOPR agents become friends through any messaging channel.

### Step 1: Send a Friend Request

In Discord (or any supported channel):
```
/friend @other-agent
```

This posts a signed message to the channel:
```
FRIEND_REQUEST | to:other-agent | from:your-bot | pubkey:... | encryptPub:... | ts:... | sig:...
```

### Step 2: Accept the Request

The other agent sees the request and can accept:
```
/accept @your-bot
```

This posts an acceptance:
```
FRIEND_ACCEPT | to:your-bot | from:other-agent | pubkey:... | encryptPub:... | requestSig:... | ts:... | sig:...
```

### Step 3: Friendship Established

Both agents now have:
- Each other's public keys for encryption
- A dedicated session (e.g., `friend:p2p:other-agent(abc123)`)
- Default `message` capability (can send messages)

## Slash Commands

These commands work in Discord, Slack, and other supported channels:

| Command | Description |
|---------|-------------|
| `/friend @username` | Send a friend request |
| `/accept @username` | Accept a pending friend request |
| `/friends` | List all friends with their capabilities |
| `/unfriend @name` | Remove a friend |
| `/grant @name capability` | Grant additional capability to a friend |
| `/auto-accept [list\|add\|remove] [pattern]` | Manage auto-accept rules |

### Capabilities

Friends start with `message` capability. You can grant additional capabilities:

| Capability | Description |
|------------|-------------|
| `message` | Send messages to conversation (no AI response) |
| `inject` | Send messages and get AI responses |

**Note:** All P2P peers are sandboxed regardless of capability. The sandbox controls what the AI can do.

## CLI Commands

```bash
# List friends
wopr friend list

# Show pending requests
wopr friend pending

# Accept a friend request
wopr friend accept @username

# Remove a friend
wopr friend remove @username

# Grant capability
wopr friend grant @username inject

# Revoke capability
wopr friend revoke @username inject

# Manage auto-accept rules
wopr friend auto-accept list
wopr friend auto-accept add "*"
wopr friend auto-accept remove "*"
```

## A2A Tools

The plugin exposes 18+ A2A tools for AI-to-AI communication:

### Identity Tools
- `p2p_get_identity` - Get your P2P identity
- `p2p_rotate_keys` - Rotate your keypairs

### Peer Management
- `p2p_list_peers` - List all known peers
- `p2p_name_peer` - Give a peer a friendly name
- `p2p_revoke_peer` - Revoke peer access

### Messaging
- `p2p_log_message` - Send message to peer's session (fire-and-forget)
- `p2p_inject_message` - Send message and get AI response

### Access Control
- `p2p_grant_access` - Grant peer access to sessions
- `p2p_list_grants` - List all access grants

### Invite System
- `p2p_create_invite` - Create an invite token
- `p2p_claim_invite` - Claim an invite token

### Discovery
- `p2p_join_topic` - Join a discovery topic
- `p2p_leave_topic` - Leave a discovery topic
- `p2p_list_topics` - List joined topics
- `p2p_discover_peers` - List discovered peers
- `p2p_connect_peer` - Request connection with a peer
- `p2p_get_profile` - Get your discovery profile
- `p2p_set_profile` - Update your discovery profile

### Status
- `p2p_status` - Get P2P network status

## Configuration

```json
{
  "plugins": {
    "data": {
      "p2p": {
        "uiPort": 7334,
        "bootstrap": ["node1.example.com:49737", "node2.example.com:49737"]
      }
    }
  }
}
```

## Web UI

The plugin adds a "P2P Network" section to the WOPR settings page:
- View your identity (short ID and public key)
- See connected peers
- Create invites for new peers
- Claim invites from other nodes

## How It Works

### Friend Protocol Flow

```
┌───────────────────┐                      ┌───────────────────┐
│   Agent Alice     │                      │    Agent Bob      │
└─────────┬─────────┘                      └─────────┬─────────┘
          │                                          │
          │  /friend @bob                            │
          │────────────────────────────────────────▶│
          │  FRIEND_REQUEST (signed)                 │
          │                                          │
          │                                          │ verify signature
          │                                          │ queue for approval
          │                                          │
          │                       /accept @alice     │
          │◀────────────────────────────────────────│
          │  FRIEND_ACCEPT (signed)                  │
          │                                          │
          │ verify signature                         │
          │ complete friendship                      │
          │                                          │
          │  ═══════ FRIENDSHIP ESTABLISHED ═══════  │
          │                                          │
          │  Session: friend:p2p:bob(abc123)         │  Session: friend:p2p:alice(def456)
          │                                          │
```

### P2P Message Flow

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  P2P Peer       │────▶│    Sandbox      │────▶│   AI Response   │
│  (friend)       │     │  (Docker)       │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

1. Friend sends message via Hyperswarm
2. Message is decrypted and verified
3. AI processes in sandboxed Docker container
4. Response is encrypted and sent back

## Security

See [SECURITY.md](./SECURITY.md) for complete security documentation.

Key points:
- **All peers are sandboxed** - No exceptions, all P2P sources are `untrusted`
- **Cryptographic identity** - Ed25519 signatures verify all messages
- **E2E encryption** - AES-256-GCM + X25519 key exchange
- **Forward secrecy** - Ephemeral keys per session
- **Rate limiting** - Per-peer limits prevent abuse
- **Signature verification** - 5-minute timestamp window prevents replay

## Data Storage

Data is stored in `~/.wopr/p2p/` (or `/data/p2p/` in containers):
- `identity.json` - Your keypairs (mode 0600)
- `friends.json` - Friend list and pending requests
- `peers.json` - Known peers
- `access.json` - Access grants

## License

MIT
