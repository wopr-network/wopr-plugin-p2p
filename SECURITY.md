# P2P Plugin Security

Security documentation for the WOPR P2P Plugin.

---

## Core Principle

**All P2P peers are sandboxed. No exceptions.**

Every message from a P2P peer runs in an isolated Docker container. There is no capability or trust level that bypasses sandboxing for P2P sources.

---

## Trust Model

All P2P sources are mapped to `untrusted` trust level:

```typescript
FRIEND_CAP_TO_TRUST_LEVEL = {
  message: "untrusted",
  inject: "untrusted",
};
```

The `trusted` and `owner` trust levels are reserved for local CLI/daemon only. P2P peers can never achieve these levels.

---

## Sandbox Isolation

When a P2P peer sends a message:

```
┌─────────────────┐     ┌─────────────────────────────────────┐
│  P2P Message    │────▶│  Docker Container                   │
│  from peer      │     │  ┌─────────────────────────────────┐│
└─────────────────┘     │  │ - No network access             ││
                        │  │ - No workspace access           ││
                        │  │ - Read-only filesystem          ││
                        │  │ - Resource limits (CPU, memory) ││
                        │  │ - Capability drop (ALL)         ││
                        │  │ - Seccomp filtering             ││
                        │  └─────────────────────────────────┘│
                        └─────────────────────────────────────┘
```

The sandbox is enforced by Docker with these security flags:
- `--network none` - No network access
- `--read-only` - Read-only root filesystem
- `--cap-drop ALL` - Drop all Linux capabilities
- `--pids-limit 100` - Limit process count
- `--memory 512m` - Memory limit
- `--cpus 0.5` - CPU limit

---

## Capabilities

P2P peers have exactly two possible capabilities:

| Capability | Description | Sandboxed? |
|------------|-------------|------------|
| `message` | Log to conversation, no AI response | Yes |
| `inject` | Send to AI and get response | Yes |

There are no other capabilities. The sandbox controls what the AI can do. Capabilities only control whether the peer can talk to the AI at all.

---

## Friend Protocol Security

### Cryptographic Identity

Each agent has:
- **Ed25519 signing keypair** - For message authentication
- **X25519 encryption keypair** - For key exchange and encryption

Keys are stored in `~/.wopr/p2p/identity.json` with mode `0600`.

### Friend Request Verification

Friend requests include a timestamp and signature:

```
FRIEND_REQUEST | to:target | from:sender | pubkey:... | encryptPub:... | ts:... | sig:...
```

Verification checks:
1. **Signature valid** - Ed25519 signature over all fields
2. **Timestamp fresh** - Within 5 minutes of receipt
3. **Target matches** - Request addressed to this agent

### Friend Accept Verification

Accepts reference the original request signature:

```
FRIEND_ACCEPT | to:requester | from:accepter | pubkey:... | encryptPub:... | requestSig:... | ts:... | sig:...
```

Verification checks:
1. **Signature valid** - Ed25519 signature over all fields
2. **Timestamp fresh** - Within 5 minutes
3. **requestSig matches** - Must match our pending outgoing request

### Session Isolation

Each friend gets their own dedicated session:
- Session name format: `friend:p2p:name(pubkey-prefix)`
- Friends can only access their own session
- No cross-session access between friends

---

## Key Rotation

Keys can be rotated with continuity proof:

```bash
# Via A2A tool
p2p_rotate_keys(reason: "scheduled" | "compromise" | "upgrade")
```

The rotation message is signed by the OLD key, proving:
- The same entity controls both keys
- Peers can update their records safely

Grace period: 24 hours (old key still accepted)

---

## Network Security

### End-to-End Encryption

All P2P messages are encrypted with AES-256-GCM:

```
┌─────────────────────────────────────────┐
│  Encrypted Payload Structure            │
├─────────────────────────────────────────┤
│  IV (12 bytes)                          │
│  Auth Tag (16 bytes)                    │
│  Encrypted Data (variable)              │
└─────────────────────────────────────────┘
```

### Forward Secrecy

Ephemeral X25519 keypairs are generated per session. If a long-term key is compromised, past messages remain secure.

### Signature Verification

All messages are signed with Ed25519. Invalid signatures are rejected.

---

## Rate Limiting

Per-peer limits prevent abuse:

| Operation | Limit | Purpose |
|-----------|-------|---------|
| Messages | 30/minute, 300/hour | Prevent flooding |
| Inject | 30/minute, 300/hour | Prevent AI abuse |
| Claims | 5/minute | Prevent invite brute-forcing |

Trust level affects limits:
- `untrusted` (all P2P): 30/min, 300/hour
- `trusted` (local only): 100/min, 1000/hour
- `owner` (local only): 1000/min, 10000/hour

---

## Size Limits

Protection against memory exhaustion:

| Limit | Value |
|-------|-------|
| Max payload | 1 MB |
| Max message | ~1 MB + 4 KB |

Messages exceeding limits are rejected before processing.

---

## Replay Protection

Messages include:
- **Nonce** - Random value (tracked to detect duplicates)
- **Timestamp** - Must be within 5 minutes of receipt

Stale or duplicate messages are rejected.

---

## Access Control

### Explicit Grants Required

Discovered peers are **not** automatically granted access. You must explicitly grant:

```bash
# Via slash command
/grant @peer inject

# Via A2A tool
p2p_grant_access(peerKey, sessions, caps)
```

### Auto-Accept Rules

Optional rules for automatic friend acceptance:

```bash
/auto-accept add "*"           # Accept all (use with caution)
/auto-accept add "trusted-bot" # Accept specific username
/auto-accept add "bot1|bot2"   # Accept multiple usernames
/auto-accept remove "*"        # Remove rule
```

Even auto-accepted friends start with `message` capability only.

---

## Attack Mitigations

| Attack | Mitigation |
|--------|------------|
| Command injection | **Sandbox** - commands run in Docker |
| File system access | **Sandbox** - no workspace access |
| Network exfiltration | **Sandbox** - no network |
| Message flooding | Rate limiting |
| Payload bombs | Size limits |
| Replay attacks | Nonce tracking + timestamp window |
| Key compromise | Forward secrecy + key rotation |
| Session hijacking | Signature verification |
| MITM | E2E encryption |
| Unauthorized access | Explicit grants only |
| Spoofed friend requests | Ed25519 signature verification |
| Recursive inject loops | Session tracking blocks p2p_inject during P2P inject |

---

## Data Protection

| File | Permissions | Contents |
|------|-------------|----------|
| `identity.json` | 0600 | Private keys |
| `friends.json` | 0600 | Friend list, pending requests |
| `peers.json` | 0600 | Known peers |
| `access.json` | 0600 | Access grants |

All files are created with restricted permissions (owner read/write only).

---

## What P2P Peers CANNOT Do

- Execute commands on your host
- Read your files
- Access your network
- Access other sessions
- Bypass sandboxing
- Escalate privileges
- Achieve `trusted` or `owner` status
- Modify their granted capabilities
- Access other friends' sessions

---

## What P2P Peers CAN Do

- Send messages to their dedicated session
- Get AI responses (running in sandbox)
- That's it

---

## Security Configuration

WOPR security integration creates these entries:

```json
{
  "sessions": {
    "friend:p2p:alice(abc123)": {
      "access": ["p2p:PUBKEY..."],
      "capabilities": ["inject"],
      "indexable": ["self"],
      "description": "Dedicated session for friend @alice"
    }
  },
  "sources": {
    "p2p:PUBKEY...": {
      "type": "p2p",
      "trust": "untrusted",
      "capabilities": ["inject"],
      "sessions": ["friend:p2p:alice(abc123)"],
      "rateLimit": {
        "perMinute": 30,
        "perHour": 300
      }
    }
  }
}
```

---

## Reporting Security Issues

If you discover a security vulnerability:

1. **Do not** create a public GitHub issue
2. Email security concerns to the maintainers
3. Include steps to reproduce
4. Allow reasonable time for a fix before disclosure
