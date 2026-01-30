# P2P Plugin Security

Security documentation for the WOPR P2P Plugin.

---

## Overview

The P2P plugin implements several security measures to protect against malicious peers and network attacks. This document describes the security architecture and hardening measures.

---

## Security Hardening Measures

### 1. Auto-Accept Disabled by Default

**Previous behavior (DANGEROUS):**
```typescript
// Automatically granted wildcard access to discovered peers
return {
  accept: true,
  sessions: ["*"],  // ALL sessions!
};
```

**Current behavior (Secure):**
```typescript
// Discovery peers are NOT automatically granted access
return {
  accept: false,
  sessions: [],
  reason: "Discovery auto-accept disabled for security. Use p2p_grant to authorize peer.",
};
```

Discovered peers must be explicitly granted access using:
- CLI: `wopr p2p grant <peer-key> <sessions>`
- A2A: `p2p_grant` tool

### 2. Reduced Key Rotation Grace Period

**Previous**: 7 days
**Current**: 24 hours

When a peer rotates their keys, the old key is valid for a grace period to allow in-flight messages to complete. A shorter grace period reduces the window for key compromise attacks.

```typescript
gracePeriodMs: 24 * 3600000  // 24 hours (was 7 days)
```

### 3. Payload Size Limits

Protection against memory exhaustion and DoS attacks.

| Limit | Value | Description |
|-------|-------|-------------|
| `MAX_PAYLOAD_SIZE` | 1 MB | Maximum encrypted payload in inject messages |
| `MAX_MESSAGE_SIZE` | ~1 MB + 4 KB | Maximum raw P2P message (payload + protocol overhead) |

Messages exceeding these limits are rejected before processing:

```typescript
// Rejected at message parsing level
if (line.length > MAX_MESSAGE_SIZE) {
  onLog(`Rejected: message too large (${line.length} > ${MAX_MESSAGE_SIZE})`);
  return;
}

// Rejected at inject handler level
if (payloadSize > MAX_PAYLOAD_SIZE) {
  onLog(`Rejected: payload too large from ${shortKey(msg.from)}`);
  // Send reject message to peer
  return;
}
```

### 4. Rate Limiting

Per-peer rate limits prevent abuse:

| Operation | Default Limit | Purpose |
|-----------|---------------|---------|
| Injects | 60/minute | Prevent message flooding |
| Handshakes | 10/minute | Prevent connection spam |
| Claims | 5/minute | Prevent invite brute-forcing |

Rate limits are checked before processing:

```typescript
if (!rateLimiter.check(msg.from, "injects")) {
  // Send rate limit rejection
  return;
}
```

### 5. Replay Protection

Messages include nonces and timestamps to prevent replay attacks:

```typescript
interface P2PMessage {
  nonce: string;    // Random 16-byte hex
  ts: number;       // Timestamp
  // ...
}
```

The replay protector tracks seen nonces and rejects duplicates:

```typescript
if (!replayProtector.check(msg.nonce, msg.ts)) {
  // Reject replayed message
  return;
}
```

### 6. Forward Secrecy

Protocol v2 uses ephemeral X25519 keypairs for each session:

```typescript
// Session-specific ephemeral key
const ephemeral = generateEphemeralKeyPair(ttlMs);

// Derived shared secret
const secret = deriveEphemeralSecret(ephemeralPriv, theirEphemeralPub);
```

If a long-term key is compromised, past encrypted messages remain secure.

---

## Trust Integration

The P2P plugin integrates with WOPR's security model:

### Trust Levels for P2P Sources

| Peer Type | Default Trust Level |
|-----------|---------------------|
| Discovered (auto-discovery) | `untrusted` |
| Claimed (via invite token) | Per grant configuration |
| Explicitly granted | Per grant configuration |

### Gateway Routing

Untrusted P2P peers cannot directly inject into privileged sessions. They must go through a gateway session:

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Untrusted      │────▶│    Gateway      │────▶│   Privileged    │
│  P2P Peer       │     │    Session      │     │   Session       │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

See [WOPR Security Documentation](https://github.com/TSavo/wopr/docs/GATEWAY.md) for gateway configuration.

---

## Access Control

### Granting Access

```bash
# Grant access to specific sessions
wopr p2p grant <peer-pubkey> session1 session2

# Grant with trust level
wopr p2p grant <peer-pubkey> session1 --trust trusted

# Grant with capabilities
wopr p2p grant <peer-pubkey> session1 --capabilities "inject,inject.tools"
```

### Revoking Access

```bash
# Revoke all access
wopr p2p revoke <peer-pubkey>

# Revoke access to specific session
wopr p2p revoke <peer-pubkey> --session mySession
```

### Listing Grants

```bash
# List all access grants
wopr p2p grants

# List grants for specific peer
wopr p2p grants --peer <peer-pubkey>
```

---

## Cryptographic Security

### Key Generation

| Key Type | Algorithm | Purpose |
|----------|-----------|---------|
| Identity | Ed25519 | Signing messages |
| Encryption | X25519 | Key exchange |
| Ephemeral | X25519 | Forward secrecy |

### Message Encryption

All inject payloads are encrypted with AES-256-GCM:

```
┌─────────────────────────────────────────┐
│  Encrypted Payload Structure            │
├─────────────────────────────────────────┤
│  IV (12 bytes)                          │
│  Auth Tag (16 bytes)                    │
│  Encrypted Data (variable)              │
└─────────────────────────────────────────┘
```

### Signature Verification

All messages are signed with Ed25519:

```typescript
// Sender signs message
const signed = signMessage(msg);  // Adds 'sig' field

// Receiver verifies signature
if (!verifySignature(msg, msg.from)) {
  // Reject invalid signature
}
```

---

## Configuration

### Security-Related Settings

```json
{
  "p2p": {
    "discoveryTrust": "untrusted",
    "autoAccept": false,
    "keyRotationGraceHours": 24,
    "maxPayloadSize": 1048576,
    "rateLimit": {
      "injects": { "perMinute": 60 },
      "handshakes": { "perMinute": 10 },
      "claims": { "perMinute": 5 }
    }
  }
}
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `WOPR_P2P_AUTO_ACCEPT` | Auto-accept discovered peers | `false` |
| `WOPR_P2P_DISCOVERY_TRUST` | Trust level for discovery | `untrusted` |
| `WOPR_P2P_MAX_PAYLOAD` | Max payload size (bytes) | `1048576` |

---

## Attack Mitigations

| Attack | Mitigation |
|--------|------------|
| Message flooding | Rate limiting (60/min) |
| Payload bombs | Size limits (1MB max) |
| Replay attacks | Nonce/timestamp tracking |
| Key compromise | Forward secrecy, 24h grace period |
| Session hijacking | Signature verification |
| Man-in-the-middle | E2E encryption, key verification |
| Unauthorized access | Explicit grants, no auto-accept |

---

## Security Events

The plugin emits security-related events:

| Event | Description |
|-------|-------------|
| `p2p.peer.rejected` | Peer connection rejected |
| `p2p.message.rejected` | Message rejected (rate limit, size, etc.) |
| `p2p.grant.created` | Access grant created |
| `p2p.grant.revoked` | Access grant revoked |
| `p2p.key.rotated` | Peer key rotation processed |

Subscribe to events for monitoring:

```typescript
events.on("p2p.message.rejected", (event) => {
  console.log(`Rejected from ${event.peer}: ${event.reason}`);
});
```

---

## Reporting Security Issues

If you discover a security vulnerability, please report it responsibly:

1. **Do not** create a public GitHub issue
2. Email security concerns to the maintainers
3. Include steps to reproduce
4. Allow reasonable time for a fix before disclosure

---

## Related Documentation

- [WOPR Security Model](https://github.com/TSavo/wopr/docs/SECURITY.md)
- [WOPR Threat Model](https://github.com/TSavo/wopr/docs/THREAT_MODEL.md)
- [Gateway Sessions](https://github.com/TSavo/wopr/docs/GATEWAY.md)
- [P2P Protocol](https://github.com/TSavo/wopr/docs/PROTOCOL.md)
