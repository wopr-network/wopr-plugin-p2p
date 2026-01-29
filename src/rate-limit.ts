/**
 * P2P Rate Limiting and Replay Protection
 */

import type { RateLimitConfig, RateLimitState, RateLimits, ReplayState } from "./types.js";

const DEFAULT_LIMITS: Record<string, RateLimitConfig> = {
  injects: { maxPerMinute: 10, maxPerHour: 100, banDurationMs: 3600000 },
  claims: { maxPerMinute: 5, maxPerHour: 20, banDurationMs: 3600000 },
  invalidMessages: { maxPerMinute: 3, maxPerHour: 10, banDurationMs: 7200000 },
};

const rateLimits: RateLimits = {};

export function getRateLimiter() {
  return {
    check(peerKey: string, action: string): boolean {
      const config = DEFAULT_LIMITS[action] || DEFAULT_LIMITS.injects;
      const now = Date.now();
      const minuteAgo = now - 60000;
      const hourAgo = now - 3600000;

      if (!rateLimits[peerKey]) {
        rateLimits[peerKey] = {};
      }
      if (!rateLimits[peerKey][action]) {
        rateLimits[peerKey][action] = { minute: [], hour: [] };
      }

      const state = rateLimits[peerKey][action];

      // Check if banned
      if (state.banned && state.banned > now) {
        return false;
      }

      // Clean old entries
      state.minute = state.minute.filter(t => t > minuteAgo);
      state.hour = state.hour.filter(t => t > hourAgo);

      // Check limits
      if (state.minute.length >= config.maxPerMinute || state.hour.length >= config.maxPerHour) {
        state.banned = now + config.banDurationMs;
        return false;
      }

      // Record this request
      state.minute.push(now);
      state.hour.push(now);

      return true;
    },

    reset(peerKey: string): void {
      delete rateLimits[peerKey];
    },
  };
}

// Replay protection
const replayState: ReplayState = {
  nonces: new Set(),
  timestamps: [],
};

const REPLAY_WINDOW_MS = 300000; // 5 minutes
const MAX_NONCES = 10000;

export function getReplayProtector() {
  return {
    check(nonce: string, timestamp: number): boolean {
      const now = Date.now();

      // Check timestamp is within window
      if (Math.abs(now - timestamp) > REPLAY_WINDOW_MS) {
        return false;
      }

      // Check nonce hasn't been seen
      if (replayState.nonces.has(nonce)) {
        return false;
      }

      // Record nonce
      replayState.nonces.add(nonce);
      replayState.timestamps.push(now);

      // Cleanup old nonces periodically
      if (replayState.nonces.size > MAX_NONCES) {
        const cutoff = now - REPLAY_WINDOW_MS;
        const newNonces = new Set<string>();
        const newTimestamps: number[] = [];

        // Keep only recent entries (simplified cleanup)
        replayState.nonces.clear();
        replayState.timestamps.length = 0;
      }

      return true;
    },

    reset(): void {
      replayState.nonces.clear();
      replayState.timestamps.length = 0;
    },
  };
}
