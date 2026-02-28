/**
 * Unit tests for the P2P Discovery module (WOP-100)
 *
 * Tests peer discovery state management, topic handling, profile updates,
 * and grant notifications. Mocks Hyperswarm for isolation.
 */

import { describe, it, expect } from "vitest";

// We need to mock identity and trust before importing discovery.
// Since node:test doesn't have vi.mock, we test the pure state functions
// by manipulating module state through the exported API.

// Import the discovery module functions
import {
  getDiscoveredPeers,
  getProfile,
  getTopics,
  notifyGrantUpdate,
  shutdownDiscovery,
  updateProfile,
} from "../src/discovery.js";

describe("Discovery Module - State Management", () => {
  // The discovery module maintains module-level state (maps, profile).
  // Without calling initDiscovery (which requires identity + Hyperswarm),
  // we test the state accessors in their default/uninitialized state.

  describe("getTopics", () => {
    it("should return empty array when no topics joined", () => {
      const topics = getTopics();
      expect(topics).toEqual([]);
    });
  });

  describe("getDiscoveredPeers", () => {
    it("should return empty array when no peers discovered", () => {
      const peers = getDiscoveredPeers();
      expect(peers).toEqual([]);
    });

    it("should accept an optional topic filter parameter", () => {
      const peers = getDiscoveredPeers("nonexistent-topic");
      expect(Array.isArray(peers)).toBeTruthy();
      expect(peers.length).toBe(0);
    });
  });

  describe("getProfile", () => {
    it("should return null when discovery not initialized", () => {
      const profile = getProfile();
      // Will be null if initDiscovery hasn't been called (or after shutdown)
      // This is the expected uninitialized state
      expect(profile).toBe(null);
    });
  });

  describe("updateProfile", () => {
    it("should return null when no profile exists (not initialized)", () => {
      const result = updateProfile({ key: "value" });
      expect(result).toBe(null);
    });
  });

  describe("notifyGrantUpdate", () => {
    it("should return false when no socket exists for the peer", () => {
      const result = notifyGrantUpdate("nonexistent-peer-key", ["session1"]);
      expect(result).toBe(false);
    });
  });

  describe("shutdownDiscovery", () => {
    it("should be safe to call when not initialized", async () => {
      // Should not throw
      await shutdownDiscovery();
    });

    it("should be safe to call multiple times", async () => {
      await shutdownDiscovery();
      await shutdownDiscovery();
    });

    it("should clear all state after shutdown", async () => {
      await shutdownDiscovery();

      expect(getProfile()).toBe(null);
      expect(getTopics()).toEqual([]);
      expect(getDiscoveredPeers()).toEqual([]);
    });
  });
});

describe("Discovery Module - Topic Operations (without init)", () => {
  // joinTopic and leaveTopic require discoverySwarm to be initialized.
  // We test the error paths here.

  it("joinTopic should throw when not initialized", async () => {
    const { joinTopic } = await import("../src/discovery.js");

    await expect(() => joinTopic("test-topic")).rejects.toThrow("Discovery not initialized");
  });

  it("leaveTopic should not throw when not initialized", async () => {
    const { leaveTopic } = await import("../src/discovery.js");

    // leaveTopic returns early if swarm is null - no error
    await leaveTopic("test-topic");
  });
});

describe("Discovery Module - requestConnection (without init)", () => {
  it("should return offline result when not initialized", async () => {
    const { requestConnection } = await import("../src/discovery.js");
    const { EXIT_PEER_OFFLINE } = await import("../src/types.js");

    const result = await requestConnection("some-peer-id");
    expect(result.accept).toBe(false);
    expect(result.code).toBe(EXIT_PEER_OFFLINE);
    expect(result.message?.includes("not initialized")).toBeTruthy();
  });
});
