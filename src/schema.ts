/**
 * P2P Plugin Storage Schema
 *
 * Defines Zod schemas for all P2P data structures.
 * These are registered with ctx.storage.register() in the plugin init.
 */

// Placeholder for Zod schemas - will be used with ctx.storage.register()
// The actual Zod types will be inferred at runtime

// Export schema definitions ready for registration with ctx.storage.register()
export const p2pTableSchemas = {
  friends: null as any,     // Replace with actual Zod schema
  pendingRequests: null as any,
  autoAcceptRules: null as any,
  accessGrants: null as any,
  peers: null as any,
};
