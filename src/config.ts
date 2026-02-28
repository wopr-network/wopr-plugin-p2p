/**
 * P2P Configuration Module
 *
 * Holds global configuration for Hyperswarm bootstrap nodes and other settings.
 * This allows all Hyperswarm instances to use the same bootstrap configuration.
 */

export interface P2PConfig {
  /** Bootstrap nodes for DHT discovery (e.g., ["172.24.0.1:49737"]) */
  bootstrap?: string[];
  /** Connection timeout in milliseconds */
  connectionTimeout?: number;
}

// Global config store
let globalConfig: P2PConfig = {};

/**
 * Set the global P2P configuration
 */
export function setP2PConfig(config: P2PConfig): void {
  globalConfig = { ...globalConfig, ...config };
}

/**
 * Get the current P2P configuration
 */
export function getP2PConfig(): P2PConfig {
  return globalConfig;
}

/**
 * Get Hyperswarm options with bootstrap configured
 * Note: Hyperswarm accepts bootstrap in opts but the TypeScript types don't include it,
 * so we cast to `any` to work around this limitation.
 */
export function getSwarmOptions(): Record<string, unknown> {
  if (globalConfig.bootstrap && globalConfig.bootstrap.length > 0) {
    return { bootstrap: globalConfig.bootstrap };
  }
  return {};
}
