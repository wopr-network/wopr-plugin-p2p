declare module 'hyperswarm' {
  import { EventEmitter } from 'events';
  import { Duplex } from 'stream';

  interface PeerInfo {
    publicKey?: Buffer;
    topics?: Buffer[];
    client?: boolean;
    server?: boolean;
    ban?: (permanent?: boolean) => void;
  }

  interface SwarmOptions {
    seed?: Buffer;
    maxPeers?: number;
    firewall?: (remotePublicKey: Buffer) => boolean;
  }

  interface JoinOptions {
    server?: boolean;
    client?: boolean;
  }

  class Hyperswarm extends EventEmitter {
    constructor(opts?: SwarmOptions);

    connections: Set<Duplex>;
    peers: Map<string, PeerInfo>;

    join(topic: Buffer, opts?: JoinOptions): void;
    leave(topic: Buffer): Promise<void>;
    destroy(): Promise<void>;

    on(event: 'connection', listener: (socket: Duplex, peerInfo: PeerInfo) => void): this;
    on(event: 'update', listener: () => void): this;
    on(event: 'close', listener: () => void): this;
  }

  export = Hyperswarm;
}
