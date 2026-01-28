/**
 * WOPR P2P Management Plugin
 *
 * Provides UI for managing P2P peers, invites, and access control.
 * Works alongside the core P2P functionality.
 */

import http from "http";
import { createReadStream } from "fs";
import { extname, join } from "path";

let ctx = null;
let uiServer = null;

// Content types for UI server
const CONTENT_TYPES = {
  ".js": "application/javascript",
  ".css": "text/css",
  ".html": "text/html",
};

// Start HTTP server to serve UI component
function startUIServer(port = 7334) {
  const server = http.createServer((req, res) => {
    const url = req.url === "/" ? "/ui.js" : req.url;
    const filePath = join(ctx.getPluginDir(), url);
    const ext = extname(filePath).toLowerCase();
    
    res.setHeader("Content-Type", CONTENT_TYPES[ext] || "application/octet-stream");
    res.setHeader("Access-Control-Allow-Origin", "*");
    
    try {
      const stream = createReadStream(filePath);
      stream.pipe(res);
      stream.on("error", () => {
        res.statusCode = 404;
        res.end("Not found");
      });
    } catch (err) {
      res.statusCode = 500;
      res.end("Error");
    }
  });
  
  server.listen(port, "127.0.0.1", () => {
    ctx.log.info(`P2P UI available at http://127.0.0.1:${port}`);
  });
  
  return server;
}

export default {
  name: "p2p",
  version: "0.1.0",
  description: "P2P network management for WOPR",

  commands: [
    {
      name: "status",
      description: "Show P2P network status",
      usage: "wopr p2p status",
      async handler(context) {
        const identity = context.getIdentity();
        const peers = context.getPeers();
        
        console.log("P2P Network Status");
        console.log("==================");
        console.log(`Identity: ${identity.shortId}`);
        console.log(`Public Key: ${identity.publicKey.slice(0, 16)}...`);
        console.log(`Peers: ${peers.length}`);
        
        if (peers.length > 0) {
          console.log("\nConnected Peers:");
          peers.forEach(peer => {
            console.log(`  - ${peer.name || peer.id.slice(0, 16)}... (${peer.sessions.length} sessions)`);
          });
        }
      },
    },
    {
      name: "friend",
      description: "Manage P2P friends",
      usage: "wopr p2p friend add <pubkey> [session...] [--token <token>]",
      async handler(context, args) {
        if (args[0] === "add" && args[1]) {
          const peerPubkey = args[1];
          console.log(`Creating invite for ${peerPubkey.slice(0, 16)}...`);
          // The daemon handles the actual invite creation via API
        } else {
          console.log("Usage: wopr p2p friend add <pubkey> [session...] [--token <token>]");
        }
      },
    },
  ],

  async init(pluginContext) {
    ctx = pluginContext;
    const config = ctx.getConfig();
    const uiPort = config.uiPort || 7334;
    
    // Start UI server
    uiServer = startUIServer(uiPort);
    
    // Register UI component
    if (ctx.registerUiComponent) {
      ctx.registerUiComponent({
        id: "p2p-panel",
        title: "P2P Network",
        moduleUrl: `http://127.0.0.1:${uiPort}/ui.js`,
        slot: "settings",
        description: "Manage P2P peers and invites",
      });
      ctx.log.info("Registered P2P UI component in WOPR settings");
    }
    
    // Also register as external link
    if (ctx.registerWebUiExtension) {
      ctx.registerWebUiExtension({
        id: "p2p",
        title: "P2P Network",
        url: `http://127.0.0.1:${uiPort}`,
        description: "P2P peer management",
        category: "network",
      });
    }
    
    ctx.log.info("P2P management plugin initialized");
  },

  async shutdown() {
    if (uiServer) {
      ctx?.log.info("P2P UI server shutting down...");
      await new Promise((resolve) => uiServer.close(resolve));
      uiServer = null;
    }
  },
};
