/**
 * P2P Core Networking
 *
 * Handles Hyperswarm connections, message passing, and protocol handshakes.
 */

import { randomBytes } from "crypto";
import Hyperswarm from "hyperswarm";
import type { Duplex } from "stream";
import { getSwarmOptions } from "./config.js";
import {
	decryptMessage,
	decryptWithEphemeral,
	encryptMessage,
	encryptWithEphemeral,
	generateEphemeralKeyPair,
	getIdentity,
	getTopic,
	parseInviteToken,
	shortKey,
	signMessage,
	verifySignature,
} from "./identity.js";
import { getRateLimiter, getReplayProtector } from "./rate-limit.js";
import {
	addPeer,
	findPeer,
	getGrantForPeer,
	grantAccess,
	isAuthorized,
	processPeerKeyRotation,
} from "./trust.js";
import type {
	ClaimResult,
	EphemeralKeyPair,
	KeyRotation,
	P2PMessage,
	SendResult,
} from "./types.js";
import {
	EXIT_INVALID,
	EXIT_OFFLINE,
	EXIT_OK,
	EXIT_RATE_LIMITED,
	EXIT_REJECTED,
	EXIT_VERSION_MISMATCH,
	MIN_PROTOCOL_VERSION,
	PROTOCOL_VERSION,
} from "./types.js";

// Security limits
const MAX_PAYLOAD_SIZE = 1024 * 1024; // 1MB max payload size
const MAX_MESSAGE_SIZE = MAX_PAYLOAD_SIZE + 4096; // Payload + protocol overhead

// Module-level logger for debugging
let moduleLogger: ((msg: string) => void) | null = null;

export function setP2PLogger(logger: (msg: string) => void): void {
	moduleLogger = logger;
}

function log(msg: string): void {
	if (moduleLogger) {
		moduleLogger(msg);
	}
}

// Session state for forward secrecy
interface SessionState {
	ephemeral: EphemeralKeyPair;
	peerEphemeralPub?: string;
	negotiatedVersion?: number;
}

/**
 * Perform version handshake with peer.
 */
async function performHandshake(
	socket: Duplex,
	myPubKey: string,
	ephemeral: EphemeralKeyPair,
): Promise<{ version: number; peerEphemeralPub: string }> {
	return new Promise((resolve, reject) => {
		const timeout = setTimeout(() => {
			reject(new Error("Handshake timeout"));
		}, 5000);

		const hello = signMessage<Omit<P2PMessage, "sig">>({
			v: PROTOCOL_VERSION,
			type: "hello",
			from: myPubKey,
			versions: [PROTOCOL_VERSION, MIN_PROTOCOL_VERSION],
			ephemeralPub: ephemeral.publicKey,
			nonce: randomBytes(16).toString("hex"),
			ts: Date.now(),
		});
		socket.write(JSON.stringify(hello) + "\n");

		let buffer = "";
		const onData = (data: Buffer) => {
			buffer += data.toString();
			if (!buffer.includes("\n")) return;

			const line = buffer.split("\n")[0];
			buffer = buffer.slice(line.length + 1);

			try {
				const msg: P2PMessage = JSON.parse(line);

				if (msg.type === "hello-ack" && msg.version !== undefined) {
					clearTimeout(timeout);
					socket.removeListener("data", onData);

					if (msg.version < MIN_PROTOCOL_VERSION) {
						reject(new Error(`Version ${msg.version} not supported`));
						return;
					}

					resolve({
						version: msg.version,
						peerEphemeralPub: msg.ephemeralPub || "",
					});
				} else if (msg.type === "hello") {
					const commonVersions = (msg.versions || [PROTOCOL_VERSION]).filter(
						(v) => v >= MIN_PROTOCOL_VERSION && v <= PROTOCOL_VERSION,
					);

					if (commonVersions.length === 0) {
						clearTimeout(timeout);
						reject(new Error("No common protocol version"));
						return;
					}

					const negotiatedVersion = Math.max(...commonVersions);

					const ack = signMessage<Omit<P2PMessage, "sig">>({
						v: PROTOCOL_VERSION,
						type: "hello-ack",
						from: myPubKey,
						version: negotiatedVersion,
						ephemeralPub: ephemeral.publicKey,
						nonce: randomBytes(16).toString("hex"),
						ts: Date.now(),
					});
					socket.write(JSON.stringify(ack) + "\n");

					clearTimeout(timeout);
					socket.removeListener("data", onData);
					resolve({
						version: negotiatedVersion,
						peerEphemeralPub: msg.ephemeralPub || "",
					});
				}
			} catch {
				// Continue buffering
			}
		};

		socket.on("data", onData);
		socket.on("error", () => {
			clearTimeout(timeout);
			reject(new Error("Socket error during handshake"));
		});
	});
}

/**
 * Log a message to a peer's session (mailbox style).
 * Message is stored in their session history. Does NOT invoke their AI.
 */
export async function sendP2PLog(
	peerIdOrName: string,
	session: string,
	message: string,
	timeoutMs = 10000,
): Promise<SendResult> {
	const identity = getIdentity();
	if (!identity) {
		return { code: EXIT_INVALID, message: "No identity" };
	}

	const peer = findPeer(peerIdOrName);
	if (!peer) {
		return { code: EXIT_INVALID, message: `Peer not found: ${peerIdOrName}` };
	}

	if (!peer.sessions.includes("*") && !peer.sessions.includes(session)) {
		return {
			code: EXIT_REJECTED,
			message: `No access to session "${session}"`,
		};
	}

	if (!peer.encryptPub) {
		return {
			code: EXIT_INVALID,
			message: "Peer has no encryption key (claim token first)",
		};
	}

	const topic = getTopic(peer.publicKey);
	const swarm = new Hyperswarm(getSwarmOptions());
	const ephemeral = generateEphemeralKeyPair();

	// Handle swarm errors to prevent crashes
	(swarm as any).on("error", (err: Error) => {
		log(`[sendP2PLog] Swarm error: ${err.message}`);
	});

	return new Promise<SendResult>((resolve) => {
		let resolved = false;
		const cleanup = async () => {
			if (!resolved) {
				resolved = true;
				await swarm.destroy();
			}
		};

		const timeout = setTimeout(async () => {
			if (!resolved) {
				await cleanup();
				resolve({ code: EXIT_OFFLINE, message: "Peer offline (timeout)" });
			}
		}, timeoutMs);

		swarm.on("connection", async (socket: Duplex) => {
			if (resolved) return;

			try {
				const { version, peerEphemeralPub } = await performHandshake(
					socket,
					identity.publicKey,
					ephemeral,
				);

				clearTimeout(timeout);

				let encryptedPayload: string;
				let useEphemeral = false;

				if (version >= 2 && peerEphemeralPub) {
					encryptedPayload = encryptWithEphemeral(
						message,
						ephemeral.privateKey,
						peerEphemeralPub,
					);
					useEphemeral = true;
				} else {
					encryptedPayload = encryptMessage(message, peer.encryptPub!);
				}

				// Send "log" type - mailbox style, no AI invocation
				const msg = signMessage<Omit<P2PMessage, "sig">>({
					v: version,
					type: "log",
					from: identity.publicKey,
					encryptPub: identity.encryptPub,
					ephemeralPub: useEphemeral ? ephemeral.publicKey : undefined,
					session,
					payload: encryptedPayload,
					nonce: randomBytes(16).toString("hex"),
					ts: Date.now(),
				});

				socket.write(JSON.stringify(msg) + "\n");

				let buffer = "";
				socket.on("data", async (data: Buffer) => {
					buffer += data.toString();
					if (buffer.includes("\n")) {
						const line = buffer.split("\n")[0];
						try {
							const response: P2PMessage = JSON.parse(line);
							if (response.type === "ack") {
								await cleanup();
								resolve({ code: EXIT_OK });
							} else if (response.type === "reject") {
								await cleanup();
								const code =
									response.reason === "rate limited"
										? EXIT_RATE_LIMITED
										: EXIT_REJECTED;
								resolve({ code, message: response.reason || "unauthorized" });
							}
						} catch {
							await cleanup();
							resolve({ code: EXIT_INVALID, message: "Invalid response" });
						}
					}
				});

				socket.on("error", async () => {
					if (!resolved) {
						await cleanup();
						resolve({ code: EXIT_OFFLINE, message: "Connection error" });
					}
				});
			} catch (err) {
				clearTimeout(timeout);
				await cleanup();
				if (err instanceof Error && err.message.includes("version")) {
					resolve({ code: EXIT_VERSION_MISMATCH, message: err.message });
				} else {
					resolve({ code: EXIT_OFFLINE, message: `Handshake failed: ${err}` });
				}
			}
		});

		swarm.join(topic, { server: false, client: true });
	});
}

/**
 * Inject a message into a peer's session and get the AI's response.
 * This invokes the peer's AI which processes the message and returns a response.
 */
export async function sendP2PInject(
	peerIdOrName: string,
	session: string,
	message: string,
	timeoutMs = 60000, // Longer timeout for AI processing
): Promise<SendResult> {
	// Enforce minimum timeout for AI processing - 30s minimum
	const effectiveTimeout = Math.max(timeoutMs, 300000); // 5 minute minimum for AI
	if (timeoutMs < 30000) {
		log(
			`[sendP2PInject] Warning: timeout ${timeoutMs}ms too short for AI, using ${effectiveTimeout}ms`,
		);
	}

	log(
		`[sendP2PInject] Starting inject to ${peerIdOrName} session ${session} (timeout: ${effectiveTimeout}ms)`,
	);

	const identity = getIdentity();
	if (!identity) {
		log(`[sendP2PInject] No identity`);
		return { code: EXIT_INVALID, message: "No identity" };
	}

	const peer = findPeer(peerIdOrName);
	if (!peer) {
		log(`[sendP2PInject] Peer not found: ${peerIdOrName}`);
		return { code: EXIT_INVALID, message: `Peer not found: ${peerIdOrName}` };
	}

	if (!peer.sessions.includes("*") && !peer.sessions.includes(session)) {
		log(`[sendP2PInject] No access to session ${session}`);
		return {
			code: EXIT_REJECTED,
			message: `No access to session "${session}"`,
		};
	}

	if (!peer.encryptPub) {
		log(`[sendP2PInject] Peer has no encryption key`);
		return {
			code: EXIT_INVALID,
			message: "Peer has no encryption key (claim token first)",
		};
	}

	const topic = getTopic(peer.publicKey);
	const swarm = new Hyperswarm(getSwarmOptions());
	const ephemeral = generateEphemeralKeyPair();
	const requestId = randomBytes(16).toString("hex");

	// Handle swarm errors to prevent crashes
	(swarm as any).on("error", (err: Error) => {
		log(`[sendP2PInject] Swarm error: ${err.message}`);
	});

	log(`[sendP2PInject] Generated requestId: ${requestId.slice(0, 8)}...`);

	return new Promise<SendResult>((resolve) => {
		let resolved = false;
		const cleanup = async () => {
			if (!resolved) {
				resolved = true;
				log(`[sendP2PInject] Cleaning up swarm`);
				await swarm.destroy();
			}
		};

		const timeout = setTimeout(async () => {
			if (!resolved) {
				log(
					`[sendP2PInject] TIMEOUT after ${effectiveTimeout}ms waiting for response`,
				);
				await cleanup();
				resolve({ code: EXIT_OFFLINE, message: "Peer offline or AI timeout" });
			}
		}, effectiveTimeout);

		swarm.on("connection", async (socket: Duplex) => {
			log(`[sendP2PInject] Connection established`);
			if (resolved) {
				log(`[sendP2PInject] Already resolved, ignoring connection`);
				return;
			}

			try {
				log(`[sendP2PInject] Starting handshake...`);
				const { version, peerEphemeralPub } = await performHandshake(
					socket,
					identity.publicKey,
					ephemeral,
				);
				log(
					`[sendP2PInject] Handshake complete v${version}, peerEphemeralPub: ${peerEphemeralPub ? "yes" : "no"}`,
				);

				let encryptedPayload: string;
				let useEphemeral = false;

				if (version >= 2 && peerEphemeralPub) {
					encryptedPayload = encryptWithEphemeral(
						message,
						ephemeral.privateKey,
						peerEphemeralPub,
					);
					useEphemeral = true;
					log(`[sendP2PInject] Using ephemeral encryption`);
				} else {
					encryptedPayload = encryptMessage(message, peer.encryptPub!);
					log(`[sendP2PInject] Using static encryption`);
				}

				// Send "inject" type with requestId - invokes AI and expects response
				const msg = signMessage<Omit<P2PMessage, "sig">>({
					v: version,
					type: "inject",
					from: identity.publicKey,
					encryptPub: identity.encryptPub,
					ephemeralPub: useEphemeral ? ephemeral.publicKey : undefined,
					session,
					payload: encryptedPayload,
					requestId,
					nonce: randomBytes(16).toString("hex"),
					ts: Date.now(),
				});

				log(
					`[sendP2PInject] Sending inject message with requestId ${requestId.slice(0, 8)}...`,
				);
				socket.write(JSON.stringify(msg) + "\n");
				log(`[sendP2PInject] Inject sent, waiting for response...`);

				let buffer = "";
				socket.on("data", async (data: Buffer) => {
					const dataStr = data.toString();
					log(
						`[sendP2PInject] Received data (${data.length} bytes): ${dataStr.slice(0, 100)}...`,
					);
					buffer += dataStr;

					while (buffer.includes("\n")) {
						const line = buffer.split("\n")[0];
						buffer = buffer.slice(line.length + 1);
						log(`[sendP2PInject] Processing line (${line.length} chars)`);

						try {
							const response: P2PMessage = JSON.parse(line);
							log(
								`[sendP2PInject] Parsed response type: ${response.type}, requestId: ${response.requestId?.slice(0, 8) || "none"}`,
							);

							// Wait for "response" message with matching requestId
							if (
								response.type === "response" &&
								response.requestId === requestId
							) {
								log(`[sendP2PInject] Got matching response! Decrypting...`);
								clearTimeout(timeout);
								await cleanup();

								// Decrypt the response payload
								let decryptedResponse: string;
								if (response.ephemeralPub && ephemeral) {
									log(`[sendP2PInject] Decrypting with ephemeral key`);
									decryptedResponse = decryptWithEphemeral(
										response.payload || "",
										ephemeral.privateKey,
										response.ephemeralPub,
									);
								} else {
									log(`[sendP2PInject] Decrypting with static key`);
									decryptedResponse = decryptMessage(
										response.payload || "",
										identity.encryptPriv,
									);
								}

								log(
									`[sendP2PInject] Decrypted response (${decryptedResponse.length} chars): ${decryptedResponse.slice(0, 100)}...`,
								);
								resolve({ code: EXIT_OK, response: decryptedResponse });
							} else if (response.type === "reject") {
								log(`[sendP2PInject] Got reject: ${response.reason}`);
								clearTimeout(timeout);
								await cleanup();
								const code =
									response.reason === "rate limited"
										? EXIT_RATE_LIMITED
										: EXIT_REJECTED;
								resolve({ code, message: response.reason || "unauthorized" });
							} else if (response.type === "ack") {
								log(`[sendP2PInject] Got ack (ignoring, waiting for response)`);
							} else {
								log(
									`[sendP2PInject] Got unexpected message type: ${response.type}`,
								);
							}
						} catch (parseErr) {
							log(`[sendP2PInject] Failed to parse response: ${parseErr}`);
							// Continue buffering
						}
					}
				});

				socket.on("error", async (err) => {
					log(`[sendP2PInject] Socket error: ${err}`);
					if (!resolved) {
						clearTimeout(timeout);
						await cleanup();
						resolve({ code: EXIT_OFFLINE, message: "Connection error" });
					}
				});

				socket.on("close", () => {
					log(`[sendP2PInject] Socket closed, resolved=${resolved}`);
				});
			} catch (err) {
				log(`[sendP2PInject] Error: ${err}`);
				clearTimeout(timeout);
				await cleanup();
				if (err instanceof Error && err.message.includes("version")) {
					resolve({ code: EXIT_VERSION_MISMATCH, message: err.message });
				} else {
					resolve({ code: EXIT_OFFLINE, message: `Handshake failed: ${err}` });
				}
			}
		});

		log(`[sendP2PInject] Joining topic...`);
		swarm.join(topic, { server: false, client: true });
	});
}

/**
 * Claim a token by connecting to the issuer.
 */
export async function claimToken(
	tokenStr: string,
	timeoutMs = 10000,
): Promise<ClaimResult> {
	const identity = getIdentity();
	if (!identity) {
		return { code: EXIT_INVALID, message: "No identity" };
	}

	let token;
	try {
		token = parseInviteToken(tokenStr);
	} catch (err) {
		return { code: EXIT_INVALID, message: `Invalid token: ${err}` };
	}

	const topic = getTopic(token.iss);
	const swarm = new Hyperswarm(getSwarmOptions());
	const ephemeral = generateEphemeralKeyPair();

	// Handle swarm errors to prevent crashes
	(swarm as any).on("error", (err: Error) => {
		log(`[claimInvite] Swarm error: ${err.message}`);
	});

	return new Promise<ClaimResult>((resolve) => {
		let resolved = false;
		const cleanup = async () => {
			if (!resolved) {
				resolved = true;
				await swarm.destroy();
			}
		};

		const timeout = setTimeout(async () => {
			if (!resolved) {
				await cleanup();
				resolve({ code: EXIT_OFFLINE, message: "Issuer offline (timeout)" });
			}
		}, timeoutMs);

		swarm.on("connection", async (socket: Duplex) => {
			if (resolved) return;

			try {
				const { version } = await performHandshake(
					socket,
					identity.publicKey,
					ephemeral,
				);
				clearTimeout(timeout);

				const msg = signMessage<Omit<P2PMessage, "sig">>({
					v: version,
					type: "claim",
					from: identity.publicKey,
					encryptPub: identity.encryptPub,
					token: tokenStr,
					nonce: randomBytes(16).toString("hex"),
					ts: Date.now(),
				});

				socket.write(JSON.stringify(msg) + "\n");

				let buffer = "";
				socket.on("data", async (data: Buffer) => {
					buffer += data.toString();
					if (buffer.includes("\n")) {
						const line = buffer.split("\n")[0];
						try {
							const response: P2PMessage = JSON.parse(line);
							if (response.type === "ack") {
								addPeer(token.iss, token.ses, token.cap, response.encryptPub);
								await cleanup();
								resolve({
									code: EXIT_OK,
									peerKey: token.iss,
									sessions: token.ses,
									caps: token.cap,
								});
							} else if (response.type === "reject") {
								await cleanup();
								resolve({
									code: EXIT_REJECTED,
									message: response.reason || "claim rejected",
								});
							}
						} catch {
							await cleanup();
							resolve({ code: EXIT_INVALID, message: "Invalid response" });
						}
					}
				});

				socket.on("error", async () => {
					if (!resolved) {
						await cleanup();
						resolve({ code: EXIT_OFFLINE, message: "Connection error" });
					}
				});
			} catch (err) {
				clearTimeout(timeout);
				await cleanup();
				resolve({ code: EXIT_OFFLINE, message: `Handshake failed: ${err}` });
			}
		});

		swarm.join(topic, { server: false, client: true });
	});
}

/**
 * Send a key rotation notification to a peer.
 */
export async function sendKeyRotation(
	peerIdOrName: string,
	rotation: KeyRotation,
	timeoutMs = 10000,
): Promise<SendResult> {
	const identity = getIdentity();
	if (!identity) {
		return { code: EXIT_INVALID, message: "No identity" };
	}

	const peer = findPeer(peerIdOrName);
	if (!peer) {
		return { code: EXIT_INVALID, message: `Peer not found: ${peerIdOrName}` };
	}

	const topic = getTopic(peer.publicKey);
	const swarm = new Hyperswarm(getSwarmOptions());
	const ephemeral = generateEphemeralKeyPair();

	// Handle swarm errors to prevent crashes
	(swarm as any).on("error", (err: Error) => {
		log(`[notifyKeyRotation] Swarm error: ${err.message}`);
	});

	return new Promise<SendResult>((resolve) => {
		let resolved = false;
		const cleanup = async () => {
			if (!resolved) {
				resolved = true;
				await swarm.destroy();
			}
		};

		const timeout = setTimeout(async () => {
			if (!resolved) {
				await cleanup();
				resolve({ code: EXIT_OFFLINE, message: "Peer offline (timeout)" });
			}
		}, timeoutMs);

		swarm.on("connection", async (socket: Duplex) => {
			if (resolved) return;

			try {
				const { version } = await performHandshake(
					socket,
					rotation.newSignPub,
					ephemeral,
				);
				clearTimeout(timeout);

				const msg: P2PMessage = {
					v: version,
					type: "key-rotation",
					from: rotation.oldSignPub,
					keyRotation: {
						v: rotation.v,
						type: "key-rotation",
						oldSignPub: rotation.oldSignPub,
						newSignPub: rotation.newSignPub,
						newEncryptPub: rotation.newEncryptPub,
						reason: rotation.reason,
						effectiveAt: rotation.effectiveAt,
						gracePeriodMs: rotation.gracePeriodMs,
						sig: rotation.sig,
					},
					nonce: randomBytes(16).toString("hex"),
					ts: Date.now(),
					sig: rotation.sig,
				};

				socket.write(JSON.stringify(msg) + "\n");

				let buffer = "";
				socket.on("data", async (data: Buffer) => {
					buffer += data.toString();
					if (buffer.includes("\n")) {
						const line = buffer.split("\n")[0];
						try {
							const response: P2PMessage = JSON.parse(line);
							if (response.type === "ack") {
								await cleanup();
								resolve({ code: EXIT_OK });
							} else if (response.type === "reject") {
								await cleanup();
								resolve({
									code: EXIT_REJECTED,
									message: response.reason || "rotation rejected",
								});
							}
						} catch {
							await cleanup();
							resolve({ code: EXIT_INVALID, message: "Invalid response" });
						}
					}
				});

				socket.on("error", async () => {
					if (!resolved) {
						await cleanup();
						resolve({ code: EXIT_OFFLINE, message: "Connection error" });
					}
				});
			} catch (err) {
				clearTimeout(timeout);
				await cleanup();
				resolve({ code: EXIT_OFFLINE, message: `Handshake failed: ${err}` });
			}
		});

		swarm.join(topic, { server: false, client: true });
	});
}

/**
 * Callbacks for P2P message handling
 */
export interface P2PCallbacks {
	// Log message to session (mailbox style) - just stores, no AI invocation
	onLogMessage?: (session: string, message: string, peerKey?: string) => void;
	// Inject message to session and get AI response
	onInjectMessage?: (
		session: string,
		message: string,
		peerKey?: string,
	) => Promise<string>;
	// Logging output
	onLog: (msg: string) => void;
}

/**
 * Create a P2P listener for incoming connections.
 */
export function createP2PListener(callbacks: P2PCallbacks): Hyperswarm | null;
/**
 * @deprecated Use createP2PListener(callbacks) with P2PCallbacks object
 */
export function createP2PListener(
	onInject: (
		session: string,
		message: string,
		peerKey?: string,
	) => Promise<void>,
	onLog: (msg: string) => void,
): Hyperswarm | null;
export function createP2PListener(
	callbacksOrInject:
		| P2PCallbacks
		| ((session: string, message: string, peerKey?: string) => Promise<void>),
	onLogArg?: (msg: string) => void,
): Hyperswarm | null {
	// Handle both old and new signatures
	let callbacks: P2PCallbacks;
	if (typeof callbacksOrInject === "function") {
		// Legacy signature: onInject, onLog
		callbacks = {
			onInjectMessage: async (session, message, peerKey) => {
				await callbacksOrInject(session, message, peerKey);
				return ""; // Legacy doesn't return response
			},
			onLog: onLogArg!,
		};
	} else {
		callbacks = callbacksOrInject;
	}

	const { onLog } = callbacks;
	const identity = getIdentity();
	if (!identity) {
		onLog("No identity - P2P disabled");
		return null;
	}

	const topic = getTopic(identity.publicKey);
	const swarm = new Hyperswarm(getSwarmOptions());

	// Handle swarm-level errors to prevent crashes
	(swarm as any).on("error", (err: Error) => {
		onLog(`[listenP2P] Swarm error: ${err.message}`);
	});

	swarm.join(topic, { server: true, client: false });

	swarm.on("connection", (socket: Duplex) => {
		onLog("P2P connection received");
		handleConnection(socket, identity.publicKey, callbacks);
	});

	onLog(`P2P listening on topic ${topic.toString("hex").slice(0, 8)}...`);
	return swarm;
}

function handleConnection(
	socket: Duplex,
	myPublicKey: string,
	callbacks: P2PCallbacks,
): void {
	const { onLogMessage, onInjectMessage, onLog } = callbacks;
	const rateLimiter = getRateLimiter();
	const replayProtector = getReplayProtector();

	const ephemeral = generateEphemeralKeyPair();
	const sessionState: SessionState = { ephemeral };
	let handshakeComplete = false;
	let buffer = "";

	// CRITICAL: Add error handler FIRST to prevent uncaught error crashes
	socket.on("error", (err: Error) => {
		onLog(
			`[handleConnection] Socket error (expected during disconnect): ${err.message}`,
		);
		// Don't rethrow - ECONNRESET is normal when peer closes connection
	});

	socket.on("close", () => {
		onLog(`[handleConnection] Socket closed`);
	});

	socket.on("data", async (data: Buffer) => {
		buffer += data.toString();
		if (!buffer.includes("\n")) return;

		const line = buffer.split("\n")[0];
		buffer = buffer.slice(line.length + 1);

		// Reject oversized messages before parsing (defense against memory exhaustion)
		if (line.length > MAX_MESSAGE_SIZE) {
			onLog(
				`Rejected: message too large (${line.length} > ${MAX_MESSAGE_SIZE})`,
			);
			return;
		}

		let msg: P2PMessage;
		try {
			msg = JSON.parse(line);
		} catch {
			return;
		}

		// Handle hello (handshake)
		if (msg.type === "hello" && !handshakeComplete) {
			const commonVersions = (msg.versions || [1]).filter(
				(v) => v >= MIN_PROTOCOL_VERSION && v <= PROTOCOL_VERSION,
			);

			if (commonVersions.length === 0) {
				const reject = signMessage<Omit<P2PMessage, "sig">>({
					v: PROTOCOL_VERSION,
					type: "reject",
					from: myPublicKey,
					reason: "no common protocol version",
					nonce: randomBytes(16).toString("hex"),
					ts: Date.now(),
				});
				socket.write(JSON.stringify(reject) + "\n");
				return;
			}

			const negotiatedVersion = Math.max(...commonVersions);
			sessionState.negotiatedVersion = negotiatedVersion;
			sessionState.peerEphemeralPub = msg.ephemeralPub;

			const ack = signMessage<Omit<P2PMessage, "sig">>({
				v: PROTOCOL_VERSION,
				type: "hello-ack",
				from: myPublicKey,
				version: negotiatedVersion,
				ephemeralPub: ephemeral.publicKey,
				nonce: randomBytes(16).toString("hex"),
				ts: Date.now(),
			});
			socket.write(JSON.stringify(ack) + "\n");
			handshakeComplete = true;
			onLog(`Handshake complete: v${negotiatedVersion}`);
			return;
		}

		// Verify signature for non-hello messages
		if (msg.type !== "hello" && msg.type !== "hello-ack") {
			// Handle key rotation
			if (msg.type === "key-rotation" && msg.keyRotation) {
				const rotation: KeyRotation = {
					...msg.keyRotation,
					type: "key-rotation",
				};
				if (processPeerKeyRotation(rotation)) {
					onLog(`Key rotation processed for ${shortKey(msg.from)}`);
					const ack = signMessage<Omit<P2PMessage, "sig">>({
						v: PROTOCOL_VERSION,
						type: "ack",
						from: myPublicKey,
						nonce: randomBytes(16).toString("hex"),
						ts: Date.now(),
					});
					socket.write(JSON.stringify(ack) + "\n");
				} else {
					onLog(`Key rotation rejected for ${shortKey(msg.from)}`);
					const reject = signMessage<Omit<P2PMessage, "sig">>({
						v: PROTOCOL_VERSION,
						type: "reject",
						from: myPublicKey,
						reason: "invalid key rotation",
						nonce: randomBytes(16).toString("hex"),
						ts: Date.now(),
					});
					socket.write(JSON.stringify(reject) + "\n");
				}
				return;
			}

			if (!verifySignature(msg, msg.from)) {
				onLog(`Rejected: invalid signature from ${shortKey(msg.from)}`);
				rateLimiter.check(msg.from, "invalidMessages");
				return;
			}

			if (!replayProtector.check(msg.nonce, msg.ts)) {
				onLog(`Rejected: replay detected from ${shortKey(msg.from)}`);
				rateLimiter.check(msg.from, "invalidMessages");
				return;
			}
		}

		// Handle claim messages
		if (msg.type === "claim" && msg.token) {
			if (!rateLimiter.check(msg.from, "claims")) {
				onLog(`Rate limited: claim from ${shortKey(msg.from)}`);
				const reject = signMessage<Omit<P2PMessage, "sig">>({
					v: PROTOCOL_VERSION,
					type: "reject",
					from: myPublicKey,
					reason: "rate limited",
					nonce: randomBytes(16).toString("hex"),
					ts: Date.now(),
				});
				socket.write(JSON.stringify(reject) + "\n");
				return;
			}

			onLog(`Claim request from ${shortKey(msg.from)}`);
			try {
				const token = parseInviteToken(msg.token);

				if (token.iss !== myPublicKey) {
					const reject = signMessage<Omit<P2PMessage, "sig">>({
						v: PROTOCOL_VERSION,
						type: "reject",
						from: myPublicKey,
						reason: "token not issued by this peer",
						nonce: randomBytes(16).toString("hex"),
						ts: Date.now(),
					});
					socket.write(JSON.stringify(reject) + "\n");
					return;
				}

				if (token.sub !== msg.from) {
					const reject = signMessage<Omit<P2PMessage, "sig">>({
						v: PROTOCOL_VERSION,
						type: "reject",
						from: myPublicKey,
						reason: "token not issued for you",
						nonce: randomBytes(16).toString("hex"),
						ts: Date.now(),
					});
					socket.write(JSON.stringify(reject) + "\n");
					return;
				}

				grantAccess(msg.from, token.ses, token.cap, msg.encryptPub);
				onLog(
					`Granted access to ${shortKey(msg.from)} for sessions: ${token.ses.join(", ")}`,
				);

				const identity = getIdentity()!;
				const ack = signMessage<Omit<P2PMessage, "sig">>({
					v: PROTOCOL_VERSION,
					type: "ack",
					from: myPublicKey,
					encryptPub: identity.encryptPub,
					nonce: randomBytes(16).toString("hex"),
					ts: Date.now(),
				});
				socket.write(JSON.stringify(ack) + "\n");
			} catch (err) {
				onLog(`Rejected claim: ${err}`);
				const reject = signMessage<Omit<P2PMessage, "sig">>({
					v: PROTOCOL_VERSION,
					type: "reject",
					from: myPublicKey,
					reason: `invalid token: ${err}`,
					nonce: randomBytes(16).toString("hex"),
					ts: Date.now(),
				});
				socket.write(JSON.stringify(reject) + "\n");
			}
			return;
		}

		// Handle log and inject messages
		if (
			(msg.type === "log" || msg.type === "inject") &&
			msg.payload &&
			msg.session
		) {
			const actionName = msg.type === "log" ? "logs" : "injects";
			if (!rateLimiter.check(msg.from, actionName)) {
				onLog(`Rate limited: ${msg.type} from ${shortKey(msg.from)}`);
				const reject = signMessage<Omit<P2PMessage, "sig">>({
					v: PROTOCOL_VERSION,
					type: "reject",
					from: myPublicKey,
					session: msg.session,
					reason: "rate limited",
					nonce: randomBytes(16).toString("hex"),
					ts: Date.now(),
				});
				socket.write(JSON.stringify(reject) + "\n");
				return;
			}

			// Check payload size limit (security hardening)
			const payloadSize =
				typeof msg.payload === "string" ? msg.payload.length : 0;
			if (payloadSize > MAX_PAYLOAD_SIZE) {
				onLog(
					`Rejected: payload too large from ${shortKey(msg.from)} (${payloadSize} > ${MAX_PAYLOAD_SIZE})`,
				);
				const reject = signMessage<Omit<P2PMessage, "sig">>({
					v: PROTOCOL_VERSION,
					type: "reject",
					from: myPublicKey,
					session: msg.session,
					reason: `payload too large: ${payloadSize} bytes exceeds ${MAX_PAYLOAD_SIZE} limit`,
					nonce: randomBytes(16).toString("hex"),
					ts: Date.now(),
				});
				socket.write(JSON.stringify(reject) + "\n");
				return;
			}

			if (!isAuthorized(msg.from, msg.session)) {
				onLog(`Rejected: unauthorized ${shortKey(msg.from)} -> ${msg.session}`);
				const reject = signMessage<Omit<P2PMessage, "sig">>({
					v: PROTOCOL_VERSION,
					type: "reject",
					from: myPublicKey,
					session: msg.session,
					reason: "unauthorized",
					nonce: randomBytes(16).toString("hex"),
					ts: Date.now(),
				});
				socket.write(JSON.stringify(reject) + "\n");
				return;
			}

			onLog(`${msg.type} from ${shortKey(msg.from)} -> ${msg.session}`);
			try {
				let decryptedPayload: string;

				if (msg.v >= 2 && msg.ephemeralPub && sessionState.ephemeral) {
					decryptedPayload = decryptWithEphemeral(
						msg.payload,
						sessionState.ephemeral.privateKey,
						msg.ephemeralPub,
					);
				} else {
					const grant = getGrantForPeer(msg.from);
					if (!grant?.peerEncryptPub) {
						throw new Error("No encryption key for sender");
					}
					decryptedPayload = decryptMessage(msg.payload, grant.peerEncryptPub);
				}

				// Handle based on message type
				if (msg.type === "log") {
					// Mailbox style - just log the message, don't invoke AI
					onLog(`[handleConnection] Processing LOG message`);
					if (onLogMessage) {
						onLogMessage(msg.session, decryptedPayload, msg.from);
					}
					// Send ack
					const ack = signMessage<Omit<P2PMessage, "sig">>({
						v: PROTOCOL_VERSION,
						type: "ack",
						from: myPublicKey,
						session: msg.session,
						nonce: randomBytes(16).toString("hex"),
						ts: Date.now(),
					});
					socket.write(JSON.stringify(ack) + "\n");
					onLog(`Logged to ${msg.session}`);
				} else if (msg.type === "inject") {
					// Invoke AI and return response
					onLog(
						`[handleConnection] Processing INJECT message, requestId: ${msg.requestId?.slice(0, 8) || "none"}`,
					);
					onLog(
						`[handleConnection] onInjectMessage handler: ${onInjectMessage ? "present" : "MISSING"}`,
					);

					if (onInjectMessage) {
						onLog(
							`[handleConnection] Calling onInjectMessage for session ${msg.session}...`,
						);
						const aiResponse = await onInjectMessage(
							msg.session,
							decryptedPayload,
							msg.from,
						);
						onLog(
							`[handleConnection] AI response received (${aiResponse.length} chars): ${aiResponse.slice(0, 100)}...`,
						);

						// Encrypt the response
						const identity = getIdentity()!;
						let encryptedResponse: string;
						let responseEphemeral: EphemeralKeyPair | undefined;

						onLog(
							`[handleConnection] Encrypting response, msg.v=${msg.v}, msg.ephemeralPub=${msg.ephemeralPub ? "yes" : "no"}, msg.encryptPub=${msg.encryptPub ? "yes" : "no"}`,
						);

						if (msg.v >= 2 && msg.ephemeralPub) {
							// Use ephemeral encryption for response - MUST use sender's ephemeralPub!
							responseEphemeral = generateEphemeralKeyPair();
							onLog(
								`[handleConnection] Using ephemeral encryption, generated key: ${responseEphemeral.publicKey.slice(0, 16)}..., sender ephemeral: ${msg.ephemeralPub.slice(0, 16)}...`,
							);
							encryptedResponse = encryptWithEphemeral(
								aiResponse,
								responseEphemeral.privateKey,
								msg.ephemeralPub, // Use sender's EPHEMERAL key, not static encryptPub!
							);
							onLog(
								`[handleConnection] Encrypted response (${encryptedResponse.length} chars)`,
							);
						} else {
							// Fallback to peer's encryption key
							const grant = getGrantForPeer(msg.from);
							if (!grant?.peerEncryptPub) {
								throw new Error("No encryption key for sender");
							}
							onLog(`[handleConnection] Using static encryption with peer key`);
							encryptedResponse = encryptMessage(
								aiResponse,
								grant.peerEncryptPub,
							);
						}

						// Send response message
						const response = signMessage<Omit<P2PMessage, "sig">>({
							v: PROTOCOL_VERSION,
							type: "response",
							from: myPublicKey,
							encryptPub: identity.encryptPub,
							ephemeralPub: responseEphemeral?.publicKey,
							session: msg.session,
							payload: encryptedResponse,
							requestId: msg.requestId,
							nonce: randomBytes(16).toString("hex"),
							ts: Date.now(),
						});

						const responseJson = JSON.stringify(response);
						onLog(
							`[handleConnection] Sending response message (${responseJson.length} chars), requestId: ${msg.requestId?.slice(0, 8)}...`,
						);
						const writeResult = socket.write(responseJson + "\n");
						onLog(`[handleConnection] socket.write returned: ${writeResult}`);
						onLog(
							`Sent AI response to ${shortKey(msg.from)} (requestId: ${msg.requestId?.slice(0, 8)}...)`,
						);
					} else {
						// No inject handler - send ack for backwards compatibility
						onLog(`[handleConnection] No inject handler, sending ack instead`);
						const ack = signMessage<Omit<P2PMessage, "sig">>({
							v: PROTOCOL_VERSION,
							type: "ack",
							from: myPublicKey,
							session: msg.session,
							nonce: randomBytes(16).toString("hex"),
							ts: Date.now(),
						});
						socket.write(JSON.stringify(ack) + "\n");
						onLog(`Delivered to ${msg.session} (no inject handler)`);
					}
				}
			} catch (err) {
				onLog(`[handleConnection] ERROR: ${msg.type} failed: ${err}`);
				const reject = signMessage<Omit<P2PMessage, "sig">>({
					v: PROTOCOL_VERSION,
					type: "reject",
					from: myPublicKey,
					session: msg.session,
					reason: `${msg.type} failed`,
					nonce: randomBytes(16).toString("hex"),
					ts: Date.now(),
				});
				socket.write(JSON.stringify(reject) + "\n");
			}
		}
	});
}
