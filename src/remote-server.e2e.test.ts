/**
 * End-to-end tests for the remote server.
 *
 * Boots a real Express app with in-memory keys, performs handshakes
 * over HTTP, sends encrypted requests, and validates the full flow.
 * Replaces the old test-integration.ts custom harness.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import crypto from 'node:crypto';

import { createApp } from './remote-server.js';
import type { Config } from './config.js';
import {
  generateKeyBundle,
  extractPublicKeys,
  EncryptedChannel,
  type KeyBundle,
  type PublicKeyBundle,
} from './crypto/index.js';
import {
  HandshakeInitiator,
  type HandshakeReply,
  type ProxyRequest,
  type ProxyResponse,
} from './protocol/index.js';

// ── Test fixtures ─────────────────────────────────────────────────────────

let server: Server;
let baseUrl: string;

let clientKeys: KeyBundle;
let serverKeys: KeyBundle;
let clientPub: PublicKeyBundle;
let serverPub: PublicKeyBundle;

const testSecrets: Record<string, string> = {
  TEST_SECRET: 'hello-from-the-vault',
  API_KEY: 'sk-test-1234567890',
};

beforeAll(async () => {
  // Generate fresh key pairs for client and server
  clientKeys = generateKeyBundle();
  serverKeys = generateKeyBundle();
  clientPub = extractPublicKeys(clientKeys);
  serverPub = extractPublicKeys(serverKeys);

  // Build a config that uses our in-memory keys directly
  const config: Config = {
    proxy: {
      remoteUrl: '', // not used server-side
      localKeysDir: '',
      remotePublicKeysDir: '',
      connectTimeout: 10_000,
      requestTimeout: 30_000,
    },
    remote: {
      host: '127.0.0.1',
      port: 0, // not used — we listen on a random port
      localKeysDir: '',
      authorizedPeersDir: '',
      secrets: testSecrets, // literal values, no env var resolution needed
      allowedEndpoints: [], // empty = allow all
      rateLimitPerMinute: 60,
    },
  };

  const app = createApp({
    config,
    ownKeys: serverKeys,
    authorizedPeers: [clientPub],
  });

  // Start on a random available port
  await new Promise<void>((resolve) => {
    server = app.listen(0, '127.0.0.1', () => {
      const addr = server.address() as AddressInfo;
      baseUrl = `http://127.0.0.1:${addr.port}`;
      resolve();
    });
  });
});

afterAll(async () => {
  await new Promise<void>((resolve, reject) => {
    server.close((err) => {
      if (err) reject(err);
      else resolve();
    });
  });
});

// ── Helpers ───────────────────────────────────────────────────────────────

/** Perform a full handshake and return the encrypted channel + session ID */
async function performHttpHandshake(): Promise<{
  channel: EncryptedChannel;
  sessionId: string;
}> {
  const initiator = new HandshakeInitiator(clientKeys, serverPub);

  // Step 1: Send init
  const initMsg = initiator.createInit();
  const initResp = await fetch(`${baseUrl}/handshake/init`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(initMsg),
  });
  expect(initResp.ok).toBe(true);

  const reply = (await initResp.json()) as HandshakeReply;

  // Step 2: Process reply and derive keys
  const sessionKeys = initiator.processReply(reply);
  const channel = new EncryptedChannel(sessionKeys);

  // Step 3: Send finish
  const finishMsg = initiator.createFinish(sessionKeys);
  const finishResp = await fetch(`${baseUrl}/handshake/finish`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Session-Id': sessionKeys.sessionId,
    },
    body: JSON.stringify(finishMsg),
  });
  expect(finishResp.ok).toBe(true);

  const finishResult = (await finishResp.json()) as { status: string; sessionId: string };
  expect(finishResult.status).toBe('established');

  return { channel, sessionId: sessionKeys.sessionId };
}

/** Send an encrypted tool request and return the decrypted response */
async function sendToolRequest(
  channel: EncryptedChannel,
  toolName: string,
  toolInput: Record<string, unknown>,
): Promise<ProxyResponse> {
  const request: ProxyRequest = {
    type: 'proxy_request',
    id: crypto.randomUUID(),
    toolName,
    toolInput,
    timestamp: Date.now(),
  };

  const encrypted = channel.encryptJSON(request);
  const resp = await fetch(`${baseUrl}/request`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/octet-stream',
      'X-Session-Id': channel.sessionId,
    },
    body: new Uint8Array(encrypted),
  });

  expect(resp.ok).toBe(true);
  return channel.decryptJSON<ProxyResponse>(Buffer.from(await resp.arrayBuffer()));
}

// ── Tests ─────────────────────────────────────────────────────────────────

describe('Health check', () => {
  it('should return ok status', async () => {
    const resp = await fetch(`${baseUrl}/health`);
    expect(resp.ok).toBe(true);

    const body = (await resp.json()) as { status: string };
    expect(body.status).toBe('ok');
  });
});

describe('Handshake', () => {
  it('should complete a full handshake successfully', async () => {
    const { channel, sessionId } = await performHttpHandshake();
    expect(sessionId).toBeDefined();
    expect(channel.sessionId).toBe(sessionId);
  });

  it('should reject unauthorized clients', async () => {
    const rogueKeys = generateKeyBundle();

    const initiator = new HandshakeInitiator(rogueKeys, serverPub);
    const initMsg = initiator.createInit();

    const resp = await fetch(`${baseUrl}/handshake/init`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(initMsg),
    });

    expect(resp.status).toBe(403);
    const body = (await resp.json()) as { error: string };
    expect(body.error).toContain('not authorized');
  });

  it('should reject finish without session ID header', async () => {
    const resp = await fetch(`${baseUrl}/handshake/finish`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 'handshake_finish', payload: 'deadbeef' }),
    });

    expect(resp.status).toBe(400);
  });

  it('should reject finish with unknown session ID', async () => {
    const resp = await fetch(`${baseUrl}/handshake/finish`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Session-Id': 'nonexistent-session',
      },
      body: JSON.stringify({ type: 'handshake_finish', payload: 'deadbeef' }),
    });

    expect(resp.status).toBe(404);
  });
});

describe('Encrypted requests', () => {
  let channel: EncryptedChannel;

  beforeAll(async () => {
    const result = await performHttpHandshake();
    channel = result.channel;
  });

  it('should list secrets', async () => {
    const response = await sendToolRequest(channel, 'list_secrets', {});
    expect(response.success).toBe(true);

    const names = response.result as string[];
    expect(names).toContain('TEST_SECRET');
    expect(names).toContain('API_KEY');
  });

  it('should get a secret by name', async () => {
    const response = await sendToolRequest(channel, 'get_secret', { name: 'TEST_SECRET' });
    expect(response.success).toBe(true);
    expect(response.result).toBe('hello-from-the-vault');
  });

  it('should get a different secret', async () => {
    const response = await sendToolRequest(channel, 'get_secret', { name: 'API_KEY' });
    expect(response.success).toBe(true);
    expect(response.result).toBe('sk-test-1234567890');
  });

  it('should return an error for unknown secrets', async () => {
    const response = await sendToolRequest(channel, 'get_secret', { name: 'DOES_NOT_EXIST' });
    expect(response.success).toBe(false);
    expect(response.error).toContain('Secret not found');
  });

  it('should return an error for unknown tools', async () => {
    const response = await sendToolRequest(channel, 'nonexistent_tool', {});
    expect(response.success).toBe(false);
    expect(response.error).toContain('Unknown tool');
  });
});

describe('Security', () => {
  it('should reject replayed encrypted payloads', async () => {
    const { channel } = await performHttpHandshake();

    // Send a valid request first
    const request: ProxyRequest = {
      type: 'proxy_request',
      id: crypto.randomUUID(),
      toolName: 'list_secrets',
      toolInput: {},
      timestamp: Date.now(),
    };
    const encrypted = channel.encryptJSON(request);
    const body = new Uint8Array(encrypted);

    // First request succeeds — consume the response to advance the recv counter
    const resp1 = await fetch(`${baseUrl}/request`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        'X-Session-Id': channel.sessionId,
      },
      body,
    });
    expect(resp1.ok).toBe(true);
    const firstResponse = channel.decryptJSON<ProxyResponse>(
      Buffer.from(await resp1.arrayBuffer()),
    );
    expect(firstResponse.success).toBe(true);

    // Replay the exact same encrypted payload — server rejects (counter mismatch)
    const resp2 = await fetch(`${baseUrl}/request`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        'X-Session-Id': channel.sessionId,
      },
      body,
    });
    // Server detects replay: either sends encrypted error (200) or session breaks (500)
    if (resp2.ok) {
      const errorResponse = channel.decryptJSON<ProxyResponse>(
        Buffer.from(await resp2.arrayBuffer()),
      );
      expect(errorResponse.success).toBe(false);
      expect(errorResponse.error).toContain('Counter mismatch');
    } else {
      expect(resp2.status).toBe(500);
    }
  });

  it('should reject requests with unknown session IDs', async () => {
    const resp = await fetch(`${baseUrl}/request`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        'X-Session-Id': 'totally-fake-session-id',
      },
      body: new Uint8Array(Buffer.from('garbage')),
    });

    expect(resp.status).toBe(401);
  });

  it('should reject requests without session ID header', async () => {
    const resp = await fetch(`${baseUrl}/request`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: new Uint8Array(Buffer.from('garbage')),
    });

    expect(resp.status).toBe(400);
  });

  it('should support multiple concurrent sessions', async () => {
    const session1 = await performHttpHandshake();
    const session2 = await performHttpHandshake();

    expect(session1.sessionId).not.toBe(session2.sessionId);

    // Both sessions should work independently
    const resp1 = await sendToolRequest(session1.channel, 'list_secrets', {});
    const resp2 = await sendToolRequest(session2.channel, 'list_secrets', {});

    expect(resp1.success).toBe(true);
    expect(resp2.success).toBe(true);
  });
});
