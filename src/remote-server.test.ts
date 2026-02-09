/**
 * Tests for remote-server helper logic.
 *
 * Since isEndpointAllowed, resolvePlaceholders, and checkRateLimit are
 * module-scoped (not exported), we replicate their logic here for unit testing.
 * This validates the algorithms used in the remote server.
 */
import { describe, it, expect, vi } from 'vitest';

// ── Replicated helper: isEndpointAllowed ──────────────────────────────────

function isEndpointAllowed(url: string, allowedEndpoints: string[]): boolean {
  if (allowedEndpoints.length === 0) return true;
  return allowedEndpoints.some(pattern => {
    const regex = new RegExp(
      '^' +
      pattern
        .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
        .replace(/\*\*/g, '.__DOUBLE_STAR__.')
        .replace(/\*/g, '[^/]*')
        .replace(/\.__DOUBLE_STAR__\./g, '.*') +
      '$',
    );
    return regex.test(url);
  });
}

// ── Replicated helper: resolvePlaceholders ────────────────────────────────

function resolvePlaceholders(str: string, secretsMap: Record<string, string>): string {
  return str.replace(/\$\{(\w+)\}/g, (match, name: string) => {
    if (name in secretsMap) return secretsMap[name];
    return match;
  });
}

// ── Replicated helper: checkRateLimit ─────────────────────────────────────

interface MockSession {
  windowRequests: number;
  windowStart: number;
}

function checkRateLimit(session: MockSession, rateLimitPerMinute: number): boolean {
  const now = Date.now();
  const windowMs = 60_000;

  if (now - session.windowStart > windowMs) {
    session.windowStart = now;
    session.windowRequests = 0;
  }

  session.windowRequests++;
  return session.windowRequests <= rateLimitPerMinute;
}

// ── Tests ─────────────────────────────────────────────────────────────────

describe('isEndpointAllowed', () => {
  it('should allow any URL when no patterns are configured', () => {
    expect(isEndpointAllowed('https://api.example.com/anything', [])).toBe(true);
    expect(isEndpointAllowed('http://localhost:3000', [])).toBe(true);
  });

  it('should match exact URLs', () => {
    const patterns = ['https://api.example.com/v1/data'];
    expect(isEndpointAllowed('https://api.example.com/v1/data', patterns)).toBe(true);
    expect(isEndpointAllowed('https://api.example.com/v1/other', patterns)).toBe(false);
  });

  it('should match single wildcard (*) within a path segment', () => {
    const patterns = ['https://api.example.com/v1/*'];
    expect(isEndpointAllowed('https://api.example.com/v1/data', patterns)).toBe(true);
    expect(isEndpointAllowed('https://api.example.com/v1/users', patterns)).toBe(true);
    // Single * should not match across /
    expect(isEndpointAllowed('https://api.example.com/v1/users/123', patterns)).toBe(false);
  });

  it('should match double wildcard (**) across path segments', () => {
    const patterns = ['https://api.example.com/**'];
    expect(isEndpointAllowed('https://api.example.com/v1/data', patterns)).toBe(true);
    expect(isEndpointAllowed('https://api.example.com/v1/users/123', patterns)).toBe(true);
    expect(isEndpointAllowed('https://api.example.com/', patterns)).toBe(true);
  });

  it('should escape special regex characters in patterns', () => {
    const patterns = ['https://api.example.com/v1/data?key=value'];
    expect(isEndpointAllowed('https://api.example.com/v1/data?key=value', patterns)).toBe(true);
    // The ? should be escaped, not treated as regex
    expect(isEndpointAllowed('https://api.example.com/v1/datXkey=value', patterns)).toBe(false);
  });

  it('should match against multiple patterns (OR logic)', () => {
    const patterns = [
      'https://api.github.com/**',
      'https://api.stripe.com/v1/*',
    ];
    expect(isEndpointAllowed('https://api.github.com/repos/foo', patterns)).toBe(true);
    expect(isEndpointAllowed('https://api.stripe.com/v1/charges', patterns)).toBe(true);
    expect(isEndpointAllowed('https://api.evil.com/hack', patterns)).toBe(false);
  });

  it('should handle dots in domain names correctly', () => {
    const patterns = ['https://api.example.com/*'];
    // The dot in example.com should be escaped, not match any char
    expect(isEndpointAllowed('https://api.example.com/test', patterns)).toBe(true);
    expect(isEndpointAllowed('https://apixexamplexcom/test', patterns)).toBe(false);
  });
});

describe('resolvePlaceholders', () => {
  it('should replace ${VAR} with secret values', () => {
    const secrets = { API_KEY: 'sk-123', TOKEN: 'tok-456' };
    expect(resolvePlaceholders('Bearer ${TOKEN}', secrets)).toBe('Bearer tok-456');
    expect(resolvePlaceholders('${API_KEY}', secrets)).toBe('sk-123');
  });

  it('should replace multiple placeholders', () => {
    const secrets = { HOST: 'example.com', PORT: '8080' };
    expect(resolvePlaceholders('https://${HOST}:${PORT}/api', secrets)).toBe(
      'https://example.com:8080/api',
    );
  });

  it('should leave unknown placeholders unchanged', () => {
    const secrets = { KNOWN: 'value' };
    expect(resolvePlaceholders('${UNKNOWN}', secrets)).toBe('${UNKNOWN}');
  });

  it('should return unchanged strings without placeholders', () => {
    const secrets = { KEY: 'value' };
    expect(resolvePlaceholders('no placeholders here', secrets)).toBe('no placeholders here');
  });

  it('should handle empty strings', () => {
    expect(resolvePlaceholders('', {})).toBe('');
  });

  it('should handle secrets with special characters', () => {
    const secrets = { PASS: 'p@$$w0rd!&' };
    expect(resolvePlaceholders('password=${PASS}', secrets)).toBe('password=p@$$w0rd!&');
  });
});

describe('checkRateLimit', () => {
  it('should allow requests within the rate limit', () => {
    const session: MockSession = { windowRequests: 0, windowStart: Date.now() };
    const limit = 5;

    for (let i = 0; i < 5; i++) {
      expect(checkRateLimit(session, limit)).toBe(true);
    }
  });

  it('should block requests exceeding the rate limit', () => {
    const session: MockSession = { windowRequests: 0, windowStart: Date.now() };
    const limit = 3;

    expect(checkRateLimit(session, limit)).toBe(true);  // 1
    expect(checkRateLimit(session, limit)).toBe(true);  // 2
    expect(checkRateLimit(session, limit)).toBe(true);  // 3
    expect(checkRateLimit(session, limit)).toBe(false); // 4 — over limit
  });

  it('should reset the window after 60 seconds', () => {
    const now = Date.now();
    const session: MockSession = {
      windowRequests: 100,
      windowStart: now - 61_000, // 61 seconds ago
    };

    // Window expired, so this should reset and allow
    expect(checkRateLimit(session, 5)).toBe(true);
    expect(session.windowRequests).toBe(1);
  });

  it('should not reset window within 60 seconds', () => {
    const now = Date.now();
    const session: MockSession = {
      windowRequests: 4,
      windowStart: now - 30_000, // 30 seconds ago, within window
    };

    // Window still active, 5th request
    expect(checkRateLimit(session, 5)).toBe(true);
    // 6th request - should exceed
    expect(checkRateLimit(session, 5)).toBe(false);
  });
});
