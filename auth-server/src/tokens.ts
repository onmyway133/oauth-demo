import type { AccessToken, UserSession } from "./types.ts"

// Access tokens — TTL 1 hour
const tokens = new Map<string, AccessToken>()

// User sessions (browser cookie → userId) — TTL 1 hour
const sessions = new Map<string, UserSession>()

const TOKEN_TTL_MS = 60 * 60 * 1000

export function issueToken(clientId: string, userId: string): string {
  const token = crypto.randomUUID()
  tokens.set(token, {
    clientId,
    userId,
    issuedAt: Date.now(),
    expiresAt: Date.now() + TOKEN_TTL_MS,
  })
  return token
}

export function validateToken(token: string): AccessToken | null {
  const payload = tokens.get(token)
  if (!payload) return null
  if (Date.now() > payload.expiresAt) {
    tokens.delete(token)
    return null
  }
  return payload
}

export function createSession(userId: string): string {
  const sessionId = crypto.randomUUID()
  sessions.set(sessionId, { userId, expiresAt: Date.now() + TOKEN_TTL_MS })
  return sessionId
}

export function getSession(sessionId: string): UserSession | null {
  const session = sessions.get(sessionId)
  if (!session) return null
  if (Date.now() > session.expiresAt) {
    sessions.delete(sessionId)
    return null
  }
  return session
}
