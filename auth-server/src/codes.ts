import type { AuthCode } from "./types.ts"

// Single-use auth codes — TTL 10 minutes
const codes = new Map<string, AuthCode>()

const CODE_TTL_MS = 10 * 60 * 1000

export function issueCode(clientId: string, redirectUri: string, userId: string, state: string): string {
  const code = crypto.randomUUID()
  codes.set(code, {
    clientId,
    redirectUri,
    userId,
    state,
    expiresAt: Date.now() + CODE_TTL_MS,
  })
  return code
}

// Consumes the code (single-use) and returns its payload, or null if invalid/expired
export function consumeCode(code: string): AuthCode | null {
  const payload = codes.get(code)
  if (!payload) return null
  codes.delete(code)
  if (Date.now() > payload.expiresAt) return null
  return payload
}
