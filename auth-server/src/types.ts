export interface OAuthClient {
  secret: string | null  // null = PKCE-only client (no secret)
  redirectUris: string[]
  name: string
}

export interface AuthCode {
  clientId: string
  redirectUri: string
  userId: string
  state: string
  expiresAt: number
  codeChallenge?: string        // PKCE: SHA256(code_verifier) base64url
  codeChallengeMethod?: string  // always "S256" in practice
}

export interface AccessToken {
  clientId: string
  userId: string
  issuedAt: number
  expiresAt: number
}

export interface User {
  id: string
  username: string
  passwordHash: string
  name: string
  email: string
}

export interface UserSession {
  userId: string
  expiresAt: number
}
