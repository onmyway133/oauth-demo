export interface OAuthClient {
  secret: string
  redirectUris: string[]
  name: string
}

export interface AuthCode {
  clientId: string
  redirectUri: string
  userId: string
  state: string
  expiresAt: number
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
