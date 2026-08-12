import type { OAuthClient } from "./types.ts"

// Registered OAuth clients — in production this would be a database
const clients = new Map<string, OAuthClient>([
  [
    "demo-app",
    {
      secret: "demo-secret",
      redirectUris: ["http://localhost:3001/callback"],
      name: "Demo Client App",
    },
  ],
])

export function getClient(clientId: string): OAuthClient | null {
  return clients.get(clientId) ?? null
}

export function validateRedirectUri(clientId: string, redirectUri: string): boolean {
  const client = clients.get(clientId)
  return client?.redirectUris.includes(redirectUri) ?? false
}
