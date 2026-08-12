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
  [
    "pkce-spa",
    {
      secret: null,  // PKCE clients have no secret — the browser can't keep one safe
      redirectUris: ["http://localhost:3002/callback.html"],
      name: "PKCE Browser App",
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
