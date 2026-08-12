import { getClient, validateRedirectUri } from "./clients.ts"
import { consumeCode, issueCode } from "./codes.ts"
import { createSession, getSession, issueToken, validateToken } from "./tokens.ts"
import { findUserByCredentials, findUserById } from "./users.ts"

const PORT = parseInt(process.env.AUTH_PORT ?? "3000")

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
}

function parseCookies(cookieHeader: string | null): Record<string, string> {
  if (!cookieHeader) return {}
  return Object.fromEntries(
    cookieHeader.split(";").map(c => {
      const [k, ...v] = c.trim().split("=")
      return [k, v.join("=")]
    })
  )
}

function errorResponse(message: string, status = 400): Response {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { "Content-Type": "application/json", ...CORS_HEADERS },
  })
}

// base64url-encode a Uint8Array (standard for PKCE)
function base64url(buf: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "")
}

// Verify PKCE: SHA256(code_verifier) must equal the stored code_challenge
async function verifyPkce(codeVerifier: string, codeChallenge: string): Promise<boolean> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(codeVerifier))
  return base64url(digest) === codeChallenge
}

// Renders the login + consent page shown to the user during /authorize
function renderConsentPage(params: {
  clientName: string
  clientId: string
  redirectUri: string
  state: string
  userId: string | null
  codeChallenge: string
  codeChallengeMethod: string
}): string {
  // Hidden fields carried through both forms so PKCE params survive login redirect
  const pkceFields = `
    <input type="hidden" name="code_challenge" value="${params.codeChallenge}" />
    <input type="hidden" name="code_challenge_method" value="${params.codeChallengeMethod}" />`

  const loginForm = `
    <form method="POST" action="/login">
      <input type="hidden" name="client_id" value="${params.clientId}" />
      <input type="hidden" name="redirect_uri" value="${params.redirectUri}" />
      <input type="hidden" name="state" value="${params.state}" />
      ${pkceFields}
      <h2>Sign in to authorize <strong>${params.clientName}</strong></h2>
      <label>Username<br><input type="text" name="username" required autofocus /></label><br>
      <label>Password<br><input type="password" name="password" required /></label><br>
      <button type="submit">Sign in</button>
    </form>`

  const approveForm = `
    <form method="POST" action="/approve">
      <input type="hidden" name="client_id" value="${params.clientId}" />
      <input type="hidden" name="redirect_uri" value="${params.redirectUri}" />
      <input type="hidden" name="state" value="${params.state}" />
      ${pkceFields}
      <h2><strong>${params.clientName}</strong> is requesting access to your profile</h2>
      <p>Scopes: <code>profile email</code></p>
      <button type="submit" name="decision" value="approve">Approve</button>
      <button type="submit" name="decision" value="deny" style="background:#e55;">Deny</button>
    </form>`

  return `<!DOCTYPE html>
<html>
<head>
  <title>OAuth Authorization</title>
  <style>
    * { box-sizing: border-box; font-family: system-ui, sans-serif; }
    body { display: flex; align-items: center; justify-content: center; min-height: 100vh; background: #f0f2f5; margin: 0; }
    .card { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 12px rgba(0,0,0,.1); width: 360px; }
    input { width: 100%; padding: 8px; margin: 4px 0 12px; border: 1px solid #ccc; border-radius: 4px; }
    button { width: 100%; padding: 10px; margin-top: 8px; border: none; border-radius: 4px; background: #0066ff; color: white; cursor: pointer; font-size: 1rem; }
    h2 { margin-top: 0; font-size: 1.1rem; }
    p { color: #555; font-size: .9rem; }
  </style>
</head>
<body>
  <div class="card">
    <div style="text-align:center; margin-bottom:1.5rem;">
      <span style="font-size:2rem">🔐</span>
      <div style="font-weight:bold; color:#0066ff; margin-top:.4rem">OAuth Demo Auth Server</div>
    </div>
    ${params.userId ? approveForm : loginForm}
  </div>
</body>
</html>`
}

const server = Bun.serve({
  port: PORT,
  async fetch(req) {
    const url = new URL(req.url)
    const cookies = parseCookies(req.headers.get("cookie"))
    const sessionId = cookies["auth_session"]
    const session = sessionId ? getSession(sessionId) : null

    // Handle CORS preflight so the browser-app (PKCE flow) can call /token and /userinfo
    if (req.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS_HEADERS })
    }

    // GET /authorize — entry point of the OAuth flow
    if (req.method === "GET" && url.pathname === "/authorize") {
      const clientId = url.searchParams.get("client_id")
      const redirectUri = url.searchParams.get("redirect_uri")
      const responseType = url.searchParams.get("response_type")
      const state = url.searchParams.get("state") ?? ""
      const codeChallenge = url.searchParams.get("code_challenge") ?? ""
      const codeChallengeMethod = url.searchParams.get("code_challenge_method") ?? ""

      if (!clientId || !redirectUri || responseType !== "code") {
        return errorResponse("Missing or invalid parameters: client_id, redirect_uri, response_type=code required")
      }
      const client = getClient(clientId)
      if (!client) return errorResponse("Unknown client_id", 401)
      if (!validateRedirectUri(clientId, redirectUri)) return errorResponse("Invalid redirect_uri", 401)

      const html = renderConsentPage({
        clientName: client.name,
        clientId,
        redirectUri,
        state,
        userId: session?.userId ?? null,
        codeChallenge,
        codeChallengeMethod,
      })
      return new Response(html, { headers: { "Content-Type": "text/html" } })
    }

    // POST /login — validates user credentials during the authorize flow
    if (req.method === "POST" && url.pathname === "/login") {
      const body = await req.formData()
      const username = body.get("username") as string
      const password = body.get("password") as string
      const clientId = body.get("client_id") as string
      const redirectUri = body.get("redirect_uri") as string
      const state = body.get("state") as string
      const codeChallenge = body.get("code_challenge") as string ?? ""
      const codeChallengeMethod = body.get("code_challenge_method") as string ?? ""

      const user = findUserByCredentials(username, password)
      if (!user) {
        const client = getClient(clientId)
        const html = renderConsentPage({
          clientName: client?.name ?? clientId,
          clientId,
          redirectUri,
          state,
          userId: null,
          codeChallenge,
          codeChallengeMethod,
        })
        return new Response(html.replace("</form>", '<p style="color:red">Invalid credentials</p></form>'), {
          headers: { "Content-Type": "text/html" },
        })
      }

      const newSessionId = createSession(user.id)
      // Carry PKCE params back through the redirect so /authorize can re-render with them
      const redirectBack =
        `/authorize?client_id=${clientId}` +
        `&redirect_uri=${encodeURIComponent(redirectUri)}` +
        `&response_type=code` +
        `&state=${state}` +
        (codeChallenge ? `&code_challenge=${codeChallenge}&code_challenge_method=${codeChallengeMethod}` : "")
      return new Response(null, {
        status: 302,
        headers: {
          Location: redirectBack,
          "Set-Cookie": `auth_session=${newSessionId}; HttpOnly; Path=/; Max-Age=3600`,
        },
      })
    }

    // POST /approve — user clicked Approve or Deny on the consent page
    if (req.method === "POST" && url.pathname === "/approve") {
      const body = await req.formData()
      const decision = body.get("decision") as string
      const clientId = body.get("client_id") as string
      const redirectUri = body.get("redirect_uri") as string
      const state = body.get("state") as string
      const codeChallenge = (body.get("code_challenge") as string) || undefined
      const codeChallengeMethod = (body.get("code_challenge_method") as string) || undefined

      if (!session) return errorResponse("Not authenticated", 401)
      if (decision !== "approve") {
        return new Response(null, {
          status: 302,
          headers: { Location: `${redirectUri}?error=access_denied&state=${state}` },
        })
      }

      const code = issueCode(clientId, redirectUri, session.userId, state, codeChallenge, codeChallengeMethod)
      return new Response(null, {
        status: 302,
        headers: { Location: `${redirectUri}?code=${code}&state=${state}` },
      })
    }

    // POST /token — exchange auth code for access token
    if (req.method === "POST" && url.pathname === "/token") {
      let body: URLSearchParams
      const contentType = req.headers.get("content-type") ?? ""
      if (contentType.includes("application/json")) {
        const json = await req.json()
        body = new URLSearchParams(json)
      } else {
        const text = await req.text()
        body = new URLSearchParams(text)
      }

      const grantType = body.get("grant_type")
      const code = body.get("code")
      const clientId = body.get("client_id")
      const redirectUri = body.get("redirect_uri")

      if (grantType !== "authorization_code") return errorResponse("unsupported_grant_type")
      if (!code || !clientId || !redirectUri) return errorResponse("invalid_request")

      const client = getClient(clientId)
      if (!client) return errorResponse("invalid_client", 401)

      const payload = consumeCode(code)
      if (!payload) return errorResponse("invalid_grant")
      if (payload.clientId !== clientId || payload.redirectUri !== redirectUri) return errorResponse("invalid_grant")

      if (payload.codeChallenge) {
        // PKCE flow: verify code_verifier instead of client_secret
        const codeVerifier = body.get("code_verifier")
        if (!codeVerifier) return errorResponse("invalid_request: code_verifier required for PKCE")
        const valid = await verifyPkce(codeVerifier, payload.codeChallenge)
        if (!valid) return errorResponse("invalid_grant: code_verifier mismatch")
      } else {
        // Auth Code + Secret flow: verify client_secret
        const clientSecret = body.get("client_secret")
        if (!clientSecret || client.secret !== clientSecret) return errorResponse("invalid_client", 401)
      }

      const accessToken = issueToken(clientId, payload.userId)

      return new Response(
        JSON.stringify({
          access_token: accessToken,
          token_type: "Bearer",
          expires_in: 3600,
        }),
        { headers: { "Content-Type": "application/json", ...CORS_HEADERS } }
      )
    }

    // GET /userinfo — protected resource, requires Bearer token
    if (req.method === "GET" && url.pathname === "/userinfo") {
      const authHeader = req.headers.get("authorization") ?? ""
      const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null
      if (!token) return errorResponse("invalid_token", 401)

      const tokenPayload = validateToken(token)
      if (!tokenPayload) return errorResponse("invalid_token", 401)

      const user = findUserById(tokenPayload.userId)
      if (!user) return errorResponse("invalid_token", 401)

      return new Response(
        JSON.stringify({
          sub: user.id,
          name: user.name,
          email: user.email,
          username: user.username,
        }),
        { headers: { "Content-Type": "application/json", ...CORS_HEADERS } }
      )
    }

    return new Response("Not found", { status: 404 })
  },
})

console.log(`OAuth Authorization Server running at http://localhost:${PORT}`)
console.log(`  GET  /authorize   — show consent page (supports PKCE via code_challenge param)`)
console.log(`  POST /login       — authenticate user`)
console.log(`  POST /approve     — issue auth code`)
console.log(`  POST /token       — exchange code for access token (PKCE or client_secret)`)
console.log(`  GET  /userinfo    — protected resource (requires Bearer token)`)
