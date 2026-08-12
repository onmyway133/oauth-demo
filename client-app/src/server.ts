import { join } from "path"

const PORT = parseInt(process.env.CLIENT_PORT ?? "3001")
const CLIENT_ID = process.env.CLIENT_ID ?? "demo-app"
const CLIENT_SECRET = process.env.CLIENT_SECRET ?? "demo-secret"
const AUTH_SERVER_URL = process.env.AUTH_SERVER_URL ?? "http://localhost:3000"
const REDIRECT_URI = `http://localhost:${PORT}/callback`

const sessions = new Map<string, { name: string; email: string; username: string; sub: string }>()

function parseCookies(cookieHeader: string | null): Record<string, string> {
  if (!cookieHeader) return {}
  return Object.fromEntries(
    cookieHeader.split(";").map(c => {
      const [k, ...v] = c.trim().split("=")
      return [k, v.join("=")]
    })
  )
}

async function serveFile(filePath: string): Promise<Response> {
  const file = Bun.file(filePath)
  const exists = await file.exists()
  if (!exists) return new Response("Not found", { status: 404 })
  return new Response(file)
}

const server = Bun.serve({
  port: PORT,
  async fetch(req) {
    const url = new URL(req.url)
    const cookies = parseCookies(req.headers.get("cookie"))
    const sessionId = cookies["client_session"]

    // GET / — serve login page
    if (url.pathname === "/" || url.pathname === "/index.html") {
      return serveFile(join(import.meta.dir, "../public/index.html"))
    }

    // GET /profile.html — serve profile page
    if (url.pathname === "/profile.html") {
      return serveFile(join(import.meta.dir, "../public/profile.html"))
    }

    // GET /login — kick off OAuth flow: redirect browser to auth server /authorize
    if (url.pathname === "/login") {
      const state = crypto.randomUUID()
      const authorizeUrl = new URL(`${AUTH_SERVER_URL}/authorize`)
      authorizeUrl.searchParams.set("response_type", "code")
      authorizeUrl.searchParams.set("client_id", CLIENT_ID)
      authorizeUrl.searchParams.set("redirect_uri", REDIRECT_URI)
      authorizeUrl.searchParams.set("state", state)

      return new Response(null, {
        status: 302,
        headers: {
          Location: authorizeUrl.toString(),
          "Set-Cookie": `oauth_state=${state}; HttpOnly; Path=/; Max-Age=600`,
        },
      })
    }

    // GET /callback — receive auth code from auth server, exchange for token, fetch user info
    if (url.pathname === "/callback") {
      const code = url.searchParams.get("code")
      const returnedState = url.searchParams.get("state")
      const error = url.searchParams.get("error")

      if (error) {
        return new Response(`<h2>Access denied: ${error}</h2><a href="/">Back</a>`, {
          headers: { "Content-Type": "text/html" },
        })
      }

      const expectedState = cookies["oauth_state"]
      if (!code || returnedState !== expectedState) {
        return new Response("<h2>Invalid state parameter (CSRF check failed)</h2><a href='/'>Back</a>", {
          status: 400,
          headers: { "Content-Type": "text/html" },
        })
      }

      // Exchange auth code for access token
      const tokenRes = await fetch(`${AUTH_SERVER_URL}/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          client_id: CLIENT_ID,
          client_secret: CLIENT_SECRET,
          redirect_uri: REDIRECT_URI,
        }),
      })
      const tokenData = (await tokenRes.json()) as { access_token: string; token_type: string }
      if (!tokenData.access_token) {
        return new Response("<h2>Token exchange failed</h2><a href='/'>Back</a>", {
          status: 502,
          headers: { "Content-Type": "text/html" },
        })
      }

      // Fetch user info from auth server using the access token
      const userRes = await fetch(`${AUTH_SERVER_URL}/userinfo`, {
        headers: { Authorization: `Bearer ${tokenData.access_token}` },
      })
      const user = (await userRes.json()) as { sub: string; name: string; email: string; username: string }

      const newSessionId = crypto.randomUUID()
      sessions.set(newSessionId, user)

      return new Response(null, {
        status: 302,
        headers: {
          Location: "/profile.html",
          "Set-Cookie": [
            `client_session=${newSessionId}; HttpOnly; Path=/; Max-Age=3600`,
            `oauth_state=; HttpOnly; Path=/; Max-Age=0`,
          ].join(", "),
        },
      })
    }

    // GET /user — return current logged-in user as JSON (called by profile.html)
    if (url.pathname === "/user") {
      if (!sessionId) return new Response(JSON.stringify({ error: "not_authenticated" }), { status: 401 })
      const user = sessions.get(sessionId)
      if (!user) return new Response(JSON.stringify({ error: "session_expired" }), { status: 401 })
      return new Response(JSON.stringify(user), { headers: { "Content-Type": "application/json" } })
    }

    // GET /logout — clear session and redirect to login
    if (url.pathname === "/logout") {
      if (sessionId) sessions.delete(sessionId)
      return new Response(null, {
        status: 302,
        headers: {
          Location: "/",
          "Set-Cookie": `client_session=; HttpOnly; Path=/; Max-Age=0`,
        },
      })
    }

    return new Response("Not found", { status: 404 })
  },
})

console.log(`OAuth Client App running at http://localhost:${PORT}`)
console.log(`  Auth Server: ${AUTH_SERVER_URL}`)
console.log(`  Client ID: ${CLIENT_ID}`)
