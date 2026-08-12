```
   ___    _         _   _        ____
  / _ \  / \  _   _| |_| |__   |  _ \  ___ _ __ ___   ___
 | | | |/ _ \| | | | __| '_ \  | | | |/ _ \ '_ ` _ \ / _ \
 | |_| / ___ \ |_| | |_| | | | | |_| |  __/ | | | | | (_) |
  \___/_/   \_\__,_|\__|_| |_| |____/ \___|_| |_| |_|\___/
```

> Build and run your own OAuth 2.0 Authorization Server, then learn the two most important flows — Authorization Code with a client secret, and PKCE for browser apps — all from scratch in Bun + TypeScript.

## Overview

This repo contains three apps:

| App | Port | Role |
|-----|------|------|
| `auth-server` | 3000 | The OAuth Authorization Server (shared by both flows) |
| `auth-code-flow/client-server` | 3001 | A traditional server-side app that uses a `client_secret` |
| `pkce-flow/browser-app` | 3002 | A pure browser SPA — all OAuth logic runs in browser JS |

## When to use which flow

| | Auth Code + Secret | PKCE |
|---|---|---|
| **You have a backend server?** | Yes | No (SPA / mobile) |
| **`client_secret`?** | Yes — stored on server, never sent to browser | No — a browser can't keep a secret |
| **Token lives in** | Server memory (session cookie is just a pointer) | Browser `sessionStorage` |
| **Threat mitigated** | Attacker can't exchange intercepted auth code without the secret | Attacker can't exchange intercepted auth code without the `code_verifier` |
| **Who calls `/userinfo`?** | The client-server (back-channel) | The browser directly |

---

## Architecture

```
  ┌───────────────────────────────────────────────────────────────────────┐
  │                            oauth-demo                                 │
  │                                                                       │
  │  ┌───────────────────────┐         ┌────────────────────────────────┐ │
  │  │   auth-code-flow/     │         │   auth-server (port 3000)      │ │
  │  │   client-server       │◄───────►│                                │ │
  │  │   (port 3001)         │back-    │  /authorize  login + consent   │ │
  │  │                       │channel  │  /approve    issue auth code   │ │
  │  │  /login  → redirect   │         │  /token      code → token      │ │
  │  │  /callback → exchange │         │  /userinfo   protected data    │ │
  │  │  /user → session JSON │         │                                │ │
  │  └───────────────────────┘         └───────────────────────────────-┘ │
  │                                              ▲                        │
  │  ┌───────────────────────┐                   │                        │
  │  │   pkce-flow/          │   browser JS ─────┘                        │
  │  │   browser-app         │   calls /token and /userinfo directly      │
  │  │   (port 3002)         │                                            │
  │  │                       │                                            │
  │  │  index.html  login    │                                            │
  │  │  callback.html        │                                            │
  │  │  profile.html         │                                            │
  │  └───────────────────────┘                                            │
  │                ▲                                                       │
  │                └──────────────── Browser ─────────────────────────────│
  └───────────────────────────────────────────────────────────────────────┘
```

---

## Auth Code + Secret Flow

The client-server exchanges the auth code using a `client_secret` that never leaves the server.

```
  Browser           client-server (3001)        auth-server (3000)
    │                      │                          │
    │── GET /login ────────►│                          │
    │                      │  [generate state nonce]  │
    │◄─ 302 /authorize?... ─│                          │
    │                       client_id                  │
    │                       redirect_uri               │
    │                       response_type=code         │
    │                       state=<nonce>              │
    │                                                  │
    │── GET /authorize?... ───────────────────────────►│
    │◄─ 200 login form ───────────────────────────── [validate client_id, redirect_uri]
    │                                                  │
    │── POST /login ──────────────────────────────────►│
    │                                            [authenticate user, set session cookie]
    │◄─ 302 back to /authorize ───────────────────────│
    │                                                  │
    │── GET /authorize (with session cookie) ─────────►│
    │◄─ 200 consent form ───────────────────────────── │
    │                                                  │
    │── POST /approve ────────────────────────────────►│
    │                                      [issue single-use auth code]
    │◄─ 302 /callback?code=...&state=... ─────────────│
    │                                                  │
    │── GET /callback?code=... ────────────►│          │
    │                      │  POST /token ─────────────►
    │                      │  code + client_id         │
    │                      │  + client_secret ←── only server knows this
    │                      │  + redirect_uri  [validate, consume code]
    │                      │◄─ { access_token } ───────│
    │                      │                           │
    │                      │  GET /userinfo ────────────►
    │                      │  Authorization: Bearer ... │
    │                      │◄─ { name, email } ─────────│
    │                      │                           │
    │                      │  [store in sessions Map]  │
    │◄─ 302 /profile.html ─│                           │
    │── GET /user ─────────►│                           │
    │◄─ { name, email } ───│                           │
```

---

## PKCE Flow

No client-server. The browser handles everything. `code_verifier` replaces the `client_secret`.

```
  Browser                                       auth-server (3000)
    │                                                 │
    │  [generate code_verifier = random 96 bytes]     │
    │  [compute code_challenge = SHA256(verifier)]    │
    │  [store verifier in sessionStorage]             │
    │                                                 │
    │── GET /authorize?                               │
    │     client_id=pkce-spa                          │
    │     code_challenge=<hash>    ──────────────────►│
    │     code_challenge_method=S256             [store challenge with auth code]
    │◄─ 200 login + consent page ─────────────────── │
    │                                                 │
    │── POST /login, POST /approve ──────────────────►│
    │◄─ 302 /callback.html?code=...&state=... ────────│
    │                                                 │
    │  [read code_verifier from sessionStorage]       │
    │                                                 │
    │── POST /token                                   │
    │     code                                        │
    │     code_verifier=<original random>  ──────────►│
    │     client_id=pkce-spa                    [SHA256(verifier) == stored challenge?]
    │     (no client_secret!)              [yes → issue access token]
    │◄─ { access_token } ────────────────────────────│
    │                                                 │
    │  [store access_token in sessionStorage]         │
    │                                                 │
    │── GET /userinfo                                 │
    │     Authorization: Bearer <token>  ────────────►│
    │◄─ { name, email } ─────────────────────────────│
    │                                                 │
    │  [show profile]                                 │
```

---

## Auth Server Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/authorize` | Validates `client_id`, `redirect_uri`. Accepts optional `code_challenge` + `code_challenge_method` for PKCE. Shows login + consent UI. |
| `POST` | `/login` | Authenticates user. Redirects back to `/authorize` preserving PKCE params. |
| `POST` | `/approve` | Issues single-use auth code (stores `code_challenge` if PKCE). Redirects to `redirect_uri`. |
| `POST` | `/token` | Exchanges auth code. **PKCE**: requires `code_verifier`, verifies `SHA256(verifier) == code_challenge`. **Secret**: requires `client_secret`. |
| `GET` | `/userinfo` | Returns `{ sub, name, email, username }`. Requires `Authorization: Bearer <token>`. CORS-enabled. |

---

## Setup

### Prerequisites

[Bun](https://bun.sh) >= 1.0 — no other dependencies.

### Run

Open three terminals:

```bash
# Terminal 1 — Auth Server (shared by both flows)
cd auth-server
bun start

# Terminal 2 — Auth Code flow (server-side app with client_secret)
cd auth-code-flow/client-server
bun start

# Terminal 3 — PKCE flow (pure browser app)
cd pkce-flow/browser-app
bun start
```

---

## Try It

### Auth Code flow — http://localhost:3001

1. Open **http://localhost:3001** and click **Login with OAuth**
2. Enter **alice** / **password123**, click Sign in → Approve
3. Profile page appears

**What to look for in DevTools:**
- The `/token` request (sent by the server, not the browser) is invisible in the Network tab — it's a back-channel call
- Browser only has a `client_session` cookie — no token visible anywhere

### PKCE flow — http://localhost:3002

1. Open **http://localhost:3002** and click **Login with PKCE**
2. Enter **alice** / **password123**, click Sign in → Approve
3. Watch the callback.html progress steps, then profile page appears

**What to look for in DevTools → Network:**
- The `/authorize` request URL contains `code_challenge=...` (a SHA256 hash)
- The `/token` request is visible — sent by the browser, contains `code_verifier` but **no `client_secret`**
- DevTools → Application → Session Storage → http://localhost:3002 → `access_token` is there

**The key difference:** in PKCE, the browser is doing the token exchange. In the Auth Code flow, the client-server does it back-channel so the browser never sees the token.

---

## Demo Users

| Username | Password | Name |
|----------|----------|------|
| alice | password123 | Alice Smith |
| bob | password456 | Bob Jones |

---

## What to explore next

- **Refresh tokens** — renew an expired access token without re-login
- **JWT access tokens** — encode user info in the token itself (stateless); use the `jose` library
- **Scopes** — let users grant partial access (`profile`, `email`, `write`)
- **Real database** — replace in-memory Maps with SQLite via Bun's built-in `bun:sqlite`
- **Token introspection** — `POST /introspect` endpoint for resource servers to validate opaque tokens
