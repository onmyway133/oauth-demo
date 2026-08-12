```
   ___    _         _   _        ____
  / _ \  / \  _   _| |_| |__   |  _ \  ___ _ __ ___   ___
 | | | |/ _ \| | | | __| '_ \  | | | |/ _ \ '_ ` _ \ / _ \
 | |_| / ___ \ |_| | |_| | | | | |_| |  __/ | | | | | (_) |
  \___/_/   \_\__,_|\__|_| |_| |____/ \___|_| |_| |_|\___/
```

> Build and run your own OAuth 2.0 Authorization Server to learn how real servers issue auth codes, exchange them for access tokens, and protect resources — all from scratch in Bun + TypeScript.

## Overview

- **Authorization Code Flow** — the most secure OAuth 2.0 grant type for server-side apps
- **Auth Server** — issues auth codes after user consent, then exchanges codes for access tokens
- **Client Credentials** — registered `client_id` + `client_secret` identify the application
- **Redirect URI** — must exactly match a pre-registered value (prevents open redirect attacks)
- **State Parameter** — random nonce to prevent CSRF attacks on the callback endpoint
- **Single-Use Codes** — auth codes expire in 10 minutes and are deleted after one use
- **Bearer Token** — the access token sent as `Authorization: Bearer <token>` on API calls
- **Protected Resource** — `/userinfo` rejects requests without a valid, non-expired token

## Architecture

```
  ┌─────────────────────────────────────────────────────────────────┐
  │                         oauth-demo                              │
  │                                                                 │
  │  ┌──────────────────────┐       ┌───────────────────────────┐  │
  │  │   client-app         │       │   auth-server             │  │
  │  │   port 3001          │       │   port 3000               │  │
  │  │                      │       │                           │  │
  │  │  public/             │       │  /authorize  (login +     │  │
  │  │    index.html        │◄─────►│              consent)     │  │
  │  │    profile.html      │       │  /approve    (issue code) │  │
  │  │                      │       │  /token      (code→token) │  │
  │  │  src/server.ts       │       │  /userinfo   (protected)  │  │
  │  │    /login            │       │                           │  │
  │  │    /callback         │       │  In-memory stores:        │  │
  │  │    /user             │       │    clients, users,        │  │
  │  │    /logout           │       │    codes, tokens,         │  │
  │  │                      │       │    sessions               │  │
  │  └──────────────────────┘       └───────────────────────────┘  │
  │                ▲                          ▲                     │
  │                │                          │                     │
  │                └─────────── Browser ──────┘                     │
  └─────────────────────────────────────────────────────────────────┘
```

## Sequence Diagram

```
  Browser              client-app (3001)         auth-server (3000)
    │                        │                          │
    │── GET / ──────────────►│                          │
    │◄─ index.html ──────────│                          │
    │   [Login button]       │                          │
    │                        │                          │
    │── GET /login ─────────►│                          │
    │                        │  [generate state nonce]  │
    │◄─ 302 Location: ───────│                          │
    │    /authorize?          │                          │
    │      client_id          │                          │
    │      redirect_uri       │                          │
    │      response_type=code │                          │
    │      state=<nonce>      │                          │
    │                        │                          │
    │── GET /authorize?... ──────────────────────────►  │
    │◄─ 200 consent page ──────────────────────────── [validate client_id,
    │   [login form]         │                          redirect_uri]
    │                        │                          │
    │── POST /login ─────────────────────────────────►  │
    │   username, password   │                    [authenticate user,
    │                        │                    create session cookie]
    │◄─ 302 back to ─────────────────────────────────   │
    │   /authorize           │                          │
    │                        │                          │
    │── GET /authorize?... ──────────────────────────►  │
    │◄─ 200 consent page ─────────────────────────── [user logged in,
    │   [Approve/Deny]       │                         show approve form]
    │                        │                          │
    │── POST /approve ───────────────────────────────►  │
    │                        │               [generate single-use auth code]
    │◄─ 302 Location: ───────────────────────────────   │
    │    /callback?          │                          │
    │      code=<authcode>   │                          │
    │      state=<nonce>     │                          │
    │                        │                          │
    │── GET /callback?code= ►│                          │
    │                        │  [verify state matches cookie]
    │                        │                          │
    │                        │── POST /token ──────────►│
    │                        │   grant_type=authorization_code
    │                        │   code, client_id,       │
    │                        │   client_secret,         │
    │                        │   redirect_uri      [validate code,
    │                        │                    client credentials,
    │                        │                    consume code (single-use)]
    │                        │◄─ { access_token,        │
    │                        │    token_type: "Bearer",  │
    │                        │    expires_in: 3600 } ───│
    │                        │                          │
    │                        │── GET /userinfo ─────────►
    │                        │   Authorization:         │
    │                        │   Bearer <access_token>  │
    │                        │                   [validate token,
    │                        │                    look up user]
    │                        │◄─ { sub, name,           │
    │                        │    email, username } ────│
    │                        │                          │
    │                        │  [store user in session] │
    │◄─ 302 /profile.html ───│                          │
    │                        │                          │
    │── GET /user ──────────►│                          │
    │◄─ { name, email } ─────│                          │
    │   [show profile]       │                          │
```

## Auth Server Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/authorize` | Validates `client_id`, `redirect_uri`, shows login + consent UI |
| `POST` | `/login` | Authenticates user; redirects back to `/authorize` with session cookie |
| `POST` | `/approve` | Issues single-use auth code; redirects to `redirect_uri?code=...` |
| `POST` | `/token` | Exchanges auth code for access token; validates client secret |
| `GET` | `/userinfo` | Returns user JSON; requires `Authorization: Bearer <token>` |

## Client App Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Login page with "Login with OAuth" button |
| `GET` | `/login` | Redirects browser to auth server `/authorize` |
| `GET` | `/callback` | Receives auth code, exchanges for token, fetches user info |
| `GET` | `/user` | Returns current user from session (called by profile page) |
| `GET` | `/logout` | Clears session; redirects to login page |

## Setup

### Prerequisites

- [Bun](https://bun.sh) >= 1.0

### Install

No packages to install — uses only Bun built-ins.

### Environment

Copy `.env.example` and adjust if needed:

```bash
cp .env.example .env
```

Default values already match the demo — no changes required to run locally.

### Run

Open two terminal tabs:

```bash
# Terminal 1 — Auth Server
cd auth-server
bun start
# → OAuth Authorization Server running at http://localhost:3000

# Terminal 2 — Client App
cd client-app
bun start
# → OAuth Client App running at http://localhost:3001
```

## Try It

1. Open **http://localhost:3001** in your browser
2. Click **Login with OAuth** — you are redirected to the auth server
3. Enter credentials: **alice** / **password123**
4. Click **Sign in** → consent screen appears
5. Click **Approve** → redirected back to the client app
6. Profile page shows Alice's name and email

### curl the API directly

After login, grab the access token from the server logs or by repeating the flow manually:

```bash
# Exchange a code (replace <code> with an actual code from the /approve redirect)
curl -X POST http://localhost:3000/token \
  -d "grant_type=authorization_code&code=<code>&client_id=demo-app&client_secret=demo-secret&redirect_uri=http://localhost:3001/callback"

# Call the protected resource
curl http://localhost:3000/userinfo \
  -H "Authorization: Bearer <access_token>"
```

## Demo Users

| Username | Password | Name |
|----------|----------|------|
| alice | password123 | Alice Smith |
| bob | password456 | Bob Jones |

## What to explore next

- Add **refresh tokens** so access tokens can be renewed without re-login
- Add **PKCE** (Proof Key for Code Exchange) for public clients that can't store a secret
- Store clients and tokens in a real database instead of in-memory Maps
- Add **scopes** so users can grant partial access
- Replace the session cookie with a **JWT** (`jose` library)
