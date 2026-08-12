import { join } from "path"

const PORT = parseInt(process.env.PKCE_PORT ?? "3002")

const server = Bun.serve({
  port: PORT,
  async fetch(req) {
    const url = new URL(req.url)

    // Map / to index.html
    let filePath = url.pathname === "/" ? "/index.html" : url.pathname

    // Only serve files from public/
    const fullPath = join(import.meta.dir, "../public", filePath)
    const file = Bun.file(fullPath)
    if (!(await file.exists())) return new Response("Not found", { status: 404 })
    return new Response(file)
  },
})

console.log(`PKCE Browser App running at http://localhost:${PORT}`)
console.log(`  All OAuth logic (PKCE, token exchange, userinfo) runs in the browser`)
console.log(`  Auth Server expected at http://localhost:3000`)
