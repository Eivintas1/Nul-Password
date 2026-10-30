const enc = new TextEncoder();
async function hmac(secret, data) {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
  return btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
async function sign(secret, ttl = 86400) {
  const exp = Math.floor(Date.now() / 1000) + ttl;
  return `${exp}.${await hmac(secret, String(exp))}`;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/api/enter" && request.method === "POST") {
      const body = await request.json().catch(() => ({}));
      if (typeof body.code === "string" && body.code === env.ACCESS_KEY) {
        return new Response(JSON.stringify({ ok: true }), {
          headers: {
            "Content-Type": "application/json",
            "Set-Cookie": `nul_access=${await sign(env.GATE_SECRET)}; Domain=.nul.ac; Path=/; Max-Age=86400; Secure; HttpOnly; SameSite=Lax`,
          },
        });
      }
      return new Response(JSON.stringify({ ok: false }), {
        status: 401, headers: { "Content-Type": "application/json" },
      });
    }
    return env.ASSETS.fetch(request);
  },
};
