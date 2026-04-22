// Copyright (c) 2026 Christopher Meng
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { Container, getContainer } from "@cloudflare/containers";
import appHtml from "./index.html";
import xxdCSS from "./style.css";
import xxdJS from "./client.js.txt";

// ── Helpers ──────────────────────────────────────────────────────────

// 64-char URL-safe alphabet — each byte & 63 selects one char with uniform
// probability (no modulo bias), which is why the size is exactly 64.
const SID_CHARS = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_";

function randomNonce(len) {
  const bytes = new Uint8Array(len);
  crypto.getRandomValues(bytes);
  let out = "";
  for (const b of bytes) out += SID_CHARS[b & 63];
  return out;
}

// HMAC-SHA-256 the visitor's IP + JA4 TLS fingerprint + a random nonce with
// a secret key. Returns a 64-char hex digest — opaque, fixed-length, one-way.
// JA4 is provided by Cloudflare Bot Management (request.cf.botManagement.ja4);
// mixing it in means bots that copy the sid cookie to a different client will
// end up on a different container shard than the original browser.
const te = new TextEncoder();

// Cache the imported CryptoKey at module scope so we pay importKey once per
// isolate instead of on every request. The secret guard keeps us correct if
// XXD_KEY is ever rotated — a changed env value busts the cache lazily.
let cachedKey = null;
let cachedSecret = null;
async function getHmacKey(secret) {
  if (cachedSecret !== secret) {
    cachedKey = await crypto.subtle.importKey(
      "raw", te.encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false, ["sign"],
    );
    cachedSecret = secret;
  }
  return cachedKey;
}

async function mintSid(secretKey, ip, ja4, nonce) {
  const key = await getHmacKey(secretKey);
  const sig = await crypto.subtle.sign("HMAC", key, te.encode(ip + ":" + ja4 + ":" + nonce));
  const hex = [];
  for (const b of new Uint8Array(sig)) hex.push(b.toString(16).padStart(2, "0"));
  return hex.join("");
}

function getCookie(req, name) {
  const hdr = req.headers.get("Cookie") || "";
  const m = hdr.match(new RegExp("(?:^|;\\s*)" + name + "=([^;]+)"));
  return m ? m[1] : null;
}

// Browsers always send Origin on POST and WS upgrade, so strict same-origin
// is enough to keep a third-party page from riding the visitor's IP to fire
// downloads (CSRF on /start, WS-hijack on /ws).
function isSameOrigin(request, url) {
  const origin = request.headers.get("Origin");
  return !!origin && origin === url.protocol + "//" + url.host;
}

async function sha256Hex(str) {
  const buf = await crypto.subtle.digest("SHA-256", te.encode(str));
  const hex = [];
  for (const b of new Uint8Array(buf)) hex.push(b.toString(16).padStart(2, "0"));
  return hex.join("");
}

// Control chars stripped + length-capped before interpolating user input into
// a log line. Keeps newline-based log injection out of Observability.
function tailSafe(s) {
  return String(s == null ? "" : s).replace(/[\x00-\x1f\x7f]/g, "?").slice(0, 2000);
}

// Per-(ip, ja4, url) request counter backed by KV. Max RL_LIMIT requests per
// RL_WINDOW seconds. Returns { blocked, count, retryAfter } where retryAfter
// is the seconds remaining before the current window expires.
//
// KV has a 60s minimum TTL, so we always extend the key to at least 60s; the
// actual window enforcement is done in-code via the stored `firstSeen`
// timestamp.
const RL_LIMIT = 3;
const RL_WINDOW = 600; // 10 minutes

async function rateLimit(kv, ip, ja4, targetUrl) {
  const key = "rl:" + (await sha256Hex(ip + ":" + ja4 + ":" + targetUrl));
  const nowSec = Math.floor(Date.now() / 1000);

  let firstSeen = nowSec;
  let count = 0;
  const raw = await kv.get(key);
  if (raw) {
    try {
      const obj = JSON.parse(raw);
      if (typeof obj.firstSeen === "number" && nowSec - obj.firstSeen < RL_WINDOW) {
        firstSeen = obj.firstSeen;
        count = obj.count || 0;
      }
    } catch (_) { /* treat as no state */ }
  }

  count += 1;
  const blocked = count > RL_LIMIT;
  const retryAfter = Math.max(1, firstSeen + RL_WINDOW - nowSec);

  // Write regardless so continued attempts don't reset the window.
  await kv.put(
    key,
    JSON.stringify({ firstSeen, count }),
    { expirationTtl: Math.max(60, retryAfter) },
  );

  return { blocked, count, retryAfter };
}

// ── Container ────────────────────────────────────────────────────────

// TODO (production roadmap):
//  1. Accept a URL, download the file (capped at container size).
//  2. Parse with xxd + objdump based on file suffix.
//  3. Stash the parsed result in R2.
//  4. Store the binary checksum in D1.

export class Xxd extends Container {
  defaultPort = 9999;
  sleepAfter = "10m"; // can be increased for larger files.
  onStart()       { console.log("Xxd started"); }
  onStop()        { console.log("Xxd stopped"); }
  onError(error)  { console.log("Xxd error:", error); }
}

// ── Worker entry ─────────────────────────────────────────────────────

const HTML = appHtml
  .replace("/* _CSS_ */", xxdCSS)
  .replace("/* _JS_ */", xxdJS);

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const ip = request.cf?.ip || request.headers.get("CF-Connecting-IP") || "unknown";
    const ja4 = request.cf?.botManagement?.ja4 || "none";
    const json = (obj, status = 200, extra) => new Response(JSON.stringify(obj), {
      status, headers: { "Content-Type": "application/json", ...(extra || {}) },
    });

    // Cookie format: "<nonce>.<sid>" where sid = HMAC(key, ip:ja4:nonce).
    // On every request we re-derive the expected sid from the *current*
    // IP + JA4 + the nonce in the cookie, and only accept the cookie if it
    // matches. A stolen cookie replayed from a different IP or a different
    // TLS client will fail verification and mint a fresh session.
    let sid = null;
    let nonce = null;
    let returning = false;
    let rejected = null;

    const cookie = getCookie(request, "sid");
    if (cookie) {
      const dot = cookie.indexOf(".");
      if (dot > 0) {
        const cnonce = cookie.slice(0, dot);
        const claimed = cookie.slice(dot + 1);
        const expected = await mintSid(env.XXD_KEY, ip, ja4, cnonce);
        if (expected === claimed) {
          sid = claimed;
          nonce = cnonce;
          returning = true;
        } else {
          rejected = "mismatch";
        }
      } else {
        rejected = "malformed";
      }
    }
    if (!returning) {
      nonce = randomNonce(10);
      sid = await mintSid(env.XXD_KEY, ip, ja4, nonce);
    }

    const { id: vid, tag: vtag } = env.XXD_VERSION_METADATA;
    console.log(`session: sid=${sid}, ip=${tailSafe(ip)}, ja4=${tailSafe(ja4)}, ` +
      `returning=${returning}, rejected=${rejected || "-"}, ` +
      `versionId=${vid}, versionTag=${vtag}`);
    const container = getContainer(env.XXD, sid);

    // All routes live under /xxd/ because the Cloudflare route is bound to
    // `demo.cicku.me/xxd*`. `path` is the pathname minus that prefix so each
    // handler below reads naturally (/, /version, /reset, /start, /ws, /ping).
    const path = url.pathname === "/xxd" ? "/" : url.pathname.replace(/^\/xxd/, "") || "/";

    // Main page
    if (path === "/") {
      const headers = new Headers({ "Content-Type": "text/html" });
      // On any fresh mint (brand-new visitor OR rejected cookie) issue the
      // new nonce.sid pair so the client swaps out any stale cookie.
      if (!returning) {
        headers.append("Set-Cookie",
          "sid=" + nonce + "." + sid + "; Path=/xxd; SameSite=Strict; HttpOnly; Secure");
      }
      const page = HTML
        .replace("<!-- _VTAG_ -->", env.XXD_VERSION_METADATA.tag || "")
        .replace("<!-- _VID_ -->", env.XXD_VERSION_METADATA.id || "");
      return new Response(page, { headers });
    }

    // Tiny probe the client hits after a dropped WebSocket. If the id the
    // page booted with differs from ours, the client hits /xxd/reset and
    // reloads, which reshards it onto a fresh DO + fresh container.
    if (path === "/version") {
      const { id = "", tag = "", timestamp = "" } = env.XXD_VERSION_METADATA;
      const bootId = url.searchParams.get("boot") || "";
      const bumped = !!(bootId && id && bootId !== id);
      console.log(`version-check: ip=${tailSafe(ip)}, sid=${sid}, boot=${tailSafe(bootId) || "-"}, ` +
        `current=${id || "-"}, tag=${tag || "-"}, timestamp=${timestamp || "-"}, bumped=${bumped}`);
      return json({ id, tag, timestamp, bumped }, 200, { "Cache-Control": "no-store" });
    }

    // Clear the sid cookie server-side (HttpOnly, so JS can't touch it).
    // Next page load mints a fresh nonce.sid, which shards to a different DO.
    if (path === "/reset") {
      console.log("sid-reset: ip=" + tailSafe(ip) + ", sid=" + sid);
      return new Response(null, { status: 204,
        headers: { "Set-Cookie": "sid=; Max-Age=0; Path=/xxd; SameSite=Strict; HttpOnly; Secure" } });
    }

    // Rate-limit pre-check. Client POSTs the target URL here before opening
    // the WebSocket; we refuse early if the visitor has exceeded the limit
    // for this particular (ip, ja4, url) combination in the last 10 minutes.
    if (path === "/start" && request.method === "POST") {
      if (!isSameOrigin(request, url)) {
        console.log("start-forbidden: ip=" + tailSafe(ip) +
          ", origin=" + tailSafe(request.headers.get("Origin") || "-"));
        return json({ error: "forbidden" }, 403);
      }
      let body;
      try { body = await request.json(); } catch (_) { body = null; }
      const targetUrl = body && typeof body.url === "string" ? body.url : "";
      if (!targetUrl) return json({ error: "missing url" }, 400);

      const rl = await rateLimit(env.XXD_RL, ip, ja4, targetUrl);
      if (!rl.blocked) return json({ ok: true, count: rl.count });

      console.log("rate-limit block: ip=" + tailSafe(ip) + ", ja4=" + tailSafe(ja4) +
        ", url=" + tailSafe(targetUrl) + ", count=" + rl.count +
        ", retryAfter=" + rl.retryAfter + "s, sid=" + sid);
      return json({
        error: "rate_limited", limit: RL_LIMIT, window: RL_WINDOW, retryAfter: rl.retryAfter,
        message: "You've submitted this URL " + rl.count + " times in the last " +
          Math.ceil(RL_WINDOW / 60) + " minutes. Please cool down for " +
          Math.ceil(rl.retryAfter / 60) + " more minute(s) before trying again.",
      }, 429, { "Retry-After": String(rl.retryAfter) });
    }

    // Proxy WebSocket + health check to the container. URL rewrite so
    // the container sees `/ws` or `/ping` — it stays oblivious to the public
    // `/xxd/...` access point. /ws needs a same-origin guard (a third-party
    // page could otherwise open a WS, send {type:"start", url:...}, and ride
    // the visitor's IP straight past /start's rate-limit); /ping is a plain
    // health probe and stays open for tooling that won't send Origin.
    if (path === "/ws" || path === "/ping") {
      if (path === "/ws" && !isSameOrigin(request, url)) {
        console.log("ws-forbidden: ip=" + tailSafe(ip) +
          ", origin=" + tailSafe(request.headers.get("Origin") || "-"));
        return new Response("forbidden", { status: 403 });
      }
      const upstream = new URL(request.url);
      upstream.pathname = path;
      return container.fetch(new Request(upstream, request));
    }

    return new Response("not found", { status: 404 });
  },
};
