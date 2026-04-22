# xxd-web

Paste a URL, get the first 256 bytes of every executable inside — rendered as a
colored hex dump in the browser. Built w/ Cloudflare Workers + Workers KV + Containers (Alpine Linux).

Live demo: <https://demo.cicku.me/xxd>

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/cicku/xxd-web/)

## How it works

1. The Worker (`src/xxd.js`) serves the page, HMACs a session id
   (`HMAC(secret, ip ⊕ ja4 ⊕ nonce)`), enforces a per-(ip, ja4, url) rate
   limit upon submission, and routes the WebSocket to a container keyed by unique
   session id.
2. The container (`server.js`) downloads the URL using `curl`,
   and dispatches to the right tool based on the suffix:
   - **Streams** (`.gz .Z .bz2 .xz .lzma .lz .lz4 .zst .br`) — `bsdcat` or
     `brotli -d -c`, piped through `pv` for progress.
   - **Archives** — `bsdtar` (libarchive) for tar, zip-family (`.jar .whl .ipa
     .apk .msix .vsix .nupkg .aab` …), `.7z`, `.rar`, `.cab`, `.iso`, `.xar`,
     `.pkg`, `.rpm`, `.deb`, `.cpio`, `.ar`, `.ova`, and compound `.tar.gz` /
     `.xz` / `.zst` / `.lz4` / etc.
   - **`p7zip` fallback** — `.dmg`, `.msi`, `.wim/esd/swm`, `.hfs`, `.vhd(x)`,
     `.vdi`, `.chm` (formats libarchive can't read).
   - **`unsquashfs`** — `.squashfs`, `.sqsh`, `.snap`.
   - **`brotli-tar`** — `.tar.br` (two-stage `brotli | bsdtar`).
3. For every extracted file, `file -b` identifies the type. Only files
   `file(1)` calls *executable* (ELF, Mach-O, PE/MZ) get `xxd -l 256`; data,
   scripts, images, shared objects are listed and skipped.
4. Stdout/stderr stream back over the WebSocket while being replayable.

## Local development

```sh
npm install
npm run dev       # wrangler dev — Worker runs locally, container runs in Docker
```

You'll also need:
- Docker running (wrangler builds the container image from `Dockerfile`).
- A local secret: `echo "XXD_KEY=$(openssl rand -hex 32)" > .dev.vars`.

## Deploy

```sh
npx wrangler secret put XXD_KEY                 # 32+ random bytes
npx wrangler kv namespace create XXD_RL         # then paste the id into wrangler.jsonc
npm version patch   # or minor / major — bumps package.json's version
npm run deploy      # ships as --tag v<version> automatically
```

Route: `demo.cicku.me/xxd*` (set in `wrangler.jsonc`).

## Bindings

| Name                   | Kind            | Purpose                               |
| ---------------------- | --------------- | ------------------------------------- |
| `XXD`                  | Durable Object  | Per-session Container instance        |
| `XXD_RL`               | KV              | Rate-limit counters                   |
| `XXD_KEY`              | Secret          | HMAC key for session ids              |
| `XXD_VERSION_METADATA` | Version metadata| Surfaced to client for reload prompts |

## Limits

- **10 GiB**
- **3 requests per 10 minutes**
- Archives with passwords or corruption are skipped.
- `sid` rotation can exhaust the predefined container quantity limit, right now the issue is ignored because of the demo purpose. 

## License

MPL-2.0 © 2026 Christopher Meng.