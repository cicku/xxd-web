// Copyright (c) 2026 Christopher Meng
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

const fs = require("fs");
const fsp = require("fs").promises;
const path = require("path");
const http = require("http");
const { spawn } = require("child_process");
const { WebSocketServer } = require("ws");

const WORK_DIR = "/ext";
const PING_MSG = JSON.stringify({ type: "ping" });
const MAX_BYTES = 10 * 1024 * 1024 * 1024;  // 10 GiB cap on remote downloads

// Decompression dispatch.
//   streams     — single-file decompressors (pv | DECOMP > OUT).
//                 bsdcat covers gzip/bz2/xz/lzma/lz/lz4/zst/compress; brotli(1)
//                 covers .br since libarchive has no brotli support.
//   bsdtar      — libarchive covers tar (+ native decompression for tar.gz /
//                 .bz2 / .xz / .lzma / .lz / .zst / .lz4), zip-family (jar,
//                 whl, ipa, apk, msix, ...), 7z, rar, cab, iso, xar, pkg, rpm,
//                 deb/udeb/ipk, cpio, ar, ova.
//   7z          — p7zip for formats libarchive can't read (dmg, msi, wim/esd,
//                 hfs, vhd/vhdx, vdi, chm).
//   unsquashfs  — squashfs-tools for squashfs / snap.
//   brotli-tar  — two-step: brotli -d -c | bsdtar - for .tar.br (libarchive
//                 lacks brotli, so bsdtar can't do this natively).
const STREAM_EXTS = [".gz", ".Z", ".bz2", ".xz", ".lzma", ".lz", ".lz4", ".zst", ".br"];

// Compound tar.X — MUST be checked before STREAM_EXTS so we extract instead of
// decompressing to a raw tar blob and hex-dumping its header. bsdtar handles
// all of these natively in a single pass.
const BSDTAR_COMPOUND_EXTS = [
  ".tar.gz", ".tar.bz2", ".tar.xz", ".tar.lzma",
  ".tar.lz", ".tar.z", ".tar.zst", ".tar.lz4",
];
const BROTLI_TAR_EXT = ".tar.br";

const BSDTAR_EXTS = [
  // Tar + common aliases
  ".tar", ".tgz", ".tbz2", ".tbz", ".txz", ".tlz", ".tzst", ".tlz4",
  // ZIP-based formats (all readable as zip by libarchive)
  ".zip",
  ".jar", ".war", ".ear", ".aar",
  ".whl", ".egg",
  ".ipa", ".xpi", ".crx",
  ".msix", ".appx", ".appxbundle", ".msixbundle", ".vsix", ".nupkg",
  ".apk", ".aab", ".xapk", ".apkm",
  // Native archive formats
  ".7z", ".rar",
  ".cab", ".iso", ".xar", ".pkg",
  ".rpm", ".deb", ".udeb", ".ddeb", ".ipk",
  ".cpio", ".ar", ".ova",
];

const P7ZIP_EXTS = [
  ".dmg",
  ".msi",
  ".wim", ".esd", ".swm",
  ".hfs", ".hfsx",
  ".vhd", ".vhdx",
  ".vdi",
  ".chm",
];

const SQUASH_EXTS = [".squashfs", ".sqsh", ".snap"];

function classify(name) {
  const lower = name.toLowerCase();
  const matches = (exts) => exts.find((e) => lower.endsWith(e));

  // Compound tar.X must win over the single-suffix stream check or we'd
  // decompress to a bare tar and hex-dump its header.
  if (matches(BSDTAR_COMPOUND_EXTS)) return { kind: "archive", tool: "bsdtar" };
  if (lower.endsWith(BROTLI_TAR_EXT)) return { kind: "archive", tool: "brotli-tar" };

  const stream = matches(STREAM_EXTS);
  if (stream) return { kind: "stream", ext: stream };

  if (matches(BSDTAR_EXTS)) return { kind: "archive", tool: "bsdtar" };
  if (matches(P7ZIP_EXTS))  return { kind: "archive", tool: "7z" };
  if (matches(SQUASH_EXTS)) return { kind: "archive", tool: "unsquashfs" };

  return { kind: "plain" };
}

// True for any IP literal we should never dial — loopback, RFC1918, CGNAT,
// link-local, IPv6 ULA, multicast, etc. Run both on URL hosts up front and
// on whatever IP curl actually resolved to (catches DNS rebinding).
function isPrivateIp(raw) {
  if (!raw) return false;
  const ip = String(raw).trim().replace(/^\[|\]$/g, "").toLowerCase();

  const v4 = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    const a = +v4[1], b = +v4[2];
    return a === 0 || a === 10 || a === 127
        || (a === 169 && b === 254)
        || (a === 172 && b >= 16 && b <= 31)
        || (a === 192 && b === 168)
        || (a === 100 && b >= 64 && b <= 127)
        || a >= 224;
  }

  const mapped = ip.match(/^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (mapped) return isPrivateIp(mapped[1]);

  if (ip === "::" || ip === "::1") return true;
  return /^f[cd]/.test(ip)          // fc00::/7 ULA
      || /^fe[89ab]/.test(ip)       // fe80::/10 link-local
      || ip.startsWith("ff");       // multicast
}

const BLOCKED_HOSTS = new Set(["localhost", "ip6-localhost", "ip6-loopback"]);
function isBlockedHost(host) {
  const h = String(host || "").toLowerCase();
  return BLOCKED_HOSTS.has(h)
      || h.endsWith(".localhost")
      || h.endsWith(".local")       // mDNS
      || h.endsWith(".internal");   // k8s / GCP
}

// Filenames come from untrusted URLs, so we shell-safe them here rather than
// trusting every downstream quoter. The regex keeps alnum + "._-" and throws
// everything else away; bare dots become "download" to avoid writing to /ext/.
function safeName(raw) {
  const n = raw.replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 200);
  return (!n || n === "." || n === "..") ? "download" : n;
}

function pathsFor(url) {
  const u = new URL(url);
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    throw new Error("Only http(s) URLs are allowed");
  }

  const host = u.hostname.replace(/^\[|\]$/g, "");
  if (isBlockedHost(host)) throw new Error("Refusing to fetch from a local/private hostname");
  if (isPrivateIp(host))   throw new Error("Refusing to fetch from a private-range IP");

  const name = safeName(u.pathname.split("/").pop() || "download");
  const port = u.port || (u.protocol === "https:" ? "443" : "80");
  return {
    url, name, host, port,
    info: classify(name),
    file: WORK_DIR + "/" + name,
    extractDir: WORK_DIR + "/extract",
  };
}

// xxd state (one run at a time)
let xxdState = "idle";  // idle | running | done | error
let xxdStartedAt = null;
const clients = new Set();

// Replay log. Capped so a noisy run (pv progress, 10k-entry tarball listings)
// doesn't blow up memory or the bytes sent to reconnecting clients. When the
// array passes TRIM_AT we slice down to MAX_LOG in one splice (amortised O(1)
// per entry) and remember the drop count so replays can surface it.
const MAX_LOG = 5000;
const TRIM_AT = 6000;
const messageLog = [];
let lastStepIdx = -1;   // index of the most recent "step" in messageLog, or -1
let truncated = 0;      // total entries dropped by the ring buffer

function xterm(type, data) {
  const msg = JSON.stringify({ type, ...data });
  if (type !== "stderr" && type !== "ping") {
    if (type === "step-update") {
      // O(1) patch of the last step. If it's been trimmed out, silently drop —
      // live clients still received the update over the wire above.
      if (lastStepIdx >= 0 && lastStepIdx < messageLog.length) {
        messageLog[lastStepIdx] = msg.replace('"step-update"', '"step"');
      }
    } else {
      if (type === "step") lastStepIdx = messageLog.length;
      messageLog.push(msg);
      if (messageLog.length > TRIM_AT) {
        const dropped = messageLog.length - MAX_LOG;
        messageLog.splice(0, dropped);
        lastStepIdx = Math.max(-1, lastStepIdx - dropped);
        truncated += dropped;
      }
    }
  }
  for (const c of clients) {
    if (c.readyState === 1) c.send(msg);
  }
}

function replay(ws) {
  if (ws.readyState !== 1) return;
  if (truncated > 0) {
    ws.send(JSON.stringify({ type: "truncated", dropped: truncated }));
  }
  for (const m of messageLog) {
    if (ws.readyState !== 1) return;
    ws.send(m);
  }
}

// Dump buffered stderr lines (only called on failure)
function dumpStderr(buf) {
  for (const line of buf.join("").split(/\r?\n/).filter(Boolean)) {
    xterm("stderr", { data: line });
  }
}

// Run a shell command and resolve with trimmed stdout. On non-zero exit we
// reject with an Error carrying the exit code and stderr tail — most CLIs put
// the real diagnostic there. Chunks are concat'd once at close so we don't
// quadratically grow a rope, and multi-byte UTF-8 across chunk boundaries
// decodes cleanly.
function captureCmd(cmd, args) {
  return new Promise((resolve, reject) => {
    const proc = spawn(cmd, args);
    const outChunks = [], errChunks = [];
    proc.stdout.on("data", (c) => outChunks.push(c));
    proc.stderr.on("data", (c) => errChunks.push(c));
    proc.on("close", (code) => {
      const out = Buffer.concat(outChunks).toString().trim();
      const err = Buffer.concat(errChunks).toString().trim();
      if (code === 0) return resolve(out);
      const msg = cmd + " exited " + code + (err ? ": " + err : "");
      reject(Object.assign(new Error(msg), { stderr: err, code }));
    });
    proc.on("error", reject);
  });
}

// Data center this container is running in — injected by the Containers
// runtime alongside CLOUDFLARE_REGION / CLOUDFLARE_COUNTRY_A2. Diagnostic use.
const COLO = process.env.CLOUDFLARE_LOCATION || "unknown";

// Control chars stripped + length-capped before interpolating user input into
// a log line. Keeps newline-based log injection out of Observability.
function tailSafe(s) {
  return String(s == null ? "" : s).replace(/[\x00-\x1f\x7f]/g, "?").slice(0, 2000);
}

// Which IP did curl resolve? Used only for diagnostic logging on probe
// failures, so "unknown" is fine on error.
async function resolveIp(url) {
  try {
    return await captureCmd("curl", [
      "-sLk", "--max-time", "5",
      "--proto", "=http,https", "--proto-redir", "=http,https",
      "-o", "/dev/null", "-w", "%{remote_ip}", "--", url,
    ]) || "unknown";
  } catch (_) { return "unknown"; }
}

// Format a byte count as a human-readable IEC string ("12.3 GiB").
function humanBytes(n) {
  const u = ["B", "KiB", "MiB", "GiB", "TiB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n.toFixed(0) : n.toFixed(2)) + " " + u[i];
}

// We pass --write-out on the same stdout stream as -D (header dump), so we
// need a marker curl's writeout prepends that no real header line can match.
const META_SENTINEL = "\n__XXD_META__:";

// Probe size + Content-Type without downloading, and return the IP curl
// actually connected to. HEAD first; fall back to a 1-byte ranged GET for
// servers that refuse HEAD or omit Content-Length on it. Protocol is locked
// to http/https on both the initial request and any redirect, so no redirect
// can pivot us to file://, gopher://, dict:// and friends.
//
// Throws on a fully failed probe, or when the resolved IP is in a private
// range (the canonical SSRF signal: user supplied a hostname that points at
// internal infra, or tried a rebinding trick).
async function probeResource(url) {
  const common = [
    "--max-time", "15", "--max-redirs", "10",
    "--proto", "=http,https", "--proto-redir", "=http,https",
    "-D", "-", "-o", "/dev/null",
    "-w", META_SENTINEL + "remote_ip=%{remote_ip}\n",
  ];
  const tries = [
    ["curl", "-sIL", ...common, "--", url],
    ["curl", "-sL", ...common, "-r", "0-0", "--", url],
  ];

  let lastErr = null;
  let errStatus = null;        // last 4xx/5xx — only surfaced if nothing ever succeeded
  let sawOk = false;
  let contentType = null;
  let ip = null;

  for (const args of tries) {
    let out;
    try { out = await captureCmd(args[0], args.slice(1)); }
    catch (e) { lastErr = e; continue; }

    const sentIdx = out.indexOf(META_SENTINEL);
    const headers = sentIdx >= 0 ? out.slice(0, sentIdx) : out;
    const meta    = sentIdx >= 0 ? out.slice(sentIdx + META_SENTINEL.length) : "";
    const thisIp  = (meta.match(/remote_ip=([^\s]+)/) || [])[1] || null;

    const statuses = [...headers.matchAll(/^HTTP\/[\d.]+\s+(\d+)/gm)];
    const status = statuses.length ? +statuses[statuses.length - 1][1] : null;

    // A 404 on HEAD doesn't invalidate a 200 on the ranged-GET fallback.
    if (status && status >= 400) { errStatus = status; continue; }
    sawOk = true;

    if (thisIp) {
      if (isPrivateIp(thisIp)) {
        throw new Error("Refusing to fetch \u2014 URL resolved to a private-range IP (" + thisIp + ")");
      }
      ip = thisIp;
    }

    if (!contentType) {
      const ct = [...headers.matchAll(/^Content-Type:\s*([^\r\n;]+)/gim)].pop();
      if (ct) contentType = ct[1].trim().toLowerCase();
    }

    const cl = [...headers.matchAll(/^Content-Length:\s*(\d+)/gim)].pop();
    if (cl) return { size: +cl[1], contentType, ip };

    const cr = headers.match(/^Content-Range:\s*bytes\s+\d+-\d+\/(\d+)/im);
    if (cr) return { size: +cr[1], contentType, ip };
  }

  if (sawOk) return { size: null, contentType, ip };
  if (errStatus) {
    throw new Error("URL returned HTTP " + errStatus + " \u2014 please check the link and try a different URL");
  }
  if (lastErr) {
    const probedIp = await resolveIp(url);
    console.log([tailSafe(probedIp), tailSafe(url), COLO].join(","));
    throw new Error("Size probe failed: " + lastErr.message);
  }
  return { size: null, contentType, ip };
}

// Keep only the tail of a captured stream. bsdtar -v on a 10k-entry archive
// would otherwise grow a multi-hundred-MB string just so badArchive() can
// grep the last few lines for an error phrase.
//
// Chunks go in as-is (O(1) push) and we only drop from the front once we
// cross 2*BUF_CAP. The join+slice happens once, on the error path.
const BUF_CAP = 64 * 1024;
function createCappedBuf() {
  const chunks = [];
  let total = 0;
  return {
    push(text) {
      chunks.push(text);
      total += text.length;
      while (total > BUF_CAP * 2 && chunks.length > 1) {
        total -= chunks.shift().length;
      }
    },
    value() {
      if (chunks.length === 0) return "";
      const s = chunks.length === 1 ? chunks[0] : chunks.join("");
      return s.length > BUF_CAP ? s.slice(-BUF_CAP) : s;
    },
  };
}

// Run a shell command, streaming both stdout and stderr to connected clients.
// `streamType` controls the message type for stdout lines — defaults to
// "stdout"; pass "xxd-line" so the client knows to mirror it into the final
// result box. Stderr is always sent as "stderr" since most tools use it for
// progress/diagnostics (curl -v, tar -v, pv, etc.) rather than errors.
function runCmd(label, cmd, args, streamType = "stdout") {
  return new Promise((resolve, reject) => {
    xterm("step", { label });
    const proc = spawn(cmd, args);
    const stdoutBuf = createCappedBuf();
    const stderrBuf = createCappedBuf();

    // Pipe chunks land at ~64 KiB boundaries, so a single line often straddles
    // two reads. Hold the trailing partial in `leftover` until we see its \n;
    // flush it on stream end. Skipping this tears lines in the UI and multiplies
    // the xterm/JSON.stringify/send cost for every client.
    function relay(stream, type, buf) {
      let leftover = "";
      stream.on("data", (chunk) => {
        const text = chunk.toString();
        buf.push(text);
        const combined = leftover + text;
        const nl = combined.lastIndexOf("\n");
        if (nl < 0) { leftover = combined; return; }
        leftover = combined.slice(nl + 1);
        for (const line of combined.slice(0, nl).split("\n")) {
          xterm(type, { data: line });
        }
      });
      stream.on("end", () => {
        if (leftover) xterm(type, { data: leftover });
      });
    }
    relay(proc.stdout, streamType, stdoutBuf);
    relay(proc.stderr, "stderr", stderrBuf);

    proc.on("close", (code) => {
      if (code === 0) return resolve();
      const msg = label + " exited with code " + code;
      reject(Object.assign(new Error(msg), {
        code, stderr: stderrBuf.value(), stdout: stdoutBuf.value(),
      }));
    });
    proc.on("error", reject);
  });
}

// Render raw terminal output (cursor movement + colors) into flat lines.
// Commands like fastfetch draw a 2D layout; this resolves it into rows.
function renderVT(raw) {
  const grid = [];  // grid[row][col] = { ch, sgr }
  let r = 0, c = 0, sgr = "";

  function growGrid(row, col) {
    while (grid.length <= row) grid.push([]);
    while (grid[row].length <= col) grid[row].push(null);
  }

  let i = 0;
  while (i < raw.length) {
    // CSI sequence: ESC [ <params> <command>
    if (raw[i] === "\x1b" && raw[i + 1] === "[") {
      let j = i + 2, p = "";
      while (j < raw.length && !((raw[j] >= "A" && raw[j] <= "Z") || (raw[j] >= "a" && raw[j] <= "z"))) {
        p += raw[j]; j++;
      }
      if (j >= raw.length) { i = j; continue; }
      const cmd = raw[j++];
      if (p.indexOf("?") >= 0) { i = j; continue; }  // skip private modes
      switch (cmd) {
        case "m":
          if (p === "" || p === "0") sgr = "";
          else sgr += "\x1b[" + p + "m";
          break;
        case "A": r = Math.max(0, r - (parseInt(p) || 1)); break;
        case "B": r += parseInt(p) || 1; break;
        case "C": c += parseInt(p) || 1; break;
        case "D": c = Math.max(0, c - (parseInt(p) || 1)); break;
        case "G": c = (parseInt(p) || 1) - 1; break;
        case "H": case "f": {
          const sp = p.split(";");
          r = (parseInt(sp[0]) || 1) - 1;
          c = (parseInt(sp[1]) || 1) - 1;
          break;
        }
      }
      i = j; continue;
    }
    if (raw[i] === "\n") { r++; c = 0; i++; continue; }
    if (raw[i] === "\r") { c = 0; i++; continue; }
    growGrid(r, c);
    grid[r][c] = { ch: raw[i], sgr };
    c++;
    i++;
  }

  // Build each line from the grid, inserting SGR only when it changes
  const lines = [];
  for (let ri = 0; ri < grid.length; ri++) {
    const row = grid[ri] || [];
    let end = row.length;
    while (end > 0 && (!row[end - 1] || (row[end - 1].ch === " " && !row[end - 1].sgr))) end--;
    let line = "", prev = "";
    for (let ci = 0; ci < end; ci++) {
      const cell = row[ci];
      if (!cell) { line += " "; continue; }
      if (cell.sgr !== prev) {
        if (prev) line += "\x1b[0m";
        if (cell.sgr) line += cell.sgr;
        prev = cell.sgr;
      }
      line += cell.ch;
    }
    if (prev) line += "\x1b[0m";
    lines.push(line);
  }
  while (lines.length && !lines[lines.length - 1]) lines.pop();
  return lines;
}

// Like runCmd but buffers stdout and renders it through a VT100 grid.
function colorfulVT(label, cmd, args) {
  return new Promise((resolve, reject) => {
    xterm("step", { label });
    const proc = spawn(cmd, args, { env: { ...process.env, TERM: "xterm-256color" } });
    const stdoutBuf = [];
    const stderrBuf = [];

    proc.stdout.on("data", (chunk) => stdoutBuf.push(chunk.toString()));
    proc.stderr.on("data", (chunk) => stderrBuf.push(chunk.toString()));

    proc.on("close", (code) => {
      if (code === 0) {
        const lines = renderVT(stdoutBuf.join(""));
        xterm("stdout", { data: "" });
        for (const line of lines) {
          if (line) xterm("stdout", { data: line });
        }
        return resolve(lines);
      }
      dumpStderr(stderrBuf);
      reject(new Error(label + " exited with code " + code));
    });

    proc.on("error", reject);
  });
}

// fastfetch output rarely changes inside a long-lived container, so we render
// it once and replay the cached lines on subsequent runs.
let osInfoCache = null;
async function osInfo() {
  if (osInfoCache) {
    xterm("step", { label: "OS information:" });
    xterm("stdout", { data: "" });
    for (const line of osInfoCache) {
      if (line) xterm("stdout", { data: line });
    }
    return;
  }
  // --pipe false stops fastfetch from auto-detecting our piped stdout and
  // disabling colors; we want the SGR codes preserved so renderVT can replay
  // them through the client's ANSI-to-HTML helper.
  osInfoCache = await colorfulVT("OS information:", "fastfetch", ["--pipe", "false"]);
}

let currentPaths = null;

// Recursive directory walk → flat list of regular file paths. Async so a
// 10k-entry extract tree doesn't stall WS pings and concurrent stdout relays.
async function walkFiles(dir) {
  const out = [];
  for (const entry of await fsp.readdir(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory())   out.push(...(await walkFiles(full)));
    else if (entry.isFile())   out.push(full);
  }
  return out;
}

// True if the given file name looks like another compressed/archived blob we
// could in principle recurse into. Just flag it forTODO.
function isNested(name) {
  return classify(name).kind !== "plain";
}

// Nuke an output directory and recreate it empty. Async because removing a
// previous extract tree of thousands of files is otherwise the worst blocking
// call in the process.
async function freshDir(dir) {
  try { await fsp.rm(dir, { recursive: true, force: true }); } catch (_) {}
  await fsp.mkdir(dir, { recursive: true });
}

async function runXxd(url) {
  xxdState = "running";
  xxdStartedAt = new Date().toISOString();
  currentPaths = pathsFor(url);
  const { name, host, port, file, extractDir, info } = currentPaths;

  fs.mkdirSync(WORK_DIR, { recursive: true });

  // Show what we're running on (cached after first invocation).
  await osInfo();
  xterm("stdout", { data: "" });

  // Download the source file (skip if it's already on disk from a previous run).
  if (fs.existsSync(file)) {
    xterm("step", { label: name + " already downloaded, skipping" });
  } else {
    // Probe size + content-type first. Refuse HTML pages outright and
    // refuse anything over the cap before paying the bandwidth to fetch it.
    // probeResource also throws if the URL resolves to a private-range IP.
    xterm("step", { label: "Checking size of " + name + "..." });
    const { size, contentType, ip } = await probeResource(url);
    if (contentType) xterm("stdout", { data: "Content-Type: " + contentType });
    if (contentType && contentType.startsWith("text/html")) {
      throw new Error("URL serves HTML (" + contentType + "), not a downloadable file. " +
        "Please paste a direct file URL and try again.");
    }
    if (size == null) throw new Error("Could not determine remote file size — please try a different URL");
    xterm("stdout", { data: "Reported size: " + humanBytes(size) });
    if (size > MAX_BYTES) {
      const gib = (size / (1024 * 1024 * 1024)).toFixed(2);
      console.log("oversize: url=" + tailSafe(url) + ", size=" + gib + " GiB (" + size + " bytes)");
      throw new Error("File is " + humanBytes(size) + " — exceeds the " + humanBytes(MAX_BYTES) +
        " limit. Please choose a smaller file and try again.");
    }

    // Pin the destination IP to whatever the probe saw, and refuse redirects
    // outright — the probe already followed them. Together this closes the
    // DNS-rebinding / round-robin window between probe and fetch.
    const curlArgs = ["-v", "-o", file, "--proto", "=http,https", "--max-redirs", "0"];
    if (ip) curlArgs.push("--resolve", host + ":" + port + ":" + ip);
    curlArgs.push("--", url);
    await runCmd("Downloading " + name + "...", "curl", curlArgs);
    xterm("step-update", { label: "Downloading " + name + "...complete" });
  }

  // Use file(1) to identify what we actually downloaded and warn if the
  // detected type doesn't look like the URL's suffix would suggest.
  xterm("step", { label: "Identifying " + name + "..." });
  const fileOut = await captureCmd("file", ["-b", file]);
  xterm("stdout", { data: "\x1b[31m" + fileOut + "\x1b[0m" });
  if (info.kind !== "plain" && !typeMatches(info, fileOut)) {
    xterm("stdout", { data: "\x1b[33m\u26a0 detected type does not match URL suffix\x1b[0m" });
  }

  // Dispatch on format. xxd only runs on files file(1) considers executable;
  // anything else (libraries, scripts, data, media) is identified and skipped.
  if (info.kind === "stream") {
    await streamDecompressAndDump(file, name, info);
  } else if (info.kind === "archive") {
    await archiveListExtractAndDump(file, name, info, extractDir);
  } else if (isExec(fileOut)) {
    await runCmd("Running xxd -l 256 " + name + "...", "xxd", ["-R", "always", "-l", "256", file], "xxd-line");
  } else {
    xterm("step", { label: "Skipping " + name + " \u2014 not an executable" });
  }

  xterm("done", {});
  xxdState = "done";
}

// Rough sanity check between the URL suffix and what file(1) thinks the bytes
// are. It's best-effort — we only flag obvious mismatches (e.g. .gz URL but the
// file isn't gzip). Unknown strings are treated as matches.
const STREAM_MARKERS = {
  ".gz": "gzip",
  ".Z": "compress",
  ".bz2": "bzip2",
  ".xz": "xz",
  ".lzma": "lzma",
  ".lz": "lzip",
  ".lz4": "lz4",
  ".zst": "zstandard",
  ".br": "brotli",
};
// Substrings we accept as "this is an archive of some flavour" — matched
// loosely against file(1)'s output. Brotli's in here because .tar.br's outer
// layer is brotli-compressed, so file(1) reports the wrapper type.
const ARCHIVE_MARKERS = [
  "archive", "zip", "tar", "cpio", "rar", "7-zip", "iso 9660", "cabinet",
  "rpm", "debian", "squashfs", "apple disk image", "composite document",
  "msi installer", "wim", "vhd", "hfs", "chm", "brotli",
];

function typeMatches(info, fileOut) {
  const t = fileOut.toLowerCase();
  if (info.kind === "stream") {
    const m = STREAM_MARKERS[info.ext];
    return !m || t.includes(m);
  }
  if (info.kind === "archive") return ARCHIVE_MARKERS.some((k) => t.includes(k));
  return true;
}

// True when file(1) describes the bytes as an executable binary. Matches the
// "executable" keyword in ELF / Mach-O / PE / MS-DOS output ("ELF 64-bit LSB
// executable, ...", "Mach-O 64-bit executable x86_64", "PE32+ executable",
// "MS-DOS executable"), but not shared objects or plain-text scripts without
// the +x bit (which curl downloads never have anyway).
function isExec(fileOut) {
  return /\bexecutable\b/i.test(fileOut);
}

// Identify the file, print its type, and xxd it only if file(1) thinks the
// bytes are a native executable. Skips libraries, scripts, data, images, etc.
async function xxdIfExec(displayName, filePath) {
  const type = await captureCmd("file", ["-b", filePath]);
  xterm("stdout", { data: "\x1b[31m" + displayName + ": " + type + "\x1b[0m" });
  if (!isExec(type)) {
    xterm("step", { label: "Skipping " + displayName + " \u2014 not an executable" });
    return;
  }
  await runCmd("Running xxd -l 256 " + displayName + "...", "xxd",
    ["-R", "always", "-l", "256", filePath], "xxd-line");
}

// Stream decompressor selection. All commands read stdin and write stdout so
// they slot into the `pv -n FILE | CMD > OUT` pipeline uniformly.
//   bsdcat            — libarchive auto-detects gzip/bz2/xz/lzma/lz/lz4/zst/.Z
//   brotli -d -c      — libarchive has no brotli reader, so call brotli(1)
const STREAM_CMDS = {
  ".br": "brotli -d -c",
};
function streamCmd(ext) { return STREAM_CMDS[ext] || "bsdcat"; }

// How much of a stream's decompressed output to keep. 64 KiB covers every
// known executable magic header and is vastly more than xxd -l 256 needs, so
// we `head -c` the pipeline and let the decompressor exit on SIGPIPE. Saves
// tens of GB of disk on large .xz / .zst / .gz blobs where we'd otherwise
// materialise the whole decompressed artifact just to dump 256 bytes.
const STREAM_HEAD_BYTES = 64 * 1024;

// Single-file decompressor: decompress just enough bytes to identify the
// payload and hex-dump the first 256, then xxd if it's executable. Nested
// archives (e.g. foo.cpio.gz → foo.cpio) are flagged up front so we don't
// decompress at all.
async function streamDecompressAndDump(file, name, info) {
  const outName = name.slice(0, -info.ext.length) || "output";
  if (isNested(outName)) {
    xterm("step", { label: "Skipping nested archive: " + outName });
    return;
  }
  const outPath = WORK_DIR + "/" + outName;
  if (!fs.existsSync(outPath)) {
    // -n prints one numeric percentage per line instead of an in-place bar,
    // which plays nicely with our line-oriented terminal. `head -c` caps the
    // output at STREAM_HEAD_BYTES; the decompressor then exits on SIGPIPE,
    // which modern decoders (bsdcat, brotli) handle silently. If the input
    // is actually corrupt we still get a real stderr line from the decoder
    // surfaced through runCmd.
    const pipeline = "pv -n " + shQuote(file) + " | " + streamCmd(info.ext) +
                     " | head -c " + STREAM_HEAD_BYTES + " > " + shQuote(outPath);
    await runCmd("Decompressing " + name + " (head)...", "sh", ["-c", pipeline]);
    xterm("step-update", { label: "Decompressing " + name + " (head)...complete" });
  } else {
    xterm("step", { label: outName + " already extracted, skipping" });
  }
  if (fs.statSync(outPath).size === 0) {
    xterm("stdout", { data: "\x1b[31m\u26a0 " + name + " looks corrupt or truncated \u2014 zero bytes decompressed\x1b[0m" });
    return;
  }
  await xxdIfExec(outName, outPath);
}

// Alpine's libarchive is built without RAR crypto, so header-encrypted RARs
// fail at listing time with "RAR encryption support unavailable". Everything
// else (wrong/missing passwords, mangled bytes) we recognise by searching the
// captured stderr for known phrases from bsdtar and p7zip.
const PW_RE = /rar encryption support unavailable|too many incorrect passphrase|passphrase (required|incorrect)|wrong password|enter password|(file|archive) is encrypted|encrypted headers/i;
const BAD_RE = /unrecognized archive format|base block header is too large|unpacker has written too many bytes|truncated|corrupt|damaged|malformed|invalid header|crc (mismatch|error)|checksum error|cannot open the file as|unexpected (end-of-file|eof)/i;

function badArchive(err) {
  const text = (err.stderr || "") + (err.stdout || "");
  if (PW_RE.test(text)) return "password-protected";
  if (BAD_RE.test(text)) return "corrupt or truncated";
  return null;
}

async function runArchiveCmd(label, cmd, args, name) {
  try {
    await runCmd(label, cmd, args);
  } catch (err) {
    const cause = badArchive(err);
    if (!cause) throw err;
    xterm("stdout", { data: "\x1b[31m\u26a0 " + name + " looks " + cause + "\x1b[0m" });
    throw Object.assign(new Error(name + " is " + cause), { cause: err });
  }
}

// Archive tool dispatch. Each entry returns a [cmd, args] tuple we feed to
// runArchiveCmd. Adding a new archive backend is a one-entry change here plus
// an extension list above.
//   bsdtar       — libarchive (tar, zip-family, 7z, rar, cab, iso, xar, pkg,
//                  rpm, deb/udeb/ipk, cpio, ar, ova, and the tar.X compound
//                  suffixes bsdtar decompresses natively).
//   7z           — p7zip fallback for formats libarchive can't read (dmg, msi,
//                  wim, hfs, vhd, vdi, chm).
//   unsquashfs   — squashfs-tools for squashfs / .snap. -f forces extraction
//                  into the (existing, empty) dir created by freshDir.
//   brotli-tar   — libarchive has no brotli reader, so pipe brotli(1) into
//                  bsdtar reading from stdin.
const ARCHIVE_TOOLS = {
  bsdtar: {
    list: (f) => ["bsdtar", ["-tvf", f]],
    extract: (f, d) => ["bsdtar", ["-xvf", f, "-C", d]],
  },
  "7z": {
    list: (f) => ["7z", ["l", f]],
    extract: (f, d) => ["7z", ["x", "-y", "-o" + d, f]],
  },
  unsquashfs: {
    list: (f) => ["unsquashfs", ["-ll", f]],
    extract: (f, d) => ["unsquashfs", ["-f", "-d", d, f]],
  },
  "brotli-tar": {
    list: (f) => ["sh", ["-c", `brotli -d -c ${shQuote(f)} | bsdtar -tvf -`]],
    extract: (f, d) => ["sh", ["-c", `brotli -d -c ${shQuote(f)} | bsdtar -xvf - -C ${shQuote(d)}`]],
  },
};

// Run `file -b` on many paths in one go. file(1) accepts multiple arguments
// and emits one type line per input, in order — so a tarball with 10k files
// takes ~1 spawn per 100 entries instead of 10k individual spawns. Chunked to
// keep argv well under ARG_MAX (~128 KiB on Alpine).
const FILE_BATCH = 100;
async function fileTypes(paths) {
  const out = [];
  for (let i = 0; i < paths.length; i += FILE_BATCH) {
    const chunk = paths.slice(i, i + FILE_BATCH);
    const raw = await captureCmd("file", ["-b", ...chunk]);
    // `file -b` returns exactly one line per input. Trailing newline is
    // stripped by captureCmd, so split on \n gives us chunk.length lines.
    out.push(...raw.split("\n"));
  }
  return out;
}

// Multi-file archive: list → extract → identify all members in batched
// file(1) calls → xxd each executable. Nested archives are flagged but not
// recursed into.
async function archiveListExtractAndDump(file, name, info, extractDir) {
  const tool = ARCHIVE_TOOLS[info.tool];
  if (!tool) throw new Error("unknown archive tool: " + info.tool);

  const [listBin, listArgs] = tool.list(file);
  const [extractBin, extractArgs] = tool.extract(file, extractDir);

  await runArchiveCmd("Listing " + name + "...", listBin, listArgs, name);
  await freshDir(extractDir);  // always fresh so repeat runs don't mix old output in
  await runArchiveCmd("Extracting " + name + "...", extractBin, extractArgs, name);

  const files = await walkFiles(extractDir);
  if (files.length === 0) { xterm("stdout", { data: "(archive contained no regular files)" }); return; }

  // Partition upfront so we only pay for file(1) on things we'll actually dump.
  const candidates = [];
  for (const f of files) {
    const rel = path.relative(extractDir, f);
    if (isNested(rel)) { xterm("step", { label: "Skipping nested archive: " + rel }); continue; }
    candidates.push({ rel, full: f });
  }
  if (candidates.length === 0) return;

  xterm("step", { label: "Identifying " + candidates.length + " extracted file(s)..." });
  const types = await fileTypes(candidates.map((c) => c.full));

  for (let i = 0; i < candidates.length; i++) {
    const { rel, full } = candidates[i];
    const type = types[i] || "(unknown)";
    xterm("stdout", { data: "\x1b[31m" + rel + ": " + type + "\x1b[0m" });
    if (isExec(type)) {
      await runCmd("Running xxd -l 256 " + rel + "...", "xxd",
        ["-R", "always", "-l", "256", full], "xxd-line");
    } else {
      xterm("step", { label: "Skipping " + rel + " \u2014 not an executable" });
    }
  }
}

// Minimal shell quoting for paths passed to `sh -c`. Good enough for WORK_DIR paths.
function shQuote(s) { return "'" + String(s).replace(/'/g, "'\\''") + "'"; }

async function resetXxd() {
  if (xxdState === "running") return;
  xxdState = "idle";
  xxdStartedAt = null;
  messageLog.length = 0;
  lastStepIdx = -1;
  truncated = 0;

  const paths = currentPaths;
  currentPaths = null;
  if (!paths) return;

  // Best-effort cleanup; run in parallel so a huge extract tree doesn't
  // serialise with the single-file unlink.
  await Promise.all([
    fsp.unlink(paths.file).catch(() => {}),
    fsp.rm(paths.extractDir, { recursive: true, force: true }).catch(() => {}),
  ]);
}

function startXxd(url) {
  if (xxdState === "running") return;
  resetXxd()
    .then(() => runXxd(url))
    .catch((err) => {
      xterm("error", { message: err.message });
      xxdState = "error";
    });
}

// HTTP server + WebSocket

const server = http.createServer((req, res) => {
  if (req.url === "/ping") {
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("pong");
    return;
  }
  res.writeHead(404, { "Content-Type": "text/plain" });
  res.end("not found");
});

const wss = new WebSocketServer({ server, path: "/ws" });

wss.on("connection", (ws) => {
  clients.add(ws);

  // Ping-pong every 8s
  const heartbeat = setInterval(() => {
    if (ws.readyState === 1) ws.send(PING_MSG);
  }, 8000);

  ws.on("message", (raw) => {
    try {
      const msg = JSON.parse(raw);
      if (msg.type === "start" && msg.url) {
        startXxd(msg.url);
      }
    } catch (_) {}
  });

  ws.on("close", () => {
    clients.delete(ws);
    clearInterval(heartbeat);
  });

  // Late joiner: replay buffered messages
  if (xxdState === "running") {
    ws.send(JSON.stringify({
      type: "status",
      state: "running",
      startedAt: xxdStartedAt,
    }));
  }
  replay(ws);
});

server.listen(9999, "0.0.0.0", () => {
  console.log("Listening on 0.0.0.0:9999");
});
