/**
 * HTTP proxy framing. One request at a time. Proxy credentials never leave this process.
 * Content-Length together with Transfer-Encoding is rejected, not forwarded.
 */

const HOP = new Set([
  "proxy-authorization",
  "proxy-authenticate",
  "proxy-connection",
  "keep-alive",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "connection",
]);

export function headerName(line) {
  const idx = String(line || "").indexOf(":");
  if (idx <= 0) return "";
  return line.slice(0, idx).trim().toLowerCase();
}

export function headerValue(lines, name) {
  const want = String(name || "").toLowerCase();
  const line = lines.find((item) => headerName(item) === want);
  if (!line) return "";
  return line.slice(line.indexOf(":") + 1).trim();
}

export function classifyFraming(lines) {
  if (lines.some((line) => /^[ \t]/.test(line))) return { ok: false, status: 400, reason: "折叠头" };
  const te = lines.filter((line) => headerName(line) === "transfer-encoding");
  const cl = lines.filter((line) => headerName(line) === "content-length");
  if (te.length && cl.length) return { ok: false, status: 400, reason: "长度和分块冲突" };
  if (cl.length > 1) return { ok: false, status: 400, reason: "多个长度" };
  if (te.length > 1) return { ok: false, status: 400, reason: "多个传输编码" };
  if (te.length === 1) {
    const value = te[0].slice(te[0].indexOf(":") + 1).trim().toLowerCase();
    if (value !== "chunked") return { ok: false, status: 400, reason: "不能识别的传输编码" };
    return { ok: true, mode: "chunked", length: 0 };
  }
  if (cl.length === 1) {
    const value = cl[0].slice(cl[0].indexOf(":") + 1).trim();
    if (!/^\d+$/.test(value)) return { ok: false, status: 400, reason: "长度无效" };
    const length = Number(value);
    if (!Number.isSafeInteger(length) || length > 64 * 1024 * 1024) return { ok: false, status: 400, reason: "长度无效" };
    return { ok: true, mode: "length", length };
  }
  return { ok: true, mode: "none", length: 0 };
}

export function hostsAgree(urlHost, urlPort, hostHeader, defaultPort = 80) {
  const raw = String(hostHeader || "").trim();
  if (!raw) return false;
  let host = raw;
  let port = null;
  if (raw.startsWith("[")) {
    const end = raw.indexOf("]");
    if (end < 0) return false;
    host = raw.slice(1, end);
    const rest = raw.slice(end + 1);
    if (rest) {
      if (!rest.startsWith(":")) return false;
      port = Number(rest.slice(1));
    }
  } else if (raw.lastIndexOf(":") > 0 && raw.indexOf(":") === raw.lastIndexOf(":")) {
    const idx = raw.lastIndexOf(":");
    host = raw.slice(0, idx);
    port = Number(raw.slice(idx + 1));
  }
  const left = String(urlHost || "").replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase();
  const right = host.replace(/\.$/, "").toLowerCase();
  if (!left || left !== right) return false;
  if (port == null) return Number(urlPort) === Number(defaultPort);
  return Number.isInteger(port) && port === Number(urlPort);
}

export function sanitizeHeaders(lines) {
  const drop = new Set(HOP);
  for (const line of lines) {
    if (headerName(line) !== "connection") continue;
    for (const token of line.slice(line.indexOf(":") + 1).split(",")) {
      const name = token.trim().toLowerCase();
      if (name) drop.add(name);
    }
  }
  return lines.filter((line) => {
    const name = headerName(line);
    return name && !drop.has(name);
  });
}

function withoutLength(lines) {
  return lines.filter((line) => headerName(line) !== "content-length");
}

function hasBareLf(text) {
  return /(?:^|[^\r])\n/.test(text);
}

function status(code, text) {
  return Buffer.from(`HTTP/1.1 ${code} ${text}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
}

function createReader(socket, hardCap = 8 * 1024 * 1024) {
  let buf = Buffer.alloc(0);
  let dead = null;
  const waiters = [];
  const pump = () => {
    while (waiters.length) {
      const waiter = waiters[0];
      if (waiter.type === "until") {
        const at = buf.indexOf(waiter.sep);
        if (at < 0) {
          if (buf.length > waiter.cap) {
            waiters.shift();
            waiter.reject(new Error("头部过大"));
            continue;
          }
          if (dead) {
            waiters.shift();
            waiter.resolve(null);
            continue;
          }
          return;
        }
        const out = buf.subarray(0, at);
        buf = buf.subarray(at + waiter.sep.length);
        waiters.shift();
        waiter.resolve(out);
        continue;
      }
      if (waiter.type === "some") {
        if (buf.length > 0) {
          const n = Math.min(buf.length, waiter.n);
          const out = buf.subarray(0, n);
          buf = buf.subarray(n);
          waiters.shift();
          waiter.resolve(out);
          continue;
        }
        if (dead) {
          waiters.shift();
          waiter.resolve(Buffer.alloc(0));
          continue;
        }
        return;
      }
      if (buf.length < waiter.n) {
        if (dead) {
          waiters.shift();
          waiter.reject(dead);
          continue;
        }
        return;
      }
      const out = buf.subarray(0, waiter.n);
      buf = buf.subarray(waiter.n);
      waiters.shift();
      waiter.resolve(out);
    }
    if (!socket.destroyed && buf.length < 64 * 1024) socket.resume();
  };
  const onData = (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    if (buf.length > hardCap) {
      dead = new Error("缓冲过大");
      socket.destroy();
      return;
    }
    if (buf.length > 256 * 1024) socket.pause();
    pump();
  };
  socket.on("data", onData);
  socket.on("error", (err) => {
    dead = err;
    pump();
  });
  socket.on("close", () => {
    if (!dead) dead = new Error("连接关闭");
    pump();
  });
  socket.resume();
  return {
    readUntil(sep, cap) {
      return new Promise((resolve, reject) => {
        waiters.push({ type: "until", sep, cap, resolve, reject });
        pump();
      });
    },
    readSome(n) {
      return new Promise((resolve, reject) => {
        waiters.push({ type: "some", n, resolve, reject });
        pump();
      });
    },
    readExactly(n) {
      return new Promise((resolve, reject) => {
        waiters.push({ type: "exact", n, resolve, reject });
        pump();
      });
    },
    detach() {
      socket.off("data", onData);
      const left = buf;
      buf = Buffer.alloc(0);
      return left;
    },
  };
}

function writeAll(dest, chunk) {
  if (!chunk || !chunk.length) return Promise.resolve();
  return new Promise((resolve, reject) => {
    let settled = false;
    const done = (err) => {
      if (settled) return;
      settled = true;
      if (err) reject(err);
      else resolve();
    };
    const ok = dest.write(chunk, (err) => done(err));
    if (!ok) dest.once("drain", () => done());
  });
}

async function pipeExact(reader, dest, length) {
  let left = length;
  while (left > 0) {
    const chunk = await reader.readExactly(Math.min(left, 16 * 1024));
    await writeAll(dest, chunk);
    left -= chunk.length;
  }
}

async function pipeChunked(reader, dest) {
  for (;;) {
    const line = await reader.readUntil(Buffer.from("\r\n"), 4096);
    if (!line) throw new Error("分块中断");
    const hex = line.toString("latin1").split(";")[0].trim();
    if (!/^[0-9a-fA-F]{1,7}$/.test(hex)) throw new Error("分块长度无效");
    const size = Number.parseInt(hex, 16);
    if (size === 0) {
      for (;;) {
        const trailer = await reader.readUntil(Buffer.from("\r\n"), 8192);
        if (!trailer || trailer.length === 0) break;
      }
      await writeAll(dest, Buffer.from("0\r\n\r\n"));
      return;
    }
    const data = await reader.readExactly(size);
    const crlf = await reader.readExactly(2);
    if (crlf.toString("latin1") !== "\r\n") throw new Error("分块格式不对");
    await writeAll(dest, Buffer.from(`${size.toString(16)}\r\n`));
    await writeAll(dest, data);
    await writeAll(dest, Buffer.from("\r\n"));
  }
}

function noBody(method) {
  return method === "GET" || method === "HEAD" || method === "DELETE" || method === "OPTIONS" || method === "TRACE";
}

function splice(left, right) {
  const close = () => {
    left.destroy();
    right.destroy();
  };
  left.on("error", close);
  right.on("error", close);
  left.on("close", () => right.destroy());
  right.on("close", () => left.destroy());
  left.pipe(right);
  right.pipe(left);
}

function carriesBody(method, status) {
  if (method === "HEAD") return false;
  if (status >= 100 && status < 200) return false;
  if (status === 204 || status === 304) return false;
  return true;
}

function connectionTokens(lines) {
  const tokens = new Set();
  for (const line of lines) {
    if (headerName(line) !== "connection") continue;
    for (const token of line.slice(line.indexOf(":") + 1).split(",")) {
      const name = token.trim().toLowerCase();
      if (name) tokens.add(name);
    }
  }
  return tokens;
}

// Close the client side if the client asked for it, or an HTTP/1.0 client did not opt into keep-alive.
// Upstream Connection is hop-by-hop: each request opens its own upstream, so it does not affect the client.
export function mustClose(reqLines) {
  const req = connectionTokens(reqLines.slice(1));
  if (req.has("close")) return true;
  return /\sHTTP\/1\.0$/i.test(reqLines[0] || "") && !req.has("keep-alive");
}

export async function serveHttpProxy(socket, options) {
  const cap = options.headerCap || 8192;
  const count = options.count || (() => undefined);
  const authorize = options.authorize || (() => true);
  const reader = createReader(socket);
  const fail = (code, text, metric = "httpReject") => {
    count(metric);
    if (!socket.destroyed) socket.end(status(code, text));
  };
  try {
    for (;;) {
      const headBuf = await reader.readUntil(Buffer.from("\r\n\r\n"), cap);
      if (!headBuf) return;
      const head = headBuf.toString("latin1");
      if (hasBareLf(head)) return fail(400, "Bad Request");
      const lines = head.split("\r\n");
      const matched = (lines[0] || "").match(/^([A-Z]+)\s+(\S+)\s+HTTP\/1\.[01]$/i);
      if (!matched) return fail(400, "Bad Request");
      const method = matched[1].toUpperCase();
      const target = matched[2];
      const framing = classifyFraming(lines);
      if (!framing.ok) return fail(400, "Bad Request", "smuggle");
      if (!authorize(lines)) return fail(407, "Proxy Authentication Required");
      if (method === "CONNECT") {
        const hostPort = target.match(/^(?:\[([^\]]+)\]|([^:]+)):(\d+)$/);
        if (!hostPort) return fail(400, "Bad Request");
        const host = hostPort[1] || hostPort[2];
        const port = Number(hostPort[3]);
        const hostHeader = headerValue(lines, "host");
        if (hostHeader && !hostsAgree(host, port, hostHeader, port)) return fail(400, "Bad Request");
        const upstream = await options.openUpstream(host, port);
        count("httpOk");
        socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        const rest = reader.detach();
        if (rest.length) socket.unshift(rest);
        splice(socket, upstream);
        return;
      }
      let url;
      try {
        url = new URL(target);
      } catch {
        return fail(400, "Bad Request");
      }
      if (url.protocol !== "http:") return fail(400, "Bad Request");
      const port = Number(url.port || 80);
      if (!hostsAgree(url.hostname, port, headerValue(lines, "host"), 80)) return fail(400, "Bad Request");
      if (framing.mode === "none" && !noBody(method)) return fail(411, "Length Required");
      // Framing is re-emitted from classifyFraming below; drop the original so it is not sent twice.
      const kept = withoutLength(sanitizeHeaders(lines.slice(1)));
      const path = `${url.pathname || "/"}${url.search || ""}`;
      const extra = framing.mode === "chunked" ? "Transfer-Encoding: chunked\r\n" : framing.mode === "length" ? `Content-Length: ${framing.length}\r\n` : "";
      const upstream = await options.openUpstream(url.hostname, port);
      const upstreamReader = createReader(upstream);
      const preface = `${method} ${path} HTTP/1.1\r\n${kept.length ? `${kept.join("\r\n")}\r\n` : ""}${extra}Connection: close\r\n\r\n`;
      await writeAll(upstream, Buffer.from(preface));
      if (framing.mode === "length") await pipeExact(reader, upstream, framing.length);
      else if (framing.mode === "chunked") await pipeChunked(reader, upstream);
      let respLines = null;
      let respFrame = null;
      let statusCode = 0;
      for (;;) {
        const respBuf = await upstreamReader.readUntil(Buffer.from("\r\n\r\n"), cap);
        if (!respBuf) {
          upstream.destroy();
          return fail(502, "Bad Gateway");
        }
        const respHead = respBuf.toString("latin1");
        if (hasBareLf(respHead)) {
          upstream.destroy();
          return fail(502, "Bad Gateway");
        }
        respLines = respHead.split("\r\n");
        const statusMatch = (respLines[0] || "").match(/^HTTP\/1\.[01]\s+(\d{3})/i);
        if (!statusMatch) {
          upstream.destroy();
          return fail(502, "Bad Gateway");
        }
        statusCode = Number(statusMatch[1]);
        if (statusCode >= 100 && statusCode < 200) {
          await writeAll(socket, Buffer.from(`${respHead}\r\n\r\n`));
          continue;
        }
        respFrame = classifyFraming(respLines);
        break;
      }
      if (!respFrame.ok) {
        upstream.destroy();
        count("smuggle");
        return fail(502, "Bad Gateway", "smuggle");
      }
      const respKept = withoutLength(sanitizeHeaders(respLines.slice(1))).filter((line) => {
        if (carriesBody(method, statusCode)) return true;
        return headerName(line) !== "transfer-encoding";
      });
      const respExtra = !carriesBody(method, statusCode)
        ? ""
        : respFrame.mode === "chunked"
          ? "Transfer-Encoding: chunked\r\n"
          : respFrame.mode === "length"
            ? `Content-Length: ${respFrame.length}\r\n`
            : "";
      const keep = carriesBody(method, statusCode) && respFrame.mode !== "none" && !mustClose(lines) ? "keep-alive" : "close";
      await writeAll(socket, Buffer.from(`${respLines[0]}\r\n${respKept.length ? `${respKept.join("\r\n")}\r\n` : ""}${respExtra}Connection: ${keep}\r\n\r\n`));
      if (!carriesBody(method, statusCode)) {
        upstream.destroy();
        count("httpOk");
        if (keep === "close") {
          socket.end();
          return;
        }
        continue;
      }
      if (respFrame.mode === "length") await pipeExact(upstreamReader, socket, respFrame.length);
      else if (respFrame.mode === "chunked") await pipeChunked(upstreamReader, socket);
      else {
        for (;;) {
          const chunk = await upstreamReader.readSome(16 * 1024);
          if (!chunk.length) break;
          await writeAll(socket, chunk);
        }
        upstream.destroy();
        socket.end();
        count("httpOk");
        return;
      }
      upstream.destroy();
      count("httpOk");
      if (keep === "close") {
        socket.end();
        return;
      }
    }
  } catch {
    count("httpReject");
    if (!socket.destroyed) socket.destroy();
  }
}
