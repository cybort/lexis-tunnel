/**
 * Resident lexicon link. Same handshake, pack tag and codebook seal as the console.
 * TCP / TLS / WebSocket only frame the prose; they are not the cipher.
 */
import { createHash, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { connect as connectTcp, createServer as createTcp, isIP, type Socket } from "node:net";
import { connect as connectTls, createServer as createTls, type TLSSocket } from "node:tls";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Module, waitInitialized } from "../../node_modules/@bokuweb/zstd-wasm/dist/esm/module.js";
import { compress as zstdCompress } from "../../node_modules/@bokuweb/zstd-wasm/dist/esm/simple/compress.js";
import { decompress as zstdDecompress } from "../../node_modules/@bokuweb/zstd-wasm/dist/esm/simple/decompress.js";
import { b64, concat, fromUtf8, utf8 } from "../lib/lexis/bytes";
import { createIdentity, identityFromJwks } from "../lib/lexis/crypto";
import { edgeFinish, edgeStart, gateAccept, gateRespond, openSession, type GatePending, type LiveSession } from "../lib/lexis/handshake";
import { honeyFromFeatures, type SessionOffer } from "../lib/lexis/kdf";
import { decodeRecord, encodeRecord, heartbeatPayload, RECORD } from "../lib/lexis/records";
import { open, seal } from "../lib/lexis/seal";
import type { MeshNode } from "../lib/lexis/types";

export { createIdentity };

export type ZstdPref = { enabled: boolean; level: number };
export type OuterName = "tcp" | "tls" | "ws" | "wss";

export type ProsePipe = {
  write(prose: string): Promise<void>;
  read(): Promise<string>;
  close(): void;
};

export type OpenCommand = {
  relay: string | null;
  rest: string;
  udp: boolean;
  host: string;
  port: number;
};

type Ack = { ok: boolean; reason: string };

let zstdReady: Promise<void> | null = null;

function ensureZstd(): Promise<void> {
  if (!zstdReady) {
    zstdReady = (async () => {
      const here = dirname(fileURLToPath(import.meta.url));
      const buf = readFileSync(join(here, "zstd.wasm"));
      const wasm = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
      (Module as unknown as { init: (src: ArrayBuffer) => void }).init(wasm);
      await waitInitialized();
    })();
  }
  return zstdReady;
}

async function packRecord(data: Uint8Array, pref: ZstdPref): Promise<Uint8Array> {
  if (!pref.enabled) return concat(new Uint8Array([0]), data);
  await ensureZstd();
  const level = Math.min(19, Math.max(1, pref.level || 3));
  const zipped = zstdCompress(data, level);
  if (zipped.length < data.length && zipped.length >= 4) return concat(new Uint8Array([1]), zipped);
  return concat(new Uint8Array([0]), data);
}

async function unpackRecord(bytes: Uint8Array): Promise<Uint8Array> {
  if (bytes.length >= 1 && bytes[0] === 0) return bytes.subarray(1);
  if (bytes.length >= 5 && bytes[0] === 1) {
    await ensureZstd();
    return zstdDecompress(bytes.subarray(1));
  }
  throw new Error("明文类型字节不认识");
}

export function parseOpen(text: string): OpenCommand {
  const raw = String(text || "").trim();
  const relay = raw.match(/^relay\s+(\S+)\s+([\s\S]+)$/);
  if (relay) {
    const rest = relay[2].trim();
    const inner = parseOpen(rest);
    return { relay: relay[1], rest, udp: inner.udp, host: inner.host, port: inner.port };
  }
  const cmd = raw.match(/^(tcp|udp)\s+(\S+)\s+(\d+)$/);
  if (!cmd) return { relay: null, rest: raw, udp: false, host: "", port: 0 };
  return {
    relay: null,
    rest: raw,
    udp: cmd[1] === "udp",
    host: cmd[2],
    port: Number(cmd[3]),
  };
}

export function hopCount(text: string): number {
  let n = 0;
  let rest = text.trim();
  while (rest.startsWith("relay ")) {
    n += 1;
    rest = rest.replace(/^relay\s+\S+\s+/, "");
  }
  return n;
}

class LinePipe implements ProsePipe {
  private buf = Buffer.alloc(0);
  private waiters: Array<(value: string | Error) => void> = [];
  private dead: Error | null = null;

  constructor(private socket: Socket) {
    socket.on("data", (chunk) => {
      this.buf = Buffer.concat([this.buf, chunk]);
      if (this.buf.length > 8 * 1024 * 1024) {
        this.fail(new Error("词表缓冲过大"));
        return;
      }
      this.pump();
    });
    socket.on("error", (err) => this.fail(err));
    socket.on("close", () => this.fail(new Error("连接关闭")));
  }

  private fail(err: Error) {
    if (!this.dead) this.dead = err;
    while (this.waiters.length) {
      const waiter = this.waiters.shift();
      waiter?.(this.dead);
    }
    this.socket.destroy();
  }

  private pump() {
    while (this.waiters.length) {
      const nl = this.buf.indexOf(0x0a);
      if (nl < 0) return;
      const line = this.buf.subarray(0, nl).toString("utf8").replace(/\r$/, "");
      this.buf = this.buf.subarray(nl + 1);
      if (!line) continue;
      const waiter = this.waiters.shift();
      waiter?.(line);
    }
  }

  write(prose: string) {
    const body = Buffer.from(`${prose}\n`, "utf8");
    return new Promise<void>((resolve, reject) => {
      this.socket.write(body, (err) => (err ? reject(err) : resolve()));
    });
  }

  read(): Promise<string> {
    if (this.dead && this.buf.indexOf(0x0a) < 0) return Promise.reject(this.dead);
    const nl = this.buf.indexOf(0x0a);
    if (nl >= 0) {
      const line = this.buf.subarray(0, nl).toString("utf8").replace(/\r$/, "");
      this.buf = this.buf.subarray(nl + 1);
      if (!line) return this.read();
      return Promise.resolve(line);
    }
    return new Promise<string>((resolve, reject) => {
      this.waiters.push((value) => (value instanceof Error ? reject(value) : resolve(value)));
    });
  }

  close() {
    this.socket.end();
  }
}

const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

class WsPipe implements ProsePipe {
  private buf = Buffer.alloc(0);
  private waiters: Array<(value: string | Error) => void> = [];
  private dead: Error | null = null;
  private fragments: Buffer[] = [];
  private early: string[] = [];

  constructor(
    private socket: Socket,
    private mask: boolean,
    initial?: Buffer,
  ) {
    if (initial?.length) this.buf = Buffer.from(initial);
    socket.on("data", (chunk) => {
      this.buf = Buffer.concat([this.buf, chunk]);
      this.pump();
    });
    socket.on("error", (err) => this.fail(err));
    socket.on("close", () => this.fail(new Error("连接关闭")));
    this.pump();
  }

  private fail(err: Error) {
    if (!this.dead) this.dead = err;
    while (this.waiters.length) this.waiters.shift()?.(this.dead);
    this.socket.destroy();
  }

  private pump() {
    for (;;) {
      if (this.buf.length < 2) return;
      const opcode = this.buf[0] & 0x0f;
      const fin = (this.buf[0] & 0x80) !== 0;
      let len = this.buf[1] & 0x7f;
      let offset = 2;
      if (len === 126) {
        if (this.buf.length < 4) return;
        len = this.buf.readUInt16BE(2);
        offset = 4;
      } else if (len === 127) {
        if (this.buf.length < 10) return;
        const big = this.buf.readBigUInt64BE(2);
        if (big > BigInt(8 * 1024 * 1024)) {
          this.fail(new Error("WebSocket 帧过大"));
          return;
        }
        len = Number(big);
        offset = 10;
      }
      const masked = (this.buf[1] & 0x80) !== 0;
      if (this.buf.length < offset + (masked ? 4 : 0) + len) return;
      let payload = this.buf.subarray(offset + (masked ? 4 : 0), offset + (masked ? 4 : 0) + len);
      if (masked) {
        const mask = this.buf.subarray(offset, offset + 4);
        payload = Buffer.from(payload);
        for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3];
      }
      this.buf = this.buf.subarray(offset + (masked ? 4 : 0) + len);
      if (opcode === 0x8) {
        this.fail(new Error("连接关闭"));
        return;
      }
      if (opcode === 0x9) {
        void this.socket.write(wsFrame(0xa, payload, this.mask));
        continue;
      }
      if (opcode === 0xa) continue;
      if (opcode === 0x1 || opcode === 0x2 || opcode === 0x0) {
        if (opcode !== 0x0) this.fragments = [];
        this.fragments.push(Buffer.from(payload));
        if (!fin) continue;
        const text = Buffer.concat(this.fragments).toString("utf8").replace(/\r?\n$/, "");
        this.fragments = [];
        if (!text) continue;
        const waiter = this.waiters.shift();
        if (waiter) waiter(text);
        else this.early.push(text);
      }
    }
  }

  write(prose: string) {
    const frame = wsFrame(0x1, Buffer.from(prose, "utf8"), this.mask);
    return new Promise<void>((resolve, reject) => {
      this.socket.write(frame, (err) => (err ? reject(err) : resolve()));
    });
  }

  read() {
    if (this.early.length) return Promise.resolve(this.early.shift() as string);
    if (this.dead) return Promise.reject(this.dead);
    return new Promise<string>((resolve, reject) => {
      this.waiters.push((value) => (value instanceof Error ? reject(value) : resolve(value)));
    });
  }

  close() {
    try {
      this.socket.write(wsFrame(0x8, Buffer.alloc(0), this.mask));
    } catch {
      /* already gone */
    }
    this.socket.end();
  }
}

function wsFrame(opcode: number, payload: Buffer, mask: boolean): Buffer {
  const len = payload.length;
  let extra = 0;
  if (len >= 126 && len < 65536) extra = 2;
  else if (len >= 65536) extra = 8;
  const head = 2 + extra + (mask ? 4 : 0);
  const out = Buffer.alloc(head + len);
  out[0] = 0x80 | opcode;
  if (len < 126) out[1] = (mask ? 0x80 : 0) | len;
  else if (len < 65536) {
    out[1] = (mask ? 0x80 : 0) | 126;
    out.writeUInt16BE(len, 2);
  } else {
    out[1] = (mask ? 0x80 : 0) | 127;
    out.writeBigUInt64BE(BigInt(len), 2);
  }
  let offset = 2 + extra;
  if (mask) {
    const key = randomBytes(4);
    key.copy(out, offset);
    offset += 4;
    for (let i = 0; i < len; i++) out[offset + i] = payload[i] ^ key[i & 3];
  } else if (len) payload.copy(out, offset);
  return out;
}

function readHttpHead(socket: Socket, cap: number): Promise<{ head: string; rest: Buffer }> {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const timer = setTimeout(() => cleanup(new Error("WebSocket 握手超时")), 10000);
    const cleanup = (err?: Error, value?: { head: string; rest: Buffer }) => {
      clearTimeout(timer);
      socket.off("data", onData);
      socket.off("error", onErr);
      if (err || !value) reject(err || new Error("WebSocket 握手失败"));
      else resolve(value);
    };
    const onErr = (err: Error) => cleanup(err);
    const onData = (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length > cap) return cleanup(new Error("WebSocket 头过长"));
      const at = buf.indexOf("\r\n\r\n");
      if (at < 0) return;
      cleanup(undefined, { head: buf.subarray(0, at).toString("utf8"), rest: Buffer.from(buf.subarray(at + 4)) });
    };
    socket.on("data", onData);
    socket.on("error", onErr);
  });
}

export async function wsClientPipe(socket: Socket, host: string, path: string): Promise<ProsePipe> {
  const key = randomBytes(16).toString("base64");
  socket.write(
    `GET ${path || "/lexis"} HTTP/1.1\r\nHost: ${host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n\r\n`,
  );
  const { head, rest } = await readHttpHead(socket, 8192);
  const accept = createHash("sha1").update(key + WS_GUID).digest("base64");
  if (!/^HTTP\/1\.[01] 101 /.test(head) || !head.toLowerCase().includes(accept.toLowerCase())) {
    socket.destroy();
    throw new Error("对端没有完成 WebSocket 升级");
  }
  return new WsPipe(socket, true, rest);
}

export async function wsServerPipe(socket: Socket, path: string): Promise<ProsePipe> {
  const { head, rest } = await readHttpHead(socket, 16384);
  const lines = head.split("\r\n");
  const request = lines[0] || "";
  const match = request.match(/^GET\s+(\S+)\s+HTTP\/1\.[01]$/);
  const got = match ? match[1].split("?")[0] : "";
  const want = path || "/lexis";
  if (!got || (got !== want && got !== `${want}/`)) {
    socket.end("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    throw new Error("WebSocket 路径不对");
  }
  const keyLine = lines.find((line) => line.toLowerCase().startsWith("sec-websocket-key:"));
  const key = keyLine ? keyLine.slice(keyLine.indexOf(":") + 1).trim() : "";
  if (!key) {
    socket.destroy();
    throw new Error("缺少 WebSocket 密钥");
  }
  const accept = createHash("sha1").update(key + WS_GUID).digest("base64");
  socket.write(
    `HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`,
  );
  return new WsPipe(socket, false, rest);
}

export function tcpPipe(socket: Socket): ProsePipe {
  return new LinePipe(socket);
}

function tlsMaterial(certPath?: string, keyPath?: string) {
  const here = dirname(fileURLToPath(import.meta.url));
  return {
    cert: readFileSync(certPath || join(here, "lexis-tls.crt")),
    key: readFileSync(keyPath || join(here, "lexis-tls.key")),
  };
}

function sniName(host: string): string | undefined {
  return host && !isIP(host) ? host : undefined;
}

export function dialOuter(opts: {
  transport: OuterName;
  host: string;
  port: number;
  path?: string;
  wsHost?: string;
  tlsVerify?: boolean;
}): Promise<ProsePipe> {
  const transport = opts.transport || "tcp";
  const tls = transport === "tls" || transport === "wss";
  const ws = transport === "ws" || transport === "wss";
  const name = sniName(opts.wsHost || opts.host);
  return new Promise((resolve, reject) => {
    const socket = tls
      ? connectTls({
          host: opts.host,
          port: opts.port,
          ...(name ? { servername: name } : {}),
          rejectUnauthorized: opts.tlsVerify !== false,
        })
      : connectTcp({ host: opts.host, port: opts.port });
    const fail = (err: Error) => {
      socket.destroy();
      reject(err);
    };
    socket.once("error", fail);
    socket.once(tls ? "secureConnect" : "connect", () => {
      socket.off("error", fail);
      void (async () => {
        try {
          if (ws) resolve(await wsClientPipe(socket, opts.wsHost || opts.host, opts.path || "/lexis"));
          else resolve(tcpPipe(socket));
        } catch (err) {
          fail(err instanceof Error ? err : new Error(String(err)));
        }
      })();
    });
  });
}

export function listenOuter(opts: {
  transport: OuterName;
  host: string;
  port: number;
  path?: string;
  certPath?: string;
  keyPath?: string;
  onSocket: (socket: Socket | TLSSocket, pipeReady: Promise<ProsePipe>) => void;
}): { close: () => void; listening: () => Promise<void> } {
  const transport = opts.transport || "tcp";
  const tlsOn = transport === "tls" || transport === "wss";
  const ws = transport === "ws" || transport === "wss";
  const material = tlsOn ? tlsMaterial(opts.certPath, opts.keyPath) : null;
  const server = tlsOn
    ? createTls({ cert: material?.cert, key: material?.key }, (socket) => deliver(socket))
    : createTcp((socket) => deliver(socket));
  function deliver(socket: Socket | TLSSocket) {
    socket.on("error", () => socket.destroy());
    const ready = ws ? wsServerPipe(socket, opts.path || "/lexis") : Promise.resolve(tcpPipe(socket));
    opts.onSocket(socket, ready);
  }
  let listenResolve: (() => void) | null = null;
  const listening = new Promise<void>((resolve) => {
    listenResolve = resolve;
  });
  server.listen(opts.port, opts.host, () => listenResolve?.());
  return {
    close: () => server.close(),
    listening: () => listening,
  };
}

export async function nodeFromIdentity(
  identity: {
    id: string;
    name: string;
    publicJwk: JsonWebKey;
    privateJwk: JsonWebKey;
    publicRawB64?: string;
  },
  role: "edge" | "gate",
): Promise<MeshNode> {
  const ident = await identityFromJwks(identity.publicJwk, identity.privateJwk);
  return {
    id: identity.id,
    name: identity.name || "词隙",
    role,
    publicJwk: ident.publicJwk,
    privateJwk: ident.privateJwk,
    publicRawB64: identity.publicRawB64 || b64(ident.publicRaw),
    fingerprint: ident.fingerprint,
    pinnedPeerId: null,
    createdAt: 0,
    kdf: null,
  };
}

export class MuxStream {
  command = "";
  ended = false;
  chunks: Uint8Array[] = [];
  private readers: Array<(chunk: Uint8Array | null) => void> = [];
  private ack: Ack | null = null;
  private ackWaiters: Array<(ack: Ack) => void> = [];
  seq = 1;

  constructor(
    readonly session: LexSession,
    readonly id: number,
    readonly local: boolean,
  ) {}

  waitAck(): Promise<Ack> {
    if (this.ack) return Promise.resolve(this.ack);
    return new Promise((resolve) => this.ackWaiters.push(resolve));
  }

  resolveAck(ack: Ack) {
    this.ack = ack;
    while (this.ackWaiters.length) this.ackWaiters.shift()?.(ack);
  }

  push(chunk: Uint8Array) {
    const reader = this.readers.shift();
    if (reader) reader(chunk);
    else this.chunks.push(chunk);
  }

  read(): Promise<Uint8Array | null> {
    if (this.chunks.length) return Promise.resolve(this.chunks.shift() as Uint8Array);
    if (this.ended) return Promise.resolve(null);
    return new Promise((resolve) => this.readers.push(resolve));
  }

  write(chunk: Uint8Array) {
    return this.session.sendChunks(this, chunk);
  }

  accept() {
    return this.session.sendRecord(RECORD.open, this.id, ++this.seq, utf8("ok"));
  }

  reject(reason: string) {
    const text = `no ${String(reason || "拒绝").replace(/[\r\n]/g, " ")}`;
    return this.session.sendRecord(RECORD.open, this.id, ++this.seq, utf8(text)).finally(() => this.finish());
  }

  async close() {
    if (this.ended) return;
    this.ended = true;
    try {
      await this.session.sendRecord(RECORD.close, this.id, ++this.seq, utf8("close"));
    } catch {
      /* peer already gone */
    }
    this.finish();
  }

  finish() {
    this.ended = true;
    this.session.streams.delete(this.id);
    while (this.readers.length) this.readers.shift()?.(null);
    if (!this.ack) this.resolveAck({ ok: false, reason: "连接关闭" });
  }
}

export class LexSession {
  streams = new Map<number, MuxStream>();
  private nextId: number;
  private sendChain: Promise<unknown> = Promise.resolve();
  private heart: ReturnType<typeof setInterval> | null = null;
  closed = false;
  private closeWaiters: Array<() => void> = [];
  onStream: ((stream: MuxStream) => void) | null = null;
  live: LiveSession;

  constructor(
    readonly pipe: ProsePipe,
    live: LiveSession,
    readonly initiator: boolean,
    readonly zstd: ZstdPref,
    readonly maxStreams: number,
    heartbeatMs: number,
  ) {
    this.live = live;
    this.nextId = initiator ? 1 : 2;
    if (heartbeatMs > 0) {
      this.heart = setInterval(() => {
        void this.sendRecord(RECORD.heartbeat, 0, 0, heartbeatPayload()).catch(() => this.shutdown());
      }, heartbeatMs);
      this.heart.unref?.();
    }
  }

  whenClosed() {
    if (this.closed) return Promise.resolve();
    return new Promise<void>((resolve) => this.closeWaiters.push(resolve));
  }

  shutdown() {
    if (this.closed) return;
    this.closed = true;
    if (this.heart) clearInterval(this.heart);
    for (const stream of this.streams.values()) stream.finish();
    this.pipe.close();
    while (this.closeWaiters.length) this.closeWaiters.shift()?.();
  }

  private enqueue<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.sendChain.then(fn, fn);
    this.sendChain = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  sendRecord(type: number, conn: number, seq: number, payload: Uint8Array) {
    return this.enqueue(async () => {
      if (this.closed) throw new Error("会话已关闭");
      const packed = await packRecord(encodeRecord(type, conn, seq, payload), this.zstd);
      const dir = this.initiator ? "e2g" : "g2e";
      const counter = this.live.counters[dir] + 1;
      const prose = await seal({
        key: this.live.sk,
        lexicon: this.live.lexicon,
        counter,
        window: this.live.window,
        direction: dir,
        plaintext: packed,
      });
      this.live = {
        ...this.live,
        counters: { ...this.live.counters, [dir]: counter },
      };
      await this.pipe.write(prose);
    });
  }

  async sendChunks(stream: MuxStream, chunk: Uint8Array) {
    const size = 16 * 1024;
    for (let i = 0; i < chunk.length; i += size) {
      const part = chunk.subarray(i, i + size);
      await this.sendRecord(RECORD.data, stream.id, ++stream.seq, part);
    }
  }

  async open(command: string): Promise<MuxStream> {
    if (this.streams.size >= this.maxStreams) throw new Error("这条链路的连接数已满");
    const id = this.nextId;
    this.nextId += 2;
    const stream = new MuxStream(this, id, true);
    stream.command = command;
    this.streams.set(id, stream);
    await this.sendRecord(RECORD.open, id, stream.seq, utf8(command));
    const ack = await Promise.race([
      stream.waitAck(),
      new Promise<Ack>((resolve) => setTimeout(() => resolve({ ok: false, reason: "打开超时" }), 15000)),
    ]);
    if (!ack.ok) {
      stream.finish();
      throw new Error(ack.reason || "对端拒绝");
    }
    return stream;
  }

  private async onRecord(type: number, conn: number, payload: Uint8Array) {
    if (type === RECORD.heartbeat) return;
    if (type === RECORD.close) {
      this.streams.get(conn)?.finish();
      return;
    }
    if (type === RECORD.open) {
      const text = fromUtf8(payload).replace(/\0/g, "");
      const existing = this.streams.get(conn);
      if (existing) {
        if (text === "ok") existing.resolveAck({ ok: true, reason: "" });
        else if (text.startsWith("no ")) existing.resolveAck({ ok: false, reason: text.slice(3) });
        else existing.resolveAck({ ok: false, reason: text || "打开失败" });
        return;
      }
      if (this.streams.size >= this.maxStreams) return;
      const stream = new MuxStream(this, conn, false);
      stream.command = text;
      this.streams.set(conn, stream);
      this.onStream?.(stream);
      return;
    }
    if (type === RECORD.data) {
      const stream = this.streams.get(conn);
      if (!stream || stream.ended) return;
      if (stream.chunks.length > 256) {
        this.shutdown();
        return;
      }
      stream.push(payload);
    }
  }

  async readLoop() {
    try {
      for (;;) {
        const prose = await this.pipe.read();
        const dir = this.initiator ? "g2e" : "e2g";
        const opened = await open({
          key: this.live.sk,
          inverse: this.live.inverse,
          window: this.live.window,
          direction: dir,
          prose,
          lastSeen: this.live.seen[dir],
          honey: this.live.honey,
        });
        if (opened.honey) continue;
        this.live = { ...this.live, seen: { ...this.live.seen, [dir]: opened.counter } };
        const raw = await unpackRecord(opened.plaintext);
        const rec = decodeRecord(raw);
        await this.onRecord(rec.type, rec.conn, rec.payload);
      }
    } catch {
      this.shutdown();
    }
  }
}

async function sessionFrom(
  pipe: ProsePipe,
  live: LiveSession,
  initiator: boolean,
  zstd: ZstdPref,
  maxStreams: number,
  heartbeatMs: number,
  onStream?: (stream: MuxStream) => void,
) {
  const session = new LexSession(pipe, live, initiator, zstd, maxStreams, heartbeatMs);
  if (onStream) session.onStream = onStream;
  void session.readLoop();
  return session;
}

export async function connectSession(opts: {
  pipe: ProsePipe;
  self: MeshNode;
  peerRawB64: string;
  offer?: Partial<SessionOffer>;
  zstd?: ZstdPref;
  maxStreams?: number;
  heartbeatMs?: number;
  onStream?: (stream: MuxStream) => void;
}) {
  const self = { ...opts.self, role: "edge" as const };
  const pending = await edgeStart(self, Date.now(), opts.offer);
  await opts.pipe.write(pending.helloWire);
  const serverWire = await opts.pipe.read();
  const finished = await edgeFinish(self, pending, opts.peerRawB64, serverWire);
  await opts.pipe.write(finished.finishWire);
  const live = await openSession({
    edge: self,
    gate: { ...self, id: "peer", name: "对端", role: "gate", publicRawB64: opts.peerRawB64 },
    sk: finished.sk,
    window: finished.window,
    helloWire: pending.helloWire,
    serverWire,
    finishWire: finished.finishWire,
    kdf: finished.kdf,
    honey: finished.honey,
    kdfMs: finished.kdfMs,
  });
  return sessionFrom(opts.pipe, live, true, opts.zstd || { enabled: false, level: 3 }, opts.maxStreams || 128, opts.heartbeatMs ?? 15000, opts.onStream);
}

export async function acceptSession(opts: {
  pipe: ProsePipe;
  self: MeshNode;
  peers: { publicRawB64: string }[];
  zstd?: ZstdPref;
  maxStreams?: number;
  heartbeatMs?: number;
  onStream?: (stream: MuxStream) => void;
}) {
  const self = { ...opts.self, role: "gate" as const };
  const helloWire = await opts.pipe.read();
  let pending: GatePending | null = null;
  let last = "没有匹配的节点公钥";
  for (const peer of opts.peers) {
    if (!peer.publicRawB64) continue;
    try {
      pending = await gateRespond(self, peer.publicRawB64, helloWire);
      break;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      last = message;
      if (!message.includes("绑定不一致")) throw err;
    }
  }
  if (!pending) throw new Error(last);
  await opts.pipe.write(pending.serverWire);
  const finishWire = await opts.pipe.read();
  await gateAccept(pending, finishWire);
  const honey = honeyFromFeatures(pending.features);
  const live = await openSession({
    edge: { ...self, id: "peer", name: "对端", role: "edge", publicRawB64: b64(pending.ltC) },
    gate: self,
    sk: pending.sk,
    window: pending.window,
    helloWire,
    serverWire: pending.serverWire,
    finishWire,
    kdf: pending.kdf,
    honey,
    kdfMs: 0,
  });
  return sessionFrom(opts.pipe, live, false, opts.zstd || { enabled: false, level: 3 }, opts.maxStreams || 128, opts.heartbeatMs ?? 15000, opts.onStream);
}

export async function pipeMux(left: MuxStream, right: MuxStream) {
  const pump = async (src: MuxStream, dst: MuxStream) => {
    try {
      for (;;) {
        const chunk = await src.read();
        if (!chunk) {
          await dst.close();
          return;
        }
        await dst.write(chunk);
      }
    } catch {
      await dst.close().catch(() => undefined);
      await src.close().catch(() => undefined);
    }
  };
  void pump(left, right);
  void pump(right, left);
}
