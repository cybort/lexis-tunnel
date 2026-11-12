// U2: local DNS service for Linux system takeover. Listens on 127.0.0.1 and (r2) ::1 over UDP
// and TCP on one port. apply-forward.sh redirects every local TCP/UDP 53 (except loopback and
// this program's own fwmark), private resolvers included, here, for redirect, tproxy and tun
// alike, whatever dnsRedirect says. With a FakeIP pool (dnsRedirect=true): A / ANY get a FakeIP
// (answerDns, shared with tun), AAAA an empty NOERROR, anything else is relayed. Without one
// (r2, dnsRedirect=false): every query is relayed. Relays go to `upstream` through the caller's
// dial functions (rules decide the exit; a direct dial carries fwmark $MARK, which the hijack
// returns on, so it cannot loop).
import { createSocket } from "node:dgram";
import { createServer } from "node:net";
import { answerDns } from "./lexis-tun.mjs";

const QTYPES = { 1: "A", 28: "AAAA", 255: "ANY" };

/** qtype label of a DNS query (for counters): A, AAAA, ANY, other, or bad. */
export function dnsQtype(packet) {
  const buf = Buffer.from(packet);
  if (buf.length < 17) return "bad";
  let pos = 12;
  for (let guard = 0; guard < 128 && pos < buf.length; guard += 1) {
    const len = buf[pos];
    if (len === 0) break;
    if ((len & 0xc0) !== 0) return "bad";
    pos += len + 1;
  }
  if (pos + 5 > buf.length) return "bad";
  return QTYPES[buf.readUInt16BE(pos + 1)] || "other";
}

function listenUdp(host, port) {
  return new Promise((resolve, reject) => {
    const udp = createSocket(host.includes(":") ? { type: "udp6", ipv6Only: true } : "udp4");
    udp.once("error", reject);
    udp.bind(port, host, () => {
      udp.off("error", reject);
      resolve(udp);
    });
  });
}

function listenTcp(host, port, onConn) {
  return new Promise((resolve, reject) => {
    const tcp = createServer(onConn);
    tcp.once("error", reject);
    tcp.listen({ port, host, exclusive: true, ipv6Only: host.includes(":") }, () => {
      tcp.off("error", reject);
      resolve(tcp);
    });
  });
}

/**
 * Start the service. port 0 = pick a free port (UDP first, then TCP on the same number, then
 * the same number on host6; a few retries if one is taken). host6 ("::1") is optional: when the
 * kernel has no IPv6 (EADDRNOTAVAIL / EAFNOSUPPORT) the service runs IPv4-only and port6 is 0.
 * Resolves { host, port, host6, port6, stats, close } or rejects (fail closed: the caller must
 * not take over). fakeIp null = relay everything (dnsRedirect=false).
 * relay(proto, query, upstream) -> Promise<Buffer|null>.
 */
export async function startDnsLocal({ host = "127.0.0.1", host6 = "", port = 0, fakeIp = null, relay, upstream = { host: "1.1.1.1", port: 53 }, log = () => undefined, tries = 8 }) {
  const stats = { queries: new Map(), hijack: new Map() };
  const bump = (map, key) => map.set(key, (map.get(key) || 0) + 1);
  const answer = async (proto, query, family = "ipv4") => {
    bump(stats.hijack, `${proto},${family}`);
    const qtype = dnsQtype(query);
    let reply = fakeIp ? answerDns(query, fakeIp) : null;
    let result = reply ? (qtype === "AAAA" ? "empty" : "fakeip") : "relay";
    if (!reply && qtype !== "bad") {
      try {
        reply = await relay(proto, Buffer.from(query), upstream);
      } catch (err) {
        log(`DNS 转发 ${upstream.host}:${upstream.port} 失败：${err.message || err}`);
      }
      if (!reply) result = "relay_fail";
    } else if (!reply) result = "bad";
    bump(stats.queries, `${proto},${qtype},${result}`);
    return reply;
  };
  const onTcp = (socket) => {
    const family = socket.remoteFamily === "IPv6" ? "ipv6" : "ipv4";
    socket.setTimeout(10000, () => socket.destroy());
    socket.on("error", () => socket.destroy());
    let buf = Buffer.alloc(0);
    socket.on("data", (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length > 70000) return socket.destroy();
      while (buf.length >= 2 && buf.length >= 2 + buf.readUInt16BE(0)) {
        const query = buf.subarray(2, 2 + buf.readUInt16BE(0));
        buf = buf.subarray(2 + query.length);
        void answer("tcp", query, family).then((reply) => {
          if (!reply || socket.destroyed) return;
          const head = Buffer.alloc(2);
          head.writeUInt16BE(reply.length);
          socket.write(Buffer.concat([head, reply]));
        });
      }
    });
  };
  const noV6 = (err) => ["EADDRNOTAVAIL", "EAFNOSUPPORT", "EPROTONOSUPPORT"].includes(err?.code);
  let udp = null;
  let tcp = null;
  let udp6 = null;
  let tcp6 = null;
  let v6 = Boolean(host6);
  let lastErr = null;
  const drop = () => {
    for (const s of [udp, udp6]) {
      try {
        s?.close();
      } catch {
        /* closed */
      }
    }
    tcp?.close();
    tcp6?.close();
    udp = tcp = udp6 = tcp6 = null;
  };
  for (let i = 0; i < (port ? 1 : tries) && !tcp; i += 1) {
    try {
      udp = await listenUdp(host, port);
      const bound = udp.address().port;
      tcp = await listenTcp(host, bound, onTcp);
      if (v6) {
        try {
          udp6 = await listenUdp(host6, bound);
          tcp6 = await listenTcp(host6, bound, onTcp);
        } catch (err) {
          if (!noV6(err)) throw err;
          // No IPv6 on this host: IPv4-only. The script decides whether that is acceptable.
          udp6?.close();
          udp6 = null;
          v6 = false;
        }
      }
    } catch (err) {
      lastErr = err;
      drop();
    }
  }
  if (!tcp) throw new Error(`${host}${host6 ? `/${host6}` : ""}:${port || "自动"} 绑不上（${lastErr?.code || lastErr?.message || lastErr}）`);
  for (const [sock, family] of [[udp, "ipv4"], [udp6, "ipv6"]]) {
    if (!sock) continue;
    sock.on("message", (msg, rinfo) => {
      void answer("udp", msg, family).then((reply) => {
        if (reply) sock.send(reply, rinfo.port, rinfo.address, () => undefined);
      });
    });
    sock.on("error", (err) => log(`本机 DNS UDP 出错：${err.message || err}`));
  }
  for (const srv of [tcp, tcp6]) srv?.on("error", (err) => log(`本机 DNS TCP 出错：${err.message || err}`));
  const bound = udp.address().port;
  return {
    host,
    port: bound,
    host6: udp6 ? host6 : "",
    port6: udp6 ? bound : 0,
    stats,
    close() {
      drop();
    },
  };
}
