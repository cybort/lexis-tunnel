/** Userspace IPv4 TCP/UDP for a TUN device. The kernel is not required to test a packet. */

const SYN = 0x02;
const FIN = 0x01;
const RST = 0x04;
const PSH = 0x08;
const ACK = 0x10;

export function inetChecksum(chunks) {
  const buf = Buffer.concat(chunks.map((part) => Buffer.from(part)));
  let sum = 0;
  for (let i = 0; i + 1 < buf.length; i += 2) sum += buf.readUInt16BE(i);
  if (buf.length % 2) sum += buf[buf.length - 1] << 8;
  while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
  return (~sum) & 0xffff;
}

function writeIp(buf, offset, ip) {
  const parts = String(ip).split(".").map((part) => Number(part));
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) throw new Error("地址无效");
  for (let i = 0; i < 4; i += 1) buf[offset + i] = parts[i];
}

function fmtIp(buf, offset) {
  return [0, 1, 2, 3].map((i) => buf[offset + i]).join(".");
}

export function parseIpv4(packet) {
  const buf = Buffer.from(packet);
  if (buf.length < 20 || buf[0] >> 4 !== 4) return null;
  const ihl = (buf[0] & 0x0f) * 4;
  if (ihl < 20 || buf.length < ihl) return null;
  const total = buf.readUInt16BE(2);
  const view = buf.subarray(0, Math.min(buf.length, Math.max(ihl, total)));
  return { src: fmtIp(view, 12), dst: fmtIp(view, 16), proto: view[9], payload: view.subarray(ihl) };
}

export function parseTcp(payload) {
  const buf = Buffer.from(payload);
  if (buf.length < 20) return null;
  const off = (buf[12] >> 4) * 4;
  if (off < 20 || buf.length < off) return null;
  return {
    sport: buf.readUInt16BE(0),
    dport: buf.readUInt16BE(2),
    seq: buf.readUInt32BE(4),
    ack: buf.readUInt32BE(8),
    flags: buf[13],
    window: buf.readUInt16BE(14),
    data: buf.subarray(off),
  };
}

export function parseUdp(payload) {
  const buf = Buffer.from(payload);
  if (buf.length < 8) return null;
  return { sport: buf.readUInt16BE(0), dport: buf.readUInt16BE(2), data: buf.subarray(8) };
}

function ipv4(src, dst, proto, payload) {
  const packet = Buffer.alloc(20 + payload.length);
  packet[0] = 0x45;
  packet.writeUInt16BE(packet.length, 2);
  packet[8] = 64;
  packet[9] = proto;
  writeIp(packet, 12, src);
  writeIp(packet, 16, dst);
  packet.writeUInt16BE(inetChecksum([packet.subarray(0, 20)]), 10);
  payload.copy(packet, 20);
  return packet;
}

export function buildTcpPacket({ src, dst, sport, dport, seq, ack, flags, payload = Buffer.alloc(0), window = 65535 }) {
  const body = Buffer.from(payload);
  const tcp = Buffer.alloc(20 + body.length);
  tcp.writeUInt16BE(sport, 0);
  tcp.writeUInt16BE(dport, 2);
  tcp.writeUInt32BE(seq >>> 0, 4);
  tcp.writeUInt32BE(ack >>> 0, 8);
  tcp[12] = 5 << 4;
  tcp[13] = flags;
  tcp.writeUInt16BE(window, 14);
  body.copy(tcp, 20);
  const pseudo = Buffer.alloc(12);
  writeIp(pseudo, 0, src);
  writeIp(pseudo, 4, dst);
  pseudo[9] = 6;
  pseudo.writeUInt16BE(tcp.length, 10);
  tcp.writeUInt16BE(inetChecksum([pseudo, tcp]), 16);
  return ipv4(src, dst, 6, tcp);
}

export function buildUdpPacket({ src, dst, sport, dport, payload = Buffer.alloc(0) }) {
  const body = Buffer.from(payload);
  const udp = Buffer.alloc(8 + body.length);
  udp.writeUInt16BE(sport, 0);
  udp.writeUInt16BE(dport, 2);
  udp.writeUInt16BE(udp.length, 4);
  body.copy(udp, 8);
  const pseudo = Buffer.alloc(12);
  writeIp(pseudo, 0, src);
  writeIp(pseudo, 4, dst);
  pseudo[9] = 17;
  pseudo.writeUInt16BE(udp.length, 10);
  udp.writeUInt16BE(inetChecksum([pseudo, udp]), 6);
  return ipv4(src, dst, 17, udp);
}

function seq() {
  return crypto.getRandomValues(new Uint32Array(1))[0];
}

const MSS = 1200;

function seqBefore(left, right) {
  return ((left - right) | 0) < 0;
}

/** 198.18.0.0/15. The address is only a local stand-in for a name. */
export function createFakeIp() {
  const base = (198 << 24) | (18 << 16);
  let cursor = 1;
  const byName = new Map();
  const byIp = new Map();
  const toIp = (n) => `${(n >>> 24) & 255}.${(n >>> 16) & 255}.${(n >>> 8) & 255}.${n & 255}`;
  const step = (n) => {
    let x = n;
    if ((x & 255) === 0 || (x & 255) === 255) x += 1;
    if ((x & 255) === 0 || (x & 255) === 255) x += 1;
    return x;
  };
  return {
    assign(name) {
      const key = String(name || "").trim().toLowerCase().replace(/\.$/, "");
      if (!key || key.includes(":") || /^\d{1,3}(\.\d{1,3}){3}$/.test(key)) return null;
      const hit = byName.get(key);
      if (hit) return hit;
      cursor = step(cursor);
      if (cursor >= 0x8000) cursor = step(1);
      const ip = toIp((base + cursor) >>> 0);
      cursor += 1;
      const old = byIp.get(ip);
      if (old && byName.get(old) === ip) byName.delete(old);
      byName.set(key, ip);
      byIp.set(ip, key);
      return ip;
    },
    lookup(ip) {
      return byIp.get(String(ip)) || null;
    },
  };
}

function readDnsName(buf, offset, depth = 0) {
  if (depth > 8 || offset >= buf.length) return null;
  const labels = [];
  let pos = offset;
  let end = offset;
  let jumped = false;
  for (let guard = 0; guard < 64; guard += 1) {
    if (pos >= buf.length) return null;
    const len = buf[pos];
    if (len === 0) {
      if (!jumped) end = pos + 1;
      return { name: labels.join("."), end };
    }
    if ((len & 0xc0) === 0xc0) {
      if (pos + 1 >= buf.length) return null;
      if (!jumped) end = pos + 2;
      const rest = readDnsName(buf, ((len & 0x3f) << 8) | buf[pos + 1], depth + 1);
      if (!rest) return null;
      if (rest.name) labels.push(rest.name);
      return { name: labels.join("."), end };
    }
    if (len > 63) return null;
    pos += 1;
    if (pos + len > buf.length) return null;
    labels.push(buf.subarray(pos, pos + len).toString("ascii").toLowerCase());
    pos += len;
    if (!jumped) end = pos;
  }
  return null;
}

export function buildDnsQuery(name, type = 1) {
  const labels = Buffer.concat(
    String(name).split(".").filter(Boolean).map((part) => {
      const body = Buffer.from(part);
      return Buffer.concat([Buffer.from([body.length]), body]);
    }).concat([Buffer.from([0])]),
  );
  const tail = Buffer.alloc(4);
  tail.writeUInt16BE(type, 0);
  tail.writeUInt16BE(1, 2);
  const header = Buffer.alloc(12);
  header.writeUInt16BE(0x1234, 0);
  header.writeUInt16BE(0x0100, 2);
  header.writeUInt16BE(1, 4);
  return Buffer.concat([header, labels, tail]);
}

/** A standard query becomes one A record in the fake pool. AAAA gets an empty answer. */
export function answerDns(packet, fakeIp, ttl = 60) {
  const buf = Buffer.from(packet);
  if (buf.length < 12 || !fakeIp) return null;
  const flags = buf.readUInt16BE(2);
  if (flags & 0x8000) return null;
  if ((flags & 0x7800) !== 0) return null;
  if (buf.readUInt16BE(4) < 1) return null;
  const question = readDnsName(buf, 12);
  if (!question || question.end + 4 > buf.length) return null;
  const qtype = buf.readUInt16BE(question.end);
  const qclass = buf.readUInt16BE(question.end + 2);
  if (qclass !== 1) return null;
  const asked = buf.subarray(12, question.end + 4);
  const header = Buffer.alloc(12);
  buf.copy(header, 0, 0, 2);
  header.writeUInt16BE(0x8000 | (flags & 0x0100) | 0x0080, 2);
  header.writeUInt16BE(1, 4);
  if (qtype === 28) {
    header.writeUInt16BE(0, 6);
    return Buffer.concat([header, asked]);
  }
  if (qtype !== 1 && qtype !== 255) return null;
  const ip = fakeIp.assign(question.name);
  if (!ip) return null;
  header.writeUInt16BE(1, 6);
  const answer = Buffer.alloc(16);
  answer.writeUInt16BE(0xc00c, 0);
  answer.writeUInt16BE(1, 2);
  answer.writeUInt16BE(1, 4);
  answer.writeUInt32BE(ttl >>> 0, 6);
  answer.writeUInt16BE(4, 10);
  const parts = ip.split(".").map((part) => Number(part));
  answer[12] = parts[0];
  answer[13] = parts[1];
  answer[14] = parts[2];
  answer[15] = parts[3];
  return Buffer.concat([header, asked, answer]);
}

export function createEngine({ dialTcp, dialUdp, emit, fakeIp = null, mss = MSS }) {
  const tcpFlows = new Map();
  const udpFlows = new Map();

  function emitTcp(flow, seqNo, flags, payload) {
    emit(buildTcpPacket({
      src: flow.dst,
      dst: flow.src,
      sport: flow.dport,
      dport: flow.sport,
      seq: seqNo,
      ack: flow.rcvNxt,
      flags,
      payload,
      window: 65535,
    }));
  }

  function sendTcp(flow, flags, payload = Buffer.alloc(0)) {
    const body = Buffer.from(payload);
    const seqNo = flow.sndNxt;
    emitTcp(flow, seqNo, flags, body);
    const len = body.length + ((flags & (SYN | FIN)) ? 1 : 0);
    if (len && (flags & RST) === 0) {
      flow.unacked.push({ seq: seqNo, flags, payload: body, len });
      flow.sndNxt = (flow.sndNxt + len) >>> 0;
    }
  }

  function ackOnly(flow) {
    emitTcp(flow, flow.sndNxt, ACK, Buffer.alloc(0));
  }

  function flight(flow) {
    return (flow.sndNxt - flow.sndUna) >>> 0;
  }

  function noteAck(flow, ack) {
    flow.unacked = flow.unacked.filter((seg) => seqBefore(ack, (seg.seq + seg.len) >>> 0));
    if (!seqBefore(ack, flow.sndUna) && !seqBefore(flow.sndNxt, ack)) flow.sndUna = ack >>> 0;
  }

  function pump(flow) {
    if (!flow.socket) return;
    while (flow.pending.length) {
      const room = flow.peerWnd - flight(flow);
      if (room <= 0) {
        flow.paused = true;
        flow.socket.pause?.();
        return;
      }
      const take = Math.min(mss, room, flow.pending[0].length);
      const chunk = flow.pending[0].subarray(0, take);
      flow.pending[0] = flow.pending[0].subarray(take);
      if (!flow.pending[0].length) flow.pending.shift();
      sendTcp(flow, ACK | PSH, chunk);
    }
    if (flow.finPending && !flow.finSent && flow.peerWnd - flight(flow) > 0) {
      flow.finSent = true;
      sendTcp(flow, ACK | FIN);
    }
    if (flow.paused && flow.peerWnd - flight(flow) > 0) {
      flow.paused = false;
      flow.socket.resume?.();
    }
  }

  function takePayload(flow, seqNo, data, flags) {
    if (seqNo !== flow.rcvNxt) {
      if (data.length && !seqBefore(seqNo, flow.rcvNxt) && ((seqNo - flow.rcvNxt) >>> 0) <= 65535) {
        if (!flow.hold || ((seqNo - flow.rcvNxt) >>> 0) < ((flow.hold.seq - flow.rcvNxt) >>> 0)) {
          flow.hold = { seq: seqNo, data, flags };
        }
      }
      return false;
    }
    if (data.length) {
      flow.socket.write(data);
      flow.rcvNxt = (flow.rcvNxt + data.length) >>> 0;
    }
    if (flags & FIN) {
      flow.rcvNxt = (flow.rcvNxt + 1) >>> 0;
      flow.hold = null;
      flow.socket.end();
      return true;
    }
    if (flow.hold && flow.hold.seq === flow.rcvNxt) {
      const held = flow.hold;
      flow.hold = null;
      takePayload(flow, held.seq, held.data, held.flags);
    }
    return true;
  }

  function resetFlow(key, flow) {
    emitTcp(flow, flow.sndNxt, RST | ACK, Buffer.alloc(0));
    flow.socket?.destroy();
    tcpFlows.delete(key);
  }

  async function onTcp(ip, tcp) {
    const key = `${ip.src}:${tcp.sport}>${ip.dst}:${tcp.dport}`;
    if (tcp.flags & RST) {
      tcpFlows.get(key)?.socket?.destroy();
      tcpFlows.delete(key);
      return;
    }
    if ((tcp.flags & SYN) && !(tcp.flags & ACK)) {
      if (tcpFlows.has(key)) return;
      const iss = seq();
      const flow = {
        src: ip.src,
        dst: ip.dst,
        sport: tcp.sport,
        dport: tcp.dport,
        sndUna: iss,
        sndNxt: iss,
        rcvNxt: (tcp.seq + 1) >>> 0,
        peerWnd: tcp.window,
        socket: null,
        unacked: [],
        pending: [],
        hold: null,
        paused: false,
        finPending: false,
        finSent: false,
      };
      tcpFlows.set(key, flow);
      const host = fakeIp?.lookup(ip.dst) || ip.dst;
      try {
        const socket = await dialTcp(host, tcp.dport);
        if (!tcpFlows.has(key)) {
          socket.destroy();
          return;
        }
        flow.socket = socket;
        socket.on("data", (chunk) => {
          flow.pending.push(Buffer.from(chunk));
          pump(flow);
        });
        socket.on("error", () => {
          if (tcpFlows.has(key)) resetFlow(key, flow);
        });
        socket.on("close", () => {
          if (!tcpFlows.has(key) || flow.finSent) return;
          flow.finPending = true;
          pump(flow);
        });
        sendTcp(flow, SYN | ACK);
      } catch {
        resetFlow(key, flow);
      }
      return;
    }
    const flow = tcpFlows.get(key);
    if (!flow?.socket) return;
    if (typeof tcp.window === "number") flow.peerWnd = tcp.window;
    if (tcp.flags & ACK) noteAck(flow, tcp.ack);
    const accepted = tcp.data.length || (tcp.flags & FIN) ? takePayload(flow, tcp.seq, tcp.data, tcp.flags) : false;
    if (accepted || tcp.data.length || (tcp.flags & ACK)) ackOnly(flow);
    pump(flow);
  }

  async function onUdp(ip) {
    const udp = parseUdp(ip.payload);
    if (!udp) return;
    if (udp.dport === 53 && fakeIp) {
      const answer = answerDns(udp.data, fakeIp);
      if (answer) {
        emit(buildUdpPacket({ src: ip.dst, dst: ip.src, sport: 53, dport: udp.sport, payload: answer }));
        return;
      }
    }
    const host = fakeIp?.lookup(ip.dst) || ip.dst;
    const key = `${ip.src}:${udp.sport}>${ip.dst}:${udp.dport}`;
    let socket = udpFlows.get(key);
    if (!socket) {
      socket = await dialUdp(host, udp.dport);
      udpFlows.set(key, socket);
      socket.on("message", (msg) => {
        emit(buildUdpPacket({ src: ip.dst, dst: ip.src, sport: udp.dport, dport: udp.sport, payload: msg }));
      });
      socket.on("error", () => udpFlows.delete(key));
    }
    await new Promise((resolve, reject) => socket.send(udp.data, udp.dport, host, (err) => (err ? reject(err) : resolve())));
  }

  return {
    async push(packet) {
      const ip = parseIpv4(packet);
      if (!ip) return;
      if (ip.proto === 6) {
        const tcp = parseTcp(ip.payload);
        if (tcp) await onTcp(ip, tcp);
        return;
      }
      if (ip.proto === 17) await onUdp(ip);
    },
    retransmit() {
      for (const flow of tcpFlows.values()) {
        for (const seg of flow.unacked) emitTcp(flow, seg.seq, seg.flags, seg.payload);
      }
    },
    close() {
      for (const flow of tcpFlows.values()) flow.socket?.destroy();
      for (const socket of udpFlows.values()) {
        try {
          socket.close();
        } catch {
          /* already closed */
        }
      }
      tcpFlows.clear();
      udpFlows.clear();
    },
  };
}

/** Remember the original destination and aim the packet at the local proxy port. */
export function redirectTcp(packet, table, proxyPort) {
  const ip = parseIpv4(packet);
  if (!ip || ip.proto !== 6) return null;
  const tcp = parseTcp(ip.payload);
  if (!tcp) return null;
  if (ip.src === "127.0.0.1" && tcp.sport === proxyPort) {
    const saved = table.get(`${ip.dst}:${tcp.dport}`);
    if (!saved) return null;
    return buildTcpPacket({
      src: saved.host,
      dst: ip.dst,
      sport: saved.port,
      dport: tcp.dport,
      seq: tcp.seq,
      ack: tcp.ack,
      flags: tcp.flags,
      payload: tcp.data,
    });
  }
  table.set(`${ip.src}:${tcp.sport}`, { host: ip.dst, port: tcp.dport });
  return buildTcpPacket({
    src: ip.src,
    dst: "127.0.0.1",
    sport: tcp.sport,
    dport: proxyPort,
    seq: tcp.seq,
    ack: tcp.ack,
    flags: tcp.flags,
    payload: tcp.data,
  });
}
