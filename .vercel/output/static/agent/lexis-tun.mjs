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

export function createEngine({ dialTcp, dialUdp, emit }) {
  const tcpFlows = new Map();
  const udpFlows = new Map();

  function reply(flow, payload, flags) {
    emit(buildTcpPacket({
      src: flow.dst,
      dst: flow.src,
      sport: flow.dport,
      dport: flow.sport,
      seq: flow.seq,
      ack: flow.ack,
      flags,
      payload,
    }));
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
      const flow = { src: ip.src, dst: ip.dst, sport: tcp.sport, dport: tcp.dport, seq: seq(), ack: (tcp.seq + 1) >>> 0, socket: null };
      tcpFlows.set(key, flow);
      try {
        const socket = await dialTcp(ip.dst, tcp.dport);
        flow.socket = socket;
        socket.on("data", (chunk) => {
          reply(flow, chunk, ACK | PSH);
          flow.seq = (flow.seq + chunk.length) >>> 0;
        });
        socket.on("error", () => {
          reply(flow, Buffer.alloc(0), RST | ACK);
          tcpFlows.delete(key);
        });
        socket.on("close", () => {
          if (!tcpFlows.has(key)) return;
          reply(flow, Buffer.alloc(0), ACK | FIN);
          flow.seq = (flow.seq + 1) >>> 0;
          tcpFlows.delete(key);
        });
        reply(flow, Buffer.alloc(0), SYN | ACK);
        flow.seq = (flow.seq + 1) >>> 0;
      } catch {
        reply(flow, Buffer.alloc(0), RST | ACK);
        tcpFlows.delete(key);
      }
      return;
    }
    const flow = tcpFlows.get(key);
    if (!flow?.socket) return;
    if (tcp.data.length) {
      if (tcp.seq !== flow.ack) return;
      flow.socket.write(tcp.data);
      flow.ack = (flow.ack + tcp.data.length) >>> 0;
      reply(flow, Buffer.alloc(0), ACK);
    }
    if (tcp.flags & FIN) {
      flow.ack = (flow.ack + 1) >>> 0;
      reply(flow, Buffer.alloc(0), ACK);
      flow.socket.end();
    }
  }

  async function onUdp(ip) {
    const udp = parseUdp(ip.payload);
    if (!udp) return;
    const key = `${ip.src}:${udp.sport}>${ip.dst}:${udp.dport}`;
    let socket = udpFlows.get(key);
    if (!socket) {
      socket = await dialUdp(ip.dst, udp.dport);
      udpFlows.set(key, socket);
      socket.on("message", (msg) => {
        emit(buildUdpPacket({ src: ip.dst, dst: ip.src, sport: udp.dport, dport: udp.sport, payload: msg }));
      });
      socket.on("error", () => udpFlows.delete(key));
    }
    await new Promise((resolve, reject) => socket.send(udp.data, udp.dport, ip.dst, (err) => (err ? reject(err) : resolve())));
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
