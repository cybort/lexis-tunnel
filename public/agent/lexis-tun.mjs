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

/** S0: why push() could not use a packet: { version, proto, reason } (proto = IPv6 next header). */
export function dropInfo(packet) {
  const buf = Buffer.from(packet);
  const version = buf.length ? buf[0] >> 4 : 0;
  if (version !== 6) return { version, proto: "", reason: version === 4 ? "bad_ipv4" : "not_ip" };
  if (buf.length < 40) return { version, proto: "", reason: "truncated" };
  const next = buf[6];
  return { version, proto: next === 6 ? "tcp" : next === 17 ? "udp" : next === 58 ? "icmpv6" : "other", reason: "no_ipv6_engine" };
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
    mss: tcpMssOption(buf.subarray(20, off)),
    data: buf.subarray(off),
  };
}

/** MSS option (kind 2, len 4) from a TCP options block, or null when absent/malformed. */
export function tcpMssOption(opts) {
  let i = 0;
  while (i < opts.length) {
    const kind = opts[i];
    if (kind === 0) break;
    if (kind === 1) {
      i += 1;
      continue;
    }
    if (i + 1 >= opts.length) break;
    const len = opts[i + 1];
    if (len < 2 || i + len > opts.length) break;
    if (kind === 2 && len === 4) {
      const v = opts.readUInt16BE(i + 2);
      return v > 0 ? v : null;
    }
    i += len;
  }
  return null;
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

export function buildTcpPacket({ src, dst, sport, dport, seq, ack, flags, payload = Buffer.alloc(0), window = 65535, mss = null }) {
  const body = Buffer.from(payload);
  // Only the MSS option is ever written (SYN segments); 4 bytes keeps the header 32-bit aligned.
  const optLen = mss ? 4 : 0;
  const tcp = Buffer.alloc(20 + optLen + body.length);
  tcp.writeUInt16BE(sport, 0);
  tcp.writeUInt16BE(dport, 2);
  tcp.writeUInt32BE(seq >>> 0, 4);
  tcp.writeUInt32BE(ack >>> 0, 8);
  tcp[12] = ((20 + optLen) / 4) << 4;
  tcp[13] = flags;
  tcp.writeUInt16BE(window, 14);
  if (optLen) {
    tcp[20] = 2;
    tcp[21] = 4;
    tcp.writeUInt16BE(Math.max(1, Math.min(65535, mss | 0)), 22);
  }
  body.copy(tcp, 20 + optLen);
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

// RFC 9293 3.7.1: without an MSS option the peer must be assumed to take 536.
const DEFAULT_PEER_MSS = 536;
const TUN_MTU = 1500;
// The engine advertises a fixed 65535-byte window (no window scaling), so nothing
// beyond rcvNxt + RCV_WND is ever accepted into the out-of-order queue.
const RCV_WND = 65535;

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

export function createEngine({ dialTcp, dialUdp, emit, fakeIp = null, mtu = TUN_MTU, mss = null, oooMaxBytes = RCV_WND, oooMaxSegs = 64, oooTotalBytes = 8 << 20, log = () => undefined, udpIdleMs = 60000, udpMax = 64, timeWaitMs = 2000, finLingerMs = 60000, rtoMs = 1000, rtoMinMs = 200, rtoMaxMs = 60000, maxRetries = 7, giveUpMs = 180000, synRtoMs = 3000, dupAckThresh = 3, loopGuard = [], onLoopDrop = () => undefined, onDrop6 = () => undefined, iss = null }) {
  // 3.0.3 loop guard: packets addressed to our own peers (gates) must never be tunnelled;
  // they only show up here when the route to the peer fell back to the tun table.
  const guarded = new Set(loopGuard);
  // MSS we announce in SYN|ACK: what fits one tun MTU (IPv4 + TCP headers without options
  // = 40 bytes), unless `mss` overrides it. The send MSS of a flow is min(this, peer's MSS).
  const localMss = Math.max(88, Math.min(65495, Number(mss) > 0 ? Number(mss) : (Number(mtu) || TUN_MTU) - 40));
  const oooBytesCap = Math.max(0, Math.min(RCV_WND, Number(oooMaxBytes) || 0));
  const oooSegsCap = Math.max(0, Number(oooMaxSegs) | 0);
  const oooTotalCap = Math.max(0, Number(oooTotalBytes) || 0);
  const oooStats = { bytes: 0, segs: 0, dropped: 0, droppedBytes: 0, outOfWindow: 0 };
  // Tests pin the initial send sequence. Production leaves this null and draws a random ISS.
  const fixedIss = iss === null || iss === undefined ? null : Number(iss) >>> 0;
  // Flows used to be removed only on RST/error, so every gracefully closed TCP
  // connection stayed in tcpFlows (with its socket and buffers) for the life of the
  // engine. Now: both FINs exchanged and ours acked -> short TIME_WAIT, then drop;
  // a half-closed flow that never completes is reset after finLingerMs.
  const tcpFlows = new Map();
  const udpFlows = new Map();
  // UDP has no close; without an idle sweep every new source port (each DNS query)
  // pinned a mux stream here and a UDP socket on the exit forever (128-stream cap).
  const udpSeen = new Map();
  // DNS flows are one-shot: short idle. Hard cap with oldest-first eviction keeps
  // UDP well below the mux stream cap even at high new-flow rates.
  const udpShort = new Set();
  const closeUdp = (key) => {
    const socket = udpFlows.get(key);
    udpFlows.delete(key);
    udpSeen.delete(key);
    udpShort.delete(key);
    try {
      socket?.close();
    } catch {
      /* already closed */
    }
  };
  const sweep = setInterval(() => {
    const now = Date.now();
    for (const [key, seen] of udpSeen) if (now - seen > (udpShort.has(key) ? Math.min(udpIdleMs, 5000) : udpIdleMs)) closeUdp(key);
  }, Math.max(1000, Math.min(2500, Math.floor(udpIdleMs / 2))));
  sweep.unref?.();

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
      window: RCV_WND,
      mss: flags & SYN ? localMss : null,
    }));
  }

  // Retransmission timeout (RFC 6298): flow.unacked holds the in-flight segments.
  // While any are outstanding one timer runs. RTO starts at rtoMs, then follows
  // SRTT/RTTVAR from ACKs of segments sent once (Karn), floored at rtoMinMs.
  // On expiry only the oldest unacked segment is resent and the timeout doubles
  // (capped at rtoMaxMs) and stays doubled until a new RTT sample; until the ACK passes the point reached when the timer
  // fired, each partial ACK resends the new oldest segment (it was sent at least
  // one RTO earlier, so it is lost, not in flight). An ACK that advances sndUna
  // resets the retry count. The flow is reset (RST) and dropped only when both
  // maxRetries consecutive expiries and giveUpMs (3 min) passed without ACK progress. Duplicate-ACK fast retransmit: see noteDupAck.
  const rtoFloor = Math.min(rtoMinMs, rtoMs);

  function stopRto(flow) {
    if (flow.rtoTimer) clearTimeout(flow.rtoTimer);
    flow.rtoTimer = null;
  }

  function resendSeg(flow, seg) {
    seg.tx += 1;
    seg.sentAt = Date.now();
    flow.lastRetxAt = seg.sentAt;
    emitTcp(flow, seg.seq, seg.flags, seg.payload);
  }

  function armRto(flow) {
    stopRto(flow);
    if (!flow.unacked.length) return;
    const wait = flow.rto;
    flow.rtoTimer = setTimeout(() => {
      flow.rtoTimer = null;
      if (tcpFlows.get(flow.key) !== flow || !flow.unacked.length) return;
      if (flow.retries >= maxRetries && Date.now() - flow.progressAt >= giveUpMs) {
        log(`tcp ${flow.key} 重传 ${flow.retries} 次仍无确认，重置`);
        resetFlow(flow.key, flow);
        return;
      }
      flow.retries += 1;
      // Backed-off RTO persists until a fresh RTT sample (RFC 6298 5.5/5.7).
      flow.rto = Math.min(rtoMaxMs, flow.rto * 2);
      flow.recover = flow.sndNxt;
      resendSeg(flow, flow.unacked[0]);
      armRto(flow);
    }, wait);
    flow.rtoTimer.unref?.();
  }

  function sampleRtt(flow, r) {
    if (!flow.srtt) {
      flow.srtt = r;
      flow.rttvar = r / 2;
    } else {
      flow.rttvar = 0.75 * flow.rttvar + 0.25 * Math.abs(flow.srtt - r);
      flow.srtt = 0.875 * flow.srtt + 0.125 * r;
    }
    flow.rto = Math.min(rtoMaxMs, Math.max(rtoFloor, flow.srtt + Math.max(10, 4 * flow.rttvar)));
  }

  function sendTcp(flow, flags, payload = Buffer.alloc(0)) {
    const body = Buffer.from(payload);
    const seqNo = flow.sndNxt;
    emitTcp(flow, seqNo, flags, body);
    const len = body.length + ((flags & (SYN | FIN)) ? 1 : 0);
    if (len && (flags & RST) === 0) {
      flow.unacked.push({ seq: seqNo, flags, payload: body, len, sentAt: Date.now(), tx: 1 });
      flow.sndNxt = (flow.sndNxt + len) >>> 0;
      if (!flow.rtoTimer) armRto(flow);
    }
  }

  function ackOnly(flow) {
    emitTcp(flow, flow.sndNxt, ACK, Buffer.alloc(0));
  }

  function flight(flow) {
    return (flow.sndNxt - flow.sndUna) >>> 0;
  }

  // Fast retransmit (RFC 5681 3.2 / RFC 6582 NewReno, no SACK): dupAckThresh pure
  // duplicate ACKs (no data, no SYN/FIN, same window, ack == sndUna, data outstanding)
  // resend the oldest unacked segment once and enter recovery with recover = sndNxt.
  // Reordering guard (RACK-style time check, RFC 8985 6.2): the oldest segment is only
  // treated as lost once it is older than lateMs = SRTT + max(2 ms, SRTT/4); a younger
  // one may just be reordered, so the decision is deferred to that age and dropped if
  // the ACK advances meanwhile. While sndUna is below recover further duplicates are
  // ignored (no repeat trigger); a partial ACK resends the new oldest segment only if it
  // is also older than lateMs (shared with RTO recovery); an ACK reaching recover ends
  // recovery. A fast retransmit does not change RTO backoff (the timer is restarted).
  // The engine has no cwnd (bounded by peerWnd), so no window halving/inflation.
  function lateMs(flow) {
    // No RTT sample yet: use the current RTO, so the guard is not disabled (age 0).
    return flow.srtt ? flow.srtt + Math.max(2, flow.srtt / 4) : flow.rto;
  }

  function stopReo(flow) {
    if (flow.reoTimer) clearTimeout(flow.reoTimer);
    flow.reoTimer = null;
  }

  function inRecovery(flow) {
    return flow.recover !== null && seqBefore(flow.sndUna, flow.recover);
  }

  function fastRetransmit(flow) {
    if (tcpFlows.get(flow.key) !== flow || !flow.unacked.length || inRecovery(flow)) return;
    if (flow.dupAcks < dupAckThresh) return;
    const wait = lateMs(flow) - (Date.now() - flow.unacked[0].sentAt);
    if (wait > 0) {
      if (!flow.reoTimer) {
        flow.reoTimer = setTimeout(() => {
          flow.reoTimer = null;
          fastRetransmit(flow);
        }, Math.ceil(wait));
        flow.reoTimer.unref?.();
      }
      return;
    }
    flow.recover = flow.sndNxt;
    flow.fastRetx += 1;
    resendSeg(flow, flow.unacked[0]);
    armRto(flow);
  }

  function noteDupAck(flow) {
    if (!flow.unacked.length) return;
    flow.dupAcks += 1;
    fastRetransmit(flow);
  }

  function noteAck(flow, ack) {
    let sample = 0;
    let synRetx = false;
    flow.unacked = flow.unacked.filter((seg) => {
      if (seqBefore(ack, (seg.seq + seg.len) >>> 0)) return true;
      // Karn: only segments sent once AND first sent after the last retransmission.
      // Segments sent before a retransmission sat behind the hole it repairs, so their
      // "RTT" includes the recovery time (inflated SRTT/RTO to tens of seconds at 5%
      // loss); segments sent after it are timed normally.
      if (seg.tx === 1 && seg.sentAt > flow.lastRetxAt) sample = Date.now() - seg.sentAt;
      if ((seg.flags & SYN) && seg.tx > 1) synRetx = true;
      return false;
    });
    // RFC 6298 5.7: SYN-ACK was retransmitted and the handshake gave no RTT sample ->
    // data starts with RTO = synRtoMs (3 s), not the backed-off value (which can sit at
    // ~RTT and fire spuriously, e.g. 2000 ms RTT after a 1 s initial RTO).
    if (synRetx && !flow.srtt && !sample) flow.rto = Math.min(rtoMaxMs, Math.max(flow.rto, synRtoMs));
    if (!seqBefore(ack, flow.sndUna) && !seqBefore(flow.sndNxt, ack) && (ack >>> 0) !== flow.sndUna) {
      flow.sndUna = ack >>> 0;
      flow.progressAt = Date.now();
      if (sample) sampleRtt(flow, Math.max(1, sample));
      flow.retries = 0;
      flow.dupAcks = 0;
      stopReo(flow);
      if (flow.recover !== null && seqBefore(flow.sndUna, flow.recover) && flow.unacked.length) {
        const head = flow.unacked[0];
        if (seqBefore(head.seq, flow.recover) && Date.now() - head.sentAt >= lateMs(flow)) resendSeg(flow, head);
      } else {
        flow.recover = null;
      }
      armRto(flow);
    }
    if (!flow.unacked.length) stopRto(flow);
  }

  function dropFlow(flow) {
    oooClear(flow);
    stopRto(flow);
    stopReo(flow);
    if (flow.timer) clearTimeout(flow.timer);
    flow.timer = null;
    if (tcpFlows.get(flow.key) === flow) tcpFlows.delete(flow.key);
  }

  function checkClosed(flow) {
    if (flow.timeWait) return;
    if (flow.finSent && flow.finRcvd && flow.sndUna === flow.sndNxt) {
      // Both directions closed and our FIN acked: linger briefly so a retransmitted
      // peer FIN still gets an ACK, then forget the flow.
      flow.timeWait = true;
      flow.socket?.destroy();
      if (flow.timer) clearTimeout(flow.timer);
      flow.timer = setTimeout(() => dropFlow(flow), timeWaitMs);
      flow.timer.unref?.();
      return;
    }
    if ((flow.finSent || flow.finRcvd) && !flow.timer) {
      flow.timer = setTimeout(() => {
        flow.timer = null;
        if (tcpFlows.get(flow.key) !== flow) return;
        // Our data is still in RTO recovery (backoff can reach rtoMaxMs, longer than
        // finLingerMs): keep lingering; the RTO give-up (maxRetries) bounds this flow.
        if (flow.unacked.length && flow.rtoTimer) return checkClosed(flow);
        resetFlow(flow.key, flow);
      }, finLingerMs);
      flow.timer.unref?.();
    }
  }

  function pump(flow) {
    if (!flow.socket || flow.aborting) return;
    while (flow.pending.length) {
      const room = flow.peerWnd - flight(flow);
      if (room <= 0) {
        flow.paused = true;
        flow.socket.pause?.();
        return;
      }
      const take = Math.min(flow.sndMss, room, flow.pending[0].length);
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

  // Out-of-order queue: flow.ooo is sorted by sequence, non-overlapping, adjacent pieces
  // coalesced. Bounded per flow (oooMaxBytes / oooMaxSegs, bytes never above the 65535
  // receive window) and engine-wide (oooTotalBytes). Over a cap the piece farthest from
  // rcvNxt is dropped first (the nearest ones are what fills the hole; the sender will
  // retransmit the rest). Freed when the hole fills, and on FIN/RST/reset/flow drop.
  const rel = (flow, sq) => (sq - flow.rcvNxt) >>> 0;

  function oooClear(flow) {
    if (!flow.ooo?.length) return;
    for (const seg of flow.ooo) oooStats.bytes -= seg.data.length;
    oooStats.segs -= flow.ooo.length;
    flow.oooBytes = 0;
    flow.ooo = [];
    flow.oooFin = null;
  }

  function oooDropTail(flow) {
    const seg = flow.ooo.pop();
    flow.oooBytes -= seg.data.length;
    oooStats.bytes -= seg.data.length;
    oooStats.segs -= 1;
    oooStats.dropped += 1;
    oooStats.droppedBytes += seg.data.length;
    // A FIN sitting beyond a dropped piece can no longer be trusted to be contiguous.
    if (flow.oooFin !== null && !seqBefore(seg.seq, flow.oooFin)) flow.oooFin = null;
  }

  function oooInsert(flow, seqNo, data, fin) {
    let start = rel(flow, seqNo);
    if (start >= RCV_WND) {
      oooStats.outOfWindow += 1;
      return;
    }
    let body = data;
    if (start + body.length > RCV_WND) {
      body = body.subarray(0, RCV_WND - start);
      fin = false;
      oooStats.outOfWindow += 1;
    }
    if (fin) flow.oooFin = (seqNo + data.length) >>> 0;
    if (!body.length || !oooSegsCap || !oooBytesCap) return;
    // Cut the new range down to the parts no queued piece covers (queued bytes win).
    const pieces = [];
    let cur = start;
    const end = start + body.length;
    for (const seg of flow.ooo) {
      const a = rel(flow, seg.seq);
      const b = a + seg.data.length;
      if (b <= cur) continue;
      if (a >= end) break;
      if (a > cur) pieces.push([cur, a]);
      cur = Math.max(cur, b);
      if (cur >= end) break;
    }
    if (cur < end) pieces.push([cur, end]);
    for (const [pa, pb] of pieces) {
      const chunk = Buffer.from(body.subarray(pa - start, pb - start));
      const item = { seq: (flow.rcvNxt + pa) >>> 0, data: chunk };
      let i = 0;
      while (i < flow.ooo.length && rel(flow, flow.ooo[i].seq) < pa) i += 1;
      flow.ooo.splice(i, 0, item);
      flow.oooBytes += chunk.length;
      oooStats.bytes += chunk.length;
      oooStats.segs += 1;
      // Coalesce with contiguous neighbours so the segment cap counts holes, not packets.
      const next = flow.ooo[i + 1];
      if (next && next.seq === ((item.seq + item.data.length) >>> 0)) {
        item.data = Buffer.concat([item.data, next.data]);
        flow.ooo.splice(i + 1, 1);
        oooStats.segs -= 1;
      }
      const prev = flow.ooo[i - 1];
      if (prev && ((prev.seq + prev.data.length) >>> 0) === item.seq) {
        prev.data = Buffer.concat([prev.data, item.data]);
        flow.ooo.splice(i, 1);
        oooStats.segs -= 1;
      }
    }
    while (flow.ooo.length && (flow.ooo.length > oooSegsCap || flow.oooBytes > oooBytesCap || oooStats.bytes > oooTotalCap)) oooDropTail(flow);
  }

  function deliver(flow, data) {
    if (!data.length) return;
    flow.socket.write(data);
    flow.rcvNxt = (flow.rcvNxt + data.length) >>> 0;
  }

  function takeFin(flow) {
    flow.rcvNxt = (flow.rcvNxt + 1) >>> 0;
    flow.finRcvd = true;
    oooClear(flow);
    flow.oooFin = null;
    flow.socket.end();
  }

  function takePayload(flow, seqNo, data, flags) {
    let fin = Boolean(flags & FIN);
    // Retransmission overlapping what we already have: keep only the new tail.
    if (seqBefore(seqNo, flow.rcvNxt)) {
      const skip = (flow.rcvNxt - seqNo) >>> 0;
      if (skip > data.length || (skip === data.length && !fin)) return false;
      data = data.subarray(skip);
      seqNo = flow.rcvNxt;
    }
    if (seqNo !== flow.rcvNxt) {
      if (data.length || fin) oooInsert(flow, seqNo, data, fin);
      return false;
    }
    if (flow.finRcvd) return false;
    deliver(flow, data);
    // Drain queued pieces that the new data reached.
    while (flow.ooo.length && !seqBefore(flow.rcvNxt, flow.ooo[0].seq)) {
      const seg = flow.ooo.shift();
      flow.oooBytes -= seg.data.length;
      oooStats.bytes -= seg.data.length;
      oooStats.segs -= 1;
      const skip = (flow.rcvNxt - seg.seq) >>> 0;
      if (skip < seg.data.length) deliver(flow, seg.data.subarray(skip));
    }
    if (fin || (flow.oooFin !== null && flow.oooFin === flow.rcvNxt)) {
      takeFin(flow);
      return true;
    }
    return true;
  }

  // RFC 5961 §3.2: a Linux peer in a synchronized state applies RST only when
  // SEG.SEQ equals RCV.NXT. Anything else inside the window is a challenge ACK,
  // and a sequence outside the window is dropped. After a lossy stretch the peer's
  // RCV.NXT is still sndUna (the next byte they have not acknowledged). sndNxt is
  // past unacknowledged payload and an unacked FIN, so a RST there does not reset
  // the socket. If their ACK was lost and they already have every byte we sent,
  // RCV.NXT is sndNxt instead, so that endpoint is sent as well. Both values are
  // sequence numbers this stack assigned; seqBefore keeps the range correct when
  // they wrap. Retransmission does not move sndUna. A later ACK whose number lies
  // in [sndUna, sndNxt] is the peer saying what RCV.NXT is, and one RST is repeated
  // at that number. The ACK field stays rcvNxt (next byte we expect), including a
  // FIN we have already taken.
  function emitReset(flow, seqNo) {
    emitTcp(flow, seqNo >>> 0, RST | ACK, Buffer.alloc(0));
  }

  function ackInSent(flow, ack) {
    const a = ack >>> 0;
    const una = flow.sndUna >>> 0;
    const nxt = flow.sndNxt >>> 0;
    if (a === una || a === nxt) return true;
    return seqBefore(una, a) && seqBefore(a, nxt);
  }

  function resetFlow(key, flow) {
    if (flow.aborting) return;
    flow.aborting = true;
    oooClear(flow);
    stopRto(flow);
    stopReo(flow);
    if (flow.timer) clearTimeout(flow.timer);
    flow.timer = null;
    const una = flow.sndUna >>> 0;
    const nxt = flow.sndNxt >>> 0;
    emitReset(flow, una);
    if (nxt !== una) emitReset(flow, nxt);
    try {
      flow.socket?.destroy();
    } catch {
      /* already closed */
    }
    flow.socket = null;
    // Long enough for one challenge ACK. No data segment is sent from this state.
    flow.timer = setTimeout(() => dropFlow(flow), 1000);
    flow.timer.unref?.();
  }

  async function onTcp(ip, tcp) {
    const key = `${ip.src}:${tcp.sport}>${ip.dst}:${tcp.dport}`;
    if (tcp.flags & RST) {
      const gone = tcpFlows.get(key);
      if (gone) {
        oooClear(gone);
        stopRto(gone);
        stopReo(gone);
      }
      gone?.socket?.destroy();
      if (gone?.timer) clearTimeout(gone.timer);
      tcpFlows.delete(key);
      return;
    }
    if ((tcp.flags & SYN) && !(tcp.flags & ACK)) {
      if (tcpFlows.has(key)) return;
      const issSeq = fixedIss === null ? seq() : fixedIss;
      const flow = {
        key,
        src: ip.src,
        dst: ip.dst,
        sport: tcp.sport,
        dport: tcp.dport,
        sndUna: issSeq,
        sndNxt: issSeq,
        rcvNxt: (tcp.seq + 1) >>> 0,
        peerWnd: tcp.window,
        socket: null,
        unacked: [],
        pending: [],
        ooo: [],
        oooBytes: 0,
        oooFin: null,
        sndMss: Math.min(localMss, tcp.mss || DEFAULT_PEER_MSS),
        paused: false,
        finPending: false,
        finSent: false,
        finRcvd: false,
        aborting: false,
        abortReplied: false,
        timeWait: false,
        timer: null,
        rtoTimer: null,
        retries: 0,
        rto: rtoMs,
        srtt: 0,
        rttvar: 0,
        recover: null,
        dupAcks: 0,
        reoTimer: null,
        fastRetx: 0,
        lastRetxAt: 0,
        progressAt: Date.now(),
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
          if (!tcpFlows.has(key) || flow.finSent || flow.aborting) return;
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
    if (!flow) return;
    if (flow.aborting) {
      if ((tcp.flags & ACK) && !flow.abortReplied && ackInSent(flow, tcp.ack)) {
        flow.abortReplied = true;
        emitReset(flow, tcp.ack >>> 0);
      }
      dropFlow(flow);
      return;
    }
    if (!flow.socket) return;
    const sameWnd = tcp.window === flow.peerWnd;
    if (typeof tcp.window === "number") flow.peerWnd = tcp.window;
    if (tcp.flags & ACK) {
      if ((tcp.ack >>> 0) === flow.sndUna && !tcp.data.length && !(tcp.flags & (SYN | FIN)) && sameWnd) noteDupAck(flow);
      else noteAck(flow, tcp.ack);
    }
    const accepted = tcp.data.length || (tcp.flags & FIN) ? takePayload(flow, tcp.seq, tcp.data, tcp.flags) : false;
    if (accepted || tcp.data.length || (tcp.flags & ACK)) ackOnly(flow);
    if (flow.timeWait) return;
    pump(flow);
    checkClosed(flow);
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
      try {
        socket = await dialUdp(host, udp.dport);
      } catch (err) {
        // A refused UDP open (no exit, rule reject, stream limit) must not become an
        // unhandled rejection that kills the agent.
        log(`udp ${host}:${udp.dport} 失败：${err?.message || err}`);
        return;
      }
      while (udpFlows.size >= udpMax) {
        let oldest = null;
        let at = Infinity;
        for (const [k, t] of udpSeen) if (t < at) { at = t; oldest = k; }
        if (oldest === null) break;
        closeUdp(oldest);
      }
      if (udp.dport === 53 || udp.dport === 5353) udpShort.add(key);
      udpFlows.set(key, socket);
      socket.on("message", (msg) => {
        udpSeen.set(key, Date.now());
        emit(buildUdpPacket({ src: ip.dst, dst: ip.src, sport: udp.dport, dport: udp.sport, payload: msg }));
      });
      socket.on("error", () => closeUdp(key));
    }
    udpSeen.set(key, Date.now());
    try {
      await new Promise((resolve, reject) => socket.send(udp.data, udp.dport, host, (err) => (err ? reject(err) : resolve())));
    } catch (err) {
      log(`udp ${host}:${udp.dport} 发送失败：${err?.message || err}`);
      closeUdp(key);
    }
  }

  return {
    async push(packet) {
      const ip = parseIpv4(packet);
      if (!ip) {
        // S0 (C8): a packet parseIpv4 cannot read used to vanish uncounted. Report it by IP
        // version; this engine has no IPv6 path yet, so every IPv6 packet is a drop.
        onDrop6(dropInfo(packet));
        return;
      }
      if (guarded.has(ip.dst)) {
        onLoopDrop(ip);
        return;
      }
      if (ip.proto === 6) {
        const tcp = parseTcp(ip.payload);
        if (tcp) await onTcp(ip, tcp);
        return;
      }
      if (ip.proto === 17) await onUdp(ip);
    },
    /** Out-of-order queue usage (engine-wide) and the MSS announced in SYN|ACK. */
    stats() {
      return { mss: localMss, ooo: { ...oooStats } };
    },
    retransmit() {
      for (const flow of tcpFlows.values()) {
        for (const seg of flow.unacked) emitTcp(flow, seg.seq, seg.flags, seg.payload);
      }
    },
    close() {
      clearInterval(sweep);
      for (const flow of tcpFlows.values()) {
        oooClear(flow);
        stopRto(flow);
        stopReo(flow);
        if (flow.timer) clearTimeout(flow.timer);
        flow.socket?.destroy();
      }
      for (const socket of udpFlows.values()) {
        try {
          socket.close();
        } catch {
          /* already closed */
        }
      }
      tcpFlows.clear();
      udpFlows.clear();
      udpSeen.clear();
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

/**
 * 3.0.3: per-flow packet dispatcher for the tun reader. Packets of one flow (protocol +
 * both endpoints) are pushed strictly in order, one at a time; different flows no longer
 * wait for each other, so one slow open (a dial or a UDP open during an outage) cannot
 * hold up every other packet. Order inside a flow is never broken: a push slower than
 * capMs is only reported (onStall); later packets of that flow keep waiting behind it.
 * Bounds: at most perFlowMax packets queued per flow (newer ones are dropped and counted,
 * TCP retransmits them, UDP may lose them), and the reader pauses (ready()) while
 * maxInflight packets are queued or running.
 */
export function flowKeyOf(packet) {
  const buf = packet;
  if (buf.length < 20 || buf[0] >> 4 !== 4) return "other";
  const ihl = (buf[0] & 0x0f) * 4;
  const proto = buf[9];
  const src = buf.readUInt32BE(12);
  const dst = buf.readUInt32BE(16);
  if ((proto === 6 || proto === 17) && buf.length >= ihl + 4) {
    return `${proto}:${src}:${buf.readUInt16BE(ihl)}:${dst}:${buf.readUInt16BE(ihl + 2)}`;
  }
  return `${proto}:${src}:${dst}`;
}

export function createFlowQueue({ push, capMs, onStall = () => undefined, onError = () => undefined, onDrop = () => undefined, maxInflight = 256, perFlowMax = 64 }) {
  const flows = new Map(); // key -> { tail, depth }
  let inflight = 0;
  let waiters = [];
  const wake = () => {
    if (inflight >= maxInflight) return;
    const list = waiters;
    waiters = [];
    for (const fn of list) fn();
  };
  const run = (key, packet) => {
    let timer = setTimeout(() => {
      timer = null;
      onStall(key);
    }, capMs);
    timer.unref?.();
    return Promise.resolve()
      .then(() => push(packet))
      .catch(onError)
      .finally(() => {
        if (timer) clearTimeout(timer);
      });
  };
  return {
    dispatch(packet) {
      const key = flowKeyOf(packet);
      let flow = flows.get(key);
      if (!flow) {
        flow = { tail: Promise.resolve(), depth: 0 };
        flows.set(key, flow);
      }
      if (flow.depth >= perFlowMax) {
        onDrop(key);
        return flow.tail;
      }
      flow.depth += 1;
      inflight += 1;
      const tail = flow.tail.then(() => run(key, packet));
      flow.tail = tail;
      void tail.finally(() => {
        flow.depth -= 1;
        inflight -= 1;
        if (flow.depth === 0 && flows.get(key) === flow) flows.delete(key);
        wake();
      });
      return tail;
    },
    ready() {
      if (inflight < maxInflight) return Promise.resolve();
      return new Promise((resolve) => waiters.push(resolve));
    },
    get inflight() {
      return inflight;
    },
    get flows() {
      return flows.size;
    },
  };
}
