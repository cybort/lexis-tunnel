import assert from "node:assert/strict";
import { createSocket } from "node:dgram";
import { readFileSync, readlinkSync, readdirSync } from "node:fs";
import { connect } from "node:net";
import test from "node:test";
import { serveInbound } from "../public/agent/lexis-agent.mjs";

const agentSrc = readFileSync(new URL("../public/agent/lexis-agent.mjs", import.meta.url), "utf8");

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function procUdpPorts() {
  // /proc/net/udp joins tx_queue:rx_queue, so the header's inode column index
  // does not line up with the data tokens. Match our socket inodes directly.
  const text = readFileSync("/proc/net/udp", "utf8");
  const inodes = new Set();
  for (const fd of readdirSync("/proc/self/fd")) {
    try {
      const m = readlinkSync(`/proc/self/fd/${fd}`).match(/^socket:\[(\d+)\]$/);
      if (m) inodes.add(m[1]);
    } catch {
      /* gone */
    }
  }
  const ports = [];
  for (const line of text.trim().split("\n").slice(1)) {
    const parts = line.trim().split(/\s+/);
    if (!parts.some((part) => inodes.has(part))) continue;
    ports.push(Number.parseInt(parts[1].split(":")[1], 16));
  }
  return ports;
}

function socksUdp(host, port, payload) {
  const body = Buffer.from(payload);
  const out = Buffer.alloc(10 + body.length);
  out[3] = 1;
  String(host)
    .split(".")
    .forEach((part, i) => {
      out[4 + i] = Number(part);
    });
  out.writeUInt16BE(port, 8);
  body.copy(out, 10);
  return out;
}

function startAgent(link, rules) {
  const logs = [];
  const prev = console.log;
  console.log = (...parts) => {
    logs.push(parts.map((part) => (typeof part === "string" ? part : String(part))).join(" "));
  };
  const server = serveInbound(
    {
      version: 1,
      role: "edge",
      mode: "fixed-port",
      logLevel: "info",
      processDefault: "direct",
      rules: rules || [{ id: "match", type: "MATCH", value: "", action: "direct" }],
      egress: { blockPrivate: false },
      link,
      inbounds: [],
      socksAuth: { user: "", pass: "" },
    },
    { id: "socks", tag: "udp-idle", protocol: "socks", listen: "127.0.0.1", port: 0 },
  );
  return new Promise((resolve, reject) => {
    const fail = (err) => {
      console.log = prev;
      reject(err);
    };
    server.once("error", fail);
    const ready = () => {
      server.off("error", fail);
      resolve({
        server,
        port: server.address().port,
        logs,
        restore() {
          console.log = prev;
        },
      });
    };
    if (server.listening) ready();
    else server.once("listening", ready);
  });
}

function associate(port) {
  const socket = connect({ host: "127.0.0.1", port });
  socket.setKeepAlive(false);
  const assoc = { socket, relayPort: 0, openedAt: 0, closedAt: 0, extraRx: 0, extraTx: 0, error: null };
  let buf = Buffer.alloc(0);
  let stage = "method";
  socket.on("error", (err) => {
    assoc.error = err.code || err.message;
  });
  socket.on("close", () => {
    assoc.closedAt = Date.now();
    if (assoc.bytesReadAtSetup != null) {
      assoc.extraRx = socket.bytesRead - assoc.bytesReadAtSetup;
      assoc.extraTx = socket.bytesWritten - assoc.bytesWrittenAtSetup;
    }
  });
  const opened = new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("associate timeout")), 3000);
    socket.on("connect", () => socket.write(Buffer.from([0x05, 0x01, 0x00])));
    socket.on("data", (chunk) => {
      if (stage === "done") return;
      buf = Buffer.concat([buf, chunk]);
      if (stage === "method") {
        if (buf.length < 2) return;
        buf = buf.subarray(2);
        stage = "reply";
        socket.write(Buffer.from([0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
      }
      if (stage === "reply" && buf.length >= 10) {
        const reply = buf.subarray(0, 10);
        buf = buf.subarray(10);
        if (reply[1] !== 0) {
          clearTimeout(timer);
          reject(new Error(`associate status ${reply[1]}`));
          return;
        }
        assoc.relayPort = reply.readUInt16BE(8);
        assoc.openedAt = Date.now();
        assoc.bytesReadAtSetup = socket.bytesRead;
        assoc.bytesWrittenAtSetup = socket.bytesWritten;
        stage = "done";
        clearTimeout(timer);
        resolve(assoc);
      }
    });
  });
  return opened;
}

function bindUdp() {
  return new Promise((resolve, reject) => {
    const socket = createSocket("udp4");
    socket.once("error", reject);
    socket.bind(0, "127.0.0.1", () => {
      socket.off("error", reject);
      resolve(socket);
    });
  });
}

function genericIdle(logs) {
  return logs.filter((line) => line.includes("空闲超时") && !line.includes("UDP association 空闲超时"));
}

async function stop(agent, ...sockets) {
  for (const socket of sockets) {
    try {
      socket?.close?.();
      socket?.destroy?.();
    } catch {
      /* already closed */
    }
  }
  await new Promise((resolve) => agent.server.close(resolve));
  agent.restore();
}

test("closeAll clears the streams map", () => {
  const body = agentSrc.slice(agentSrc.indexOf("function startUdpAssociate"));
  const closeAll = body.slice(body.indexOf("const closeAll"), body.indexOf("udp.on(\"error\""));
  assert.match(closeAll, /streams\.clear\(\)/);
  assert.match(closeAll, /directs\.clear\(\)/);
  assert.match(agentSrc, /udpAssociateIdleMs/);
  assert.doesNotMatch(agentSrc.slice(0, agentSrc.indexOf("function startUdpAssociate")), /udpAssociateIdleMs:\s*link\.idleMs/);
});

test("active legal UDP outlives a short global idleMs", { timeout: 20000 }, async () => {
  const agent = await startAgent({ idleMs: 800, udpAssociateIdleMs: 4000 });
  const assoc = await associate(agent.port);
  const udp = await bindUdp();
  let rx = 0;
  udp.on("message", () => {
    rx += 1;
  });
  const echo = await bindUdp();
  echo.on("message", (msg, rinfo) => echo.send(msg, rinfo.port, rinfo.address));
  const timer = setInterval(() => {
    udp.send(socksUdp("127.0.0.1", echo.address().port, "ping"), assoc.relayPort, "127.0.0.1");
  }, 300);
  await sleep(2500);
  clearInterval(timer);
  assert.equal(assoc.closedAt, 0, "control closed while UDP was active");
  assert.equal(genericIdle(agent.logs).length, 0);
  assert.ok(rx > 0, "echo did not return");
  assoc.socket.destroy();
  await sleep(50);
  assert.equal(assoc.extraRx, 0);
  assert.equal(assoc.extraTx, 0);
  await stop(agent, udp, echo);
});

test("no legal UDP reclaims at udpAssociateIdleMs", { timeout: 20000 }, async () => {
  const agent = await startAgent({ idleMs: 20000, udpAssociateIdleMs: 1500 });
  const assoc = await associate(agent.port);
  const until = Date.now() + 4000;
  while (!assoc.closedAt && Date.now() < until) await sleep(30);
  assert.ok(assoc.closedAt, "association was not reclaimed");
  const life = assoc.closedAt - assoc.openedAt;
  assert.ok(life >= 1400 && life <= 2200, `life ${life}`);
  assert.ok(agent.logs.some((line) => line.includes("UDP association 空闲超时")));
  assert.equal(genericIdle(agent.logs).length, 0);
  assert.equal(assoc.extraRx, 0);
  assert.equal(assoc.extraTx, 0);
  await stop(agent);
});

test("rejected and malformed packets do not renew", { timeout: 20000 }, async () => {
  const agent = await startAgent({ idleMs: 20000, udpAssociateIdleMs: 1500 }, [
    { id: "port9", type: "PORT", value: "9", action: "reject" },
    { id: "match", type: "MATCH", value: "", action: "direct" },
  ]);
  const assoc = await associate(agent.port);
  const udp = await bindUdp();
  const timer = setInterval(() => {
    udp.send(socksUdp("127.0.0.1", 9, "nope"), assoc.relayPort, "127.0.0.1");
    udp.send(Buffer.from([0, 0, 1]), assoc.relayPort, "127.0.0.1");
  }, 200);
  const until = Date.now() + 4000;
  while (!assoc.closedAt && Date.now() < until) await sleep(30);
  clearInterval(timer);
  assert.ok(assoc.closedAt, "rejected traffic kept the association");
  const life = assoc.closedAt - assoc.openedAt;
  assert.ok(life >= 1400 && life <= 2200, `life ${life}`);
  await stop(agent, udp);
});

test("a foreign source does not renew or get forwarded", { timeout: 20000 }, async () => {
  const agent = await startAgent({ idleMs: 20000, udpAssociateIdleMs: 1500 });
  const assoc = await associate(agent.port);
  const client = await bindUdp();
  const stranger = await bindUdp();
  const echo = await bindUdp();
  let echoes = 0;
  echo.on("message", (msg, rinfo) => {
    echoes += 1;
    echo.send(msg, rinfo.port, rinfo.address);
  });
  client.send(socksUdp("127.0.0.1", echo.address().port, "one"), assoc.relayPort, "127.0.0.1");
  await sleep(100);
  const timer = setInterval(() => {
    stranger.send(socksUdp("127.0.0.1", echo.address().port, "evil"), assoc.relayPort, "127.0.0.1");
  }, 100);
  const until = Date.now() + 4000;
  while (!assoc.closedAt && Date.now() < until) await sleep(30);
  clearInterval(timer);
  assert.ok(assoc.closedAt, "foreign source kept the association");
  const life = assoc.closedAt - assoc.openedAt;
  assert.ok(life >= 1400 && life <= 2500, `life ${life}`);
  assert.equal(echoes, 1);
  await stop(agent, client, stranger, echo);
});

test("reply-only traffic renews; outbound-only traffic renews", { timeout: 20000 }, async () => {
  const agent = await startAgent({ idleMs: 800, udpAssociateIdleMs: 1500 });
  const assoc = await associate(agent.port);
  const client = await bindUdp();
  const pusher = await bindUdp();
  let pushed = false;
  pusher.on("message", (_msg, rinfo) => {
    if (pushed) return;
    pushed = true;
    const iv = setInterval(() => {
      try {
        pusher.send(Buffer.from("push"), rinfo.port, rinfo.address);
      } catch {
        clearInterval(iv);
      }
    }, 300);
    pusher.unref?.();
    assoc.socket.once("close", () => clearInterval(iv));
  });
  client.send(socksUdp("127.0.0.1", pusher.address().port, "open"), assoc.relayPort, "127.0.0.1");
  await sleep(3600);
  assert.equal(assoc.closedAt, 0, "replies did not renew the association");
  assoc.socket.destroy();
  await sleep(30);

  const agent2 = await startAgent({ idleMs: 800, udpAssociateIdleMs: 1500 });
  const assoc2 = await associate(agent2.port);
  const client2 = await bindUdp();
  const sink = await bindUdp();
  const iv = setInterval(() => {
    client2.send(socksUdp("127.0.0.1", sink.address().port, "out"), assoc2.relayPort, "127.0.0.1");
  }, 300);
  await sleep(3600);
  clearInterval(iv);
  assert.equal(assoc2.closedAt, 0, "outbound datagrams did not renew the association");
  assert.equal(genericIdle(agent.logs).length + genericIdle(agent2.logs).length, 0);
  assoc2.socket.destroy();
  await stop(agent, client, pusher);
  await stop(agent2, client2, sink);
});

test("peer FIN and destroy drop udp sockets and the idle timer within 1s", { timeout: 20000 }, async (t) => {
  const sockets = [];
  let agent = null;
  t.after(async () => {
    for (const socket of sockets) {
      try {
        socket.destroy?.();
        socket.close?.();
      } catch {
        /* already closed */
      }
    }
    if (agent) await stop(agent);
  });
  for (const how of ["end", "destroy"]) {
    agent = await startAgent({ idleMs: 20000, udpAssociateIdleMs: 700 });
    const assoc = await associate(agent.port);
    sockets.push(assoc.socket);
    const client = await bindUdp();
    const sink = await bindUdp();
    sockets.push(client, sink);
    client.send(socksUdp("127.0.0.1", sink.address().port, "x"), assoc.relayPort, "127.0.0.1");
    await sleep(80);
    const seen = procUdpPorts();
    assert.ok(seen.includes(assoc.relayPort), `relay ${assoc.relayPort} not in ${seen.join(",")}`);
    const idleBefore = agent.logs.filter((line) => line.includes("UDP association 空闲超时")).length;
    const t0 = Date.now();
    if (how === "end") assoc.socket.end();
    else assoc.socket.destroy();
    let clearedMs = null;
    while (Date.now() - t0 < 1000) {
      if (!procUdpPorts().includes(assoc.relayPort)) {
        clearedMs = Date.now() - t0;
        break;
      }
      await sleep(20);
    }
    assert.ok(clearedMs != null && clearedMs <= 1000, `${how} left the relay bound`);
    await sleep(900);
    const idleAfter = agent.logs.filter((line) => line.includes("UDP association 空闲超时")).length;
    assert.equal(idleAfter, idleBefore, `${how} left the idle timer running`);
    assert.equal(procUdpPorts().includes(assoc.relayPort), false);
    await stop(agent, client, sink);
    agent = null;
  }
});
