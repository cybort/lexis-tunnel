// Userspace tun engine for the three outage models.
// Defaults only: giveUpMs / maxRetries / rto are NOT overridden.
// Upstream payload starts at RST_DATA_EPOCH_MS (written by the driver) so the
// handshake can finish during the open window and the body is sent while the
// path is down. That delay is the test's upstream schedule, not an engine timer.
import fs from "node:fs";
import net from "node:net";
import { createEngine, parseIpv4, parseTcp } from "../../public/agent/lexis-tun.mjs";

const RST = 0x04;
const logPath = process.env.RST_LOG;
const epochFile = process.env.RST_EPOCH_FILE;
if (!logPath || !epochFile) {
  console.error("RST_LOG and RST_EPOCH_FILE are required");
  process.exit(2);
}

const log = (obj) => fs.appendFileSync(logPath, `${JSON.stringify({ wall: Date.now(), ...obj })}\n`);
log({ ev: "boot", giveUpMs: "default", maxRetries: "default", rtoMs: "default", note: "createEngine timeouts not overridden" });

function readEpoch() {
  try {
    const text = fs.readFileSync(epochFile, "utf8").trim();
    const n = Number(text);
    return Number.isFinite(n) && n > 0 ? n : 0;
  } catch {
    return 0;
  }
}

const server = net.createServer((socket) => {
  socket.on("error", () => undefined);
  let started = false;
  const begin = () => {
    if (started) return;
    started = true;
    const fire = () => {
      log({ ev: "upstream-start" });
      const chunk = Buffer.alloc(1200, 0x61);
      const timer = setInterval(() => {
        if (socket.destroyed) {
          clearInterval(timer);
          return;
        }
        if (!socket.write(chunk)) socket.pause();
      }, 10);
      socket.on("drain", () => socket.resume());
      socket.on("close", () => clearInterval(timer));
    };
    const waitFor = () => {
      const at = readEpoch();
      if (!at) {
        setTimeout(waitFor, 20);
        return;
      }
      const wait = at - Date.now();
      log({ ev: "upstream-arm", dataEpoch: at, waitMs: wait });
      setTimeout(fire, Math.max(0, wait));
    };
    waitFor();
  };
  socket.on("data", () => begin());
});

function writeFrame(packet) {
  const body = Buffer.from(packet);
  const head = Buffer.alloc(4);
  head.writeUInt32BE(body.length);
  process.stdout.write(Buffer.concat([head, body]));
}

server.listen(0, "127.0.0.1", () => {
  const port = server.address().port;
  const engine = createEngine({
    dialTcp: () =>
      new Promise((resolve, reject) => {
        const socket = net.connect(port, "127.0.0.1", () => resolve(socket));
        socket.once("error", reject);
      }),
    dialUdp: async () => {
      throw new Error("udp unused");
    },
    emit: (packet) => {
      const ip = parseIpv4(packet);
      const tcp = ip && ip.proto === 6 ? parseTcp(ip.payload) : null;
      if (tcp && tcp.flags & RST) {
        log({ ev: "rst", seq: tcp.seq >>> 0, ack: tcp.ack >>> 0, flags: tcp.flags, len: tcp.data.length });
      }
      writeFrame(packet);
    },
    log: (line) => log({ ev: "engine", line }),
  });

  let buf = Buffer.alloc(0);
  let chain = Promise.resolve();
  process.stdin.on("data", (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    while (buf.length >= 4) {
      const n = buf.readUInt32BE(0);
      if (n > 1_000_000 || buf.length < 4 + n) break;
      const pkt = Buffer.from(buf.subarray(4, 4 + n));
      buf = Buffer.from(buf.subarray(4 + n));
      chain = chain
        .then(() => engine.push(pkt))
        .catch((err) => log({ ev: "push-error", message: String(err?.message || err) }));
    }
  });
  process.stdin.on("end", () => {
    engine.close();
    server.close();
    setTimeout(() => process.exit(0), 50);
  });
  process.stderr.write("READY\n");
  log({ ev: "ready", port });
});
