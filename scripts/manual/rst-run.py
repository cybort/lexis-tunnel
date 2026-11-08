#!/usr/bin/env python3
"""One outage model against the real Linux TCP stack and the userspace tun engine.

Models (driver clock, origin A = monotonic/wall at forward start):
  persistent  — drop every IN and OUT packet once age >= 2s, including RST
  local-rst   — same, except an RST the engine itself emitted is still written to the tun
  restored    — drop while 2s <= age < 220s, then pass both directions with no RST special case

The engine's giveUpMs / maxRetries / RTO are not changed. Upstream body bytes start
at origin A + 2.5s so the handshake (and the client's GET) finish in the open window
and the body is generated while the path is down. 2.5s is this harness's upload
schedule, not an engine timeout.

Origin B is the client monotonic clock taken immediately before socket().
"""
import json
import os
import select
import socket
import struct
import subprocess
import sys
import threading
import time

IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
TUNSETIFF = 0x400454CA
DLT_RAW = 101
ETH_P_ALL = 0x0003

MODEL = sys.argv[1]
OUT = sys.argv[2]
PREFIX = {"persistent": "10.224.0", "local-rst": "10.225.0", "restored": "10.226.0"}[MODEL]
LOCAL = f"{PREFIX}.1"
PEER = f"{PREFIX}.2"
HERE = os.path.dirname(os.path.abspath(__file__))
ENGINE = os.path.join(HERE, "rst-engine.mjs")


def pcap_open(path, linktype):
    f = open(path, "wb")
    f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
    return f


def pcap_pkt(f, data, wall):
    sec = int(wall)
    usec = int((wall - sec) * 1_000_000)
    f.write(struct.pack("<IIII", sec, usec, len(data), len(data)))
    f.write(data)
    f.flush()


def tcp_info(pkt):
    if len(pkt) < 20 or (pkt[0] >> 4) != 4:
        return None
    ihl = (pkt[0] & 0x0F) * 4
    if pkt[9] != 6 or len(pkt) < ihl + 20:
        return None
    sport, dport, seq, ack = struct.unpack("!HHII", pkt[ihl : ihl + 12])
    flags = pkt[ihl + 13]
    return {"sport": sport, "dport": dport, "seq": seq, "ack": ack, "flags": flags, "payload": max(0, len(pkt) - ihl - ((pkt[ihl + 12] >> 4) * 4))}


def is_rst(pkt):
    info = tcp_info(pkt)
    return bool(info and (info["flags"] & 0x04))


# Open long enough for the handshake under nice 19. This is the harness fault
# schedule, not an engine timer. Upstream body starts half a second later.
# On this host the default give-up (180s without ACK progress, RTO capped at 60s)
# emits the RST near 190s. The restored model ends the fault at 160s so that RST
# is written onto a path that is already up, and no data retransmission is armed
# in between (the previous RTO fire is still inside the fault). 220s would still
# cover a 190s RST, so it would not test delivery.
FAULT_AT = 5.0
DATA_DELAY = 5.5
# 5s open window + 218s fault = 223s. On the recorded run the default give-up
# fired at about 229s, so the RST left after the path was already restored.
RESTORED_END = 223.0


def should_drop(direction, pkt, age_s):
    if age_s < FAULT_AT:
        return False
    if MODEL == "persistent":
        return True
    if MODEL == "local-rst":
        # Only an engine-emitted RST bypasses the fault. Never synthesize one.
        return not (direction == "out" and is_rst(pkt))
    if MODEL == "restored":
        return age_s < RESTORED_END
    raise SystemExit(f"unknown model {MODEL}")


def main():
    os.makedirs(OUT, exist_ok=True)
    subprocess.run(["ip", "link", "set", "lo", "up"], check=False)
    subprocess.run(["sysctl", "-w", "net.ipv4.conf.all.rp_filter=0"], check=False, capture_output=True)
    subprocess.run(["sysctl", "-w", "net.ipv4.conf.default.rp_filter=0"], check=False, capture_output=True)
    subprocess.check_call(["ip", "tuntap", "add", "dev", "lexis0", "mode", "tun"])
    subprocess.check_call(["ip", "addr", "add", f"{LOCAL}/30", "dev", "lexis0"])
    subprocess.check_call(["ip", "link", "set", "lexis0", "up"])
    tun = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack("16sH22s", b"lexis0", IFF_TUN | IFF_NO_PI, b"\x00" * 22)
    import fcntl

    fcntl.ioctl(tun, TUNSETIFF, ifr)

    epoch_file = os.path.join(OUT, "data-epoch")
    open(epoch_file, "w").close()
    log_path = os.path.join(OUT, "engine.jsonl")
    open(log_path, "w").close()
    env = os.environ.copy()
    env["RST_LOG"] = log_path
    env["RST_EPOCH_FILE"] = epoch_file
    proc = subprocess.Popen(
        ["node", ENGINE],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        bufsize=0,
    )
    ready = threading.Event()

    def read_err():
        for line in proc.stderr:
            if line.strip() == b"READY":
                ready.set()
                return

    threading.Thread(target=read_err, daemon=True).start()
    if not ready.wait(15):
        raise SystemExit("engine did not become ready")

    raw = pcap_open(os.path.join(OUT, "tun-inject.pcap"), DLT_RAW)
    af = pcap_open(os.path.join(OUT, "afpacket.pcap"), 1)
    trace_f = open(os.path.join(OUT, "driver.jsonl"), "w")
    stop = threading.Event()
    # Origin A is after READY and after the pcap files exist, immediately
    # before the reader and the client. Fault and upstream body are relative
    # to this instant, so startup does not consume the open window.
    mono0 = time.monotonic()
    wall0 = time.time()
    with open(epoch_file, "w") as f:
        f.write(str(int(wall0 * 1000) + int(DATA_DELAY * 1000)))
    stats = {"in": 0, "out": 0, "drop_in": 0, "drop_out": 0, "rst_out_pass": 0, "rst_out_drop": 0}
    af_meta = {"packets": 0, "error": None}

    def age_s():
        return time.monotonic() - mono0

    def trace(direction, pkt, dropped):
        info = tcp_info(pkt) or {}
        rec = {
            "t": round(age_s(), 6),
            "dir": direction,
            "drop": dropped,
            "len": len(pkt),
            **info,
        }
        trace_f.write(json.dumps(rec) + "\n")
        if info.get("flags", 0) & 0x04 or dropped:
            trace_f.flush()

    def pump_engine_out():
        buf = b""
        while not stop.is_set():
            chunk = proc.stdout.read(65536)
            if not chunk:
                break
            buf += chunk
            while len(buf) >= 4:
                n = struct.unpack("!I", buf[:4])[0]
                if n > 1_000_000 or len(buf) < 4 + n:
                    break
                pkt, buf = buf[4 : 4 + n], buf[4 + n :]
                stats["out"] += 1
                dropped = should_drop("out", pkt, age_s())
                trace("out", pkt, dropped)
                if is_rst(pkt):
                    stats["rst_out_drop" if dropped else "rst_out_pass"] += 1
                if dropped:
                    stats["drop_out"] += 1
                    continue
                try:
                    os.write(tun, pkt)
                except OSError:
                    continue
                pcap_pkt(raw, pkt, time.time())

    def pump_tun_in():
        while not stop.is_set():
            r, _, _ = select.select([tun], [], [], 0.2)
            if not r:
                continue
            try:
                pkt = os.read(tun, 65535)
            except OSError:
                continue
            if not pkt:
                continue
            stats["in"] += 1
            dropped = should_drop("in", pkt, age_s())
            trace("in", pkt, dropped)
            if dropped:
                stats["drop_in"] += 1
                continue
            frame = struct.pack("!I", len(pkt)) + pkt
            try:
                proc.stdin.write(frame)
                proc.stdin.flush()
            except BrokenPipeError:
                return

    def sniff():
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
            s.bind(("lexis0", 0))
            s.settimeout(0.5)
        except OSError as exc:
            af_meta["error"] = f"{type(exc).__name__}: {exc}"
            return
        while not stop.is_set():
            try:
                pkt, _ = s.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError as exc:
                af_meta["error"] = str(exc)
                return
            af_meta["packets"] += 1
            pcap_pkt(af, pkt, time.time())

    threads = [
        threading.Thread(target=pump_engine_out, daemon=True),
        threading.Thread(target=pump_tun_in, daemon=True),
        threading.Thread(target=sniff, daemon=True),
    ]
    for t in threads:
        t.start()

    client = {}
    # Origin B: immediately before the client socket exists.
    b_mono = time.monotonic()
    b_wall = time.time()
    client["originB_wall_epoch"] = b_wall
    client["originB_minus_A_s"] = round(b_mono - mono0, 6)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(320)
    payload = 0
    try:
        t_conn = time.monotonic()
        sock.connect((PEER, 80))
        client.setdefault("events", []).append({"ev": "connect", "t_from_B_s": round(time.monotonic() - b_mono, 6)})
        sock.sendall(b"GET 50000000 out\n")
        client["events"].append({"ev": "sendall", "t_from_B_s": round(time.monotonic() - b_mono, 6), "connect_s": round(t_conn - b_mono, 6)})
        while True:
            data = sock.recv(65536)
            if not data:
                client["result"] = "EOF"
                client["errno"] = None
                break
            payload += len(data)
    except ConnectionResetError as exc:
        client["result"] = "ECONNRESET"
        client["errno"] = exc.errno
    except socket.timeout:
        client["result"] = "TimeoutError"
        client["errno"] = None
    except OSError as exc:
        client["result"] = type(exc).__name__
        client["errno"] = exc.errno
    client["t_from_B_s"] = round(time.monotonic() - b_mono, 6)
    client["payload"] = payload
    client["originA_wall_epoch"] = wall0
    client["originA_note"] = "driver time.time()/monotonic at forward start, after engine READY, before client socket"
    client["originB_note"] = "time.monotonic immediately before socket(); t_from_B_s uses that clock"
    client["client_timeout_s"] = 320
    client["upstream_body_from_A_s"] = DATA_DELAY
    client["fault"] = {
        "start_s": FAULT_AT,
        "restored_end_s": RESTORED_END if MODEL == "restored" else None,
        "note": "Harness schedule. Engine giveUpMs stays 180000 and RTO stays default. Open window is 5s so a nice-19 delayed handshake still finishes before the fault; body starts at 5.5s.",
    }

    stop.set()
    try:
        proc.stdin.close()
    except Exception:
        pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    raw.close()
    af.close()
    trace_f.close()
    for t in threads:
        t.join(timeout=2)

    engine_rst = []
    if os.path.exists(log_path):
        for line in open(log_path):
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("ev") == "rst" and rec.get("wall", 0) >= wall0 * 1000:
                rec["t_from_A_s"] = round((rec["wall"] / 1000) - wall0, 6)
                engine_rst.append(rec)
    inject_rst = []
    # Re-read tun-inject pcap for RST timestamps relative to B and A.
    inject_rst = rst_from_pcap(os.path.join(OUT, "tun-inject.pcap"), wall0, b_wall)
    af_rst = rst_from_pcap(os.path.join(OUT, "afpacket.pcap"), wall0, b_wall, ipv4_offset=guess_l2(os.path.join(OUT, "afpacket.pcap")))

    passed, reason = verdict(client, engine_rst, inject_rst)
    report = {
        "model": MODEL,
        "passed": passed,
        "reason": reason,
        "prefix": PREFIX,
        "originA_wall_epoch": wall0,
        "originB_wall_epoch": b_wall,
        "engine_rst": engine_rst,
        "inject_rst": inject_rst,
        "af_packet_rst": af_rst,
        "af_packet": af_meta,
        "stats": stats,
        "client": client,
    }
    with open(os.path.join(OUT, "client.json"), "w") as f:
        json.dump(client, f, indent=2)
    with open(os.path.join(OUT, "result.json"), "w") as f:
        json.dump(report, f, indent=2)
    print(json.dumps({"model": MODEL, "passed": passed, "reason": reason, "client_result": client.get("result"), "payload": payload, "engine_rst_t": [r.get("t_from_A_s") for r in engine_rst], "inject_rst": len(inject_rst)}, indent=2))
    return 0 if passed else 1


def guess_l2(path):
    # AF_PACKET on a tun often includes a 16-byte sockaddr-style header or Ethernet.
    # Return a byte offset where IPv4 might start, or 0 to try the buffer as IP.
    try:
        data = open(path, "rb").read(64)
    except OSError:
        return 0
    if len(data) < 24:
        return 0
    return 0


def rst_from_pcap(path, wall0, b_wall, ipv4_offset=0):
    out = []
    try:
        f = open(path, "rb")
    except OSError:
        return out
    hdr = f.read(24)
    if len(hdr) < 24:
        return out
    while True:
        ph = f.read(16)
        if len(ph) < 16:
            break
        sec, usec, incl, orig = struct.unpack("<IIII", ph)
        blob = f.read(incl)
        if len(blob) < incl:
            break
        wall = sec + usec / 1_000_000
        for off in (0, 14, 16):
            info = tcp_info(blob[off:])
            if info and (info["flags"] & 0x04):
                info["t_from_A_s"] = round(wall - wall0, 6)
                info["t_from_B_s"] = round(wall - b_wall, 6)
                info["l2_off"] = off
                out.append(info)
                break
    f.close()
    return out


def verdict(client, engine_rst, inject_rst):
    if not client.get("result"):
        return False, "empty client result"
    if client["result"] not in ("TimeoutError", "ECONNRESET", "EOF", "ConnectionResetError"):
        return False, f"unexpected client result {client['result']}"
    if not engine_rst:
        return False, "engine emitted no RST (harness or engine did not reach give-up)"
    earliest = min(r["t_from_A_s"] for r in engine_rst)
    # Default give-up is 180s without ACK progress, plus up to one capped RTO.
    # A result earlier than 170s means the engine timeout was shortened or the clock is wrong.
    if earliest < 170:
        return False, f"RST at {earliest}s from A is earlier than the default give-up; refusing to treat it as a pass"
    if MODEL == "persistent":
        if inject_rst:
            return False, "persistent model delivered an RST into the tun"
        if client["result"] != "TimeoutError":
            return False, f"persistent client ended with {client['result']} instead of TimeoutError"
        return True, "control: engine RST existed, tun inject saw none, client timed out"
    if not inject_rst:
        return False, "RST-reachable model did not inject an RST into the tun"
    if client["result"] not in ("ECONNRESET", "EOF"):
        return False, f"client result {client['result']} errno={client.get('errno')} payload={client.get('payload')}"
    return True, "client application observed reset or EOF after a real injected RST"


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        fail = {"result": "harness-exception", "error": f"{type(exc).__name__}: {exc}", "model": MODEL}
        os.makedirs(OUT, exist_ok=True)
        with open(os.path.join(OUT, "client.json"), "w") as f:
            json.dump(fail, f, indent=2)
        raise
