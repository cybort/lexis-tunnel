#!/usr/bin/env python3
"""Same-netns linux.ipv6 block↔off. Fresh off, fresh block, then repeated toggles.

Only rules this program installs (table 165, the four local prefixes, priority 200)
may change. A foreign IPv6 rule must survive. IPv4 HTTP must stay up in every mode.
"""
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time

OUT = sys.argv[1] if len(sys.argv) > 1 else "/opt/cursor/artifacts/ipv6-switch"
HERE = os.path.dirname(os.path.abspath(__file__))
IP = "/usr/sbin/ip"
PORT = 8080
results = []


def run(args, ns=None, check=True):
    cmd = [IP]
    if ns:
        cmd = [IP, "netns", "exec", ns] + args
        # `ip netns exec ns ip ...` — args already start with ip's subcommand,
        # so rebuild properly.
        cmd = [IP, "netns", "exec", ns, IP, *args]
    else:
        cmd = [IP, *args]
    p = subprocess.run(cmd, text=True, capture_output=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"{cmd} -> {p.returncode} {p.stderr}")
    return p


def sh(script, ns):
    path = "/tmp/lexis-apply-forward.sh"
    # The file must be visible inside the netns; /tmp is shared.
    with open(path, "w") as f:
        f.write(script)
    os.chmod(path, 0o755)
    p = subprocess.run([IP, "netns", "exec", ns, "sh", path], text=True, capture_output=True, env={**os.environ, "PATH": "/usr/sbin:/usr/bin:/bin"})
    if p.returncode != 0:
        raise RuntimeError(f"apply failed {p.returncode}\n{p.stdout}\n{p.stderr}")
    return p.stdout


def gen(mode):
    p = subprocess.run(["node", os.path.join(HERE, "gen-forward.mjs"), mode], text=True, capture_output=True, check=True)
    return p.stdout


def ns_add(name):
    run(["netns", "del", name], check=False)
    run(["netns", "add", name])
    run(["link", "set", "lo", "up"], ns=name)
    subprocess.run([IP, "netns", "exec", name, "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=0"], capture_output=True)
    subprocess.run([IP, "netns", "exec", name, "sysctl", "-w", "net.ipv6.conf.default.disable_ipv6=0"], capture_output=True)
    subprocess.run([IP, "netns", "exec", name, "sysctl", "-w", "net.ipv4.conf.all.rp_filter=0"], capture_output=True)


def veth(cns, gns):
    run(["link", "add", "v6c", "type", "veth", "peer", "name", "v6g"], check=False)
    # delete leftovers in root then create
    subprocess.run([IP, "link", "del", "v6c"], capture_output=True)
    run(["link", "add", "v6c", "type", "veth", "peer", "name", "v6g"])
    run(["link", "set", "v6c", "netns", cns])
    run(["link", "set", "v6g", "netns", gns])
    subprocess.run([IP, "netns", "exec", cns, "sysctl", "-w", "net.ipv6.conf.v6c.disable_ipv6=0"], capture_output=True)
    subprocess.run([IP, "netns", "exec", gns, "sysctl", "-w", "net.ipv6.conf.v6g.disable_ipv6=0"], capture_output=True)
    subprocess.run([IP, "netns", "exec", cns, "sysctl", "-w", "net.ipv6.conf.v6c.accept_dad=0"], capture_output=True)
    subprocess.run([IP, "netns", "exec", gns, "sysctl", "-w", "net.ipv6.conf.v6g.accept_dad=0"], capture_output=True)
    run(["addr", "add", "10.98.0.1/24", "dev", "v6c"], ns=cns)
    run(["addr", "add", "2001:db8:98::1/64", "dev", "v6c"], ns=cns)
    run(["link", "set", "v6c", "up"], ns=cns)
    run(["addr", "add", "10.98.0.2/24", "dev", "v6g"], ns=gns)
    run(["addr", "add", "2001:db8:98::2/64", "dev", "v6g"], ns=gns)
    run(["link", "set", "v6g", "up"], ns=gns)


def start_server(ns):
    code = r"""
import socket, threading, time
def serve(addr, fam):
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    for _ in range(50):
        try:
            s.bind(addr)
            break
        except OSError:
            time.sleep(0.05)
    else:
        raise SystemExit(f"bind failed {addr}")
    s.listen(16)
    while True:
        c, _ = s.accept()
        try:
            c.recv(1024)
            c.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        except Exception:
            pass
        finally:
            c.close()
threading.Thread(target=serve, args=(("10.98.0.2", 8080), socket.AF_INET), daemon=True).start()
threading.Thread(target=serve, args=(("2001:db8:98::2", 8080), socket.AF_INET6), daemon=True).start()
time.sleep(3600)
"""
    return subprocess.Popen([IP, "netns", "exec", ns, "python3", "-c", code])


def http(ns, dest, ipv6=False):
    code = f"""
import socket, time
t = time.monotonic()
s = socket.socket(socket.AF_INET6 if {ipv6} else socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2)
err = None
code = None
try:
    s.connect({dest!r})
    s.sendall(b"GET / HTTP/1.0\\r\\nHost: x\\r\\n\\r\\n")
    data = b""
    while True:
        b = s.recv(1024)
        if not b:
            break
        data += b
    code = 200 if b"200" in data.split(b"\\r\\n", 1)[0] else 0
except Exception as e:
    err = f"{{type(e).__name__}}: {{e}}"
    if getattr(e, "errno", None) is not None:
        err += f" errno={{e.errno}}"
finally:
    s.close()
print(code if code else 0)
print(f"{{time.monotonic()-t:.6f}}")
print(err or "")
"""
    p = subprocess.run([IP, "netns", "exec", ns, "python3", "-c", code], text=True, capture_output=True)
    lines = (p.stdout or "").splitlines() + ["", "", ""]
    return {"code": int(lines[0] or 0), "seconds": float(lines[1] or 0), "error": lines[2], "stderr": p.stderr}


def count_v6_tcp(ns, iface, seconds=0.4):
    code = f"""
import socket, struct, time
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x86DD))
s.bind(("{iface}", 0))
s.settimeout(0.05)
end = time.monotonic() + {seconds}
n = 0
while time.monotonic() < end:
    try:
        pkt, _ = s.recvfrom(65535)
    except socket.timeout:
        continue
    # Ethernet or raw IPv6. Look for TCP (next header 6) to port {PORT}.
    for off in (0, 14):
        if len(pkt) < off + 40:
            continue
        if pkt[off] >> 4 != 6:
            continue
        nh = pkt[off + 6]
        base = off + 40
        if nh == 6 and len(pkt) >= base + 4:
            dport = struct.unpack("!H", pkt[base+2:base+4])[0]
            if dport == {PORT}:
                n += 1
print(n)
"""
    box = {}

    def go():
        p = subprocess.run([IP, "netns", "exec", ns, "python3", "-c", code], text=True, capture_output=True)
        try:
            box["n"] = int((p.stdout or "0").strip().splitlines()[-1])
        except ValueError:
            box["n"] = -1
            box["err"] = p.stderr

    th = threading.Thread(target=go)
    th.start()
    time.sleep(0.05)
    return th, box


def rules(ns):
    p = subprocess.run([IP, "netns", "exec", ns, IP, "-6", "rule", "show"], text=True, capture_output=True)
    v4 = subprocess.run([IP, "netns", "exec", ns, IP, "rule", "show"], text=True, capture_output=True)
    return {"v6": p.stdout, "v4": v4.stdout}


def v6_block_count(text):
    return sum(1 for line in text.splitlines() if "lookup 165" in line and "200:" in line)


def record(name, **kw):
    results.append({"name": name, **kw})
    print(name, json.dumps(kw, ensure_ascii=False)[:500])


def scenario_fresh(mode):
    cns, gns = f"v6{mode}c", f"v6{mode}g"
    ns_add(cns)
    ns_add(gns)
    veth(cns, gns)
    srv = start_server(gns)
    time.sleep(0.6)
    sh(gen(mode), cns)
    th, box = count_v6_tcp(gns, "v6g", 0.6)
    v6 = http(cns, ("2001:db8:98::2", PORT), ipv6=True)
    v4 = http(cns, ("10.98.0.2", PORT), ipv6=False)
    th.join(timeout=2)
    shown = rules(cns)
    record(
        f"fresh-{mode}",
        v6=v6,
        v4=v4,
        gate_v6_tcp=box.get("n"),
        v6_lookup_165=v6_block_count(shown["v6"]),
        ok_shape=None,
    )
    srv.kill()
    run(["netns", "del", cns], check=False)
    run(["netns", "del", gns], check=False)


def scenario_toggle():
    cns, gns = "v6swc", "v6swg"
    ns_add(cns)
    ns_add(gns)
    veth(cns, gns)
    srv = start_server(gns)
    time.sleep(0.6)
    # Foreign rule: different prefix and priority. Must survive every toggle.
    run(["-6", "rule", "add", "to", "2001:db8:99::/64", "lookup", "main", "priority", "77"], ns=cns)
    steps = ["block", "off", "block", "off", "off", "block", "block"]
    trace = []
    for mode in steps:
        sh(gen(mode), cns)
        th, box = count_v6_tcp(gns, "v6g", 0.5)
        v6 = http(cns, ("2001:db8:98::2", PORT), ipv6=True)
        v4 = http(cns, ("10.98.0.2", PORT), ipv6=False)
        th.join(timeout=2)
        shown = rules(cns)
        foreign = "2001:db8:99::/64" in shown["v6"] and "77:" in shown["v6"]
        trace.append({
            "mode": mode,
            "v6_code": v6["code"],
            "v6_error": v6["error"],
            "v6_s": v6["seconds"],
            "v4_code": v4["code"],
            "gate_v6_tcp": box.get("n"),
            "lookup_165": v6_block_count(shown["v6"]),
            "foreign": foreign,
            "v4_has_165": "lookup 165" in shown["v4"],
        })
    record("toggle", steps=trace)
    srv.kill()
    run(["netns", "del", cns], check=False)
    run(["netns", "del", gns], check=False)


def main():
    os.makedirs(OUT, exist_ok=True)
    scenario_fresh("off")
    scenario_fresh("block")
    scenario_toggle()
    fresh_off = results[0]
    fresh_block = results[1]
    toggle = results[2]["steps"]
    problems = []
    if fresh_off["v6"]["code"] != 200:
        problems.append(f"fresh off ipv6 {fresh_off['v6']}")
    if fresh_off["v4"]["code"] != 200:
        problems.append(f"fresh off ipv4 {fresh_off['v4']}")
    if fresh_block["v6"]["code"] == 200:
        problems.append("fresh block ipv6 unexpectedly succeeded")
    if not (fresh_block["v6"]["seconds"] < 1.0):
        problems.append(f"fresh block was not immediate: {fresh_block['v6']}")
    if fresh_block["gate_v6_tcp"] not in (0, None) and fresh_block["gate_v6_tcp"] != 0:
        problems.append(f"fresh block gate saw {fresh_block['gate_v6_tcp']} tcp packets")
    if fresh_block["gate_v6_tcp"] != 0:
        problems.append(f"fresh block gate count {fresh_block['gate_v6_tcp']}")
    if fresh_block["v4"]["code"] != 200:
        problems.append(f"fresh block ipv4 {fresh_block['v4']}")
    for step in toggle:
        if step["v4_code"] != 200:
            problems.append(f"toggle {step['mode']} ipv4 {step['v4_code']}")
        if not step["foreign"]:
            problems.append(f"foreign rule missing after {step['mode']}")
        if not step["v4_has_165"]:
            problems.append(f"ipv4 table rule missing after {step['mode']}")
        if step["mode"] == "off":
            if step["v6_code"] != 200:
                problems.append(f"off did not restore ipv6: {step}")
            if step["lookup_165"] != 0:
                problems.append(f"off left lookup 165: {step['lookup_165']}")
        else:
            if step["v6_code"] == 200:
                problems.append(f"block did not stick: {step}")
            if step["lookup_165"] != 1:
                problems.append(f"block lookup count {step['lookup_165']} (want 1, idempotent)")
            if step["gate_v6_tcp"] not in (0,):
                problems.append(f"block still emitted gate tcp {step['gate_v6_tcp']}")
    report = {"passed": not problems, "problems": problems, "results": results}
    with open(os.path.join(OUT, "result.json"), "w") as f:
        json.dump(report, f, indent=2)
    print(json.dumps({"passed": report["passed"], "problems": problems}, indent=2, ensure_ascii=False))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    finally:
        for name in ("v6offc", "v6offg", "v6blockc", "v6blockg", "v6swc", "v6swg"):
            subprocess.run([IP, "netns", "del", name], capture_output=True)
