#!/bin/sh
set -eu
HERE=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
DEST="${HOME}/.lexis"
mkdir -p "$DEST"
cp "$HERE/lexis-agent.mjs" "$HERE/lexis-frame.mjs" "$HERE/lexis-http.mjs" "$HERE/lexis-tun.mjs" "$HERE/zstd.wasm" "$HERE/lexis.config.json" "$DEST/"
if [ -f "$HERE/LexisVpnService.kt" ]; then
  cp "$HERE/LexisVpnService.kt" "$DEST/"
fi
if [ -f "$HERE/lexis-tls.crt" ] && [ -f "$HERE/lexis-tls.key" ]; then
  cp "$HERE/lexis-tls.crt" "$HERE/lexis-tls.key" "$DEST/"
fi
for name in lexis.seal.json lexis.passphrase; do
  if [ -f "$HERE/$name" ]; then
    cp "$HERE/$name" "$DEST/"
  fi
done
for name in lexis.config.json lexis.seal.json lexis.passphrase lexis-tls.key; do
  if [ -f "$DEST/$name" ]; then
    chmod 600 "$DEST/$name"
  fi
done
if ! command -v node >/dev/null 2>&1; then
  echo "在 Termux 里先安装 Node.js 22：pkg install nodejs"
  exit 1
fi
BOOT="${HOME}/.termux/boot"
mkdir -p "$BOOT"
cat > "$BOOT/lexis" << EOF
#!/data/data/com.termux/files/usr/bin/sh
command -v termux-wake-lock >/dev/null 2>&1 && termux-wake-lock
cd "${DEST}" || exit 1
nohup node lexis-agent.mjs >> agent.log 2>&1 &
EOF
chmod +x "$BOOT/lexis" "$DEST/lexis-agent.mjs"
if ! pgrep -f "lexis-agent.mjs" >/dev/null 2>&1; then
  nohup node "$DEST/lexis-agent.mjs" >>"$DEST/agent.log" 2>&1 &
fi
echo "词隙已在后台运行。装上 Termux:Boot 后，开机会执行 ~/.termux/boot/lexis。"
echo "系统接管要读 ${DEST}/vpn-session.json，需要带 VpnService 的系统组件。本脚本只负责常驻进程。"
echo "状态页 http://127.0.0.1:17890/"
