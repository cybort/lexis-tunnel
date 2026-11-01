#!/bin/sh
set -eu
HERE=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
DEST="${HOME}/.lexis"
mkdir -p "$DEST"
cp "$HERE/lexis-agent.mjs" "$HERE/lexis-frame.mjs" "$HERE/zstd.wasm" "$HERE/lexis-tls.crt" "$HERE/lexis-tls.key" "$HERE/lexis.config.json" "$DEST/"
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
