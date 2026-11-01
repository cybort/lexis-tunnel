#!/bin/sh
set -eu
HERE=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
DEST="${HOME}/.config/lexis"
mkdir -p "$DEST"
cp "$HERE/lexis-agent.mjs" "$HERE/lexis-frame.mjs" "$HERE/zstd.wasm" "$HERE/lexis.config.json" "$DEST/"
if [ -f "$HERE/lexis-tls.crt" ] && [ -f "$HERE/lexis-tls.key" ]; then
  cp "$HERE/lexis-tls.crt" "$HERE/lexis-tls.key" "$DEST/"
fi
chmod +x "$DEST/lexis-agent.mjs"
if ! command -v node >/dev/null 2>&1; then
  echo "需要 Node.js 22"
  exit 1
fi
NODE=$(command -v node)
if command -v systemctl >/dev/null 2>&1; then
  mkdir -p "${HOME}/.config/systemd/user"
  sed -e "s#@NODE@#${NODE}#" -e "s#@HOME@#${HOME}#" "$HERE/lexis-agent.service" > "${HOME}/.config/systemd/user/lexis-agent.service"
  systemctl --user daemon-reload
  systemctl --user enable --now lexis-agent.service
  echo "词隙已交给 systemd 用户服务，断线会自己拉起。"
else
  nohup "$NODE" "$DEST/lexis-agent.mjs" >>"$DEST/agent.log" 2>&1 &
  echo $! > "$DEST/lexis-agent.pid"
  echo "没有 systemd，已在后台启动。PID $(cat "$DEST/lexis-agent.pid")"
fi
echo "状态页 http://127.0.0.1:17890/"
