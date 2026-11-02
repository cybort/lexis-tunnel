# Resident agent only. Do not copy a TLS private key into this image.
# The sample lexis.config.json has an empty token, so the process exits until a real config is mounted.
# link.allowLan stays false. Listeners stay on loopback. Publishing a port needs that flag, which also widens reverse doors.
# HEALTHCHECK uses 127.0.0.1:17890/health. Health stays red until a config with a real token is mounted.
# The image user is not root, so tproxy and TUN are not available here.
FROM node:22-bookworm-slim
WORKDIR /opt/lexis
COPY lexis-agent.mjs lexis-frame.mjs lexis-http.mjs lexis-tun.mjs zstd.wasm lexis.config.json 使用说明.txt ./
COPY linux/lexis-sockopt.node linux/sockopt.c ./
RUN groupadd --system lexis && useradd --system --gid lexis --home-dir /opt/lexis --no-create-home lexis \
 && chown -R lexis:lexis /opt/lexis
USER lexis
EXPOSE 1080 17890
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:17890/health').then((r)=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "lexis-agent.mjs"]
