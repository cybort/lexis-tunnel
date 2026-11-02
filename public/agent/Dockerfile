# Resident agent only. Do not copy a TLS private key into this image.
# The sample lexis.config.json has an empty token, so the process exits until you mount a real config.
FROM node:22-bookworm-slim
WORKDIR /opt/lexis
COPY lexis-agent.mjs lexis-frame.mjs lexis-http.mjs lexis-tun.mjs zstd.wasm lexis.config.json 使用说明.txt ./
COPY linux/lexis-sockopt.node linux/sockopt.c ./
EXPOSE 1080 17890
CMD ["node", "lexis-agent.mjs"]
