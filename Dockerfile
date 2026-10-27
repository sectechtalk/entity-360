# Entity 360 container image (Azure Container Apps). Build: docker build -t ghcr.io/your-org/entity-360:<tag> .
FROM node:22-alpine
ENV NODE_ENV=production PORT=8080 HOST=0.0.0.0
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY server ./server
COPY public ./public
USER node
EXPOSE 8080
CMD ["node", "server/index.mjs"]
