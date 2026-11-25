FROM node:22-bookworm-slim
WORKDIR /app
ENV NODE_ENV=production
COPY package*.json ./
RUN if [ -f package-lock.json ]; then npm ci --omit=dev; else npm install --omit=dev; fi
COPY src ./src
COPY public ./public
COPY migrations ./migrations
EXPOSE 4000
USER node
CMD ["sh", "-c", "node src/migrate.js && exec node src/server.js"]
