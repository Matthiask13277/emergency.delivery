FROM node:22-bookworm-slim
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
RUN mkdir -p /app/data/generated-documents /tmp/emergency-config \
    && chown -R node:node /app /tmp/emergency-config
USER node
ENV NODE_ENV=production
ENV PORT=8080
ENV EMERGENCY_CONFIG_DIR=/tmp/emergency-config
EXPOSE 8080
CMD ["node","server.js"]
