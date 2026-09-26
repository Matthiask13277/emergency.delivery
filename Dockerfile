FROM node:22-bookworm-slim
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY . .
RUN mkdir -p /app/data/generated-documents /tmp/emergency-config \
    && chown -R node:node /app /tmp/emergency-config
USER node
ENV NODE_ENV=production
ENV PORT=8080
ENV EMERGENCY_CONFIG_DIR=/tmp/emergency-config
ENV EMERGENCY_DB_DIR=/tmp/emergency-db
EXPOSE 8080
CMD ["node", "start-online.js"]
