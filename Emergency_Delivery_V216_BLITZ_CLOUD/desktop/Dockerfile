FROM node:22-bookworm-slim
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
ENV NODE_ENV=production
ENV PORT=3000
ENV EMERGENCY_DB_DIR=/data/database
ENV EMERGENCY_CONFIG_DIR=/data/config
EXPOSE 3000
CMD ["node","server.js"]
