# Multi-stage production container build for Incognito Backend API
FROM node:22-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

FROM node:22-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=4000

# Install non-root security user
RUN addgroup -S incognito && adduser -S incognito -G incognito

COPY --from=builder /app/package*.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/backend ./backend
COPY --from=builder /app/dist ./dist

USER incognito
EXPOSE 4000

CMD ["node", "./node_modules/tsx/dist/cli.mjs", "backend/server.ts"]
