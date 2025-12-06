FROM node:20-alpine AS base

WORKDIR /app

RUN corepack enable && corepack prepare pnpm@latest --activate

COPY package.json pnpm-lock.yaml ./

RUN pnpm install --frozen-lockfile

COPY . .

EXPOSE 5173

CMD ["pnpm", "dev", "--host"]

