FROM node:22-alpine AS base

WORKDIR /app

# Enable corepack and prepare pnpm
RUN corepack enable && corepack prepare pnpm@latest --activate

# Copy package files
COPY package.json pnpm-lock.yaml .npmrc ./

# Set global store dir to avoid loops
RUN pnpm config set store-dir /root/.pnpm-store

# Install dependencies as root
RUN pnpm install --frozen-lockfile

# Copy app code
COPY . .

EXPOSE 5173

CMD ["pnpm", "dev", "--host"]
