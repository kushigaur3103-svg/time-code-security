# Stage 1: Dependencies & Build
FROM node:20-alpine AS builder
WORKDIR /app

COPY package*.json ./
COPY prisma ./prisma/

# Install dependencies and generate Prisma Client
RUN npm install
RUN npx prisma generate

# Copy UI and build
COPY . .
RUN npm run build

# Stage 2: Production Runner
FROM node:20-alpine
WORKDIR /app

# Copy the built assets from the builder
COPY --from=builder /app ./

# Next.js will read the PORT environment variable natively
ENV PORT=3001 
EXPOSE 3001

CMD ["npm", "start"]
