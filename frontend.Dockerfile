# Build stage: compiles the Next.js production build. Runs once at `docker build` time, never
# at container start — the app.CMD field is now the runtime stage's only, near-instant
# `next start`, so an ALB/ECS health check no longer races a multi-minute build.
#
# BACKEND_URL/NEXT_PUBLIC_BACKEND_URL must be build args, not just runtime env vars: `next build`
# computes next.config.js's rewrites() destination ONCE into a static routes manifest, and inlines
# every NEXT_PUBLIC_* reference into the client bundle via webpack — neither is re-read at
# `next start`. A value only set at container start (the old single-stage image's implicit
# behavior, since build and start shared one live environment there) silently falls back to
# next.config.js's own http://localhost:4000 default here, with no runtime override possible —
# confirmed live via ECONNREFUSED 127.0.0.1:4000 in the frontend's own logs.
FROM node:alpine3.22 AS build
ARG BACKEND_URL
ARG NEXT_PUBLIC_BACKEND_URL
ENV BACKEND_URL=$BACKEND_URL
ENV NEXT_PUBLIC_BACKEND_URL=$NEXT_PUBLIC_BACKEND_URL
WORKDIR /frontend
COPY ./frontend/package*.json ./
RUN npm install
COPY ./frontend .
RUN npm run build

# Runtime stage: only what `next start` needs — no build toolchain, smaller image.
FROM node:alpine3.22 AS runtime
WORKDIR /frontend
ENV NODE_ENV=production
COPY --from=build /frontend/package*.json ./
COPY --from=build /frontend/node_modules ./node_modules
COPY --from=build /frontend/.next ./.next
COPY --from=build /frontend/public ./public
COPY --from=build /frontend/next.config.js ./next.config.js

EXPOSE 8080
CMD ["npm", "run", "start"]
