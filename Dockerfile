# One image, four roles. Which one a container plays is decided by its command:
#   npm run registry   the registry mirror (its own key, its own clock)
#   npm run venue      the venue
#   npm run app        the hosted console, which also runs clients' agents
# Agents are started by the app as child processes inside its own container, so
# the app container is the one that needs the data volume and the headroom.
FROM node:22-slim

RUN apt-get update && apt-get install -y --no-install-recommends tini ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /srv
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev || npm install --omit=dev
COPY tsconfig.json ./
COPY src ./src

RUN useradd --system --uid 10001 --home /srv interchange \
  && mkdir -p /data && chown -R interchange:interchange /srv /data
USER interchange
ENV NODE_ENV=production
VOLUME ["/data"]

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["npm", "run", "app"]
