FROM node:25-slim
WORKDIR /app

# Switch to the unprivileged user *before* npm ci, not after. Running the
# install as root leaves /app/node_modules root-owned, and the dev server —
# which runs as `node` — then can't create Vite's .vite/deps_temp_* dirs, so
# dependency optimisation fails with EACCES on every request.
#
# This was masked for a long time by `COPY . .` dropping the host's
# node-owned node_modules over the root-owned one. frontend/.dockerignore now
# (correctly) keeps the host's install out of the build context, which is what
# exposed it. Do not reorder these lines.
RUN chown node:node /app
USER node

COPY --chown=node:node package*.json ./
RUN npm ci
COPY --chown=node:node . .
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000/', r => process.exit(r.statusCode < 500 ? 0 : 1)).on('error', () => process.exit(1))"
CMD ["npm", "run", "dev", "--", "--host"]
