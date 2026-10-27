FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY package.json ./
COPY lib ./lib
COPY public ./public
COPY staff-ui ./staff-ui
COPY server.js ./
# Persist these two folders with a volume: the SQLite database and uploaded images.
RUN mkdir -p data uploads && chown -R node:node /app
USER node
EXPOSE 3000
VOLUME ["/app/data", "/app/uploads"]
CMD ["node", "--disable-warning=ExperimentalWarning", "server.js"]
