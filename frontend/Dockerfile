FROM node:24-alpine@sha256:a0b9bf06e4e6193cf7a0f58816cc935ff8c2a908f81e6f1a95432d679c54fbfd

ENV NEXT_TELEMETRY_DISABLED=1

WORKDIR /app
COPY package.json ./
COPY package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY . .
RUN npm run build
RUN addgroup -g 10001 threatcommand \
    && adduser -S -u 10001 -G threatcommand threatcommand \
    && chown -R threatcommand:threatcommand /app

EXPOSE 3000
USER threatcommand
CMD ["npm", "start"]
