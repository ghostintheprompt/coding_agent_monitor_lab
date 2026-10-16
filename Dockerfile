FROM node:20-slim
WORKDIR /app
COPY package.json .
COPY monitors.js .
COPY test.js .
COPY fixtures ./fixtures
CMD ["node", "test.js"]
