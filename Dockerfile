FROM node:25.9.0-alpine3.23

# Use CICKU mirror to bypass HTTPS error.
RUN sed -i 's|https://dl-cdn.alpinelinux.org/|http://us.mirrors.cicku.me/|g' /etc/apk/repositories \
    && apk add --no-cache curl ca-certificates xxd pv fastfetch file \
       libarchive-tools p7zip binutils brotli squashfs-tools

WORKDIR /app
RUN npm init -y && npm install ws
COPY server.js .

EXPOSE 9999
CMD ["node", "server.js"]
