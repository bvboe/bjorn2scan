FROM cgr.dev/chainguard/wolfi-base:latest AS builder

ARG VERSION=unknown
WORKDIR /build

# Generate version.js with the build-time version
RUN echo "window.BJORN2SCAN_VERSION = '${VERSION}';" > version.js

FROM cgr.dev/chainguard/nginx:latest

COPY ./html/ /usr/share/nginx/html/
COPY --from=builder /build/version.js /usr/share/nginx/html/version.js
COPY ./nginx-conf/nginx.conf /etc/nginx/nginx.conf
