# syntax=docker/dockerfile:1.7

# Keep the runtime layout, entrypoint, libraries, and tools aligned with the
# HAProxy Technologies Alpine CE image previously used by the Helm chart.
ARG HAPROXY_BASE_IMAGE=docker.io/haproxytech/haproxy-alpine:3.4.3@sha256:7a3ef2dd8b5b27defc8c7c0dfcded9c2e54d0bbe0b9ac80dc903b0b4129452f9

FROM ${HAPROXY_BASE_IMAGE} AS haproxy-builder

USER root

RUN apk add --no-cache --virtual .build-deps \
      build-base \
      jemalloc-dev \
      linux-headers \
      lua5.4-dev \
      make \
      openssl \
      openssl-dev \
      pcre2-dev \
      zlib-dev

WORKDIR /usr/src/haproxy
COPY . .

# These flags mirror haproxytech/haproxy-docker-alpine:3.4.3. The
# linux-musl target enables Linux splice automatically; validation fails the
# image build if splice or another required feature is missing.
RUN test "$(cat VERSION)" = "3.4.4" && \
    make clean && \
    make -j"$(nproc)" \
      TARGET=linux-musl \
      CPU=generic \
      USE_PCRE2=1 \
      USE_PCRE2_JIT=1 \
      USE_TFO=1 \
      USE_LINUX_TPROXY=1 \
      USE_GETADDRINFO=1 \
      USE_LUA=1 \
      LUA_LIB=/usr/lib/lua5.4 \
      LUA_INC=/usr/include/lua5.4 \
      USE_PROMEX=1 \
      USE_SLZ=1 \
      USE_OPENSSL_AWSLC=1 \
      USE_PTHREAD_EMULATION=1 \
      SSL_INC=/opt/aws-lc/include \
      SSL_LIB=/opt/aws-lc/lib \
      USE_QUIC=1 \
      LDFLAGS="-L/opt/aws-lc/lib -Wl,-rpath,/opt/aws-lc/lib" \
      ADDLIB=-ljemalloc \
      all && \
    ./haproxy -vv > /tmp/haproxy-build-info.txt && \
    grep -q 'TARGET  = linux-musl' /tmp/haproxy-build-info.txt && \
    grep -q '+LINUX_SPLICE' /tmp/haproxy-build-info.txt && \
    grep -q '+PROMEX' /tmp/haproxy-build-info.txt && \
    grep -q '+OPENSSL_AWSLC' /tmp/haproxy-build-info.txt && \
    grep -q '+LUA' /tmp/haproxy-build-info.txt && \
    grep -q '+PCRE2_JIT' /tmp/haproxy-build-info.txt && \
    grep -q '+QUIC' /tmp/haproxy-build-info.txt

FROM ${HAPROXY_BASE_IMAGE}

ARG VCS_REF=unknown
ENV HAPROXY_BRANCH=3.4 \
    HAPROXY_MINOR=3.4.4 \
    HAPROXY_SHA256=custom-source-tree
LABEL Name="HAProxy" \
      Release="Community Edition" \
      Vendor="HAProxy" \
      Version="3.4.4-custom" \
      org.opencontainers.image.title="HAProxy 3.4.4 Custom" \
      org.opencontainers.image.version="3.4.4-custom" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.description="HAProxy 3.4.4 custom build with the haproxytech Alpine feature set"

USER root

COPY --from=haproxy-builder /usr/src/haproxy/haproxy /usr/local/sbin/haproxy

RUN chmod 0755 /usr/local/sbin/haproxy && \
    ln -sf /usr/local/sbin/haproxy /usr/sbin/haproxy && \
    haproxy -vv > /tmp/haproxy-runtime-info.txt && \
    grep -q 'HAProxy version 3.4.4' /tmp/haproxy-runtime-info.txt && \
    grep -q '+LINUX_SPLICE' /tmp/haproxy-runtime-info.txt && \
    rm -f /tmp/haproxy-runtime-info.txt

# ENTRYPOINT, CMD, STOPSIGNAL, default configuration, Data Plane API, AWS-LC,
# and runtime libraries are inherited from HAPROXY_BASE_IMAGE.
