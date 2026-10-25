# syntax=docker/dockerfile:1
# Build context: sensor/capture/
#   docker build -t sentinel-capture sensor/capture

# ---- build ------------------------------------------------------------------
FROM debian:bookworm-slim AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      g++ cmake make pkg-config libpcap-dev ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY CMakeLists.txt ./
COPY src ./src
COPY tests ./tests
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DSENTINEL_BUILD_TESTS=OFF -DSENTINEL_WERROR=ON \
 && cmake --build build -j"$(nproc)" \
 && strip build/sentinel-capture

# ---- runtime ----------------------------------------------------------------
FROM debian:bookworm-slim
COPY --from=build /src/build/sentinel-capture /usr/local/bin/sentinel-capture

# Runs as an unprivileged user. Capturing needs CAP_NET_RAW: compose grants it
# (cap_add: [NET_RAW], network_mode: host), and the file capability set here
# lets the non-root process actually use it. libcap2-bin is only needed for
# setcap and is purged in the same layer.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libpcap0.8 libcap2-bin \
 && setcap cap_net_raw+ep /usr/local/bin/sentinel-capture \
 && apt-get purge -y libcap2-bin && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin sentinel \
 && install -d -o sentinel -g sentinel /var/lib/sentinel/windows

USER sentinel
ENV SENTINEL_WINDOWS_DIR=/var/lib/sentinel/windows
VOLUME ["/var/lib/sentinel/windows"]
ENTRYPOINT ["/usr/local/bin/sentinel-capture"]
