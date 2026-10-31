# syntax=docker/dockerfile:1
# Build for the sensor's original x86-64 CPU, without DPDK/Hyperscan.
# Prebuilt images and Debian's DPDK dependency require SSE4.2 on newer CPUs.
FROM debian:trixie-slim AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential rustc cargo pkg-config curl ca-certificates python3-yaml \
      libpcap-dev libpcre2-dev libyaml-dev zlib1g-dev libjansson-dev \
      libcap-ng-dev libmagic-dev liblz4-dev libnss3-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN curl -fsSL --retry 3 -o suricata.tar.gz \
      https://deb.debian.org/debian/pool/main/s/suricata/suricata_8.0.7.orig.tar.gz \
 && echo 'a9d46a9c8f40e81f8a6df3ecc2c5a9a8e8da985876299108d92da547c013ba8c  suricata.tar.gz' | sha256sum -c - \
 && tar -xzf suricata.tar.gz --strip-components=1
ENV CFLAGS="-O2 -march=x86-64 -mtune=generic" \
    RUSTFLAGS="-C target-cpu=x86-64" \
    CARGO_BUILD_JOBS=2
RUN --mount=type=cache,target=/src/rust/target \
    ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var \
      --disable-gccmarch-native --disable-dpdk --disable-af-xdp \
 && make -j2 \
 && make DESTDIR=/out install install-conf

FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      suricata-update ca-certificates libpcap0.8t64 libpcre2-8-0 libyaml-0-2 \
      zlib1g libjansson4 libcap-ng0 libmagic1t64 liblz4-1 libnss3 \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --gid 10001 sentinel \
 && useradd --uid 10001 --gid sentinel --no-create-home --shell /usr/sbin/nologin sentinel \
 && mkdir -p /var/log/suricata /var/lib/suricata /var/run/suricata
COPY --from=build /out/usr/bin/suricata /usr/bin/suricata
COPY --from=build /out/etc/suricata /etc/suricata
COPY entrypoint.sh /docker-entrypoint.sh
RUN chmod 0755 /docker-entrypoint.sh /etc/suricata \
 && chmod 0644 /etc/suricata/*.config /etc/suricata/*.yaml
ENTRYPOINT ["/docker-entrypoint.sh"]
