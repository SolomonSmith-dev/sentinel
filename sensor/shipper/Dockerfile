# Sentinel shipper image.
# Reference data is downloaded at build time and never committed:
#   - iptoasn.com ip2country-v4.tsv (PDDL)  -> country lookup
#   - IEEE MA-L oui.csv                     -> MAC vendor names
# Rebuild the image to refresh them.

FROM python:3.12-slim-bookworm AS data
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /data
RUN curl -fsSL --retry 3 -o ip2country-v4.tsv.gz https://iptoasn.com/data/ip2country-v4.tsv.gz \
 && gunzip ip2country-v4.tsv.gz \
 && test "$(wc -l < ip2country-v4.tsv)" -gt 10000
RUN curl -fsSL --retry 3 -A "Mozilla/5.0 (sentinel-shipper build)" -o oui.csv https://standards-oui.ieee.org/oui/oui.csv \
 && head -1 oui.csv | grep -q "Assignment" \
 && test "$(wc -l < oui.csv)" -gt 10000

FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
RUN apt-get update \
 && apt-get install -y --no-install-recommends tzdata \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install .

COPY --from=data /data/ip2country-v4.tsv /data/oui.csv /usr/share/sentinel/

RUN groupadd --system --gid 10001 sentinel \
 && useradd --system --uid 10001 --gid sentinel --no-create-home --shell /usr/sbin/nologin sentinel \
 && mkdir -p /var/lib/sentinel/windows /var/lib/sentinel/state \
 && chown -R sentinel:sentinel /var/lib/sentinel
USER 10001:10001

ENTRYPOINT ["sentinel-shipper"]
