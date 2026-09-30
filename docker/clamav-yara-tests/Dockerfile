FROM ubuntu:24.04

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        clamav \
        yara \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tests
COPY docker/clamav-yara-tests/run-smoke.sh /tests/run-smoke.sh
RUN chmod +x /tests/run-smoke.sh

CMD ["/tests/run-smoke.sh"]
