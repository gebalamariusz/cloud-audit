FROM python:3.12-slim@sha256:ccc7089399c8bb65dd1fb3ed6d55efa538a3f5e7fca3f5988ac3b5b87e593bf0

LABEL maintainer="Mariusz Gebala <kontakt@haitmg.pl>"
LABEL org.opencontainers.image.source="https://github.com/gebalamariusz/cloud-audit"
LABEL org.opencontainers.image.description="Scan your cloud infrastructure for security, cost, and reliability issues."

WORKDIR /app

RUN groupadd -r cloudaudit && \
    useradd -r -g cloudaudit -d /app -s /sbin/nologin cloudaudit

# Copy dependency spec first for better layer caching
COPY pyproject.toml README.md ./
COPY src/ src/

RUN pip install --no-cache-dir --no-input .

USER cloudaudit

ENTRYPOINT ["cloud-audit"]
CMD ["--help"]
