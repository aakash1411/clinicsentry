## ClinicSentry — multi-stage Docker build.
##
## Stage 1: builder — installs deps into an isolated venv.
## Stage 2: runtime — slim image with only the venv + source.
##
## Build:  docker build -t clinicsentry:latest .
## Run:    docker run --rm -e CLINICSENTRY_HMAC_KEY=$(openssl rand -base64 32) \
##                  clinicsentry:latest demo
##
## The image runs as non-root user 1000 and exposes no ports by default; the
## dashboard service publishes its own port.

ARG PYTHON_VERSION=3.11

# ----- builder ---------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim-bookworm AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONUNBUFFERED=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH=/opt/venv/bin:$PATH

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv "$VIRTUAL_ENV"

WORKDIR /build
COPY pyproject.toml ./
COPY README.md ./
COPY src/ ./src/

RUN pip install --upgrade pip \
    && pip install -e '.[all,otel,metrics,postgres,s3,dashboard]'

# ----- runtime ---------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim-bookworm AS runtime

ENV PYTHONUNBUFFERED=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1

# Create non-root user.
RUN groupadd --system --gid 1000 cg \
    && useradd --system --uid 1000 --gid cg --shell /sbin/nologin --home /app cg

COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /build /app
WORKDIR /app

USER 1000:1000

ENTRYPOINT ["clinicsentry"]
CMD ["--help"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD clinicsentry --help > /dev/null || exit 1

LABEL org.opencontainers.image.title="ClinicSentry" \
      org.opencontainers.image.description="Compliance middleware for clinical AI agents." \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/aakash1411/clinicsentry"
