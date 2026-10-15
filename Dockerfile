# PoAC verifier with the pinned Lean toolchain (tier C4 enabled).
#
# Build:  docker build -t poac-verifier .
# Run:    see docker-compose.yml for the hardened runtime flags
#         (read-only FS, tmpfs /tmp, memory + pids limits, no capabilities).

# --- stage 1: toolchain --------------------------------------------------------
FROM debian:bookworm-slim AS lean
ARG LEAN_VERSION=4.33.1
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN useradd -m -u 10001 poac
USER poac
WORKDIR /home/poac
# elan installs the pinned release only; no default toolchain resolution later
RUN curl -sSf https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh \
    | sh -s -- -y --no-modify-path --default-toolchain none \
 && /home/poac/.elan/bin/elan toolchain install "leanprover/lean4:v${LEAN_VERSION}" \
 && /home/poac/.elan/toolchains/leanprover--lean4---v${LEAN_VERSION}/bin/lean --version

# --- stage 2: runtime ------------------------------------------------------------
FROM python:3.12-slim
ARG LEAN_VERSION=4.33.1
RUN useradd -m -u 10001 poac
# only the toolchain directory is copied — not elan itself, so the runtime
# image cannot download or switch toolchains
COPY --from=lean --chown=poac:poac \
     /home/poac/.elan/toolchains/leanprover--lean4---v${LEAN_VERSION} \
     /opt/lean
ENV POAC_LEAN_BIN=/opt/lean/bin/lean \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /app
COPY --chown=poac:poac pyproject.toml README.md LICENSE ./
COPY --chown=poac:poac src ./src
RUN pip install --no-cache-dir ".[kms]" \
 && rm -rf /root/.cache \
 && install -d -o poac -g poac -m 700 /data   # persistent state; ownership seeds fresh named volumes
VOLUME /data
USER poac
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/.well-known/agent-capability.json', timeout=2).status == 200 else 1)"
CMD ["poac-verifier", "--host", "0.0.0.0", "--port", "8000"]
