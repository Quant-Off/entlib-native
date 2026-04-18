FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV SAW_VERSION=1.5

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    build-essential \
    pkg-config \
    libssl-dev \
    z3 \
    unzip \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain nightly --component llvm-tools-preview
ENV PATH="/root/.cargo/bin:${PATH}"

RUN mkdir -p /opt/saw && \
    curl -fL "https://github.com/GaloisInc/saw-script/releases/download/v${SAW_VERSION}/saw-${SAW_VERSION}-ubuntu-22.04-X64-with-solvers.tar.gz" \
    | tar xz --strip-components=1 -C /opt/saw
ENV PATH="/opt/saw/bin:${PATH}"

COPY . /workspace
WORKDIR /workspace
