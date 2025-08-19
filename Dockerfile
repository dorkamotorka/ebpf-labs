FROM ubuntu:latest

# Base packages & eBPF dependencies
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
      apt-transport-https \
      ca-certificates \
      curl \
      gnupg \
      lsb-release \
      software-properties-common \
      clang \
      llvm \
      jq \
      libelf-dev \
      libcap-dev \
      libpcap-dev \
      libbfd-dev \
      binutils-dev \
      build-essential \
      make \
      bpfcc-tools \
      python3-pip \
      linux-tools-common && \
    # Try to install tools for the running kernel; ignore if not present in repos
    (apt-get install -y "linux-tools-$(uname -r)" || true) && \
    rm -rf /var/lib/apt/lists/*

# Enable Ubuntu debug symbol repos and install bpftrace dbgsym
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends ubuntu-dbgsym-keyring && \
    UB_CODENAME="$(. /etc/os-release && echo "${UBUNTU_CODENAME}")" && \
    printf "deb http://ddebs.ubuntu.com %s main restricted universe multiverse\n\
deb http://ddebs.ubuntu.com %s-updates main restricted universe multiverse\n\
deb http://ddebs.ubuntu.com %s-proposed main restricted universe multiverse\n" \
      "$UB_CODENAME" "$UB_CODENAME" "$UB_CODENAME" \
      | tee /etc/apt/sources.list.d/ddebs.list >/dev/null && \
    apt-get update -y && \
    apt-get install -y --no-install-recommends bpftrace-dbgsym && \
    rm -rf /var/lib/apt/lists/*

# libbpf-dev and asm include symlink
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends libbpf-dev && \
    arch_multi="$(dpkg-architecture -qDEB_HOST_MULTIARCH)" && \
    ln -sf "/usr/include/${arch_multi}/asm" /usr/include/asm && \
    rm -rf /var/lib/apt/lists/*

# bpftool from source (with libbfd symlink)
RUN arch_multi="$(dpkg-architecture -qDEB_HOST_MULTIARCH)" && \
    ln -sf "/usr/lib/${arch_multi}/libbfd.so" /usr/lib/libbfd.so && \
    git clone --recurse-submodules https://github.com/libbpf/bpftool.git /tmp/bpftool && \
    cd /tmp/bpftool && git submodule update --init && \
    cd src && make -j"$(nproc)" install && \
    cd / && rm -rf /tmp/bpftool

# Golang from longsleep PPA
RUN add-apt-repository -y ppa:longsleep/golang-backports && \
    apt-get update -y && \
    apt-get install -y --no-install-recommends golang-go && \
    rm -rf /var/lib/apt/lists/*

# Show versions for quick sanity check (optional)
RUN set -x && \
    which bpftool && bpftool version || true && \
    go version && \
    clang --version | head -n1 && \
    llvm-as --version | head -n1 && \
    ld --version | head -n1