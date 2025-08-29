FROM ghcr.io/iximiuz/labs/rootfs:ubuntu-24-04

RUN sudo apt-get update -y

# Base packages & eBPF dependencies
RUN sudo apt-get install -y --no-install-recommends \
        apt-transport-https \
        ca-certificates \
        curl \
        gnupg \
        lsb-release \
        software-properties-common \
        clang \
        llvm \
        jq \
        git \
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
    (sudo apt-get install -y "linux-tools-$(uname -r)" || true)

# Enable Ubuntu debug symbol repos and install bpftrace dbgsym
RUN sudo apt-get install -y --no-install-recommends ubuntu-dbgsym-keyring && \
    UB_CODENAME="$(. /etc/os-release && echo "${UBUNTU_CODENAME}")" && \
    printf "deb http://ddebs.ubuntu.com %s main restricted universe multiverse\n\
deb http://ddebs.ubuntu.com %s-updates main restricted universe multiverse\n\
deb http://ddebs.ubuntu.com %s-proposed main restricted universe multiverse\n" \
      "$UB_CODENAME" "$UB_CODENAME" "$UB_CODENAME" \
      | sudo tee /etc/apt/sources.list.d/ddebs.list >/dev/null && \
    sudo apt-get update -y && \
    sudo apt-get install -y --no-install-recommends bpftrace-dbgsym 

# Install dependencies for building libbpf
RUN apt-get update && apt-get install -y \
        git make gcc clang libelf-dev zlib1g-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Build and install libbpf from source
RUN git clone --depth=1 https://github.com/libbpf/libbpf.git /tmp/libbpf && \
    cd /tmp/libbpf/src && \
    make BUILD_STATIC_ONLY=0 OBJDIR=/tmp/libbpf/build DESTDIR=/usr install && \
    rm -rf /tmp/libbpf

# Ensure asm headers are accessible (same as your original)
RUN ln -sf /usr/include/$(uname -m)-linux-gnu/asm /usr/include/asm

# bpftool from source (with libbfd symlink)
RUN sudo ln -sf /usr/lib/$(uname -m)-linux-gnu/libbfd.so /usr/lib/libbfd.so && \
    sudo git clone --recurse-submodules https://github.com/libbpf/bpftool.git && \
    cd bpftool && \
    sudo git submodule update --init && \
    cd src && \
    sudo make install

# Bpftop from source
RUN sudo curl -fLJ https://github.com/Netflix/bpftop/releases/latest/download/bpftop-x86_64-unknown-linux-gnu -o bpftop && \
    sudo chmod +x bpftop && \
    sudo mv bpftop /usr/bin/bpftop

# Golang from longsleep PPA
RUN sudo add-apt-repository -y ppa:longsleep/golang-backports && \
    sudo apt-get update -y && \
    sudo apt-get install -y --no-install-recommends golang-go
    
RUN sudo rm -rf /var/lib/apt/lists/*

# Show versions for quick sanity check (optional)
#RUN set -x && \
#    which bpftool && bpftool version || true && \
#    go version && \
#    clang --version | head -n1 && \
#    llvm-as --version | head -n1 && \
#    ld --version | head -n1