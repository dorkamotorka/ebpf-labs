---
kind: tutorial

title: BTFHub and Building Truly Portable eBPF Programs

description: |
  TODO

playground:
  name: ebpf-playground-2bd77c1c

tasks:
  clone_hello_world:
    init: true
    user: laborant
    run: |
      git clone https://github.com/dorkamotorka/ebpf-labs-advanced.git /home/laborant/ebpf-labs-advanced

categories:
- linux
- programming

tagz:
- eBPF

createdAt: 2025-09-10
updatedAt: 2025-09-10

cover: __static__/tracing2.png

---

::image-box
---
:src: __static__/tracing2.png
:alt: eBPF Tracing
:max-width: 600px
---
::

Aqua Security maintains a repository called btfhub-archive, which provides prebuilt BTF files for a wide range of kernels that lack embedded BTF.

You can download the relevant BTF files for the kernels you want to support and embed them directly into your eBPF program—eliminating the need for BTF support on the target system entirely.

I could stop here and show you a simple example of how it’s done—but I’ve taken it a step further.