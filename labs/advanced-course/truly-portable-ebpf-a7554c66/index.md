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

Although most modern kernels include BTF support, you can’t always rely on it when writing portable eBPF programs.

Without BTF in the target kernel, the loader can’t resolve types, adjust offsets, or fix up field accesses—leading to load failures or incorrect behavior.

In this tutorial, you’ll learn how to avoid this limitation by embedding BTF data for nearly all target kernels directly into your eBPF application binary. This way, your program can run correctly even on systems that lack native BTF support.

::image-box
---
:src: __static__/tracing2.png
:alt: eBPF Tracing
:max-width: 600px
---
::

In the previous tutorial, [Why Does My eBPF Program Work on One Kernel but Fail on Another?](https://labs.iximiuz.com/tutorials/portable-ebpf-programs-46216e54), we covered [BPF CO-RE](https://docs.ebpf.io/concepts/core/), `vmlinux.h`, and BTF concepts. We concluded that to make an eBPF program portable across different kernel versions—where kernel structs may change—the binary must include embedded BTF information, and the target kernel must also be compiled with BTF support.

And the problem is that, for most eBPF projects, you can’t really predict in advance what environments your program will run in.  

Sure, you could document that a kernel with BTF support is a requirement—but that’s tedious for developers, and the bigger issue is that enabling BTF usually requires rebuilding and rebooting the kernel. That’s often not acceptable, whether because of the sheer number of machines involved or because downtime simply isn’t an option.

To solve this, Aqua Security maintains [btfhub-archive](https://github.com/aquasecurity/btfhub-archive), a repository of prebuilt BTF files for a wide range of kernels that lack embedded BTF.  

By downloading the appropriate BTF files for the kernels you want to support and embedding them directly into your eBPF program, you can completely eliminate the need for BTF support on the target system.

And ideally this would happen automatically during build-time of your application.

Let's see how.

Sections:
- Generate an eBPF skeleton for my example program
- Automatically downloads and embeds BTF data from btfhub-archive for all kernel/OS versions
- Minimizes the BTF data to include only the types actually used by the example eBPF program
- Produces a single binary that can run across a wide range of kernels—without requiring BTF support on the target system