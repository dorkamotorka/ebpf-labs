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

Although most modern kernels include BTF support, you can’t always rely on it when designing portable eBPF programs.

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

## Installing and Minimizing the BTF Information from btfhub-archive Repository

Installing the BTF files for different Operating system and kernel is as simple as visiting [btfhub-archive](https://github.com/aquasecurity/btfhub-archive).

But while it might sound as simple as just installing and embedding the full BTF information for each kernel into our output binary this wouldn't be ideal. 

In reality, we don’t need the **entire** BTF of the target kernel. What our eBPF program really depends on is just the subset of kernel types and structs it directly interacts with.

By embedding only minimal BTF files, we not only reduce the size of the output binary and speed up compilation, but we also make the eBPF program load and attach much faster on the target kernel.

The challenge is figuring out which subset of the BTF information from the `btfhub-archive` is actually needed. Doing this by hand would be tedious, but fortunately `bpftool` provides a neat feature that solves it automatically. Based on the compiled eBPF object (`.o`), it determines exactly which kernel structs and fields your program touches and generates the minimal BTF for you:

```bash
sudo bpftool gen min_core_btf <full.btf> <out.min.btf> <bpf .o file>
```

This command trims the full BTF down to just the types required by your program. The result is a compact minimal BTF file that your eBPF loader can use to correctly adjust offsets on whichever kernel your program runs.

## Embedding BTF Information to eBPF Application Binary

But we're not really done, since we haven't yet learned how to tell the eBPF loader to take this BTF files into an account.

Before our program is loaded on the target kernel, we need to detect the Operating System and the kernel version to determine which BTF file should be taken into an account for the specific environment where the user is running our eBPF program. And ideally we wouldn't be even doing this, so we should have a check in place that only does this if the BTF information is not present.

The code to achieve that was adopted from [Inspektor Gadget](https://github.com/inspektor-gadget/inspektor-gadget/tree/main). Namely the `btfgen.go` file that you can find inside the `ebpf-labs-advanced/lab3` directory.

The main functionality inside the `ebpf-labs-advanced/lab3/btfgen.go` file is the `GetBTFSpec()` function that retrieves the BTF information and provide it to the ` ebpf.ProgramOptions` that is set when we are loading our eBPF program to the kernel.

```go [main.go] {2-7,11}
...
opts := ebpf.CollectionOptions{
        Programs: ebpf.ProgramOptions{
                // This is where the BTF for the identified kernel is loaded
                KernelTypes: GetBTFSpec(),
        },
}

// Load the compiled eBPF ELF with BTF information into the kernel.
var objs traceObjects
if err := loadTraceObjects(&objs, &opts); err != nil {
        log.Fatal("Loading eBPF objects:", err)
}
defer objs.Close()
...
```

But as you can imagine, installing, generating minimal BTF files would be quite tedious to do by hand, so we prepared a `Makefile` and `Makefile.btfgen` which allow you to achieve all of that using a simple `make` command.

::remark-box
---
kind: info
---

Our Makefiles actually only install BTF files for x86 architecture, otherwise the `make` process would take incredibly long, but this could be easily extended.
::

And it doesn't really get much harder that this.