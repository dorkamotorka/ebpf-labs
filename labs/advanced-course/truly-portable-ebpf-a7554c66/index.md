---
kind: tutorial

title: Building Truly Portable eBPF Programs and BTFHub

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

Although most modern kernels ship with [BTF](https://docs.ebpf.io/concepts/btf/) enabled, you can’t really rely on this when building portable eBPF programs.

Without BTF in the (target) kernel, the eBPF loader cannot resolve types, fix offsets, or adjust field accesses to ensure the eBPF program reads kernel structures correctly.

In this tutorial, you’ll learn how to overcome this limitation by embedding BTF data for a wide range of kernels directly into your eBPF application binary. With this approach, your program will run reliably even on systems that lack BTF support.

::image-box
---
:src: __static__/tracing2.png
:alt: eBPF Tracing
:max-width: 600px
---
::

In the previous tutorial, [Why Does My eBPF Program Work on One Kernel but Fail on Another?](https://labs.iximiuz.com/tutorials/portable-ebpf-programs-46216e54), we covered [BPF CO-RE](https://docs.ebpf.io/concepts/core/), `vmlinux.h`, and BTF concepts. The takeaway was that  if you want your eBPF program to run across different kernels (where struct layouts likely to differ) you need two things:
- Your program binary packed with embedded BTF inforomation for kernel structs it interacts with.
- The target kernel itself built with BTF support.

Sounds simple enough, but for most eBPF projects you can’t really predict in advance what environments your program will run in.  

Sure, you could document that a kernel with BTF support is required, but enabling BTF not only requires rebuilding and rebooting the kernel, but is also not practical at scale and is rarely acceptable in environments where downtime is not an option.

To address this, Aqua Security maintains [btfhub-archive](https://github.com/aquasecurity/btfhub-archive), a repository of prebuilt BTF files for almost all kernels that lack embedded BTF.

By downloading the appropriate BTF files for the kernels you want to support and embedding them directly into your eBPF program, you can eliminate the need for BTF support on the target system.

## Installing and Minimizing the BTF Information from btfhub-archive Repository

Installing BTF files for different operating systems and kernels is as easy as grabbing them from [btfhub-archive](https://github.com/aquasecurity/btfhub-archive).

But while it might sound tempting to just install and bundle the **entire** BTFs for each kernel into your binary, that’s not really the best approach.

Nonetheless, your eBPF program doesn’t need the whole BTF of the target kernel. It only cares about the specific kernel types and structs it actually interacts with.

Doing that manually would be painful—but luckily, `bpftool` can help with that. It can look at your compiled eBPF object (`.o`), figure out exactly which structs and fields the program uses, and spit out the minimal BTF for you.

```bash
sudo bpftool gen min_core_btf <full.btf> <out.min.btf> <bpf .o file>
```

This command trims the full BTF down to just the types required by your program. By embedding just the minimal BTF, you cut down the binary size, speed up compilation, and make program loading and attaching way faster on the target kernel.

But that's only half the solution.

## Embedding BTF Information into eBPF Application Binary

Before the program loads on the target kernel, it needs to detect the OS and kernel version to we know which BTF file to use for that specific environment. And of course, ideally, we wouldn’t need this step at all—the check should only run if BTF information isn’t already available at the target kernel.

For this part, the code is taken from [Inspektor Gadget](https://github.com/inspektor-gadget/inspektor-gadget/tree/main), specifically the `btfgen.go` file (you can find it in `ebpf-labs-advanced/lab3`).

The core piece here is the `GetBTFSpec()` function inside `ebpf-labs-advanced/lab3/btfgen.go`. 

It fetches the right BTF info and passes it into `ebpf.ProgramOptions`, which is what we set when loading our eBPF program into the kernel.

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

But as you can imagine, installing and generating minimal BTF files by hand would be pretty tedious. 

To simplify the process, we’ve implemented a `Makefile` and `Makefile.btfgen` that automate everything behind a single `make` command. This workflow:  
- **Compiles the eBPF program** and generates the Go bindings to interact with it  
- **Fetches and embeds BTF data** from btfhub-archive repository for different kernel and OS versions  
- **Strips the BTF data down** to only the types your eBPF program actually uses
- **Builds a single portable binary** that can run across a wide range of kernels—even on systems without BTF support  

Both files (in the `ebpf-labs-advanced/lab3`) include detailed comments to make it easier for you to follow along and understand each step. 

Go ahead and give it a try — and maybe grab a coffee while you’re at it.

```bash
cd ebpf-labs-advanced/lab3 # Go inside the lab directory if you haven't yet
git submodule init # Initialize btfhub-archive repository
make # Run build
```

::remark-box
---
kind: info
---

Our Makefiles only install BTF files for the x86 architecture—otherwise the `make` process would take too long for this demo. But extending it is straightforward if you need others.
::
