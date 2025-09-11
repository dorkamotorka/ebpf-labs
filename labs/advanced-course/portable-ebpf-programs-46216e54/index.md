---
kind: tutorial

title: Why Does My eBPF Program Work on One Kernel but Fail on Another?

description: |
  In this tutorial, we look at why eBPF programs can fail across kernel versions due to changes in structs, tracepoints, and function layouts. We look at examples of how these differences cause portability issues and how BPF CO-RE, BTF and vmlinux.h address them.

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

cover: __static__/tracing.png

---

In a perfect world, everyone’s systems would be fully updated, patched regularly, and running the latest kernel.

But let’s be real—that’s rarely the case.

Some environments still rely on legacy versions of Ubuntu or Fedora, while others don't have their kernels compiled with BTF (BPF Type Format) support.

And if you’re maintaining any open-source tools, things get even messier. You have zero control over what kind of system your users will run your program on.

All of this makes it tricky to ensure that your eBPF programs can run reliably across different distributions, ultimately affecting whether your eBPF tool gets adopted or not.

So how do we make eBPF programs truly portable?

::image-box
---
:src: __static__/tracing.png
:alt: eBPF Tracing
:max-width: 600px
---
::

To better understand the problem, let’s look at a hypothetical example.

Suppose you compile an eBPF program on kernel version 5.3, but it fails to run on 5.4.

**Why?** 

Because each kernel version ships with its own kernel headers, which define structs and memory layouts. Even small changes in these definitions can break eBPF programs.

Take structs, for example. Let’s say we have one representing a TCP header in kernel 5.3:

```c
struct tcphdr {       /* Offset Size */
    __be16  source;   /* 0      2    */
    __be16  dest;     /* 2      2    */
    __be32  seq;      /* 4      4    */
    __be32  ack_seq;  /* 8      4    */
    __be16  window;   /* 12     2    */
    __sum16 check;    /* 14     2    */
    __be16  urg_ptr;  /* 16     2    */
};
```

In the next kernel release, 5.4, kernel developers might decide to place these fields into a new struct or rename the seq field to seque or perhaps move these fields up or down (changing their offset):

```c
struct tcphdr {       /* Offset Size */
    __be16  source;   /* 0      2    */
    __be16  dest;     /* 2      2    */
    __be32  ack_seq;  /* 4      4    */
    __be32  seque;    /* 8      4    */
    __be16  window;   /* 12     2    */
    __sum16 check;    /* 14     2    */
    __be16  urg_ptr;  /* 16     2    */
};
```

::remark-box
---
kind: info
---

In this hypothetical struct, `seq` was renamed to `seque`, and switched with `ack_seq` which causes the offsets to change.
::

**See the problem?**

Your code may rely on specific fields or offsets, which are likely to change across kernel versions.

Since the eBPF program itself has no control over these changes, there’s an inherent need for a solution to ensure the portability of eBPF programs.

::details-box
---
:summary: Example of real-world kernel struct changes
---

In [this commit](https://git.kernel.org/pub/scm/linux/kernel/git/tip/tip.git/commit/?id=026842d148b920dc28f0499ede4950dcb098d4d5), the syscall tracepoint context was modified so that the field holding the syscall number was renamed from `nr` to `__syscall_nr`.

And as explained [here](https://tanelpoder.com/posts/ebpf-pt-regs-error-on-linux-blame-fred/), the introduction of the **FRED** (Flexible Return and Event Delivery) mechanism on x86 (kernel v6.9) altered the way `pt_regs` are stored on the stack, adding padding and moving register offsets.
::

## BPF CO-RE (Compile Once – Run Everywhere)
If you search online, you'll find plenty of resources recommending the use of [BPF CO-RE (Compile Once – Run Everywhere)](https://docs.ebpf.io/concepts/core/) to address this issue.

In other words, rather than writing the programs like this:

```c {1-12,15-16,19}
struct trace_sys_enter_execve {
    short common_type;
    char common_flags;
    char common_preempt_count;
    int common_pid;

    s32 syscall_nr;        // offset=8,  size=4
    u32 pad;               // offset=12, size=4 (pad)
    const u8 *filename;    // offset=16, size=8
    const u8 *const *argv; // offset=24, size=8
    const u8 *const *envp; // offset=32, size=8
};

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve_tp_non_core(struct trace_sys_enter_execve *ctx) {
    const char *filename_ptr = (const char *)(ctx->filename);

    u8 buf[ARGSIZE];
    bpf_probe_read_user_str(buf, sizeof(buf), filename_ptr);

    bpf_printk("Tracepoint triggered for execve syscall with parameter filename: %s\n", buf);
    return 0;
}
```

You should replace the lines of code that access the kernel struct context with the BPF_CORE_READ() family, which enables access to struct fields in a way that adapts across kernel versions:

```c {2-3,6}
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve_tp(struct trace_event_raw_sys_enter *ctx) {
    char *filename_ptr = (char *)BPF_CORE_READ(ctx, args[0]);

    u8 filename[ARGSIZE];
    bpf_core_read_user_str(&filename, sizeof(filename), filename_ptr);

    bpf_printk("Tracepoint (CO-RE) triggered for execve syscall with parameter filename: %s\n", filename);
    return 0;
}
```
::remark-box
---
kind: info
---
💡 If you look carefully, also the input context was changed. Instead of using the hardcoded `struct trace_sys_enter_execve`, we use `struct trace_event_raw_sys_enter`. 

Why is that? Read along.
::

In short, the `BPF_CORE_READ()` family of helpers enables relocatable reads of kernel structs.

So if a certain struct field (like filename in the example) sits at a different offset in another OS or kernel version, these helpers can still locate and read it correctly.

TODO: add here explantion of the `BPF_CORE_READ()` family of helpers

Under the hood, this is made possible by BPF CO-RE relocation information and [BTF (BPF Type Format)](https://docs.ebpf.io/concepts/btf/).

**Wait, what? CO-RE relocation information? BTF?** Read along.

## vmlinux.h Header file

If you peek into almost any production eBPF codebase, you’ll notice all of them include the `vmlinux.h` header. There's one also in our lab directory.

This file contains definitions for all kernel structs like `trace_event_raw_sys_enter` in the example above, generated based on the currently running kernel.

::remark-box
---
kind: info
---
💡 You can generate this header file using:
```bash
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

But in general, these files are usually build during build time, e.g. in the `Makefile`.
::

Here’s where it gets interesting — this header includes a few special lines at both the top and bottom:

```c
#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif
...
# Kernel Struct definitions
...
#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif
```

The line `__attribute__((preserve_access_index))` at the top of `vmlinux.h`, tells the compiler to emit BPF CO-RE (Compile Once – Run Everywhere) relocation information for every struct field your eBPF program accesses into your eBPF object file.

And the `clang attribute push` ensures this applies to all struct definitions until the matching `clang attribute pop` at the bottom of the file.

In other words, when you reference a field (like `filename` in the example above) from a kernel struct, the compiler doesn’t just hardcode its offset. Instead, it records metadata—like the field’s name, type, offset, and parent struct.

::details-box
---
:summary: More information on the metadata record
---

Compiler records the metadata within [`bpf_core_relo struct`](https://codebrowser.dev/linux/linux/include/uapi/linux/bpf.h.html#7501) or so-called BPF CO-RE relocation structure, defined as:
```c
struct bpf_core_relo {
	__u32 insn_off;
	__u32 type_id;
	__u32 access_str_off;
	enum bpf_core_relo_kind kind;
};
```
where the arguments are:
- `insn_off`: Identifies the instruction being relocated, such as one that sets a register to a specific value.
- `type_id`: References BTF (BPF Type Format) metadata, which describes the layout of the target kernel structure.
- `access_str_off`: Specifies how a particular field is accessed relative to the structure.
::

This metadata is recorded in BPF Type Format (BTF).

## BPF Type Format (BTF)

We can actually dump the recorded BTF information for the tracepoint example above using:

```bash
sudo bpftool prog # Find the BTF ID
sudo bpftool btf dump id <prog-btf-id>
```
```
TODO
```

And for your eBPF program to work across kernel versions—where struct layouts may differ—the target kernel must also be compiled with BTF support. Without it, the program won’t be able to resolve the correct fields offsets at runtime.

TODO: to avoid any kind of confusion, BTF is just metadata record of kernel structs and their layout..TODO: improve

**Why is this necessary?**

When your eBPF program is loaded by a BPF loader like [libbpf](https://github.com/libbpf/libbpf), the loader compares the program’s BTF data with the target kernel’s BTF. Since it's quite likely your program won't run only on the kernel it was compiled on, the loader needs to resolve types, updates offsets, and adjusts field accesses to ensure the program reads kernel structures correctly.

This process is known as <i>field offset relocation</i>.

**But one subtle limitation of this approach is that tools relying on BTF data implicitly depend on the target kernel being compiled with BTF support.**

TODO: How to check if BTF is present

Although most eBPF kernels nowadays support BTF, it's not really something we can rely on when we want to design truly portable eBPF programs.

Without BTF support in the target kernel, the loader can't perform field offset relocation, and the program may fail to load or behave incorrectly.

**But can we do something to avoid this dependency?**

Actually—yes, but we'll cover that in the next tutorial.

TODO: mention this lab includes the portable code for all the examples from lab1.