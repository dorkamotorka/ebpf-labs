---
kind: tutorial

title: "eBPF Tracepoints, Kprobes, or Fprobes: Which One Should You Choose?"

description: |
  In this tutorial, we’ll explore how different eBPF tracing mechanisms work in practice by focusing on a single use case: capturing execve system call events. We’ll start with tracepoints, move on to raw tracepoints, and then cover kprobes and fprobes, showing how each attaches to the kernel and what data they expose. Along the way, we’ll compare their trade-offs in terms of stability, performance, and portability.

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

createdAt: 2025-09-09
updatedAt: 2025-09-09

cover: __static__/tracing.png

---

It is safe to say that almost all eBPF programs can capture and send kernel event data to user space applications. 

However, eBPF tracing program types like kprobes, fprobes, and tracepoints are often preferred because they hook into kernel functions or events with access to rich, actionable data for tasks like performance monitoring or syscall argument tracing. 

But their overlapping functionality can make choosing the right one confusing.

In this tutorial, we’ll implement several different eBPF tracing programs where all capture `execve` syscall events and compare their strengths and trade-offs.

::image-box
---
:src: __static__/tracing.png
:alt: eBPF Tracing
:max-width: 600px
---
::

## eBPF Tracepoint

eBPF tracepoint programs attach to predefined hook points in the Linux kernel. These hook points are defined in the kernel source code with a `TRACE_EVENT` macro. Once attached, an eBPF program runs its custom logic whenever the kernel hits the corresponding tracepoint.

::details-box
---
:summary: More information on TRACE_EVENT macro
---

`TRACE_EVENT` is the generic macro for defining custom tracepoints in the kernel, while `TRACE_EVENT_SYSCALL` is a specialized variant for syscalls through which eBPF Tracepoint hook are created. 

In fact, there is **NO** static `sys_enter_execve` tracepoint defined in the kernel.

Instead, per-syscall tracepoints are generated at build time using the `TRACE_EVENT_SYSCALL` template in [`include/trace/events/syscalls.h`](https://codebrowser.dev/linux/linux/include/trace/events/syscalls.h.html) and syscall metadata from the architecture’s syscall tables like [`arch/x86/entry/syscalls/syscall_64.tbl`](https://raw.githubusercontent.com/torvalds/linux/master/arch/x86/entry/syscalls/syscall_64.tbl). This generation is handled by code in [`kernel/trace/trace_syscalls.c`](https://codebrowser.dev/linux/linux/kernel/trace/trace_syscalls.c.html) to produce an entry tracepoint like `sys_enter_execve` to which eBPF can then attach to.
::

For example, the `sys_enter_execve` tracepoint fires when a process calls `execve`, exposing the program name and arguments. This makes it useful for tasks such as auditing, security monitoring, or analyzing user activity.

You can find all events that eBPF tracepoints can hook onto, using:

```bash
sudo cat /sys/kernel/debug/tracing/available_events
```
```
drm:drm_vblank_event
drm:drm_vblank_event_queued
drm:drm_vblank_event_delivered
...
syscalls:sys_exit_execveat
syscalls:sys_enter_execveat
syscalls:sys_exit_execve
syscalls:sys_enter_execve # <- here is our tracepoint
syscalls:sys_exit_pipe
...
```

The output format is in the form `<category>:<name>`.

Using the `category` and the `name`, you can then view the input arguments for each tracepoint by printing the contents of `/sys/kernel/debug/tracing/events/<category>/<name>/format`.

```bash
sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format
```
```
name: sys_enter_execve
ID: 660
format:
        field:unsigned short common_type;           offset:0; size:2; signed:0;
        field:unsigned char common_flags;           offset:2; size:1; signed:0;
        field:unsigned char common_preempt_count;   offset:3; size:1; signed:0;
        field:int           common_pid;             offset:4; size:4; signed:1;

        field:int        __syscall_nr;              offset:8;  size:4; signed:1;
        field:const char * filename;                offset:16; size:8; signed:0;
        field:const char *const * argv;             offset:24; size:8; signed:0;
        field:const char *const * envp;             offset:32; size:8; signed:0;

print fmt: "filename: 0x%08lx, argv: 0x%08lx, envp: 0x%08lx", ((unsigned long)(REC->filename)), ((unsigned long)(REC->argv)), ((unsigned long)(REC->envp))
```

::remark-box
---
kind: info
---

💡 The first four arguments, are actually not accessible by the eBPF code. This is a choice that dates back to the original inclusion of this code. See explaination in [commit 98b5c2c65c29](https://github.com/torvalds/linux/commit/98b5c2c65c2951772a8fc661f50d675e450e8bce).
::

With this information, you can then define an input context struct that matches the accessible fields and then write your eBPF tracepoint program against it.

```c [trace.c]
...
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

::remark-box
---
kind: info
---

💡 `SEC("tp/xx/yy")` and `SEC("tracepoint/xx/yy")` are equivalent, and you can use either one according to personal preference.
::

But there are two downsides to this:
- First, **tracepoints only exist where kernel developers have added them**. If you need visibility into something that is not supported by the listed tracepoints, you either go through the long process of proposing a new tracepoint upstream (and convincing Linus to accept it), or use an alternative technique.
- Second, they’re **not always ideal for high-performance use cases** — we’ll dig into that shortly.

## eBPF Raw Tracepoint

Raw tracepoints may look similar to regular tracepoints, since both correspond to events you can view under `/sys/kernel/debug/tracing/available_events`. The difference lies in how the kernel passes arguments to them.

For regular tracepoints, the kernel pre-processes the arguments and builds a context struct. In contrast, eBPF raw tracepoints receive their arguments in a raw format via `struct bpf_raw_tracepoint_args`, and the program must interpret them manually.

Because no extra work is done to package fields, raw tracepoints typically [run faster with less overhead than regular tracepoints](https://lwn.net/Articles/750569/).

Another important difference is that there are no per-syscall raw tracepoints like `sys_enter_execve`. Instead, only the generic `sys_enter` and `sys_exit` tracepoints exist. 

::details-box
---
:summary: What is the difference between sys_enter and sys_exit tracepoint?
---

💡 `sys_enter` hooks trigger on every syscall event entry, while `sys_exit` hooks trigger on its return, capturing the return value of the syscall.
::

This means that if you want to act on a specific syscall event inside your raw tracepoint eBPF program, you need to filter by syscall ID.

```c [trace.c]{1,3-14}
SEC("raw_tracepoint/sys_enter")
int handle_execve_raw_tp_non_core(struct bpf_raw_tracepoint_args *ctx) {
    // There is no method to attach a raw_tp directly to a single syscall... 
    // this is because there are no static defined tracepoints on single syscalls but only on generic sys_enter/sys_exit
    // So we have to filter by syscall ID
    //
    // The arguments of input context struct are defined in TP_PROTO of the tracepoint definition in kernel.
    // Ref: https://codebrowser.dev/linux/linux/include/trace/events/syscalls.h.html#20
    // In this case it is TP_PROTO(struct pt_regs *regs, long id):
    // args[0] -> struct pt_regs *regs
    // args[1] -> long id
    unsigned long id = ctx->args[1];
    if (id != 59)   // execve sycall ID
	    return 0;

    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];

    const char *filename;
    // Intentionally accessing the register (without using PT_REGS_PARM* macro) directly for illustration
    bpf_probe_read(&filename, sizeof(filename), &regs->di);

    char buf[ARGSIZE];
    bpf_probe_read_user_str(buf, sizeof(buf), filename);

    bpf_printk("Raw tracepoint triggered for execve syscall with parameter filename: %s\n", buf);
    return 0;
}
```
::remark-box
---
kind: info
---

💡 `SEC("raw_tp/xx")` and `SEC("raw_tracepoint/xx")` are equivalent, and you can use either one according to personal preference.
::

Notice also that we are reading the arguments of the syscall from the CPU registers. The [System V ABI](https://gitlab.com/x86-psABIs/x86-64-ABI/-/jobs/artifacts/master/raw/x86-64-ABI/abi.pdf?job=build) specifies which arguments should be present in which CPU registers.

```c [trace.c]
...
    bpf_probe_read(&filename, sizeof(filename), &regs->di);
...
```

Since we rely on CPU registers, we need to target our binary for specific system architectures. One way to achieve this is to provide a `—-target` flag.

```go [main.go]{3}
package main                                                                
                                                                            
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 trace trace.c
 
import (
  "log"
```

## eBPF Kernel Probes (kprobes)

Regular and raw eBPF tracepoints might in fact be sufficient for your use case, but their main limitation is that they are limited to a set of predefined hook points (and perf events) in the kernel, disallowing you to trace arbitrary kernel events.

Kprobes alleviate this by allowing dynamic hooks into any kernel function, including within function body, not just at the start or return.

::remark-box
---
kind: info
---

💡 Some functions marked with the `notrace` keyword are exceptions, and kprobes cannot hook onto them.
::

Conveniently, you can list all kernel symbols in `/proc/kallsyms`:
```bash
sudo cat /proc/kallsyms | less
```
```
ffffffff81000000 T startup_64
ffffffff81000000 T _stext
ffffffff81000000 T _text
ffffffff81000060 T secondary_startup_64
ffffffff81000065 T secondary_startup_64_no_verify
ffffffff81000120 t verify_cpu
...
ffffffff812b7710 T __ia32_sys_execveat
ffffffff812b7780 T __ia32_sys_execve
ffffffff812b77d0 T __x64_sys_execveat
ffffffff812b7840 T __x64_sys_execve # <- Our kernel function
...
```

::remark-box
---
kind: info
---

💡 If a function is not in `/proc/kallsyms`, it's likely because is was inlined at compile time. Also verify they are not blacklisted in `/sys/kernel/debug/krpobes/blacklist`.
::

```c [trace.c]
SEC("kprobe/__x64_sys_execve")
int kprobe_execve_non_core(struct pt_regs *ctx) {
    // On x86-64, the entry wrapper __x64_sys_execve is called with a pointer to struct pt_regs in %rdi -> pt_regs.di
    struct pt_regs *regs = (struct pt_regs *)ctx->di;

    // Read the filename "from the inner regs"
    unsigned long di = 0;
    bpf_probe_read_kernel(&di, sizeof(di), &regs->di);
    const char *filename = (const char *)di;

    char buf[ARGSIZE];
    bpf_probe_read_user_str(buf, sizeof(buf), filename);

    bpf_printk("Kprobe triggered for execve syscall with parameter filename: %s\n", buf);

    return 0;
}
```

But the issue with kprobes is that you **depend on whatever code happens to be in the kernel your system runs and are not assured to be stable across different kernel versions**. Functions might exist in certain kernel versions, while not in others, structs can change, rename, or remove a field you are using.

In the upcoming tutorial, we’ll look at how to avoid these kinds of “non-portable” scenarios.

::remark-box
---
kind: info
---

💡 The same applies for **kretprobes** — kernel probes one can attach to the exit of the function.
::

Also, when we attach a kprobe, it’s similar to inserting a breakpoint in a debugger: the [kernel patches the target instruction with one that triggers a debug exception](https://elixir.bootlin.com/linux/v6.15.6/source/kernel/kprobes.c#L1152). When this instruction executes, the exception handler calls our probe handler.

And while this mechanism works well, it has a downside.

Each probe hit generates an exception, causing context switches and exception handling. That overhead may be negligible for infrequent probes, but if many probes are attached to “hot” kernel functions, performance can degrade significantly.

Is there some alternative to allow triggering eBPF programs with less overhead? Yes, of course — read along.

## Fprobes (fentry/fexit)

As mentioned above, kprobes work by patching an instruction to trigger a debug exception, which adds context-switch and exception-handling overhead.  

Fprobes in contrast build on the ftrace mechanism. The compiler inserts a NOP at each function entry, which can be patched at runtime into an [eBPF trampoline](https://lwn.net/Articles/804937/). This trampoline calls the eBPF program directly, avoiding exceptions and making attach and detach operations faster with much lower overhead.  

The trade-off is that fprobes can only attach to function entry points (fentry) and exits (fexit). However, they can also attach to BPF programs such as XDP, TC, or cGroup hooks.

Additionally, fexit probes have access to the function’s input parameters, something kretprobes cannot provide.


```c [trace.c]
SEC("fentry/__x64_sys_execve")
int fentry_execve(u64 *ctx) {
    struct pt_regs *regs = (struct pt_regs *)ctx[0];

    // x86-64: first arg in rdi -> pt_regs.di
    const char *filename = (const char *)regs->di;
    char buf[ARGSIZE];
    bpf_probe_read_user_str(buf, sizeof(buf), filename);

    bpf_printk("Fentry tracepoint triggered (CO-RE) for execve syscall with parameter filename: %s\n", buf);
    return 0;
}
```

They do however require at least kernel version 5.5 which might be an issue if you need to support older kernels, at least for now. But otherwise they are mostly superior to kprobes.

::remark-box
---
kind: info
---
💡 For the kprobe example above, I intentionally read the register value using `&regs→di`, but I could also use [`PT_REGS_PARM*`](https://docs.ebpf.io/ebpf-library/libbpf/ebpf/PT_REGS_PARM/) macro which should be preffered.

::

Before I let you go, note that there are also BTF-enabled tracepoints, which we’ll cover in the upcoming tutorial alongside an introduction to BTF (BPF Type Format).