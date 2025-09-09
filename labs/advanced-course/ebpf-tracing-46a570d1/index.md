---
kind: tutorial

title: "eBPF Tracepoints, Kprobes, or Fprobes: Which One Should You Choose?"

description: |
  TODO

playground:
  name: ebpf-playground-2bd77c1c

tasks:
  clone_hello_world:
    init: true
    user: laborant
    run: |
      git clone https://github.com/dorkamotorka/ebpf-hello-world.git /home/laborant/ebpf-hello-world

categories:
- linux
- programming

tagz:
- eBPF

createdAt: 2025-09-09
updatedAt: 2025-09-09

cover: __static__/cover.png

---

It is safe to say that almost all eBPF programs can extract and send kernel event data to user space applications. 

However, eBPF tracing program types like kprobes, fprobes, and tracepoints are often preferred because they hook onto kernel events with access to rich, actionable data for tasks like performance monitoring or syscall argument tracing. 

But their overlapping functionality can make choosing the right one confusing.

TODO: image

## eBPF Tracepoint

Tracepoints are predefined hook points in the Linux kernel, and eBPF programs can be attached to these tracepoints to execute custom logic whenever the kernel reaches those points.

For example, the `sys_enter_execve` tracepoint captures the entry of the execve system call, providing information about the program being executed and its arguments, making it a valuable in things like auditing security events, or analyzing Linux user activity.

You can find all events that eBPF tracepoints can hook onto, using:

```bash
sudo cat /sys/kernel/debug/tracing/available_events
```
TODO: add output

The output format is in the form `<category>:<name>`.

You can view the input arguments for a tracepoint by checking the contents of `/sys/kernel/debug/tracing/events/<category>/<name>/format`.

```bash
sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format
```
TODO: add output

::remark-box
---
kind: info
---

💡 The first four arguments, are not accessible by the eBPF code. This is a choice that dates back to the original inclusion of this code. See explaination in [commit 98b5c2c65c29](https://github.com/torvalds/linux/commit/98b5c2c65c2951772a8fc661f50d675e450e8bce).
::

But other fields can generally be accessed using our eBPF program like showcased at the bottom in the print fmt line.

Using that we can write our eBPF Tracepoint program.

TODO: add code

💡 SEC("tp/xx/yy") and SEC("tracepoint/xx/yy") are equivalent, and you can use either one according to personal preference.

But there are two downsides to this:

Tracepoints only exists in places where kernel devs have put them. If you need to trace something that isn't supported you need another technique.

Additionally, you need to make sure the tracepoint you are attaching to is available under your kernel version.

TODO: not talking about portability (just slightly mention that we will)

## eBPF Raw Tracepoint

Raw Tracepoint may seem not much different than the regular Tracepoint. They are both able to attach to events listed in the `/sys/kernel/debug/tracing/available_events` file.

But the main difference is that raw tracepoint does not pass the input context to the eBPF program as tracepoints do — a.k.a. constructing the appropriate parameter fields. The Raw tracepoint eBPF program accesses the raw arguments of the event using struct `bpf_raw_tracepoint_args`.

Therefore, raw tracepoint usually [performs a little better than tracepoint](https://lwn.net/Articles/750569/).

Another (rather large) difference is that, in the kernel, there’s actually no static defined tracepoints on single syscalls but only on generic `sys_enter`/`sys_exit`.

::remark-box
---
kind: info
---

💡 `sys_enter` hooks trigger on every syscall event entry, while `sys_exit` hooks trigger on its return, capturing the return value of the syscall.
::

Therefore, if we want to act on specific syscall kernel event, we need to “filter” by syscall ID inside our Raw Tracepoint eBPF program.

TODO: highlight it in the code

This is different than regular tracepoints that rely on perf events which allows them to directly attach to a specific kernel event like tp/syscalls/sys_enter_execve as showcased above.

::remark-box
---
kind: info
---

💡 Perf events are a kernel feature for monitoring and profiling Linux systems, capturing hardware events (e.g., cache misses), software events (e.g., context switches), and kernel tracepoints.
::

Notice also that we are reading the arguments of the syscall by extracting them from the CPU registers. The [System V ABI](https://gitlab.com/x86-psABIs/x86-64-ABI/-/jobs/artifacts/master/raw/x86-64-ABI/abi.pdf?job=build) specifies which arguments should be present in which CPU registers.

Since we rely on CPU registers, we need to target our binary for specific system architectures. One way to achieve this is to provide a —-target flag if you are using clang.

::remark-box
---
kind: info
---

💡 For the example above, I intentionally read the register value using &regs→di, while the rest of the examples will utilize PT_REGS_PARM* macros which should be preffered.
::

## eBPF Kernel Probes (kprobes)

Regular and raw eBPF tracepoints might in fact be sufficient for your use case, but their main limitation is that they are limited to a set of predefined hook points (and perf events) in the kernel, disallowing you to trace arbitrary kernel events.

Kprobes alleviate this by allowing dynamic hooks into any kernel function, including within function body, not just at the start or return.

::remark-box
---
kind: info
---

💡 Some functions marked with the notrace keyword are exceptions, and kprobes cannot hook onto them.
::

Conveniently, you can list all kernel symbols in `/proc/kallsyms`:
```bash
sudo cat /proc/kallsyms
```
```
TODO: output
```

::remark-box
---
kind: info
---

💡 If a function is not in /proc/kallsyms, it's likely because is was inlined at compile time. Also verify they are not blacklisted in /sys/kernel/debug/krpobes/blacklist.
::

TODO: hihglight code

But the issue with kprobes is that you depend on whatever code happens to be in the kernel your system runs and are not assured to be stable across different kernel versions. Functions might exist in certain kernel versions, while not in others, structs can change, rename, or remove a field you are using.

TODO: We'll look at how to avoid such situations in portable eBPF programs tutorial

The same issues apply to kretprobes — kernel probes one can attach to the exit of the function.

Additionally, when we attach a kprobe, it’s similar to inserting a breakpoint in a debugger: the [kernel patches the target instruction with one that triggers a debug exception](https://elixir.bootlin.com/linux/v6.15.6/source/kernel/kprobes.c#L1152) (e.g., BRK on ARM64). When this instruction executes, the exception handler calls our probe handler.

And while this mechanism works well, it has a downside.

Each probe hit generates an exception, causing context switches and exception handling. That overhead may be negligible for infrequent probes, but if many probes are attached to “hot” kernel functions, performance can degrade significantly.

Is there some alternative to allow triggering eBPF programs with less overhead?

Yes — read along.

## Fprobes (fentry/fexit)

Unlike kprobes, fprobes can only attach to only kernel function entry points using fentry or exit points using fexit, as their attaching mechanism ([eBPF trampoline](https://lwn.net/Articles/804937/)) differs from that of kprobes.

As mentioned above, Kprobes patch an instruction to trigger a debug exception, adding context-switch and exception-handling overhead.

But, fprobes use the ftrace mechanism where the compiler inserts a NOP at each function entry, which can be patched at runtime into a trampoline.

The trampoline sets up arguments, calls the eBPF program directly, then returns to the function. By avoiding exceptions and using direct calls, fprobes attach/detach faster and run with much lower overhead.

Fprobes programs can also be attached to BPF programs such as XDP, TC or cGroup programs which makes debugging eBPF programs easier. Kprobes lack this capability.

Another advantage is that fexit hook has access to the input parameters to the function, which kretprobe does not.

They do however require at least kernel version 5.5 which might be an issue if you need to support older kernels, at least for now. But otherwise they are mostly superior to kprobes.

::remark-box
---
kind: info
---

💡 Kernel version 5.7 introduces another fprobe program type, named Fmodify_return which run after the fentry program but before the function we are tracing. They allow to override the return value of the kernel function.
::