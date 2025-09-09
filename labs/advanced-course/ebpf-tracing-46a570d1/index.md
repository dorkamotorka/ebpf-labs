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