---
kind: tutorial

title: All The Ways To Receive Kernel Events in User Space

description: |
  TODO

playground:
  name: ebpf-playground-2bd77c1c

tasks:
  clone_hello_world:
    init: true
    user: laborant
    run: |
      git clone https://github.com/dorkamotorka/ebpf-labs-misc.git /home/laborant/ebpf-labs-misc

categories:
- linux
- programming

tagz:
- eBPF

createdAt: 2025-09-16
updatedAt: 2025-09-16

cover: __static__/cover.png

---

eBPF applications—no matter what shape they take—almost always interact with user space in some way.

This interaction can take many forms—for example, kernel-level data can enrich user-space signals for better observability, or kernel programs can trigger events such as a firewall rule being hit or a binary execution being blocked, which then need to be logged, processed, and presented in user space.

Regardless of the use case, all such eBPF applications share a common mechanism: a buffer that allows kernel space programs to send kernel events data to user space program(s).

There are two primary mechanisms for this:
- **Perf buffer** which allows kernel programs to push kernel events into a per-CPU buffer that user space can poll and read.
- **Ring buffer** which allows kernel programs to push kernel events into a single circular buffer that is shared among all the CPUs.

The Ring Buffer is the successor to the perf buffer that supports reserve/submit API, preserves event ordering and better signalling of data availability when a sample is submitted. 

Yet many large projects—such as Tetragon and Tracee—still rely on perf buffer. **Why is that the case?**

In this tutorial, you'll learn about these communication mechanisms, explore their trade-offs, and how real-world eBPF projects handle high-throughput event delivery without losing critical kernel data.

## eBPF Perf Buffer

The Perf Buffer is a mechanism in eBPF that consists of per-CPU circular buffers. 

Meaning, each CPU has its own buffer where kernel-space eBPF programs can write events data, and user-space applications can read it.

TODO: image - working principle (with circular buffers on the image!)

While widely used, this design introduces **two major drawbacks** that often unnecessarily complicate real-world applications.

First, making it memory-efficient is tricky for applications with highly variable workloads (e.g., long idle periods interrupted by sudden floods of events). If you allocate:
- **large buffers** to avoid losing kernel events during spikes, you waste memory during idle times.
- **small buffers** to stay memory-efficient in steady state, you risk frequent data drops during bursts.

This mainly matters at large scale, but there’s another issue.

Whenever you want to push a kernel event you must:
- prepare a data sample (often in a local variable or eBPF map), and
- copy it into the Perf Buffer—hoping the buffer isn’t full. If it is, the copy is wasted, and all the processing work was for nothing.

```c [perf.c] {3,13}
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve_tp(struct trace_event_raw_sys_enter *ctx) {
    struct event e = {};

    u64 pid_tgid = bpf_get_current_pid_tgid();
    e.pid  = pid_tgid >> 32;
    e.tgid = (u32)pid_tgid;

    const char *filename_ptr = (const char *)BPF_CORE_READ(ctx, args[0]);
    bpf_core_read_user_str(e.filename, sizeof(e.filename), filename_ptr);

    // Emit to perf buffer (one record on the current CPU)
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}
```

::details-box
---
:summary: More information about `bpf_perf_event_output` helper
---

`bpf_perf_event_output` helper takes 4 arguments. In the example above, these are:
- **Program context (`ctx`)** – usually passed directly from the hook (e.g., `struct xdp_md *ctx`).  
- **Perf Event Array map** – a `BPF_MAP_TYPE_PERF_EVENT_ARRAY` that stores the events.  
- **Flags** – either `BPF_F_CURRENT_CPU` (write to the current CPU’s buffer) or `BPF_F_INDEX_MASK` (explicitly select another CPU buffer by index).  
- **Event data** – a pointer to your event structure (e.g., `&e`) and its size.  

::

Additionally, since each CPU has its own buffer, there's no guarantee events will be delivered in order that they occur, if they happen in rapid succession.

Just imagine a workload that needs to track correlated events like process lifecycle or connection lifetime. Order of events in such cases is super important and it's quite hard to be sure that would be the case if you use Perf Buffer, since short-lived processes can occur on different CPUs which can result in events arriving in the wrong order across buffers.

In practice, this forces developers to add complex event reordering logic in user space—even for problems that should otherwise be straightforward.

TODO: lost samples

## eBPF Ring Buffer

TODO: https://www.deep-kondah.com/deep-dive-into-ebpf-ring-buffers/

Starting with Linux 5.8, eBPF introduced the Ring Buffer, a multi-producer, single-consumer (MPSC) queue that is shared between all CPUs. 

TODO: image - working principle

This by design also preserves event ordering. Meaning, if event A is submitted before event B, it is guaranteed to be consumed first since it's a single global FIFO (first-in, first-out) queue. TODO: mention soft locking 

It also introduces a reservation/submit API, which instead of first preparing a sample and then copying it into the buffer (only to discover later that there is no space left), a program can reserve space in advance. 

TODO: code

TODO: as a side note mention that max_entries is used to specify the size of ring buffer and has to be a power of 2 value. Why?!

TODO: mention different flags or submitting

In other words, if the reservation succeeds, the data is written directly into the reserved memory and submitted with no extra copies. If the reservation fails, the program knows immediately and avoids wasting work on data that would have been dropped.

Not to mention, for nearly all practical use cases, the [Ring Buffer outperforms the Perf Buffer](https://patchwork.ozlabs.org/project/netdev/patch/20200529075424.3139988-5-andriin@fb.com/).

TODO: eBPF perfbuf, theoretically, can support higher throughput of data due to per-CPU buffers, but this becomes relevant only when we are talking about millions of events per second. But that not really a valid reason, since one can also use multiple eBPF Ring buffers.

TODO: What is the diff between commit and discard? The difference between commit and discard is very small. Discard just marks a record as discarded, and such records are supposed to be ignored by consumer code. Discard is useful for some advanced use-cases, such as ensuring all-or-nothing multi-record submission, or emulating temporary malloc()/free() within single BPF program invocation.


TODO: bpf_ringbuf_query() helper allows to query various properties of ring buffer.
Currently 4 are supported:
  - BPF_RB_AVAIL_DATA returns amount of unconsumed data in ring buffer;
  - BPF_RB_RING_SIZE returns the size of ring buffer;
  - BPF_RB_CONS_POS/BPF_RB_PROD_POS returns current logical possition of
    consumer/producer, respectively.
Returned values are momentarily snapshots of ring buffer state and could be
off by the time helper returns, so this should be used only for
debugging/reporting reasons or for implementing various heuristics, that take
into account highly-changeable nature of some of those characteristics.

But here's comes a (relatively) tricky question - why do then tools like Tracee and Tetragon use perf-buffer if it's that bad?

## How do solution like Tracee and Tetragon Implement it

- Kernel Compatibility
-------
TODO: spucaj
Perf Buffer provides per-CPU queues, which can be read independently by multiple user-space threads. This makes it easier to build parallel pipelines or distribute load across consumers.

In very high-throughput systems (e.g., security monitoring on hundreds of thousands of events/sec), having per-CPU streams can reduce contention on a single reader thread.
______