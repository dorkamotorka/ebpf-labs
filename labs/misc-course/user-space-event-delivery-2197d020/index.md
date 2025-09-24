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

For eBPF applications to be useful, kernel events must often be delivered to user space for processing.

These events may enrich user-space signals for observability, or represent security actions—such as a firewall rule being hit or a binary execution being blocked—that must be logged, processed, and presented in user space.

Regardless of the use case, this transfer relies on a common mechanism, a buffer that moves event data from kernel space to user space.

There are two primary mechanisms for this:
- **Perf buffer** (introduced in v4.3), allows kernel programs to push kernel events into a per-CPU buffer that user space can poll and read.
- **Ring buffer** (introduced in v5.8), allows kernel programs to push kernel events into a single circular buffer that is shared among all the CPUs.

The ring buffer is the successor to the perf buffer that supports reserve/submit API, preserves event ordering and better signalling of data availability when a sample is submitted. 

Yet many large projects—such as Tetragon and Tracee—still rely on perf buffer. 

**Why is that the case?**

In this tutorial, you'll learn about these data-exchange mechanisms, explore their trade-offs, and how real-world eBPF projects handle high-throughput event delivery without losing critical kernel data.

## eBPF Perf Buffer vs Ring Buffer

The perf buffer is a mechanism in eBPF that consists of per-CPU circular buffers, whereas the ring buffer is a circular buffer shared among all the CPUs. 

TODO: image - working principle (with circular buffers on the image!)

::remark-box
---
kind: info
---

💡 You can actually create multiple ring buffers, which may be useful for large volumes of events.
::

Compared to ring buffer, design of the perf buffer introduces **three major drawbacks** that often unnecessarily complicate real-world applications and hinder it's performance.

#### Unnecessary Processing and Load

Whenever you want to push a kernel event to a perf buffer you must first prepare a data sample (often in a local variable or eBPF map), and then copy it into the Perf Buffer.

This is all fine, unless the buffer is not full, but if it is, the copy is wasted, and all the processing work was for nothing.

```c [simple-perf-buffer/perf.c] {3,11-12}
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
- **Program context (`ctx`)** – passed directly from the hook (e.g., `struct trace_event_raw_sys_enter *ctx`).  
- **Perf Event Array map** – a `BPF_MAP_TYPE_PERF_EVENT_ARRAY` that stores the events.  
- **Flags** – either `BPF_F_CURRENT_CPU` (write to the current CPU’s buffer) or `BPF_F_INDEX_MASK` (explicitly select another CPU buffer by index).  
- **Event data** – a pointer to your event structure (e.g., `&e`) and its size.  
::

To address this, ring buffer introduces a **reserve/submit API**, which instead of first preparing a sample and then copying it into the buffer (only to discover later that there is no space left), a program can reserve space in advance. 

```c [simple-ring-buffer/ring.c] {3-8,16-17}
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve_tp(struct trace_event_raw_sys_enter *ctx) {
    // Reserve space on the ring buffer
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        // If the buffer is full, just drop the event
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid  = pid_tgid >> 32;
    e->tgid = (u32)pid_tgid;
    const char *filename_ptr = (const char *)BPF_CORE_READ(ctx, args[0]);
    bpf_core_read_user_str(e->filename, sizeof(e->filename), filename_ptr);

    // Submit to ring buffer
    bpf_ringbuf_submit(e, 0);
    return 0;
}
```
::details-box
---
:summary: More information about `bpf_ringbuf_submit` helper
---

`bpf_ringbuf_submit` helper takes 2 arguments. In the example above, these are:  
- **Data pointer** – a pointer returned by `bpf_ringbuf_reserve` that references the reserved space in the ring buffer.  
- **Flags** – declares how the notification of new data availability should be handled. Will be discussed below.  

Once called, the reserved data is committed to the ring buffer and becomes available to user space.  
::

::details-box
---
:summary: What if space is reserved but the program flow does NOT lead to bpf_ringbuf_submit?
---

Sometimes your eBPF program reserves space in the ring buffer, but later determines that no event needs to be sent to user space (e.g., filtering syscalls only for specific PID). In that case, the `bpf_ringbuf_discard` helper releases the reserved space without submitting an event.

```c {12-17}
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve_tp(struct trace_event_raw_sys_enter *ctx) {
    // Reserve space on the ring buffer
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        // If the buffer is full, just drop the event
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid  = pid_tgid >> 32;
    // Example condition: only report execve calls from PID 1234
    if (e->pid != 1234) {
        // Free reserved space without sending an event
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
...
```
::

#### Event Ordering

Consider a workload that tracks correlated events, such as process lifecycles (fork → exec → exit) or network connection lifetimes. In such cases, ordering is critical.

With a perf buffer, where each CPU has its own buffer, there’s no guarantee that events will reach user space in the same order they occurred if they happen in rapid succession, since each buffer fills and drains at different rates.

::details-box
---
:summary: How to circumvent this problem?
---

In practice, one way to correctly re-order events in the user-space is by adding a timestamp to the kernel event structure send to the user space. Based on this timestamp the events can be ordered in user space.
```c [simple-perf-buffer/perf.c] {8}
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve_tp(struct trace_event_raw_sys_enter *ctx) {
    struct event e = {};

    u64 pid_tgid = bpf_get_current_pid_tgid();
    e.pid  = pid_tgid >> 32;
    e.tgid = (u32)pid_tgid;
    e.ts   = bpf_ktime_get_ns();
    const char *filename_ptr = (const char *)BPF_CORE_READ(ctx, args[0]);
    bpf_core_read_user_str(e.filename, sizeof(e.filename), filename_ptr);

    // Emit to perf buffer (one record on the current CPU)
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}
```
::

By contrast, with a single global ring buffer shared across all CPUs, all events go into the same FIFO queue and are delivered sequentially to user space, preserving order without extra complexity.

#### Data Availability Signalling

Often the biggest overhead when forward to kernel events to user space comes from in-kernel signalling of data availability when a sample is submitted to the buffer. This signal then lets kernel’s poll/epoll system know to wake up user-space handlers blocked on waiting for the new data.

And if events come in at a very high rate, this results in lots of wakeups and context switches, which can dominate CPU usage.

This is true for both perfbuf and ringbuf.

Perfbuf handles that with the ability to set up sampled notification, in which case only every Nth sample will send a notification. 

```go [advanced-perf-buffer/main.go] {5-8}
reader, err := perf.NewReaderWithOptions(
  objs.Events, 
  os.Getpagesize(), 
  perf.ReaderOptions{
    // The number of events required in any per CPU buffer before
    // Read will process data. The default is zero - a.k.a immediate reads.
    WakeupEvents: 3,
  }
)
```

::remark-box
---
kind: info
---

💡 And you need to make sure that it works for you that you won’t see the last N-1 samples, until the Nth sample arrives. This might or might not be a big deal for your particular case.

One other configurable option of perf buffer is also to be able to overwrite old samples, once full instead of dropping them.
::

ringbuf went a different route with this. `bpf_ringbuf_output()` and `bpf_ringbuf_submit()` accept an extra flags argument and you can specify either:
- `0`: Default value, which performs adaptive notification depending on whether the user-space consumer is lagging behind or not
- `BPF_RB_NO_WAKEUP`: Don't wake up user space handler and avoid the interrupt
- `BPF_RB_FORCE_WAKEUP`: Force sending a wake up notification

 which will send notifications only when a configurable amount of data is enqueued in the ring buffer.

In practice, no flag is a good and safe default, but if you need to get an extra performance, manually controlling data notifications depending on your custom criteria (e.g., amount of enqueued data in the buffer) might give you a big boost in performance.

```c [simple-ring-buffer/ring.c] {2-13,19-21}
// Hardcoded, but could also be adjustable from user space
const long wakeup_data_size = 2048;

static __always_inline long get_flags() {
  long sz;

  if (!wakeup_data_size) {
    return 0;
  }

  sz = bpf_ringbuf_query(&events, BPF_RB_AVAIL_DATA);
  return sz >= wakeup_data_size ? BPF_RB_FORCE_WAKEUP : BPF_RB_NO_WAKEUP;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve_tp(struct trace_event_raw_sys_enter *ctx) {
  //...

  // Submit to ring buffer but notify only if more full then wakeup_data_size
  long flags = get_flags();
  bpf_ringbuf_submit(e, flags);
  return 0;
}
```

Taking all of this into account, eBPF perf buffer with their per-CPU buffer desing could theoretically support higher throughput in some very specific setups (e.g. well-tuned per-CPU consumers, minimal overhead), but that usually requires a lot of fine-tuning.

But for nearly all practical use cases, the [Ring Buffer outperforms the Perf Buffer](https://patchwork.ozlabs.org/project/netdev/patch/20200529075424.3139988-5-andriin@fb.com/).

But here's comes a (relatively) tricky question - why do then tools like Tracee and Tetragon use perf-buffer if it's that inefficient and "complex"?

## Implementations in the Wild

With tools like [Tracee](https://www.aquasec.com/products/tracee/) and [Tetragon](https://tetragon.io/), which are widely adopted across diverse environments, it’s not enough to consider only the technical constraints — kernel version support is just as critical.

For example, kernel 5.8 is still relatively “new” in many production setups. To remain compatible with older kernels, these tools continue to rely on perf buffers. From a client’s perspective, this compatibility is far more valuable than requiring them to upgrade and restart tens of thousands of machines — an operation that could cause significant downtime.

Regardless of which buffering mechanism is used, the biggest risk is buffer overflow. This ultimately comes down to how efficiently user space consumption is implemented.

Ideally, events should be consumed from the buffer as frequently as possible for real-time observability, while taking into an account the cost of constant data availability notifications and context switches. The processing of those events can then be offloaded to worker threads or subprocesses, ensuring that consumption itself remains fast and non-blocking.

```go [advanced-perf-buffer/main.go] {1-2,10,21,32-47}
// Instantiate Queue for forwarding messages
recordsQueue := make(chan *perf.Record, 8192)

// Reader loop in a goroutine so we can cancel via context.
var wg sync.WaitGroup
wg.Add(1)
go func() {
  defer wg.Done()
  for {
    rec, err := reader.Read()
    if err != nil {
      // When Close() is called, Read() returns an error; exit cleanly.
      if errors.Is(err, perf.ErrClosed) {
        return	
      }
      log.Fatalf("Failed to read perf event: %v", err)
      return
    } else {
      if len(rec.RawSample) > 0 {
        select {
          case recordsQueue <- &rec:
          default:
            log.Printf("recordsQueue channel is full, drop the event")
        }
      }
    }
  }
}()

// Start processing records from records queue.
wg.Add(1)
go func() {
  defer wg.Done()
  for {
    select {
    case record := <-recordsQueue:
      // Here we could further pass the data to other goroutines
      var ev event
      if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &ev); err != nil {
        fmt.Printf("failed to decode record: %v\n", err)
        continue
      }

      fmt.Printf("execve pid=%d tgid=%d file=%q\n", ev.PID, ev.TGID, cString(ev.Filename[:]))
      // ...
  }
}()
```

While this does significatly improve and configure your application to handle higher volumes of kernel events, it's still quite tricky and quite some testing needs to be performed to tune your application for highly variable workloads (e.g., long idle periods interrupted by sudden floods of events like a DoS attack or burst of API calls). If you allocate:
- **large buffers** to avoid losing kernel events during spikes, you waste memory during idle times.
- **small buffers** to stay memory-efficient in steady state, you risk frequent data drops during bursts.


::remark-box
---
kind: warning
---
**⭐️ Extra Insight ⭐️**

What if I told you neither ring buffer, nor perf buffer is they right way to go for a really high volumes of kernel events?

Taking inspirations from the creations of the [Jibril (runtime monitoring and threat detection engine based on eBPF)](https://jibril.garnet.ai/), they approach the problem of high volume data and real-time threat detection a bit differently.

While it's hard to go into the details, as their code is not open-source, but from the discussions that we had - the problem with both perf buffer and ring buffer that prevents modern tools to perform real-time detection is the limitation of the FIFO queue concept that both utilize.

In environments generating hundreds of thousands of events per second (e.g. 600k+), both perf buffers and ring buffers can hit their capacity limits. Every event still needs to pass through a FIFO queue and be processed in user space, which inevitably adds latency and makes true real-time detections harder.

Jibril takes a different approach. 

Instead of streaming all kernel events into user space, it caches event data directly in eBPF maps inside the kernel. User space then queries this cached state on demand. 

This design alleviates pressure on buffers, avoids constant data copying, and enables detections closer to real time — since checks can be done against kernel-resident state rather than waiting for events to flow through a queue.

They've nicely documented this approach [here](https://jibril.garnet.ai/information/theory-behind/new-era).
::


TODO: as a side note mention that max_entries is used to specify the size of ring buffer and has to be a power of 2 value. Why?!

TODO: perf buffer vs Perf Buffer (capital letters)

TODO: add content from the book

TODO: https://www.deep-kondah.com/deep-dive-into-ebpf-ring-buffers/