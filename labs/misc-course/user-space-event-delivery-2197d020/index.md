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

This interaction can happen in different forms:

- **Observability enrichment**: kernel-level data augments user-space data, providing richer and more granular signals to end users.
- **Action reporting**: kernel programs trigger events (e.g., security decisions, network blocks) that need to be logged, processed, and eventually presented in a user-space application, often through a UI.

Regardless of the use case, all eBPF applications share a common mechanism: a buffer that connects kernel space and user space, enabling communication between them.

There are two primary mechanisms for this: (TODO improve this)
- **Perf buffer** (introduced in Linux 2.6.31, 2009): Allows kernel programs to push events into a per-CPU buffer that user space can poll and read.
- **Ring buffer** (introduced in Linux 5.8, 2020): a newer, simpler mechanism that uses a lock-free circular buffer to pass variable-sized data between kernel and user space with lower overhead and fewer moving parts.

The ring buffer is the successor to the perf buffer (TODO: explain improvements here), yet many large projects—such as Tetragon and Tracee—still rely on perf buffer. Why is that?

Additionally, both mechanisms are designed for a multiple-producer, single-consumer (MPSC) model (TODO: confirm this). However, large-scale projects often need additional strategies to prevent buffer overflows and event loss when the kernel generates a burst of events that exceed the allocated buffer size.

In this tutorial, you'll learn about these communication mechanisms, explore their trade-offs, and how real-world eBPF projects handle high-throughput event delivery without losing critical kernel data.

## Perf Buffer

TODO: image - working principle

## Ring Buffer

TODO: image - working principle

## How do solution like Tracee and Tetragon Use it