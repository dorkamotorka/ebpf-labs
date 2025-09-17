---
kind: tutorial

title: All The Ways To Loop and Iterate in eBPF

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

createdAt: 2025-09-17
updatedAt: 2025-09-17

cover: __static__/cover.png

---

Loops are a common concept in almost every programming language, but in eBPF they can be a bit more complicated. 

Not to mention, there are 5+ different ways to loop — so which one should you use and how?

The primary motivation behind supporting loops in programming is simple — reduce the complexity of the programs, where you need to perform a certain operation on multiple objects.

In eBPF, there are countless needs to support them, such as:

- Loop through directory entries in getdents64 system call
- Iterating over network packet header options or processing nested headers
- Iterate over a large number of virtual memory areas (VMAs)
- Iterating over processes inside a cgroups

TODO: image

In the following sections, we’ll address each one separately. 

TODO: for each section add code

## Loop Unrolling

Before v5.3, eBPF programs could not loop, because they required a backward jump to earlier instructions in the code, which could potentially lead to infinite loops or other issues that the BPF verifier was not designed to handle at the time.

For a very long time, the workaround was to unroll loops using #pragma unroll compiler directive, which converted them into a series of line instructions executed in series.

This saved the programmer typing in the same lines many times.

**So what’s the issue with this approach?**

Besides not being a “native” looping mechanism, converting loops into a series of line instructions can significantly increase the size of the eBPF program. In other words, as the number of loop iterations increases, the size of the resulting program binary will grow. This may or may not be an issue, depending on the complexity of the operations performed inside the loop.

Another concern is that while the loops are unrolled, the program is constrained by the eBPF instruction set limit, which we’ll discuss in the next section.

## Bounded Loops

From v5.3 onward, the verifier was able to follow branches backward as well as forward as part of its process of checking all the possible execution paths.1

This enabled support for loops, referred to as the "bounded loops".

Basically the same as before, just without the unroll directive.

**So what’s the issue with this approach?**

The main issue with this approach is that, in addition to handling loops, the eBPF verifier also needs to ensure that the program stays below the instruction limit. In other words, there is a limit on the number of instructions an eBPF program can execute to ensure it finishes in a reasonable time.

::remark-box
---
kind: info
---

💡 Until kernel version 5.4, the instruction limit was 4096. This limit was then increased to 1M in later versions.
::

You can easily reach this limit with the simple example above by increasing the number of loops (NUM_LOOPS) to 1M, which will then produce the following error:

```
BPF program is too large. Processed 1000001 insn
```

And loops with more complex operations need even fewer iterations to exceed that limit.

::details-box
---
:summary: But why is there even an instruction limit?
---
The eBPF program must release the CPU within a reasonable timeframe to allow the system to perform other tasks. If an eBPF program fails to do so, it can significantly impact the system's performance, leading to issues such as disrupted networking and causing applications to lock up or run slowly.

**Okay, but what is considered an instruction?**

In eBPF, one instruction can be thought of as rough equivalent of a single operation or machine instruction. This can include:

Loading or storing data (e.g., loading a value into a register).

Arithmetic operations (e.g., counter++).

Comparisons (e.g., i < NUM_LOOPS in the loop condition).
::

## Loop Helper

Sometimes, you really need to iterate over a large range, which can be more complex than the 1M instruction limit imposed on bounded loops. To address this, kernel v5.17 introduced the [bpf_loop](https://docs.ebpf.io/linux/helper-function/bpf_loop/) helper function.

This helper allows for up to ~8 million iterations and is not constrained by the eBPF instruction limit because the loop occurs within the helper function, with the kernel managing it. The verifier only needs to check the instructions of the callback function triggered once, as the helper function also ensures that the loop will always terminate without requiring the verifier to check each iteration.

The helper function requires the following inputs:
- First argument: The maximum number of iterations (limited to ~8 million).
- Second argument: The callback function called for each iteration.
- Third argument [optional]: A context variable that allows passing data from the main program to the callback function.
- Fourth argument [optional]: A "flags" parameter, which is currently unused but included for potential future use cases.

## (Numeric) Open Coded Iterators

For similar reasons as to why the bpf_loop helper function was introduced, in v6.4, open-coded iterators were added.

Their primary intention is to provide a framework for implementing all kinds of iterators (e.g., cgroups, tasks, files), but as far as I know, it currently only implements the numeric iterator. The numeric iterator allows us to iterate over a range of numbers, enabling us to create a for loop. It’s slightly hack-ish, but still viable.

The advantage of this method is that the verifier is not required to check every iteration, as with a bounded loop, and it doesn't require a callback function like with the bpf_loop helper.

Every iterator type has:
- bpf_iter_<type>_new function to initialize the iterator
- bpf_iter_<type>_next function to get the next element, and
- bpf_iter_<type>_destroy function to clean up the iterator

For example, in the case of the numeric iterator, the bpf_iter_num_new, bpf_iter_num_next and bpf_iter_num_destroy functions are used.

TODO: code

Based on these iterators, libbpf provides bpf_for helper function for a more natural feeling way to write the above:

TODO: code

And also a bpf_repeat helper:

TODO: code

⭐️ BONUS TIP: Map Iteration Helper
Since v5.13 it is also possible to use the bpf_for_each_map_elem helper to iterate over maps so you don't have to use loops for that.