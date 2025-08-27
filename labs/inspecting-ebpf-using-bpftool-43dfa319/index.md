---
kind: tutorial

title: Inspecting and Monitoring eBPF Applications

description: |
  This tutorial builds on "From Zero to Your First eBPF Program" and "Storing Data in eBPF: Your First eBPF Map" by introducing bpftool and bpftop. You’ll learn how to inspect eBPF programs and maps loaded into the kernel with bpftool, gaining deeper visibility into how your eBPF application runs. We’ll also explore bpftop, a top-like interface that lets you monitor eBPF program activity in real time.

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
- ebpf

createdAt: 2025-08-27
updatedAt: 2025-08-27

cover: __static__/ebpf-tools.png

---

When you start the tutorial, you’ll see a `Term 1` terminal and an `IDE` on the right-hand side. You are logged in as `laborant`, and the current working directory already contains the `ebpf-hello-world` folder. Inside, you’ll find the [eBPF Hello World labs](https://github.com/dorkamotorka/ebpf-hello-world), implemented with [ebpf-go](https://ebpf-go.dev/) — a Golang eBPF framework developed as part of the [Cilium](https://cilium.io/) project.

This tutorial serves as the continuation of [From Zero to Your First eBPF Program](https://labs.iximiuz.com/tutorials/my-first-ebpf-program-5120140e) and [Storing Data in eBPF: Your First eBPF Map](https://labs.iximiuz.com/tutorials/ebpf-maps-tutorial-3efd4617), expanding on the introduced concepts.

In this part, we’ll dive into [bpftool](https://github.com/libbpf/bpftool) and [bpftop](https://github.com/Netflix/bpftop). With `bpftool`, you’ll learn how to inspect eBPF programs and maps loaded into the kernel, gaining deeper visibility into how your application runs. We’ll then look at `bpftop`, a top-like interface that makes it easy to monitor eBPF program activity in real time.

::image-box
---
:src: __static__/ebpf-tools.png
:alt: 'Inspecting and Monitoring eBPF Applications'
---
::

TODO: pre-load and run the eBPF program and mention it above that this is already done (if not easy - just do it)

## Inspecting eBPF Applications

Inspecting eBPF applications is essential for debugging and validation, since it lets you confirm that your programs and maps are correctly loaded into the kernel. It also gives you visibility into the internal state of maps, so you can track how data changes over time - like our `exec_count` eBPF map in our previous tutorial.

The most widely used tool for this purpose is [bpftool](https://github.com/libbpf/bpftool). 

Since this in a eBPF playground, this tool is already installed.

```bash
sudo bpftool --help
```

::details-box
---
:summary: Why do you need to run it using `sudo`?
---

`bpftool` needs to be run using `sudo` because most of its operations interact directly with the kernel. Loading, attaching, or inspecting eBPF programs and maps requires privileged access to kernel resources (like bpf() syscalls, /sys/fs/bpf/, and network interfaces).

And as mentioned in [the first tutorial](https://labs.iximiuz.com/tutorials/my-first-ebpf-program-5120140e), these actions are restricted to processes with `CAP_BPF`, `CAP_SYS_ADMIN`, or other specific capabilities—privileges that are normally only available to root (or a process started with `sudo`).

::

Here are some common use cases of bpftool:

- **Listing BPF Programs and Maps**: View a list of loaded eBPF programs and maps on your system. It provides information such as program IDs, names, types, and associated maps.

```bash

sudo bpftool map list # For listing eBPF Maps loaded into the Kernel
# OR
sudo bpftool prog list # Fort listing eBPF Programs loaded and attached in the kernel (TODO: does it need to be attached?)
```

::details-box
---
:summary: What is the difference between loaded and attached eBPF program?
---

An eBPF program is **loaded** when it has been verified and accepted into the kernel, but it isn’t yet active. We'll talk about the verification process in an upcoming tutorial.

A program becomes active and **attached** when it is bound to a specific hook or event source (like `tracepoint/syscalls/sys_enter_execve` in our example), meaning the kernel will actually run it when that event occurs.

::

- **Inspecting eBPF Objects**: Provides detailed information about eBPF programs, maps, and other BPF objects. It allows you to retrieve attributes (like which user loaded the eBPF program), statistics (like how many times the program has been triggered - TODO: check this), and configuration parameters of these objects.

TODO: command and show the parameters mentioned above

- **Managing eBPF Maps**: Provides functionality to create, update, and delete eBPF maps. You can specify the map type, key size, value size, and other relevant parameters while creating or modifying a map.

TODO: update entry and list the map + delete entry and list the map

- **Debugging and Tracing**: Offers features for debugging and tracing eBPF programs. It enables you to attach to programs and monitor their execution, including printing debug output and tracing events.

TODO: mention logging

TODO: add how to check available eBPF program helper function + notification that this is not always the best way

- **Loading and Unloading eBPF Programs**: Although you will rarely use it like this, bpftool also allows you to load eBPF programs into the kernel. You can specify the program type, source code file, and associated maps. It also provides options to unload and detach programs from the kernel.

TODO: command for loading our execve program

TODO: maybe add some other?


## Monitoring eBPF Applications

TODO: bpftop

Congrats, you've came to the end of this tutorial. 🥳