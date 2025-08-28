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

In this part, we’ll learn how and why to use [bpftool](https://github.com/libbpf/bpftool) to inspect eBPF programs and maps in the kernel, and [bpftop](https://github.com/Netflix/bpftop), a top-like interface for monitoring eBPF program activity in real time.

::image-box
---
:src: __static__/ebpf-tools.png
:alt: 'Inspecting and Monitoring eBPF Applications'
---
::

Before we can inspect and monitor anything, we first need some eBPF application running. The code for this lab is in `ebpf-hello-world/lab3`. Open the `Term 1` terminal, navigate to this directory, then build and run the eBPF application as you did in the previous tutorials.

::details-box
---
:summary: Forgot how to do it?
---

Using `go generate` you compile the eBPF kernel program (`hello.c`) into an object file (`hello_bpf.o`) and generates a Go source file (`hello_bpf.go`) that embeds the object and provides helper functions to work with it.
```bash
go generate
```

Then `go build` picks up the `main.go` and `hello_bpf.go` and builds the final eBPF application binary `lab3`
```bash
go build
```

Finally, run the eBPF Application using:
```bash
sudo ./lab3
```
::

## Inspecting eBPF Applications

Inspecting eBPF applications comes useful for debugging and validation, since it lets you confirm that your programs and maps are correctly loaded into the kernel. It also gives you visibility into the internal state of maps, so you can track how data changes over time - like our `exec_count` eBPF map in our previous tutorial.

The most widely used tool for this purpose is [bpftool](https://github.com/libbpf/bpftool), maintained within the upstream Linux kernel.

Since this in a eBPF playground, this tool is already installed. Open the **Term 2** tab on the right (click the `+` at the top), and run:

```bash
sudo bpftool --help
```

::details-box
---
:summary: Why do you need to run it using `sudo`?
---

Most `bpftool` operations interact directly with the kernel. Loading, attaching, or inspecting eBPF programs and maps requires privileged access to kernel resources.

And as noted in [the first tutorial](https://labs.iximiuz.com/tutorials/my-first-ebpf-program-5120140e), these actions are restricted to processes with `CAP_BPF`, `CAP_SYS_ADMIN`, or other specific capabilities—privileges that are normally only available to root (or a process started with `sudo`).

::

Here are some common use cases of `bpftool`.

#### Listing BPF Programs and Maps

View a list of loaded eBPF programs and maps on your system. It provides information such as program IDs, names, types, and associated maps.

```bash
sudo bpftool map list # Shows all eBPF Maps loaded into the kernel
# AND
sudo bpftool prog list # Shows all eBPF programs currently loaded into the kernel, regardless of whether they are attached to a hook or not.
```

::details-box
---
:summary: What is the difference between loaded and attached eBPF program?
---

An eBPF program is **loaded** when it has been verified and accepted into the kernel, but it isn’t yet active. We'll talk about the verification process in an upcoming tutorial.

A program becomes active and **attached** when it is bound to a specific hook or event source (like `tracepoint/syscalls/sys_enter_execve` in our example), meaning the kernel will actually run it when that event occurs.

::

#### Inspecting eBPF Programs

View detailed information about eBPF programs. It allows you to retrieve attributes like which user loaded the eBPF program and when has it been loaded.

```bash
sudo bpftool prog list # Get the program ID
```
```
...
15: tracepoint  name handle_execve_tp  tag 8236b54ceef5a3ce  gpl
        loaded_at 2025-08-28T07:36:11+0000  uid 0
        xlated 560B  jited 375B  memlock 4096B  map_ids 5,7
        btf_id 6
```

The program in the example output has been assigned the ID 15. This "identity" is a number assigned to each program as it’s loaded. 

Knowing the ID, you can ask `bpftool` to show more information about this program.

```bash
sudo bpftool prog show id 15 --pretty
```
```
{
    "id": 15, 
    "type": "tracepoint", 
    "name": "handle_execve_tp",
    "tag": "8236b54ceef5a3ce", 
    "gpl_compatible": true,
    "loaded_at": 1756366571,
    "uid": 0,
    "orphaned": false, 
    "bytes_xlated": 560,
    "jited": true,
    "bytes_jited": 375, 
    "bytes_memlock": 4096,
    "map_ids": [5,7
    ],
    "btf_id": 6
}
```

::details-box
---
:summary: What are all these output variables?
---

- **id**: ID of the eBPF Program.
- **type**: Type of the eBPF program.
- **name**: Name of the eBPF program, which is the function name from the source code.
- **tag**: SHA (Secure Hashing Algorithm) sum of the program’s instructions, which can be used as another identifier for the program. The program ID can vary every time you load or unload the program, but the tag will remain the same.
- **gpl_compatible**: The program is defined with a GPL-compatible license. Check kernel program for the line `char _license[] SEC("license") = "GPL";`.
- **loaded_at**: Unix timestamp showing when the program was loaded.
- **uid**: User that loaded the eBPF program. In this case, it is User ID 0 (which is root).
- **orphaned**: Whether the program is loaded in the kernel but no longer has any active attachment to a hook.
- **bytes_xlated**: There are 560 bytes of translated eBPF bytecode in this program. This is the eBPF bytecode after it has passed through the verifier (and possibly been modified by the kernel for reasons we’ll discuss later). This is pretty low level, but it’s not quite machine code yet.
- **jited**: Whether this program is JIT-compiled. eBPF uses a JIT compiler to convert translated eBPF bytecode to machine code that runs natively on the target CPU.
- **bytes_jited**: The JIT compilation resulted in 375 bytes of machine code.
- **bytes_memlock**: This program reserves 4,096 bytes of memory that won’t be paged out.
- **map_ids**: To which eBPF Maps this program refers to.
- **btf_id**: Indicates there is a block of BTF information for this program. We'll learn about BTF later.

::

#### Managing eBPF Maps 

Lookup, create, update, and delete eBPF map entries. You can specify the map type, key size, value size, and other relevant parameters while creating or modifying a map.

```bash
sudo bpftool map list # Get the map ID
```
```
...
5: hash  name exec_count  flags 0x0
        key 256B  value 8B  max_entries 16384  memlock 5378048B
        btf_id 4
...
```

Knowing the ID, you can ask `bpftool` to dump maps content, using:

```bash
sudo bpftool map dump id 5
```

Or lookup a specific map entry:

```bash
keyhex=$(python3 - <<'PY'
s=b"/bin/bash\0".ljust(256, b"\x00")
print(" ".join(f"{b:02x}" for b in s))
PY
)
sudo bpftool map lookup id 5 key hex $keyhex
```
**NOTE**: As we lookup using the hex value of the key, we need to provide the exact 256-byte key the map expects (slightly tedious and hard). The example perform the lookup on the `/bin/bash` key.

Or update a value under a specific key in the map:

```bash
keyhex=$(python3 - <<'PY'
s=b"/bin/bash\0".ljust(256, b"\x00")
print(" ".join(f"{b:02x}" for b in s))
PY
)
sudo bpftool map update id 5 key hex $keyhex value hex 2a 00 00 00 00 00 00 00
```

**NOTE**: The map’s value size is 8 bytes (`__u64`) and we need to provide a hex value in [little-endian order](https://en.wikipedia.org/wiki/Endianness) (slightly tedious). In our case we set the value to `42` (`2a 00 00 00 00 00 00 00` in hex).

Or delete a specific entry:

```bash
keyhex=$(python3 - <<'PY'
s=b"/bin/bash\0".ljust(256, b"\x00")
print(" ".join(f"{b:02x}" for b in s))
PY
)
sudo bpftool map delete id 5 key hex $keyhex
```

In practice, your eBPF application will do all the updates/lookups to the eBPF map, but while debugging your code - this commands come incredibly useful.

#### Debugging and Tracing

Offers features for debugging and tracing eBPF programs. Until now, we always printed the logs using:

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

But exactly the same, can be achieved using:

```bash
sudo bpftool prog trace
```

There’s NO `--prog` or `--id` flag in `bpftool prog trace` to only show logs from one eBPF program, so whichever program calls `bpf_printk()`, the logs are mixed together in the output of these commands.

But in general, `bpf_printk()` should only be utilized during the development. Not only high-frequency events can overwhelm the trace buffer and the output of the mentioned commands is corrupted, but also they can cause significant performance overhead on your eBPF application.

#### Listing Available eBPF Features

List features your current kernel actually supports.

We can check the capabilities available in your kernel, using:

```bash
sudo bpftool feature probe kernel
```

This command outputs a detailed list of supported BPF program types, map types, helpers, and other kernel capabilities. It’s especially useful if you’re running on different distributions or kernel versions, since not every feature may be enabled or available.

For example, if you want to check whether your kernel supports specific eBPF maps or helpers like `bpf_loop()`, this probe will tell you.
TODO: mention that this is not always the best way

And many other commands, but these are the most frequent that you'll see in the wild.

## Monitoring eBPF Applications

TODO: bpftop

Congrats, you've came to the end of this tutorial. 🥳