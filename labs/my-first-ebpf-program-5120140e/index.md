---
kind: tutorial

title: Your First eBPF Program (and All the Steps Before)

description: |
  In this first tutorial, you’ll run a pre-coded eBPF program and see it in action without writing any code yourself. We’ll walk through the important parts of the program so you understand how eBPF hooks and runs in the kernel. The goal is to get familiar with the workflow and core concepts before you start writing your own eBPF programs.

playground:
  name: ebpf-playground-2bd77c1c

tasks:
  clone_hello_world:
    init: true
    user: laborant
    run: |
      git clone https://github.com/dorkamotorka/ebpf-hello-world.git /home/laborant/ebpf-hello-world

categories:
- programming
- linux

tagz:
- ebpf

createdAt: 2025-08-20
updatedAt: 2025-08-20

cover: __static__/cover.png

---

When you start the tutorial, you’ll see a `Term 1` terminal and an `IDE` on the right-hand side. You are logged in as `root`, and the current working directory (`/`) already contains the `ebpf-hello-world` folder. Inside, you’ll find the [eBPF Hello World example](https://github.com/dorkamotorka/ebpf-hello-world), implemented with [ebpf-go](https://ebpf-go.dev/) — a Golang eBPF framework developed as part of the Cilium project.

And there are several good reasons for this choice:

- **Cloud Native alignment** – Most Cloud Native tools are written in Go. Learning eBPF through a Golang framework puts you one step ahead if you plan to integrate eBPF with Kubernetes, container runtimes, or cloud tooling.

- **Proven and well-supported** – ebpf-go is maintained by Cilium and supported by many large enterprises. Cilium is a leading project in the eBPF ecosystem, and its backing ensures the framework remains stable, secure, and production-ready.

- **Developer experience** – The API is idiomatic Go, making it easier for Go developers to quickly become productive without context switching between languages.

- **Ecosystem integration** – ebpf-go is widely adopted across observability, security, and networking projects. Skills you build here will directly transfer to real-world tools you may already be using.

- **Community and documentation** – The project has active contributors, solid documentation, and plenty of real-world examples, which makes the learning curve much smoother.

If this still hasn’t convinced you, check out our [blog post](https://ebpfchirp.substack.com/p/go-c-rust-and-more-picking-the-right) where we compare different frameworks and break down their pros and cons.

## eBPF Code Flow

If you open the `ebpf-hello-world` folder—using either the `Term 1` terminal or the `IDE`—you’ll find a minimal (arguably the smallest) eBPF application we could put together.

Every eBPF application typically has two parts:

- **User-space program**: Loads the kernel-space program and attaches it to the desired tracepoint or probe in the kernel. (Here: `main.go`)
- **Kernel-space program**: Runs inside the kernel once the tracepoint/probe is hit. This is where the actual eBPF kernel logic lives. (Here: `hello.c`)

We have intentionally added code comments to (almost) every code line, just for the sake of this tutorial. Start by looking into `hello.c` and follow along with the `main.go`.

TODO: add an image of the flow

::details-box
---
:summary: What about vmlinux.h file?
---

At a high level, your eBPF program needs access to kernel context and data structures to do anything meaningful. For example, we might extend this tutorials' code and read the arguments passed to the `execve` system call. These arguments are available through the `trace_event_raw_sys_enter` struct — and that struct is defined in `vmlinux.h`.
::

## Generating and Building the eBPF Application

Let's build the application, using:

```bash
cd ebpf-hello-world # Go inside the project folder if you haven't already
go generate
go build
```

Well, this is interesting - what's the difference between `go build` and `go generate` or even what are they at all?

While `go build` is a pretty standard command that compiles your Go code into a binary (an executable), `go generate` is a bit less common.

By definition, `go generate` runs (code generation) commands that you define in special `//go:generate` comments inside your source files. And if you look inside the `main.go` file, you'll find one at the top.

```go [main.go]{3}
package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf hello hello.c

import (
	"log"
	"os"
...
```

Namely, the `go generate` command will invoke a handy tool called [bpf2go](https://github.com/cilium/ebpf/tree/main/cmd/bpf2go) with some arguments passed to it. But what's really interesting, if you look inside the code of this tool is that it is nothing more that just a wrapper around `clang` - compiler for C, C++, and related languages, built as part of the LLVM project, which happens to also be used for compiling eBPF kernel code.

TODO: image from Linkedin for bpf2go

In other words, `go generate` compiles the eBPF kernel program (`hello.c`) into an object file (`hello_bpf.o`) and generates a Go source file (`hello_bpf.go`) that embeds the object and provides helper functions to work with it.

Lastly, `go build` picks up the `main.go` and `hello_bpf.go` and builds the final eBPF application binary `hello`.

::details-box
---
:summary: What about `//go:build ignore` at the top of hello.c file?
---

Since Go files and C files are in the same folder, the Go toolchain tries to treat everything in that folder as part of the build. But files like `hello.c` are not Go files, and by default `go build` will complain if it encounters them.
::

## Running the eBPF Application

Now, to actually run the compiled `hello` binary and eBPF applications in general, the `CAP_BPF` [Linux capability](https://man7.org/linux/man-pages/man7/capabilities.7.html) is required. 

That's mandatory because the logic almost always uses privileged BPF operations like loading the eBPF code into the kernel (, creating eBPF maps, loading BTF information, iterating over programs and maps, etc.).

::remark-box
---
kind: info
---

💡 `CAP_BPF` is available since Linux kernel 5.8 and was introduced to separate out BPF functionality from the overloaded `CAP_SYS_ADMIN` capability.
::

However, since in this demo environment and you can log in as the `root`, this is not a problem. 

We can just run `hello`, using:

```bash
sudo ./hello
```

`hello` eBPF application should now capture and log `Hello world` each time a process is executed on the system. 

Well, not really. In order for this tutorial to remain as simple as possible, our two programs aren't anyhow communicating with each other, since they would need a buffer to exchange data. We'll get there in another tutorial, but in case you are interested - this would be implemented via [different kind of BPF maps](https://docs.kernel.org/bpf/maps.html).

For now, everytime the process is executed on the system, our eBPF application does in fact capture this and runs itself, but this is only indicated through the eBPF logs, to which we are writing `Hello world` using `bpf_printk("Hello world");` line.

```c [hello.c]{4}
...
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve_tp(struct trace_event_raw_sys_enter *ctx) {
    bpf_printk("Hello world");
    return 0;
}
```

On the right side at the top, open the second `Term 2` tab by clicking (`+`), and view the logs using:
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

It's unlikely, but possible you won't see any `Hello world` logs. This could be, since there is little going on in a small VM like ours, so let's execute some process ourself.

Open the third `Term 3` tab, and execute:

```bash
cat /etc/os-release
# or
uname -a
```

Switch back to the second `Term 2` tab and see the output.
