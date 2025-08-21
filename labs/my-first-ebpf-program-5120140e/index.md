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

When you start the tutorial, you’ll see a `Term 1` terminal and an `IDE` on the right-hand side. You are logged in as `root`, and the current working directory (`/`) already contains the `ebpf-hello-world` folder. Inside it, you’ll find [eBPF Hello World example](https://github.com/dorkamotorka/ebpf-hello-world) implemented using eBPF/Golang framework from Cilium called [ebpf-go](https://ebpf-go.dev/). 

And there are several good reasons for this choice:

- **Cloud Native alignment** – Most Cloud Native tools are written in Go. Learning eBPF through a Golang framework puts you one step ahead if you plan to integrate eBPF with Kubernetes, container runtimes, or cloud tooling.

- **Proven and well-supported** – ebpf-go is maintained by Cilium and supported by many large enterprises. Cilium is a leading project in the eBPF ecosystem, and its backing ensures the framework remains stable, secure, and production-ready.

- **Developer experience** – The API is idiomatic Go, making it easier for Go developers to quickly become productive without context switching between languages.

- **Ecosystem integration** – ebpf-go is widely adopted across observability, security, and networking projects. Skills you build here will directly transfer to real-world tools you may already be using.

- **Community and documentation** – The project has active contributors, solid documentation, and plenty of real-world examples, which makes the learning curve much smoother.

If this still hasn’t convinced you, take a look at one of our [blog post](https://ebpfchirp.substack.com/p/go-c-rust-and-more-picking-the-right) where we compare different frameworks along with their pros and cons.

## Explaining the eBPF Code Flow

If you open the `ebpf-hello-world` folder—using either the `Term 1` terminal or the `IDE`—you’ll find a minimal (arguably the smallest) eBPF application we could put together.

Every eBPF application typically has two parts:

- **User-space program**: Loads the kernel-space program and attaches it to the desired tracepoint or probe in the kernel. (Here: `main.go`)
- **Kernel-space program**: Runs inside the kernel once the tracepoint/probe is hit. This is where the actual eBPF kernel logic lives. (Here: `hello.c`)

We have intentionally added code comments to (almost) every code line, just for the sake of this tutorial. Start by looking into `hello.c` and follow along with the `main.go`.

::remark-box
---
kind: info
---
💡 For this simple example, these two programs aren't anyhow communicating with each other, since they would need a buffer to exchange data. We'll get there in another tutorial, but in case you are interested - this would be implemented via [different kind of BPF maps](https://docs.kernel.org/bpf/maps.html).
::

## Building and Running the eBPF Application

Let's build the application, using:

```bash
cd ebpf-hello-world # Go inside the project if you haven't already
go generate
go build
```

Well, this is interesting - what's the difference between `go build` and `go generate`?

While `go build` is a pretty standard command that compiles your Go code into a binary (an executable), `go generate` is a bit more tricky in this case where we have to run it beforehand.

By definition, `go generate` runs code generation commands that you define in special `//go:generate` comments inside your source files. And if you look inside the `main.go` file, you'll find one at the top.

Namely, the `go generate` command will invoke a handy tool called [bpf2go](https://github.com/cilium/ebpf/tree/main/cmd/bpf2go) with some arguments passed to it. But what's really interesting, if you look inside the code of this tool is that it is nothing more that just a wrapper around `clang` - compiler for C, C++, and related languages, built as part of the LLVM project, which happens to also be used for compiling eBPF kernel code.

TODO: image from Linkedin for bpf2go

In other words, `go generate` compiles the eBPF kernel program (`hello.c`) into an object file (`hello_bpf.o`) and generates a Go source file (`hello_bpf.go`) that embeds the object and provides helper functions to work with it.

Lastly, `go build` picks up the `main.go` and `hello_bpf.go` and builds the final eBPF application binary `hello`.

::remark-box
---
kind: info
---

💡 We also need to set `//go:build ignore`, since Go files and C files are in the same folder, the Go toolchain tries to treat everything in that folder as part of the build. But files like `hello.c` are not Go files, and by default `go build` will complain if it encounters them.
::

Now, to actually run the compiled `hello` binary, the `CAP_BPF` [Linux capability](https://man7.org/linux/man-pages/man7/capabilities.7.html) is required. 

That's mandatory because our logic uses privileged BPF operations (e.g. loading the eBPF code into the kernel) and at the same time many Linux distributions anyway don't allow unprivileged eBPF. 

::remark-box
---
kind: info
---

💡 `CAP_BPF` is available since Linux kernel 5.8 and was introduced to separate out BPF functionality from the overloaded `CAP_SYS_ADMIN` capability. It allows loading all types of BPF programs, create most map types, load BTF, iterate programs and maps. 
::

However, since in this demo environment and you can log in as the `root`, this is not a problem. 

Run `hello`:

```bash
sudo ./hello
```

TODO: it logs to kernel logs

`hello` will now show output each time any process is executed. But since there is little going on in a small VM like ours, we will generate some events. On the left side on the top, switch to the second `Term 2` tab, and execute:

```bash
cat /etc/os-release
```

Switch back to the first `Term 1` tab and see the output: a process execution of `cat` command has been captured and logged.

If you leave execsnoop running, from time to time you might see output generated by other processes running on the VM.

TODO: make it a helloworld for different programming languages
