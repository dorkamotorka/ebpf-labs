---
kind: tutorial

title: "eBPF Verifier: Why the Kernel Can Safely Run eBPF Programs"

description: |
  In this tutorial, you’ll learn why it is safe to run eBPF code in the kernel, its advantages compared to kernel modules, and why the verifier is the most crucial component of eBPF.

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

createdAt: 2025-09-01
updatedAt: 2025-09-01

cover: __static__/cover.png

# Uncomment to embed (one or more) challenges.
# challenges:
#   challenge_name_1: {}
#   challenge_name_2: {}

---

When you start the tutorial, you’ll see a `Term 1` terminal and an `IDE` on the right-hand side. You are logged in as `laborant`, and the current working directory already contains the `ebpf-hello-world` folder. Inside, you’ll find the [eBPF Hello World labs](https://github.com/dorkamotorka/ebpf-hello-world), implemented with [ebpf-go](https://ebpf-go.dev/) — a Golang eBPF framework developed as part of the [Cilium](https://cilium.io/) project.

This tutorial serves as the continuation of [From Zero to Your First eBPF Program](https://labs.iximiuz.com/tutorials/my-first-ebpf-program-5120140e), [Storing Data in eBPF: Your First eBPF Map](https://labs.iximiuz.com/tutorials/ebpf-maps-tutorial-3efd4617) and [Inspecting and Monitoring eBPF Applications](https://labs.iximiuz.com/tutorials/inspecting-ebpf-using-bpftool-43dfa319), expanding on the introduced concepts.

In this part, you’ll learn how the eBPF verifier ensures that eBPF code runs safely in the kernel.

::image-box
---
:src: __static__/ebpf-verifier.png
:alt: eBPF Verifier
:max-width: 600px
---
::

## eBPF Verifier

We’ve mentioned the verification step a few times throughout these tutorials, so you already know that when you load an eBPF program into the kernel, this process ensures that the program is safe.

This verification is done by the eBPF verifier. And by “safe,” we don’t mean in terms of cybersecurity, but rather that it prevents system crashes or kernel panics.

It’s not a general-purpose static code analyzer. It doesn’t perform other types of checks, such as making sure that your eBPF code actually collects the type of data you want it to collect. So, don’t think of the verifier as a general-purpose static code analyzer or debugger.

In other words, verification involves checking every possible execution path through the program and ensuring that every instruction is safe. This involves: 
- **Validating Helper Functions**: Ensures only approved kernel helper functions are called, as different helper functions are valid for different BPF program types. (Remember the `sudo bpftool feature probe`?)
- **Validating Helper Function Arguments**: Ensures the arguments passed to helper functions are valid.
- **Checking the License**: Ensures that if you are using a BPF helper function that’s licensed under GPL, your program also has a GPL-compatible license.
- **Checking Memory Access**: Ensures the program only reads and writes to memory it is allowed to access. 
- **Checking Pointers Before Dereferencing Them**: Ensures pointers in code are safe and not null or out of bounds before use.
- **Accessing Context**: Ensures that the program accesses only the fields in the context structure it is allowed to.
- **Running to Completion**: Ensures the program will eventually finish instead of running forever.
- **Loops**: Ensures that loops are bounded and cannot cause infinite execution.
- **Checking the Return Code**: Ensures the program returns a valid value for its type of hook.
- **Invalid Instructions**: Rejects any instruction that is not supported or not allowed in eBPF.
- **Unreachable Instructions**: Flags and removes instructions that the program can never reach during execution.  

These checks are ranging from intuitive to some complex, so here, we’ll primarily focus on practical examples—how to handle common eBPF verification errors and useful debugging tips. For a deeper dive into the internals, we recommend [Learning eBPF, Chapter 6: The eBPF Verifier book](https://isovalent.com/books/learning-ebpf/).

Additionally, different kernel versions can have different versions of the verifier. It’s important to know which version your code will run against and ensure that you conform to the requirements of that version.

::remark-box
---
kind: info
---

💡 One thing to bear in mind is that the verifier works on eBPF bytecode, not directly on the source. And that bytecode depends on the output from the compiler. Because of things like compiler optimization, a change in the source code might not always result in exactly what you expect in the bytecode, so correspondingly it might not give you the result you expect in the verifier’s verdict. 

For example, the verifier will reject unreachable instructions, but the compiler might optimize them away before the verifier sees them.
::

#### Checking the License

TODO

#### Checking Pointers Before Dereferencing Them

TODO

#### Running to Completion

TODO

Limit is hardcoded to the kernel: https://elixir.bootlin.com/linux/v5.19.17/source/include/uapi/linux/bpf_common.h#L54 (TODO: this is for 4096)

___________________________________

In our personal experience, the easiest and most trivial way to debug verifier code is by using a combination of `bpf_printk()` function and commenting/uncommenting lines of code to determine the cause of the verification error and take it from there either through the byte code or general understanding of the checks that we discussed above.

When still learning eBPF, getting code through the verifier seemed like a dark art and you might find yourself needing assistance to resolve verifier errors. And that's okay - we've all been there. The [eBPF community Slack channel](https://ebpf.io/slack) is a good place to ask for help or just ping us directly.

::remark-box
---
kind: info
---

💡 There's also a [eBPF verifier errors GitHub repository](https://github.com/parttimenerd/ebpf-verifier-errors) that collects different verifier errors and their resolution. Although it's a gamble, whether it will be maintained over time but a nice resource when you're encountering issues.
::

Congrats, you've came to the end of this tutorial. 🥳