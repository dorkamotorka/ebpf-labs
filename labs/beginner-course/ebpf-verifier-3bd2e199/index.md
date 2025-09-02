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

cover: __static__/ebpf-verifier.png

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

The code for this lab is located in the `ebpf-hello-world/lab4` directory. The program is intentionally broken—meaning the verifier will reject it. Your task in the upcoming steps is to understand why it fails and then work on fixing it.

## eBPF Verifier

We’ve mentioned verification several times throughout these tutorials, so you already know that when you load an eBPF program into the kernel, this process ensures that the program is safe.

This verification is done by the eBPF verifier. And by “safe”, we don’t mean cybersecurity-related security, but simply that the program won’t crash the system or cause a kernel panic.

::remark-box
---
kind: info
---

💡 Safe execution is one of the biggest advantages of eBPF compared to traditional kernel modules. With kernel modules, even a small bug can crash the entire system, while the eBPF verifier prevents that from happening.
::

It’s also important to note that the verifier is not a general-purpose static analyzer or debugger. For example, it won’t tell you whether your eBPF code is collecting the right data—it only ensures the program can safely execute inside the kernel.

To do this, the verifier checks every possible execution path through your program and validates that each instruction is safe. This includes:
- **Validating Helper Functions**: Ensures only approved kernel helper functions are called, as different helper functions are valid for different BPF program types. (Remember the `sudo bpftool feature probe` output?)
- **Validating Helper Function Arguments**: Ensures the arguments passed to helper functions are valid.
- **Checking the License**: Ensures that if you are using an eBPF helper function that’s licensed under GPL, your program also has a GPL-compatible license.
- **Checking Memory Access**: Ensures the program only reads and writes to memory it is allowed to access. 
- **Checking Pointers Before Dereferencing Them**: Ensures pointers in code are safe and not null or out of bounds before use.
- **Accessing Context**: Ensures that the program accesses only the fields in the context structure it is allowed to.
- **Running to Completion**: Ensures the program will eventually finish instead of running forever.
- **Loops**: Ensures that loops are bounded and cannot cause infinite execution.
- **Checking the Return Code**: Ensures the program returns a valid value for its type of hook.
- **Invalid Instructions**: Rejects any instruction that is not supported or not allowed in eBPF.
- **Unreachable Instructions**: Flags and removes instructions that the program can never reach during execution.  

In the next sections, we’ll look at a few of these checks with practical examples and tips for debugging them. For more details, we recommend [Learning eBPF, Chapter 6: The eBPF Verifier book](https://isovalent.com/books/learning-ebpf/).

#### Checking the License

When an eBPF program is loaded into the kernel, the verifier inspects which helper functions it uses. If any of those helpers are marked “GPL-only,” the program must declare a GPL-compatible license, as described in the licensing documentation.

TODO: improve from here on
::details-box
---
:summary: But how can you check if the helper function in use is GPL-licensed?
---

TODO: While the latter two are non-GPL licenced, the bpf_probe_read_user_str() which is [GPL-only](https://codebrowser.dev/linux/linux/kernel/trace/bpf_trace.c.html#bpf_probe_read_user_str_proto).
::

If you look inside the `lab4/hello.c` file, you'll find `bpf_probe_read_user_str()`, `bpf_map_update_elem()` and `bpf_map_lookup_elem()`.

```c [hello.c]{6, 11, 16}
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve_tp(struct trace_event_raw_sys_enter *ctx) {
    const char *filename = (const char *)ctx->args[0];

    struct path_key key = {};
    long n = bpf_probe_read_user_str(key.path, sizeof(key.path), filename);
    if (n <= 0) {
        return 0; // couldn't read the path
    }

    __u64 *val = bpf_map_lookup_elem(&exec_count, &key);
    if (val) {
        *val += 1;
    } else {
        __u64 init = 1;
        bpf_map_update_elem(&exec_count, &key, &init, BPF_NOEXIST);
    }
...
```

If you build and run this program, you're gonna see something like this:
```
load program: invalid argument: cannot call GPL-restricted function from non-GPL compatible program
```

Therefore, if you want to avoid the verification error in our code example, you need to uncomment the line of code that defines the license.

```c [hello.c]
char _license[] SEC("license") = "GPL";
```

::remark-box
---
kind: info
---

TODO: Does it need to be always equal to GPL? Ref: https://ebpf.io/blog/ebpf-licensing-guide/
::

To see this output, we actually added, the following lines to our user space:
```go [main.go]
var objs helloObjects
// For printing eBPF verifier logs
// Ref: https://pkg.go.dev/github.com/cilium/ebpf#ProgramOptions
opts := &ebpf.CollectionOptions{
    Programs: ebpf.ProgramOptions{
        LogLevel:     2,       // 1 = basic, 2 = verbose
        LogSizeStart: 1 << 20, // 1MB buffer to avoid truncation
    },
}
if err := loadHelloObjects(&objs, opts); err != nil {
    // If verification fails, ebpf-go returns a VerifierError that includes the log.
    // Print it for easier debugging
    var ve *ebpf.VerifierError
    if errors.As(err, &ve) {
        log.Printf("Verifier error: %+v\n", ve)
    }
    log.Fatal("Loading eBPF objects:", err)
}
defer objs.Close()
```

TODO: what does that mean for user space

#### Checking Pointers Before Dereferencing Them

TODO: Let's say you want to debug if you program is running correctly, or what paths of the binaries are stored in the ebpf map, when you run a certain command
All pointers need to be checked before they are dereferenced (access the value stored at the memory address), since null is not a valid memory location

::remark-box
---
kind: info
---

💡 One thing to bear in mind is that the verifier works on eBPF bytecode, not directly on the source. And that bytecode depends on the output from the compiler. Because of things like compiler optimization, a change in the source code might not always result in exactly what you expect in the bytecode, so correspondingly it might not give you the result you expect in the verifier’s verdict. 

For example, the verifier will reject unreachable instructions, but the compiler might optimize them away before the verifier sees them.
::

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