---
kind: tutorial

title: "eBPF Verifier: Why the Kernel Can Safely Run eBPF Programs"

description: |
  In this tutorial, you’ll learn why it is safe to run eBPF code in the kernel, some of its advantages compared to kernel modules, and why the verifier is the most crucial component of eBPF.

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

In this part, you’ll learn how the eBPF verifier ensures that eBPF code can run safely in the kernel.

::image-box
---
:src: __static__/ebpf-verifier.png
:alt: eBPF Verifier
:max-width: 600px
---
::

The code for this lab is located in the `ebpf-hello-world/lab4` directory. The program is intentionally broken—meaning the verifier will reject it if you try to run it. Your task in the upcoming steps is to understand why it fails and then work on fixing it.

## eBPF Verifier

We’ve mentioned verification several times throughout these tutorials, so you already know that when you load an eBPF program into the kernel, this process ensures that the program is safe.

This verification is done by the [eBPF verifier](https://docs.ebpf.io/linux/concepts/verifier/). And by “safe”, we don’t mean cybersecurity-related security, but simply that the program won’t crash the system or cause a kernel panic.

::remark-box
---
kind: info
---

💡 Safe execution is one of the biggest advantages of eBPF compared to traditional kernel modules. With kernel modules, even a small bug can crash the entire system, while the eBPF verifier prevents that from happening.
::

To achieve this, the verifier checks every possible execution path through your program and validates that each instruction is safe. This includes:
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

In the next sections, we’ll look at a few of these checks with practical examples and tips for debugging them. For more details about the eBPF verifier itself, we recommend [Learning eBPF, Chapter 6: The eBPF Verifier book](https://isovalent.com/books/learning-ebpf/).

#### Checking the License

When an eBPF program is loaded into the kernel, the verifier inspects which helper functions it uses. If any of those helpers are marked “GPL-only,” the program must declare a GPL-compatible license, as described in the licensing documentation.

::details-box
---
:summary: But how can you check if the helper function in use is GPL-licensed?
---

The most reliable way is to inspect the Linux kernel source and look for the `<helper-function>_proto` definition. 

For example, the prototype for `bpf_probe_read_user_str()` is [`bpf_probe_read_user_str_proto`](https://codebrowser.dev/linux/linux/kernel/trace/bpf_trace.c.html#bpf_probe_read_user_str_proto), where the `.gpl_only` boolean field indicates that the helper is restricted to GPL-licensed programs.
::

::details-box
---
:summary: Does that mean I also have to license by user-space part of the eBPF application as GPL?
---

When it comes to user space, your eBPF loader code and supporting libraries do **NOT** need to be GPL-licensed, only the in-kernel eBPF program does. 

This separation allows companies and projects to keep user space tooling under permissive licenses while still relying on GPL-only helpers in the kernel. For more details, see the [eBPF Licensing Guide](https://ebpf.io/blog/ebpf-licensing-guide/).
::

To show this on the example, look inside the `ebpf-hello-world/lab4/hello.c` file and you'll find `bpf_probe_read_user_str()`, `bpf_map_update_elem()` and `bpf_map_lookup_elem()` - but notice there’s no license definition anywhere in the code:
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

If you build and run this program, you’ll see the following verifier error:
```
load program: invalid argument: cannot call GPL-restricted function from non-GPL compatible program
```

This is expected: like mentioned above or if you check the Linux kernel source, you’ll notice that among these helpers, `bpf_probe_read_user_str()` is GPL-only.

To resolve this, you need to declare your program’s license explicitly. Add the following line anywhere in your code — top, bottom, or even in the middle doesn’t matter, as long as it’s present:
```c [hello.c]
char _license[] SEC("license") = "GPL";
```

::details-box
---
:summary: Does it always have to be GPL? What about dual-licensed options like Dual MIT/GPL?
---

Not necessarily. The eBPF license string just needs to be GPL-compatible.
The Linux kernel accepts several options, including **GPL**, **GPL v2**, **Dual BSD/GPL**, **Dual MIT/GPL**, and **Dual MPL/GPL**.  

Many projects actually choose a **dual license** in order to:
- satisfy the eBPF verifier in case of GPL-ed helper functions
- give other projects flexibility to integrate eBPF code into non-GPL projects without being forced to adopt GPL for their entire codebase

For full details on accepted annotations, see the kernel’s [license-rules documentation](https://github.com/torvalds/linux/blob/master/Documentation/process/license-rules.rst).
::

#### Checking Pointers Before Dereferencing Them

Let’s say you want to debug whether your program is running correctly by printing which binary paths are executed and stored in the eBPF map.

To do this, you might try adding the following lines just before the end of your eBPF program:
```c [hello.c]{10-11}
...
    __u64 *val = bpf_map_lookup_elem(&exec_count, &key);
    if (val) {
        *val += 1;
    } else {
        __u64 init = 1;
        bpf_map_update_elem(&exec_count, &key, &init, BPF_NOEXIST);
    }

    // Step 2: Print `key.path` and `*val`
    bpf_printk("execve: %s (count: %llu)\n", key.path, *val);

    return 0;
}
```

However, this won’t really work. If you try to run the program, you’ll hit a verifier error like:
```
load program: invalid argument: last insn is not an exit or jmp (2 line(s) omitted)
```

We could now disassemble the `hello_bpf.o` kernel object (built with `go generate` command) to track down the error, but that would be another tutorial on its own. In this case, the issue is actually visible directly in our code.

The problem is that we never verify whether `*val` points to valid memory. The `bpf_map_lookup_elem` helper may in fact return `null` which is not a valid memory location and cannot be safely dereferenced. To fix this, we need to move our `bpf_printk()` statement inside the `if (val)` branch:

```c [hello.c]{10-13}
...
    __u64 *val = bpf_map_lookup_elem(&exec_count, &key);
    if (val) {
        *val += 1;
    } else {
        __u64 init = 1;
        bpf_map_update_elem(&exec_count, &key, &init, BPF_NOEXIST);
    }

    // Step 2: Print `key.path` and `*val`
    if (val) {
        bpf_printk("execve: %s (count: %llu)\n", key.path, *val);
    }

    return 0;
}
```

To summarize this, always check pointers before dereferencing them.

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

::remark-box
---
kind: info
---

💡 One thing to bear in mind is that the verifier works on eBPF bytecode, not directly on the source. And that bytecode depends on the output from the compiler. Because of things like compiler optimization, a change in the source code might not always result in exactly what you expect in the bytecode, so correspondingly it might not give you the result you expect in the verifier’s verdict. 

For example, the verifier will reject unreachable instructions, but the compiler might optimize them away before the verifier sees them.
::

Congrats, you've came to the end of this tutorial. 🥳