This is a solution to an eBPF Beginner Challenge.

To fix the “broken” program, you needed to add the license definition. Specifically, the following line:
```c [hello.c]
char _license[] SEC("license") = "GPL";
````

This is necessary because the challenge code uses the GPL-only eBPF helper function `bpf_probe_read_user_str()`.

The next step was finding the eBPF program ID. You can easily identify it from the output of:

```bash
sudo bpftool prog list
```

If the above command doesn’t show your program, it means the program isn’t running.

Hopefully, your program is running — in that case, grab its ID and use the following command to determine the UID of the user who loaded it:

```bash
sudo bpftool prog show id <ID> --pretty
```

After that, you needed to do a bit of searching — whether in the documentation, ChatGPT, or elsewhere — to discover that the following command tells you whether an eBPF program of type `tracepoint` supports the `bpf_override_return()` helper:
```sh
sudo bpftool feature probe
```

And since you had already found the program ID earlier, finding the map ID should have been much easier. It’s as simple as:
```sh
sudo bpftool map list
```

Finally, the tricky one — which eBPF map flag should you provide to `bpf_map_update_elem()` so that it only adds the entry if the key doesn’t already exist?

The answer is `BPF_NOEXIST`, which could be found [in the documentation](https://docs.ebpf.io/linux/helper-function/bpf_map_update_elem/).