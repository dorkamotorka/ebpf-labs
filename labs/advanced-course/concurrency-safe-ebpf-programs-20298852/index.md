---
kind: tutorial

title: How to Safely Update Map Values in eBPF

description: |
  This tutorial builds on "From Zero to Your First eBPF Program", "Storing Data in eBPF: Your First eBPF Map" and TODO by TODO. You’ll learn how to TODO

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

createdAt: 2025-08-30
updatedAt: 2025-08-30

cover: __static__/ebpf-lock.png

---

When you start the tutorial, you’ll see a `Term 1` terminal and an `IDE` on the right-hand side. You are logged in as `laborant`, and the current working directory already contains the `ebpf-hello-world` folder. Inside, you’ll find the [eBPF Hello World labs](https://github.com/dorkamotorka/ebpf-hello-world), implemented with [ebpf-go](https://ebpf-go.dev/) — a Golang eBPF framework developed as part of the [Cilium](https://cilium.io/) project.

This tutorial serves as the continuation of [From Zero to Your First eBPF Program](https://labs.iximiuz.com/tutorials/my-first-ebpf-program-5120140e), [Storing Data in eBPF: Your First eBPF Map](https://labs.iximiuz.com/tutorials/ebpf-maps-tutorial-3efd4617) and TODO expanding on the introduced concepts.

In this part, we’ll learn how and why TODO

::image-box
---
:src: __static__/ebpf-lock.png
:alt: 'Safely Updating Map Values in eBPF'
---
::