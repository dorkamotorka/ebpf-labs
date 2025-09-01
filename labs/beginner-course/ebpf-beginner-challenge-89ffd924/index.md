---
kind: challenge

title: eBPF Challenge for Beginners

description: |
  TODO

categories:
- linux
- programming

tagz:
- eBPF

difficulty: easy

createdAt: 2025-08-30
updatedAt: 2025-08-30

cover: __static__/ebpf-challenge.png

playground:
  name: ebpf-playground-2bd77c1c

tasks:
  clone_hello_world:
    init: true
    user: laborant
    run: |
      git clone https://github.com/dorkamotorka/ebpf-hello-world.git /home/laborant/ebpf-hello-world

  verify_program:
    run: |
      # first check
      [ $(sudo bpftool prog show | grep -c "name handle_execve_tp") -lt 1 ] && echo "No running eBPF programs" && exit 1

      sleep 2  # making sure it's stable enough

      # second check
      [ $(sudo bpftool prog show | grep -c "name handle_execve_tp") -lt 1 ] && echo "No running eBPF programs" && exit 1

      # Get its ID for the next step
      sudo bpftool prog show | awk '/name handle_execve_tp/ {print $1}' | sed 's/://'

  verify_map:
    run: |
      # first check
      [ $(sudo bpftool map show | grep -c "name exec_count") -lt 1 ] && echo "No loaded eBPF maps" && exit 1

      sleep 2  # making sure it's stable enough

      # second check
      [ $(sudo bpftool map show | grep -c "name exec_count") -lt 1 ] && echo "No loaded eBPF maps" && exit 1

      # Get its ID for the next step
      sudo bpftool map show | awk '/name exec_count/ {print $1}' | sed 's/://'

  verify_program_id:
    needs:
      - verify_program
    env:
      - PROGRAM_ID=x(.needs.verify_program.stdout)
    run: |
      PROVIDED_ID="$(cat /tmp/program-id.txt)"
      if [ "${PROVIDED_ID}" == "" ]; then
        echo "Provided program ID is empty"
        exit 1
      fi

      if [[ "${PROGRAM_ID}" != "${PROVIDED_ID}"* ]]; then
        echo "Program ID is not correct"
        exit 1
      fi

  verify_map_id:
    needs:
      - verify_map
    env:
      - MAP_ID=x(.needs.verify_map.stdout)
    run: |
      PROVIDED_ID="$(cat /tmp/map-id.txt)"
      if [ "${PROVIDED_ID}" == "" ]; then
        echo "Provided map ID is empty"
        exit 1
      fi

      if [[ "${MAP_ID}" != "${PROVIDED_ID}"* ]]; then
        echo "Map ID is not correct"
        exit 1
      fi
---

In this challenge, you will need to perform the most fundamental eBPF related operation - start a program.

::image-box
---
:src: __static__/ebpf-challenge.png
:alt: eBPF Challenge
:max-width: 600px
---
::

You need to run the program that was build during the eBPF tutorials for beginners, because to complete this challenge you will also need to inspect the running program and answer a few questions about it.
It can be found under `ebpf-hello-world/solution` directory.

::simple-task
---
:tasks: tasks
:name: verify_program
---
#active
Waiting for the eBPF program to start...

#completed
Yay! The eBPF program is running 🎉
::

::simple-task
---
:tasks: tasks
:name: verify_map
---
#active
Waiting for the eBPF map to load...

#completed
Yay! The eBPF map is loaded 🎉
::

::hint-box
---
:summary: Hint 1
---

It's an easy one - generate the Go source file (`hello_bpf.go`) that embeds the eBPF object, build the final eBPF application binary and run it.
::


Now, when you have a running program, let's try to understand what it actually is.

To keep track of eBPF program, each one is assigned a unique ID. Can you find the ID of the program that you've just started?

::user-input-task
---
:tasks: tasks
:name: verify_program_id
:validateRegex: ^[a-f0-9]+$
:destination: /tmp/program-id.txt
---
#active
Waiting for the program ID to be identified...

#completed
Yay! You've found the running program ID 🎉
::

::hint-box
---
:summary: Hint 2
---

`sudo bpftool --help` is your friend 😉
::

Can you find the ID of the map that was defined in the program and loaded?

::user-input-task
---
:tasks: tasks
:name: verify_map_id
:validateRegex: ^[a-f0-9]+$
:destination: /tmp/map-id.txt
---
#active
Waiting for the map ID to be identified...

#completed
Yay! You've found the map ID 🎉
::

::hint-box
---
:summary: Hint 2
---

`sudo bpftool --help` is your friend 😉
::