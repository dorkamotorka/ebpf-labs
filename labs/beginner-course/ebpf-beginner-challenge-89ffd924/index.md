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

  verify_user:
    run: |
      # Extract its UID
      sudo bpftool prog show name challenge --json | jq -r '.uid'

  verify_program:
    run: |
      # first check
      [ $(sudo bpftool prog show | grep -c "name challenge") -lt 1 ] && echo "No running eBPF programs" && exit 1

      sleep 2  # making sure it's stable enough

      # second check
      [ $(sudo bpftool prog show | grep -c "name challenge") -lt 1 ] && echo "No running eBPF programs" && exit 1

      # Get its ID for the next step
      sudo bpftool prog show | awk '/name challenge/ {print $1}' | sed 's/://' || echo ""


  verify_program_id:
    needs:
      - verify_program
    env:
      - PROGRAM_ID=x(.needs.verify_program.stdout)
    failcheck: |
      if ! sudo bpftool prog show name challenge &>/dev/null; then
        echo "The eBPF program is no longer loaded. Did it unload or fail to attach?"
        exit 1
      fi
    hintcheck: |
      if ! sudo bpftool prog show name challenge &>/dev/null; then
        echo "To understand what happened, try running 'sudo bpftool prog list'."
        echo "It'll show all running eBPF programs."
        exit 0
      fi
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
  
  verify_answer:
    run: |
      ANSWER="$(cat /tmp/answer.txt)"
      if [ "${ANSWER}" == "" ]; then
        echo "Provided answer is empty"
        exit 1
      fi

      if [[ "no" != "${ANSWER}"* ]]; then
        echo "Answer is not correct"
        exit 1
      fi

  verify_map:
    run: |
      # first check
      [ $(sudo bpftool map show | grep -c "name exec_count") -lt 1 ] && echo "No loaded eBPF maps" && exit 1

      sleep 2  # making sure it's stable enough

      # second check
      [ $(sudo bpftool map show | grep -c "name exec_count") -lt 1 ] && echo "No loaded eBPF maps" && exit 1

      # Get its ID for the next step
      sudo bpftool map show | awk '/name exec_count/ {print $1}' | sed 's/://' || echo ""

  verify_map_id:
    needs:
      - verify_map
    env:
      - MAP_ID=x(.needs.verify_map.stdout)
    failcheck: |
      if ! sudo bpftool map show name exec_count &>/dev/null; then
        echo "The eBPF map is no longer loaded. Did it unload?"
        exit 1
      fi
    hintcheck: |
      if ! sudo bpftool map show name exec_count &>/dev/null; then
        echo "To understand what happened, try running 'sudo bpftool map list'."
        echo "It'll show all loaded eBPF maps."
        exit 0
      fi
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

  verify_map_flag:
    run: |
      PROVIDED_FLAG="$(cat /tmp/map-flag.txt)"
      if [ "${PROVIDED_FLAG}" == "" ]; then
        echo "Provided flag is empty"
        exit 1
      fi

      if [[ "BPF_NOEXIST" != "${PROVIDED_FLAG}"* ]]; then
        echo "Provided flag is not correct"
        exit 1
      fi

  verify_user_id:
    needs:
      - verify_user
    env:
      - USER_ID=x(.needs.verify_user.stdout)
    failcheck: |
      if ! sudo bpftool prog show name challenge &>/dev/null; then
        echo "The eBPF program is no longer loaded. Did it unload or fail to attach?"
        exit 1
      fi
    hintcheck: |
      if ! sudo bpftool prog show name challenge &>/dev/null; then
        echo "To understand what happened, try running 'sudo bpftool prog list'."
        echo "It'll show all running eBPF programs."
        exit 0
      fi
    run: |
      PROVIDED_ID="$(cat /tmp/user-id.txt)"
      if [ "${PROVIDED_ID}" == "" ]; then
        echo "Provided user ID is empty"
        exit 1
      fi

      if [[ "${USER_ID}" != "${PROVIDED_ID}"* ]]; then
        echo "User ID is not correct"
        exit 1
      fi
---

In this challenge, you’ll tackle the most fundamental eBPF tasks. We’ve taught you the basics — now it’s your turn to put them into practice.

::image-box
---
:src: __static__/ebpf-challenge.png
:alt: eBPF Challenge
:max-width: 600px
---
::
 
Before you get going, build and run the eBPF application. You’ll find it in the `ebpf-hello-world/challenge` directory — and yes, we’ve slipped in a verifier error on purpose just to keep you on your toes. Your mission - figure out why it fails and fix it.

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

It’s an easy one — try building and running the "broken" program and you’ll understand.
::

Now that your program is running, let’s inspect it.

Keep it running, then open a second `Term 2` terminal on the right (click the `+` at the top).

Every eBPF program gets a unique ID for tracking. Can you find the ID of the program you just started?

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
:summary: Hint 1
---

`sudo bpftool --help` is your friend 😉
::

Sometimes, knowing which user loaded an eBPF program is useful for accountability and security.

Let's find the User Identifier (UID) that loaded the eBPF program of type `tracepoint` with name `challenge`.

::user-input-task
---
:tasks: tasks
:name: verify_user_id
:validateRegex: ^[0-9]+$
:destination: /tmp/user-id.txt
---
#active
Waiting for the UID to be identified...

#completed
Well, that wasn’t too tricky — it was you! The `challenge` program is the very one you built and ran. But since you used `sudo`, it was technically loaded by `root`. But we’ll let you take the credit this time. 😉
::

We also learned that not all eBPF programs support every eBPF helper function. Can you find whether an eBPF program of type `tracepoint` support the `bpf_override_return()` helper? (Answer with `yes` or `no`)

::remark-box
---
kind: info
---

💡 `bpf_override_return()` lets an eBPF program forcibly change the return value of a probed kernel function.
::

::user-input-task
---
:tasks: tasks
:name: verify_answer
:validateRegex: ^[a-z]+$
:destination: /tmp/answer.txt
---
#active
Waiting for the answer...

#completed
Yay! You are correct 🎉
::

::hint-box
---
:summary: Hint 1
---

This one is up to you — either the eBPF documentation or `sudo bpftool --help` will point you in the right direction 😉
::

What about eBPF maps - can you find the ID of the `exec_count` eBPF map that was defined and loaded in your eBPF program?

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
:summary: Hint 1
---

`sudo bpftool --help` is your friend 😉
::

Can you recall what eBPF map flag should one provide to the `bpf_map_update_elem()` that adds the entry only if the key doesn't exist yet.

::user-input-task
---
:tasks: tasks
:name: verify_map_flag
:validateRegex: ^[A-Z_]+$
:destination: /tmp/map-flag.txt
---
#active
Waiting for the eBPF map flag to be identified...

#completed
Yay! You've found the correct flag 🎉
::

::hint-box
---
:summary: Hint 1
---
Feel free to check the eBPF docs — you don’t need to know everything by heart, just how to find it 😉
::