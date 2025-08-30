---
kind: challenge

title: eBPF Beginner Challenge (TODO)

description: |
  TODO

categories:
- linux
- programming

tagz:
- ebpf

difficulty: easy

createdAt: 2025-08-30
updatedAt: 2025-08-30

cover: __static__/ebpf-challenge.png

playground:
  name: docker

tasks:
  init_task_1:
    init: true
    run: |
      echo "This is an init task"

  verify_something:
    run: |
      [ -f /tmp/something ]
---

_Begginer challenge description_

Docs: https://github.com/iximiuz/labs-content-samples/blob/main/sample-challenge/index.md

::simple-task
---
:tasks: tasks
:name: verify_something
---
#active
Waiting for the `/tmp/something` file to be created...

#completed
Yay! The `/tmp/something` file was created 🎉
::

::hint-box
---
:summary: Hint 1
---

Just do it!
::

(place your challenge content here)