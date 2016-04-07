ctaes
=====

Simple C module for constant-time AES encryption and decryption.

Features:
* Simple, pure C code without any dependencies.
* No tables or data-dependent branches whatsoever, but using bit sliced approach from https://eprint.iacr.org/2009/129.pdf.
* Very small object code: slightly over 4k of executable code when compiled with -Os.
* Slower than implementations based on precomputed tables, but can do ~10 MB/s on modern CPUs.

Performance
-----------

Compiled with GCC 4.8.4 with -O2, on an Intel(R) Core(TM) i7-4800MQ CPU, numbers in CPU cycles:

| Algorithm | Key schedule | Encryption per byte | Decryption per byte |
| --------- | ------------:| -------------------:| -------------------:|
| AES-128   |         3.4k |                 176 |                 197 |
| AES-192   |         3.7k |                 199 |                 225 |
| AES-256   |         4.6k |                 221 |                 252 |

Build steps
-----------

Object code:

    $ gcc -O2 ctaes.c -c -o ctaes.o

Tests:

    $ gcc -O2 ctaes.c test.c -o test

Benchmark:

    $ gcc -O2 ctaes.c bench.c -o bench
