# Secure chat
P2P chat application, where sensible messages are encrypted.

We implemented three protocols:
•	Ephemeral RSA: to exchange temporary keys between server and clients
•	Needham–Schroeder Protocol (Denning-Sacco variant): to exchange keys between clients
•	Hash Functions: to store passwords

# Installation
To build project:

```sh
gcc -Wall -o compile ./compile.c
./compile
```
Then to execute project write in command line:

```sh
./server
./client
```

# Contributors
[Antonio Di Tecco](https://github.com/djqwert)
Luigi Treccozzi
