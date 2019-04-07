# malloc
Implementation of `malloc` library (`malloc`, `free`, etc.) made for Computer Systems course at University of Wrocław.

It utilises linked lists of arenas consisting of memory pages acquried through syscalls.
Arenas are divided between chunks of size atleast of a biggest hardware word (effectively equal to `2*sizeof(void *)`),
which are then returned to user.

Feel free to run any app using my malloc via this command: 
`LD_PRELOAD=./malloc.so xeyes`

## Requirements:
* gcc
* Make
* pkg-config
