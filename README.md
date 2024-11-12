# Conway's Game Of Life in eBPF

This is the code for the demo from John Fastabend and Liz Rice's KubeCon Paris
talk about the evolution of the complexities that eBPF can handle. By implementing 
[Conway's Game of Life](https://en.wikipedia.org/wiki/Conway%27s_Game_of_Life) in eBPF, we show that it is now Turing Complete. 

* [Slides](https://speakerdeck.com/lizrice/ebpfs-abilities-and-limitations-the-truth)
* [Video](https://www.youtube.com/watch?v=tClsqnZMN6I)

There are now two scheduling options:
* Pure BPF, using BPF timers, with the game initially kicked off using a network event
* An option to schedule the repeated BPF program using perf events

## Prerequisites

You will need to run this on a Linux (virtual) machine. It was tested on Ubuntu 22.04 with 5.15.0-107-generic kernel. 
The `lima.yaml` file includes apt-get commands for installing the build pre-requisites.

```
limactl start --name game-of-life lima.yaml
limactl shell game-of-life 
```

## Building and running this demo

* Build by running `make`
* Run with root privileges: `sudo ./life`

With no parameters, this attaches the eBPF game of life program to a perf event that is triggered by the perf system every second. 

Use the `--port` parameter to specify a port for the pure eBPF version. This loads the program and attaches it to a network egress event.  For example `sudo ./life --port 65137`
* In another terminal, send a packet on TCP port 65137 (0x71FE), for example by
  running `nc 127.0.0.1 65137`
    * This is enough to trigger the egress event (you don't need anything to be listening on that port)