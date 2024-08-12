# Conway's Game Of Life in eBPF

This is the code for the demo from John Fastabend and Liz Rice's KubeCon Paris
talk about the evolution of the complexities that eBPF can handle.

* [Slides](https://speakerdeck.com/lizrice/ebpfs-abilities-and-limitations-the-truth)
* [Video](https://www.youtube.com/watch?v=tClsqnZMN6I)

## Prerequisites

You will need to run this on a Linux (virtual) machine. It was tested on Ubuntu 22.04 with 5.15.0-107-generic kernel. 
The `lima.yaml` file includes apt-get commands for installing the build pre-requisites.

## Building and running this demo

* Build by running `make`
* Run with root privileges: `sudo ./life`
    * This loads the program and attaches it to a network egress event.
* In another terminal, send a packet on TCP port 65137 (0x71FE), for example by
  running `nc 127.0.0.1 65137`
    * This is enough to trigger the egress event (you don't need anything to be listening on that port)
