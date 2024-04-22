# Conway's Game Of Life in eBPF 

This is the code for the demo from John Fastabend and Liz Rice's KubeCon Paris talk 
* [slides](https://speakerdeck.com/lizrice/ebpfs-abilities-and-limitations-the-truth)
* [video](https://www.youtube.com/watch?v=tClsqnZMN6I)

Kick this off by sending a packet on TCP port 65137 (which is 0x71FE), for
example by running `nc 127.0.0.1 65137`. You don't need anything to be listening
for that packet.