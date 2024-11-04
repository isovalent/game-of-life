// Copyright (C) Isovalent, Inc. - All Rights Reserved.
package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go life bpf_life.c

type MsgLifeEvent struct {
	Cells         [4096]uint8
	Generation    uint32
	Width         uint32
	Height        uint32
	LengthInBytes uint32
}

func printCells(e *MsgLifeEvent) {
	fmt.Printf("\033[H")
	for x := uint32(0); x < e.Width; x++ {
		fmt.Printf("%2d", x)
	}
	fmt.Printf("\n");

	for y := uint32(0); y < e.Height; y++ {
		fmt.Printf("%2d", y)
		for x := uint32(0); x < e.Width; x++ {
			state := e.Cells[x+(y*e.Width)] & 0x01

			if state != 0 {
				fmt.Printf("\033[07m  \033[m")
			} else {
				fmt.Printf("  ")
			}
		}
		fmt.Printf("\033[E")
	}

	fmt.Printf("Life event generation %d received: %d x %d\n", e.Generation, e.Width, e.Height)
}

func readLoop(rd *ringbuf.Reader) {
	// With ringbuf up read forever until errors
	var event MsgLifeEvent

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("received signal, exiting...")
				return
			}
			log.Printf("reading from reader: %s\n", err)
			continue
		}
		err = binary.Read(bytes.NewBuffer(record.RawSample), binary.NativeEndian, &event)
		if err != nil {
			log.Printf("reading life event error\n")
			continue
		}

		printCells(&event)
	}
}

// Trigger the Game of Life using perf events every second
func perfSetup(objs *lifeObjects) (link.Link, error) {
	attr := unix.PerfEventAttr{
		Type:   unix.PERF_TYPE_SOFTWARE,
		Config: unix.PERF_COUNT_SW_CPU_CLOCK,
		Bits:   unix.PerfBitFreq,
		Sample: uint64(1),
	}

	fd, err := unix.PerfEventOpen(&attr,
		-1, // Any pid
		0,  // We can't specify CPU -1 and pid -1, so we just pick CPU 0 for this example
		-1, // group fd
		unix.PERF_FLAG_FD_CLOEXEC)

	if err != nil {
		log.Fatalf("open perf event: %w", err)
	}	

	opts := link.RawLinkOptions{
		Target:  fd,
		Program: objs.BpfLifePerfEvent,
		Attach:  ebpf.AttachPerfEvent,
	}

	return link.AttachRawLink(opts)
}

// Trigger the Game of Life using a port
func portSetup(port int, objs *lifeObjects) (link.Link, error) {
	le_port := (port >> 8) + ((port & 0xff) << 8)
	params := lifeUserParams{
		Port: uint16(le_port),
	}

	err := objs.Params.Put(uint32(0), params)
	if err != nil {
		log.Fatalf("failed to set args %v", err)
	}

	// Get the first-mounted cgroupv2 path.
	cgroupPath, err := detectCgroupPath()
	if err != nil {
		log.Fatal(err)
	}

	// Link the bpf_life program to the cgroup.
	return link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: objs.BpfLife,
	})
}

func main() {
	var port int

	// Port 65137 is 0x71fe in hex
	flag.IntVar(&port, "port", 0, "Specify port 65137 to kick off Game of Life with a network event and schedule with BPF timers.")
	flag.Parse()

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Println(err)
		log.Fatal("Are you running as root?")
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := lifeObjects{}
	if err := loadLifeObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Set up the eBPF program to be triggered by either a port or perf events.
	var err error
	var l link.Link
	if port != 0 {
		l, err = portSetup(port, &objs)
		fmt.Printf("Waiting for packets on port %d...\n", port)
	} else {
		l, err = perfSetup(&objs)
		fmt.Printf("Waiting for perf events...\n")
	}

	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()	

	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// The eBPF program writes game of life state to a ring buffer.
	rd, err := ringbuf.NewReader(objs.LifeRingbuf)
	if err != nil {
		log.Fatalf("new ringbuf reader failed: %v", err)
	}

	// Close the reader when the process receives a signal.
	go func() {
		<-stopper
		if err := rd.Close(); err != nil {
			log.Fatalf("closing ringbuf reader: %v", err)
		}
	}()

	// Read from the ring buffer and print the Game of Life state.
	readLoop(rd)
}

// detectCgroupPath returns the first-found mount point of type cgroup2
// and stores it in the cgroupPath global variable.
func detectCgroupPath() (string, error) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		// example fields: cgroup2 /sys/fs/cgroup/unified cgroup2 rw,nosuid,nodev,noexec,relatime 0 0
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) >= 3 && fields[2] == "cgroup2" {
			return fields[1], nil
		}
	}

	return "", errors.New("cgroup2 not mounted")
}
