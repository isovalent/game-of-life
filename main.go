package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
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
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go life bpf_life.c -- -I../headers

type MsgLifeEventPart struct {
	Cells         [2048]uint8
	Part          uint32
	Width         uint32
	Height        uint32
	LengthInBytes uint32
}

type MsgLifeEvent struct {
	Cells         []uint8
	Width         uint32
	Height        uint32
	LengthInBytes uint32
}

func handleLife(r *bytes.Reader) (error) {
	m := MsgLifeEvent{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		return err
	}

	return nil
}

func printCells(e *MsgLifeEvent) {
	fmt.Printf("\033[H")
	for x := uint32(0); x < e.Width; x++ {
		fmt.Printf("%d ", x);
	}

	for y := uint32(0); y < e.Height; y++ {
		fmt.Printf("%d ", y);
		for x := uint32(0); x < e.Width; x++ {
			state := e.Cells[x+(y*e.Width)] & 0x01;

			if state != 0 {
				fmt.Printf("\033[07m  \033[m")
			} else {
				fmt.Printf("  ")
			}
		}
		fmt.Printf("\033[E")
	}
}

func readLoop(rd *ringbuf.Reader) {
	// With ringbuf up read forever until errors
	var eventPart1 MsgLifeEventPart
	var eventPart2 MsgLifeEventPart
	var event MsgLifeEvent
	var last MsgLifeEvent

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				fmt.Printf("received signal, exiting..\n")
				return
			}
			fmt.Printf("reading from reader: %s\n", err)
			continue
		}
		err = binary.Read(bytes.NewBuffer(record.RawSample), binary.NativeEndian, &eventPart1)
		if err != nil {
			fmt.Printf("parsing perfring error1\n")
			continue
		}

		record, err = rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				fmt.Printf("received signal, exiting..\n")
				return
			}
			fmt.Printf("reading from reader: %s\n", err)
			continue
		}
		err = binary.Read(bytes.NewBuffer(record.RawSample), binary.NativeEndian, &eventPart2)
		if err != nil {
			fmt.Printf("parsing perfring error2\n")
			continue
		}

		event.Width = eventPart2.Width
		event.Height = eventPart2.Height
		event.LengthInBytes = eventPart2.LengthInBytes

		event.Cells = nil
		event.Cells = append(event.Cells, eventPart1.Cells[:]...)
		event.Cells = append(event.Cells, eventPart2.Cells[:]...)

		/*
		for j := uint32(0); j < last.Width * last.Height; j++ {
			if event.Cells[j] != last.Cells[j] {
				fmt.Printf("Change @ %d: %d -> %d\n", j, event.Cells[j], last.Cells[j]);
			}
		}
		*/
		printCells(&event)
		last = event;
		fmt.Printf("Life Record received: %d x %d\n", last.Width, last.Height)
	}
}

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := lifeObjects{}
	if err := loadLifeObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Get the first-mounted cgroupv2 path.
	cgroupPath, err := detectCgroupPath()
	if err != nil {
		log.Fatal(err)
	}

	// Link the count_egress_packets program to the cgroup.
	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: objs.BpfLife,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	log.Println("Waiting for events..")

	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
		
	rd, err := ringbuf.NewReader(objs.LifeRingbuf)
	if err != nil {
		fmt.Printf("new ringbuf reader failed: %w", err)
		return
	}

	// Close the reader when the process receives a signal, which will exit
	// the read loop.
	go func() {
		<-stopper

		if err := rd.Close(); err != nil {
			log.Fatalf("closing ringbuf reader: %s", err)
		}
	}()

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