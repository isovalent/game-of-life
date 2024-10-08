TARGET = life
ARCH = $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_C = bpf_${TARGET}.c
BPF_OBJ = ${TARGET}_bpfel.o

USER_GO = main.go

$(TARGET): vmlinux.h $(USER_GO) $(BPF_OBJ) 
	go build 

$(BPF_OBJ): $(BPF_C)
	go generate

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
