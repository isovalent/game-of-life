TARGET = life
ARCH = $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_C = bpf_${TARGET}.c

USER_GO = main.go

$(TARGET): $(USER_GO) $(BPF_C) vmlinux.h
	go generate
	go build 

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
