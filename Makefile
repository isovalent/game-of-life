TARGET = life
ARCH = $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_C = bpf_${TARGET}.c
BPF_OBJ = ${BPF_TARGET:=.o}

USER_GO = main.go
USER_SKEL = ${TARGET}_bpfel.go ${TARGET}_bpfeb.go

all: $(TARGET) $(BPF_OBJ)
.PHONY: all

$(TARGET): $(USER_GO) $(USER_SKEL) 
	go build .

$(BPF_OBJ): $(BPF_C) vmlinux.h 
	clang \
	    -target bpf \
	    -D __BPF_TRACING__ \
        -D __TARGET_ARCH_$(ARCH) \
	    -Wall \
	    -O2 -g -o $@ -c $<
	llvm-strip -g $@

$(USER_SKEL):
	go generate .

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
