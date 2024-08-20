//go:build ignore
// Copyright 2024 Isovalent, Inc. 
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

// Fix compilation error "field has incomplete type 'struct bpf_timer'""
// For some reason vmlinux.h does not have the definition of `struct bpf_timer` 
// even though it is present in /usr/src/linux-headers-5.15.0-107/include/uapi/linux/bpf.h 
struct bpf_timer {
	__u64 :64;
	__u64 :64;
} __attribute__((aligned(8)));

struct elem {
	struct bpf_timer t;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct elem);
	__uint(max_entries, 1);
} life_timer_array SEC(".maps");

#define CLOCK_MONOTONIC   1
#define MAX_CELL_MAP_SIZE 4096 
// #define SAMPLE_CELL_SIZE 2048
#define SAMPLE_CELL_SIZE 4096

struct cell_sample {
	char cells[SAMPLE_CELL_SIZE];
	unsigned int generation;
	unsigned int width;
	unsigned int height;
	unsigned int length_in_bytes;
};

struct cellmap {
	char cells[MAX_CELL_MAP_SIZE];
	char temp[MAX_CELL_MAP_SIZE];
	unsigned int width;
	unsigned int height;
	unsigned int length_in_bytes;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct cellmap);
} board SEC(".maps");

#define WIDTH 64
#define HEIGHT 64 
#define MASK 0xfff

int cell_math(unsigned int offset, int add)
{
	unsigned int xleft, xright, yup, ydown;
	char *cell_ptr;
	struct cellmap *m;
	int key = 0;

	m = bpf_map_lookup_elem(&board, &key);
	if (!m)
		return -1;

	cell_ptr = m->cells;

	if ((offset % WIDTH) == 0)
		xleft = (WIDTH - 1);
	else
		xleft = -1;

	if (offset % WIDTH == (WIDTH-1))
		xright = -(WIDTH - 1);
	else
		xright = 1;

	if (offset < WIDTH)
		yup = (WIDTH * (HEIGHT - 1));
	else
		yup = -WIDTH;

	if (offset > (WIDTH * (HEIGHT - 1)))
		ydown = -(WIDTH*(HEIGHT-1));
	else
		ydown = WIDTH;


	// bpf_printk("before cell_ptr[(%d)] -> %d\n", offset, cell_ptr[offset&MASK]);
	if (add > 0)
		cell_ptr[(offset & MASK)] |= 0x01;
	else
		cell_ptr[(offset & MASK)] &= ~0x01;
	// bpf_printk("after cell_ptr[(%d)] -> %d\n", offset, cell_ptr[offset&MASK]);

	cell_ptr[(offset + yup + xleft) & MASK] += add;
	cell_ptr[(offset + yup) & MASK] += add;
	cell_ptr[(offset + yup + xright) & MASK] += add;

	cell_ptr[(offset + xleft) & MASK] += add;
	cell_ptr[(offset + xright) & MASK] += add;

	cell_ptr[(offset + ydown + xleft) & MASK] += add;
	cell_ptr[(offset + ydown) & MASK] += add;
	cell_ptr[(offset + ydown + xright) & MASK] += add;

	return 0;
}

__attribute__((noinline))
int set_cell(unsigned int offset)
{
	return cell_math(offset, 2);
}

__attribute__((noinline))
int clear_cell(unsigned int offset)
{
	return cell_math(offset, -2);
}

__attribute__((noinline))
int random_init(void)
{
	struct cellmap *m;
	int percent, i;
	int key = 0;

	m = bpf_map_lookup_elem(&board, &key);
	if (!m)
		return -1;

	percent = 400;//(WIDTH * HEIGHT / 4);

	for (i = 0; i < percent; i++) {
		uint32_t rand = bpf_get_prandom_u32();

		set_cell(rand % (WIDTH *HEIGHT));
	}
	return 0;
}

int init_cellmap(void)
{
	struct cellmap *m;
	int h = HEIGHT;
	int w = WIDTH;
	int zero = 0;

	m = bpf_map_lookup_elem(&board, &zero);
	if (!m)
		return -1;

	m->width = w;
	m->height = h;
	m->length_in_bytes = w * h;

	random_init();

	return 0;
}

__attribute__((noinline))
int next_generation_x(unsigned int cell_off)
{
	unsigned char *cell_ptr;
	unsigned int x, count;
	struct cellmap *m;
	int key = 0;

	m = bpf_map_lookup_elem(&board, &key);
	if (!m)
		return -1;

	cell_ptr = (unsigned char *)m->temp;

	// bpf_printk("generate: x: %d -> %d\n", cell_off, cell_off % WIDTH);
	for (x = 0; x < WIDTH; x++) {
		if (cell_off > MAX_CELL_MAP_SIZE) {
			bpf_printk("cell_ff > MAX_CELL continue; %d\n", 0);
			continue;
		}

		if (!cell_ptr[cell_off]) {
			cell_off++;
			continue;
		}

		count = cell_ptr[cell_off] >> 1; // # of neighboring on-cells
		// bpf_printk("cellptr[%d] = %d\n", cell_off, count);
		if (cell_ptr[cell_off] & 0x01) {
			if ((count != 2) && (count != 3)){
				// bpf_printk("clear cell_off %d\n", cell_off);
				clear_cell(cell_off);
			}
		} else {
			if (count == 3) {
				// bpf_printk("set_cell %d\n", cell_off);
				set_cell(cell_off);
			}
		}
		cell_off++;
	}
	return cell_off;
}

// Ensure copy_cellmap is called before next gen. It about simplifying the
// routines for the verifier.
__attribute__((noinline))
int next_generation(void)
{
	unsigned int cell_off;
	unsigned int y;

	cell_off = 0;
	for (y=0; y < HEIGHT; y++) {
		cell_off = next_generation_x(cell_off);
	}
	return 0;
}
 
__attribute__((noinline))
int copy_cellmap(void)
{
	struct cellmap *m;
	int key = 0;

	m = bpf_map_lookup_elem(&board, &key);
	if (!m)
		return -1;

	for (int i = 0; i < m->length_in_bytes && i < MAX_CELL_MAP_SIZE; i++) {
		m->temp[i] = m->cells[i];
	}

	return 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096*4);
} life_ringbuf SEC(".maps");

unsigned int game_round = 0;

__attribute__((noinline))
int send_update(void)
{
	struct cell_sample *sample;
	struct cellmap *m, *r;
	long flags = 0;
	int key = 0;

	m = bpf_map_lookup_elem(&board, &key);
	if (!m)
		return -1;

	sample = (struct cell_sample *)bpf_ringbuf_reserve(&life_ringbuf, sizeof(*sample), 0);
	if (!sample) {
		bpf_printk("failed reserve ringbuf\n", 0);
		return 0;
	}

	for (int i = 0; i < m->length_in_bytes && i < SAMPLE_CELL_SIZE; i++) {
		sample->cells[i] = m->cells[i];
	}
	sample->generation = game_round;
	sample->width = m->width;
	sample->height = m->height;
	sample->length_in_bytes = m->length_in_bytes;
	bpf_ringbuf_submit(sample, flags);
	return 0;
}

static int do_game(void *map, int *key, struct bpf_timer *timer)
{
	int err;

	bpf_printk("Do Game %d\n", game_round++);
	err = copy_cellmap();
	if (err)
		return 0;

	bpf_printk("Next Generation %d\n", game_round);
	next_generation();
	bpf_printk("Send Update %d\n", game_round);
	send_update();

	bpf_timer_start(timer, 2000000000, 0);
	return 0;
}

int game(void)
{
	struct bpf_timer *arr_timer;
	int array_key = 0;
	int err;

	arr_timer = bpf_map_lookup_elem(&life_timer_array, &array_key);
	if (!arr_timer) {
		bpf_printk("!arr_timer error %d\n", 0);
		return -1;
	}

	err = bpf_timer_init(arr_timer, &life_timer_array, CLOCK_MONOTONIC);
	if (err) {
		bpf_printk("timer init err: %d\n", err);
		return 0;
	}
	bpf_timer_set_callback(arr_timer, do_game);
	bpf_timer_start(arr_timer, 2000000000 /* call timer_cb1 asap */, 0);
	return 0;
}

bool started = false;

SEC("cgroup_skb/egress")
int bpf_life(struct __sk_buff *skb)
{
	struct iphdr ip;
	struct tcphdr tcp;
	unsigned int tcp_off;

	// Only run once
	if (started)
		return 1;

	if (bpf_skb_load_bytes(skb, 0, &ip, sizeof(struct iphdr)) < 0)
		return 1;

	if (!ip.version)
		return 1;

	if (ip.protocol != IPPROTO_TCP)
		return 1;

	// IP headers can vary in length so this finds the start of the TCP header
	tcp_off = ip.ihl;
	tcp_off &= 0x0f;
	tcp_off *= 4;

	if (bpf_skb_load_bytes(skb, tcp_off, &tcp, sizeof(struct tcphdr)) < 0)
		return 1;

	// Kick off Game of Life by sending a TCP packet on port 0x71fe
	// for example, run: nc 127.0.0.1 65137
	if (tcp.source != 0x71fe)
		return 1;

	bpf_printk("Start life %d\n", 0);
	started = true;
	init_cellmap();
	send_update();
	bpf_printk("Start Game %d\n", 0);
	game();
	return 0; 
}
