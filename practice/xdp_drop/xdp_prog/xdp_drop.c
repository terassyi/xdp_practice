#include <linux/bpf.h>
#include "bpf_helpers.h"

SEC("xdp")
int xdp_drop(struct xdp_md *ctx) {
	return XDP_DROP;
}