#include <linux/bpf.h>
#include "bpf_helpers.h"

SEC("xdp")
int xdp_pass(struct xdp_md *ctx) {
	return XDP_PASS;
}
