// #include <linux/bpf.h>
#include <asm/types.h>
// #include <netinet/if_ether.h>
// #include <net/ethernet.h>
// #include <netinet/ip.h>
#include "bpf_helpers.h"

// Ethernet header
struct ethhdr {
  __u8 h_dest[6];
  __u8 h_source[6];
  __u16 ether_type;
} __attribute__((packed));

// IPv4 header
struct iphdr {
  __u8 ihl : 4;
  __u8 version : 4;
  __u8 tos;
  __u16 tot_len;
  __u16 id;
  __u16 frag_off;
  __u8 ttl;
  __u8 protocol;
  __u16 check;
  __u32 saddr;
  __u32 daddr;
} __attribute__((packed));



struct perf_event_item {
    __u32 src_ip, dst_ip;
    // u16 src_port, dst_port;
};

// PerfEvent eBPF map
BPF_MAP_DEF(perfmap) = {
    .map_type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .max_entries = 128,
};
BPF_MAP_ADD(perfmap);
_Static_assert(sizeof(struct perf_event_item) == 8, "wrong size of perf_event_item");

SEC("xdp")
int xdp_dump(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    __u64 packet_size = data_end - data;

    struct ethhdr *ethhdr = data;
    if (data + sizeof(*ethhdr) > data_end) {
        return XDP_ABORTED;
    }

    if (ethhdr->ether_type != 0x08) {
        return XDP_PASS;
    }

    data += sizeof(*ethhdr);
    struct iphdr *iphdr = data;
    if (data + sizeof(*iphdr) > data_end) {
        return XDP_ABORTED;
    }
    // if (iphdr->protocol != IPPROTO_TCP) {
    //     return XDP_PASS;
    // }
    
    data += iphdr->ihl * 4;

    struct perf_event_item event = {
        .src_ip = iphdr->saddr,
        .dst_ip = iphdr->daddr,
    };

    __u64 flags = BPF_F_CURRENT_CPU | (packet_size << 32);
    bpf_perf_event_output(ctx, &perfmap, flags, &event, sizeof(event));

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
