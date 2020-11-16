#include "bpf_helpers.h"
#include <asm/types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#ifdef memcpy
#define __builtin_memcpy

BPF_MAP_DEF(tx_port) = {
    .map_type = BPF_MAP_TYPE_DEVMAP,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 256,
};

BPF_MAP_DEF(redirect_params) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .key_size = ETH_ALEN,
    .value_size = ETH_ALEN,
    .max_entries = 1,
};

static __always_inline__ void swap_src_dst_mac(struct ethhdr *eth) {
    __u64 tmp = eth->h_dest;
    eth->h_dest = eth->h_source;
    eth->h_source = tmp;
}

static __always_inline__ void swap_src_dst_ipv4(struct iphdr *iph) {
    __u32 tmp = iph->daddr;
    iph->daddr = iph->saddr;
    iph->saddr = tmp;
}

static __always_inline__ void swap_src_dst_ipv6(struct ipv6hdr *ipv6h) {
    in6_addr tmp = ipv6h->daddr;
    ipv6h->daddr = ipv6h->saddr;
    ipv6h->saddr = tmp;
}

SEC("xdp")
int xdp_redirect(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    __u64 packet_size = data_end - data;
    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end) {
        return XDP_ABORTED;
    }

    


}
