#include "bpf_helpers.h"

#define MAX_RULES 15

struct ethhdr {
    __u8 h_dest[6];
    __u8 h_source[6];
    __u16 ether_type;
} __attribute__((packed));

struct iphdr {
    __u8 ihl: 4;
    __u8 version: 4;
    __u8 tos;
    __u16 tot_len;
    __u16 id;
    __u16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __u8 check;
    __u32 saddr;
    __u32 daddr;
} __attribute__((packed));

BPF_MAP_DEF(matches) = {
    .map_type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = MAX_RULES,
};
BPF_MAP_ADD(matches);

BPF_MAP_DEF(blacklist) = {
    .map_type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(__u64),
    .value_size = sizeof(__u32),
    .max_entries = MAX_RULES,
};
BPF_MAP_ADD(blacklist);

SEC("xdp")
int firewall(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *ether = data;
    if (data + sizeof(struct ethhdr) > data_end) {
        return XDP_ABORTED;
    }
    if (ether->ether_type != 0x0800) {
        return XDP_DROP;
    }

    data += sizeof(*ether);
    struct iphdr *iph = data;
    if (data + sizeof(struct iphdr) > data_end) {
        return XDP_ABORTED;
    }

    struct {
        __u32 prefixlen;
        __u32 saddr;
    } key;
    key.prefixlen = 32;
    key.saddr = iph->saddr;

    __u64 *rule_index = bpf_map_lookup_elem(&blacklist, &key);
    if (rule_index) {
        __u32 *index = *(__u32 *)(rule_index);
        __u64 *counter = bpf_map_lookup_elem(&matches, &index);
        if (counter) {
            (*counter)++;
        }
        return XDP_DROP;
    }
    return XDP_PASS;

}

char _license[] SEC("license") = "GPLv2";
