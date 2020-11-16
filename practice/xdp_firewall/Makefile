GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
CLANG := clang
CLANG_INCLUDE := -I../../include

GO_SOURCE := main.go
GO_BINARY := main

EBPF_SOURCE := xdp_prog/xdp_firewall.c
EBPF_BINARY := xdp_prog/xdp_firewall.o

all: build_bpf build_go

build_bpf: $(EBPF_BINARY)

build_go: $(GO_BINARY)

clean:
	$(GOCLEAN)
	rm -f $(GO_BINARY)
	rm -f $(EBPF_BINARY)

$(EBPF_BINARY): $(EBPF_SOURCE)
	$(CLANG) $(CLANG_INCLUDE) -O2 -target bpf -c $^  -o $@

$(GO_BINARY): $(GO_SOURCE)
	$(GOBUILD) -v -o $@
