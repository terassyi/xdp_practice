package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/dropbox/goebpf"
)

type ipAddressList []string

func (i *ipAddressList) String() string {
	return fmt.Sprintf("%+v", *i)
}

func (i *ipAddressList) Set(value string) error {
	if len(*i) == 16 {
		return errors.New("Up to 16 IPv4 addresses supported")
	}
	if !strings.Contains(value, "/") {
		value += "/32"
	}
	if strings.Contains(value, ":") {
		return fmt.Errorf("%s is not an IPv4 address", value)
	}
	_, _, err := net.ParseCIDR(value)
	if err != nil {
		return err
	}
	// Valid, add to the list
	*i = append(*i, value)
	return nil
}

var (
	iface  string
	ipList ipAddressList
)

func init() {
	flag.StringVar(&iface, "iface", "", "interface to bind xdp program")
}

func main() {
	flag.Var(&ipList, "drop", "IPv4 CIDR to DROP traffic from, repeatable")
	flag.Parse()
	if iface == "" {
		panic("-iface is required.")
	}
	if len(ipList) == 0 {
		panic("at least one IPv4 address to DROP required (-drop)")
	}
	bpf := goebpf.NewDefaultEbpfSystem()
	if err := bpf.LoadElf("./xdp_prog/xdp_firewall.o"); err != nil {
		panic(err)
	}
	printBpfInfo(bpf)

	matches := bpf.GetMapByName("matches")
	if matches == nil {
		panic("eBPF map matches is not found")
	}
	blacklist := bpf.GetMapByName("blacklist")
	if blacklist == nil {
		panic("eBPF map blacklist is not found")
	}
	xdp := bpf.GetProgramByName("firewall")
	if xdp == nil {
		panic("eBPF program firewall is not found")
	}
	fmt.Println("Blacklisting IPv4 addresses...")
	for index, ip := range ipList {
		fmt.Printf("\t%s\n", ip)
		err := blacklist.Insert(goebpf.CreateLPMtrieKey(ip), index)
		if err != nil {
			panic(err)
		}
	}
	fmt.Println()
	if err := xdp.Load(); err != nil {
		panic(err)
	}
	if err := xdp.Attach(iface); err != nil {
		panic(err)
	}
	defer xdp.Detach()

	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)
	fmt.Println("XDP program successfully loaded and attached. Counters refreshed every second.")
	fmt.Println("Press CTRL+C to stop.")
	fmt.Println()

	ticker := time.NewTicker(1 * time.Second)
	for {
		select {
		case <-ticker.C:
			fmt.Println("IP                 DROPs")
			for i := 0; i < len(ipList); i++ {
				value, err := matches.LookupInt(i)
				if err != nil {
					panic(err)
				}
				fmt.Printf("%18s    %d\n", ipList[i], value)
			}
			fmt.Println()
		case <-ctrlC:
			fmt.Println("\nDetaching program and exit")
			return
		}
	}
}

func printBpfInfo(bpf goebpf.System) {
	fmt.Println("Maps:")
	for _, item := range bpf.GetMaps() {
		fmt.Printf("\t%s: %v, Fd %v\n", item.GetName(), item.GetType(), item.GetFd())
	}
	fmt.Println("\nPrograms:")
	for _, prog := range bpf.GetPrograms() {
		fmt.Printf("\t%s: %v, size %d, license \"%s\"\n",
			prog.GetName(), prog.GetType(), prog.GetSize(), prog.GetLicense(),
		)

	}
	fmt.Println()
}
