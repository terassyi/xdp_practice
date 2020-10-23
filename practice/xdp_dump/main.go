package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/signal"

	"github.com/dropbox/goebpf"
)

type perfEventItem struct {
	SrcIP, DstIP uint32
}

const metadataSize int = 8

func main() {
	fmt.Println("xdp dump example program")

	bpf := goebpf.NewDefaultEbpfSystem()
	if err := bpf.LoadElf("./xdp_prog/xdp_dump.o"); err != nil {
		panic(err)
	}
	printBpfInfo(bpf)

	perfMap := bpf.GetMapByName("perfmap")
	if perfMap == nil {
		panic(fmt.Errorf("perfmap is not found"))
	}

	xdp := bpf.GetProgramByName("xdp_dump")
	if xdp == nil {
		panic(fmt.Errorf("xdp program is not found"))
	}

	if err := xdp.Load(); err != nil {
		panic(err)
	}

	if err := xdp.Attach("eth1"); err != nil {
		panic(err)
	}
	defer xdp.Detach()

	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)

	perf, _ := goebpf.NewPerfEvents(perfMap)
	perfEvent, err := perf.StartForAllProcessesAndCPUs(4096)
	if err != nil {
		panic(err)
	}

	fmt.Println("XDP program successfully loaded and attached.\n")

	go func() {
		var event perfEventItem
		for {
			if eventData, ok := <-perfEvent; ok {
				reader := bytes.NewReader(eventData)
				// data, err := ioutil.ReadAll(reader)
				// if err != nil {
				// 	panic(err)
				// }
				// fmt.Println(hex.Dump(data))
				binary.Read(reader, binary.LittleEndian, &event)
				fmt.Printf("[INFO] src=%v dst=%v\n", intToIPv4(event.SrcIP), intToIPv4(event.DstIP))
				if len(eventData)-metadataSize > 0 {
					// event contains packet sample as well
					fmt.Println(hex.Dump(eventData[metadataSize:]))
				}
			} else {
				break
			}
		}
	}()

	<-ctrlC

	perf.Stop()
	fmt.Println("xdp program is stopped.")
}

func printBpfInfo(bpf goebpf.System) {
	fmt.Println("Maps:")
	for _, item := range bpf.GetMaps() {
		m := item.(*goebpf.EbpfMap)
		fmt.Printf("\t%s: %v, Fd %v\n", m.Name, m.Type, m.GetFd())
	}
	fmt.Println("\nPrograms:")
	for _, prog := range bpf.GetPrograms() {
		fmt.Printf("\t%s: %v, size %d, license \"%s\"\n",
			prog.GetName(), prog.GetType(), prog.GetSize(), prog.GetLicense(),
		)

	}
	fmt.Println()
}

func intToIPv4(ip uint32) net.IP {
	res := make([]byte, 4)
	binary.LittleEndian.PutUint32(res, ip)
	return net.IP(res)
}
