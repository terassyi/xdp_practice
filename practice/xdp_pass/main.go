package main

import (
	"fmt"
	"github.com/dropbox/goebpf"
	"os"
	"os/signal"
)

//var iface = flag.String("iface", "", "Interface to bind XDP program to")

func main() {
	//flag.Parse()
	fmt.Println("\nXDP pass example program\n")

	bpf := goebpf.NewDefaultEbpfSystem()
	if err := bpf.LoadElf("./xdp_prog/xdp_pass.o"); err != nil {
		panic(err)
	}

	xdp := bpf.GetProgramByName("xdp_pass")
	if xdp == nil {
		panic("xdp program is not found")
	}

	if err := xdp.Load(); err != nil {
		panic(err)
	}
	if err := xdp.Attach("eth1"); err != nil {
		panic(err)
	}
	defer xdp.Detach()

	// Add CTRL+C handler
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)

	go func() {
		select {}
	}()

	// Wait until Ctrl+C pressed
	<-ctrlC
}
