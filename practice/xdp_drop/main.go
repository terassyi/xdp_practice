package main

import (
	"fmt"
	"github.com/dropbox/goebpf"
	"os"
	"os/signal"
)

func main() {
	fmt.Println("xpd drop example program")
	bpf := goebpf.NewDefaultEbpfSystem()
	if err := bpf.LoadElf("./xdp_prog/xdp_drop.o"); err != nil {
		panic(err)
	}
	xdp := bpf.GetProgramByName("xdp_drop")
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

