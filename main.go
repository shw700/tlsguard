package main

import (
	"os"
	"os/signal"
	"syscall"
	"fmt"
	"log"

	nfqueue "github.com/subgraph/go-nfnetlink/nfqueue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func runFilter() {
	q := nfqueue.NewNFQueue(1)

	ps, err := q.Open()

	if err != nil {
		log.Fatal("Error opening NFQueue:", err)
	}
	defer q.Close()

	go func() {
		for p := range ps {
			ipLayer := p.Packet.Layer(layers.LayerTypeIPv4)
			if ipLayer == nil {
				continue
			}

			ip, _ := ipLayer.(*layers.IPv4)
			if ip == nil {
				continue
			}

			if ip.Version == 6 {
				ip6p := gopacket.NewPacket(ip.LayerContents(), layers.LayerTypeIPv6, gopacket.Default)
				p.Packet = ip6p

			}

			filterPacket(p)
		}
	}()

	for {
	}
}

func main() {
	if os.Geteuid() != 0 {
		log.Fatal("Server Must be run as root")
	}

	fmt.Println("Starting netfilter queue...")
	runFilter()

	sigKillChan := make(chan os.Signal, 1)
	signal.Notify(sigKillChan, os.Interrupt, os.Kill)

	sigHupChan := make(chan os.Signal, 1)
	signal.Notify(sigHupChan, syscall.SIGHUP)

	for {
		select {
		case <-sigHupChan:
		case <-sigKillChan:
			return
		}
	}

}
