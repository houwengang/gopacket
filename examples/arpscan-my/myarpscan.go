package main

import (
	"bytes"
	"errors"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	// Get a list of all interfaces.
	ifaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}

	var wg sync.WaitGroup
	for _, iface := range ifaces {
		if iface.Name == "vethb" {
			wg.Add(1)
			// Start up a scan on each interface.
			go func(iface net.Interface) {
				defer wg.Done()
				if err := myscan(&iface); err != nil {
					log.Printf("interface %v: %v", iface.Name, err)
				}
			}(iface)
		}
	}
	// Wait for all interfaces' scans to complete.  They'll try to run
	// forever, but will stop on an error, so if we get past this Wait
	// it means all attempts to write have failed.
	wg.Wait()
}

// scan scans an individual interface's local network for machines using ARP requests/replies.
//
// scan loops forever, sending packets out regularly.  It returns an error if
// it's ever unable to write a packet.
func myscan(iface *net.Interface) error {
	// We just look for IPv4 addresses, so try to find if the interface has one.
	var addr *net.IPNet
	if addrs, err := iface.Addrs(); err != nil {
		return err
	} else {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					addr = &net.IPNet{
						IP:   ip4,
						Mask: ipnet.Mask[len(ipnet.Mask)-4:],
					}
					break
				}
			}
		}
	}
	// Sanity-check that the interface has a good address.
	if addr == nil {
		return errors.New("no good IP network found")
	} else if addr.IP[0] == 127 {
		return errors.New("skipping localhost")
	} else if addr.Mask[0] != 0xff || addr.Mask[1] != 0xff {
		return errors.New("mask means network is too large")
	}
	log.Printf("Using network range %v for interface %v", addr, iface.Name)

	// Open up a pcap handle for packet reads/writes.
	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer handle.Close()

	// Start up a goroutine to read in packet data.
	stop := make(chan struct{})
	go myreadARP(handle, iface, stop)
	defer close(stop)
	for {
		time.Sleep(10 * time.Second)
	}
}

// readARP watches a handle for incoming ARP responses we might care about, and prints them.
//
// readARP loops until 'stop' is closed.
func myreadARP(handle *pcap.Handle, iface *net.Interface, stop chan struct{}) {
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		var packet gopacket.Packet
		select {
		case <-stop:
			return
		case packet = <-in:
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arp := arpLayer.(*layers.ARP)
			if bytes.Equal([]byte(iface.HardwareAddr), arp.SourceHwAddress) {
				log.Printf("This is a packet is %v", arp.Operation)
				continue
			}
			// Note:  we might get some packets here that aren't responses to ones we've sent,
			// if for example someone else sends US an ARP request.  Doesn't much matter, though...
			// all information is good information :)
			log.Printf("IP %v is at %v", net.IP(arp.SourceProtAddress), net.HardwareAddr(arp.SourceHwAddress))
			log.Printf("Dst IP %v is at %v", net.IP(arp.DstProtAddress), net.HardwareAddr(arp.DstHwAddress))

			aMac, _ := net.ParseMAC("00:50:56:b4:50:2e")
			log.Printf("dst ip: %v", net.IP(arp.DstProtAddress).String())
			if net.IP(arp.DstProtAddress).String() == "192.168.0.20" {
				log.Print("write arp")
				eth := layers.Ethernet{
					SrcMAC:       iface.HardwareAddr,
					DstMAC:       net.HardwareAddr(arp.SourceHwAddress),
					EthernetType: layers.EthernetTypeARP,
				}
				log.Printf("src mac: %v", []byte(aMac))
				log.Printf("dst mac: %v", arp.SourceHwAddress)
				log.Printf("src ip: %v", []byte(net.IP(arp.DstProtAddress)))
				log.Printf("dst ip: %v", []byte(net.IP(arp.SourceProtAddress)))
				arp := layers.ARP{
					AddrType:          layers.LinkTypeEthernet,
					Protocol:          layers.EthernetTypeIPv4,
					HwAddressSize:     6,
					ProtAddressSize:   4,
					Operation:         layers.ARPReply,
					SourceHwAddress:   []byte(aMac),
					DstHwAddress:      []byte(net.HardwareAddr(arp.SourceHwAddress)),
					SourceProtAddress: []byte(net.IP(arp.DstProtAddress)),
					DstProtAddress:    []byte(net.IP(arp.SourceProtAddress)),
				}
				// Set up buffer and options for serialization.
				buf := gopacket.NewSerializeBuffer()
				opts := gopacket.SerializeOptions{
					FixLengths:       true,
					ComputeChecksums: true,
				}
				// Send one packet for every address.
				gopacket.SerializeLayers(buf, opts, &eth, &arp)
				if err := handle.WritePacketData(buf.Bytes()); err != nil {
					log.Print("failed")
				}
			}
		}
	}
}
