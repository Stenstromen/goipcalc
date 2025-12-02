package main

import (
	"fmt"
	"math/big"
	"net"
	"strings"
)

func ipcalc6(address net.IP, mask int) {
	printSummary6(address, mask)
}

func printSummary6(address net.IP, netmask int) {
	prefix := address.Mask(net.CIDRMask(netmask, 128))

	fmt.Printf("%-9s", "Address:")
	fmt.Printf("%-40s", address.String())
	fmt.Printf("%-130s", ntoB6(address))
	fmt.Println()

	fmt.Printf("%-9s", "Netmask:")
	fmt.Printf("%-40s", fmt.Sprintf("%d", netmask))
	fmt.Printf("%-130s", ntoB6(prefixLenToN6(netmask)))
	fmt.Println()

	fmt.Printf("%-9s", "Prefix:")
	fmt.Printf("%-40s", fmt.Sprintf("%s/%d", prefix.String(), netmask))
	fmt.Printf("%-130s", ntoB6(prefix))
	fmt.Println()
	fmt.Println()
}

func ntoB6(ip net.IP) string {
	var b strings.Builder
	ip16 := ip.To16()
	for i := 15; i >= 0; i-- {
		byteVal := ip16[i]
		for j := 7; j >= 0; j-- {
			if (byteVal & (1 << j)) != 0 {
				b.WriteString("1")
			} else {
				b.WriteString("0")
			}
		}
		if i > 0 && i%2 == 0 {
			b.WriteString(":")
		}
	}
	return b.String()
}

func prefixLenToN6(prefixLen int) net.IP {
	n := big.NewInt(0)
	for i := 127; i > 127-prefixLen; i-- {
		n.Or(n, big.NewInt(0).Lsh(big.NewInt(1), uint(i)))
	}
	return bigIntToIP6(n)
}

func bigIntToIP6(n *big.Int) net.IP {
	ip := make(net.IP, 16)
	bytes := n.Bytes()
	copy(ip[16-len(bytes):], bytes)
	return ip
}
