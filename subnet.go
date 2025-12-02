package main

import (
	"fmt"
	"math/bits"
)

func subnets(network uint32, mask1, mask2 int) {
	mask1Uint := cidrToMask(mask1)
	mask2Uint := cidrToMask(mask2)

	if optHTML {
		fmt.Print("<table border=\"0\" cellspacing=\"0\" cellpadding=\"0\">\n")
	}

	printLine("Netmask", mask2Uint, mask2Uint, mask1Uint, mask2, mask1, true)
	printLine("Wildcard", ^mask2Uint, mask2Uint, mask1Uint, mask2, mask1, false)

	if optHTML {
		fmt.Print("</table>\n")
	}

	fmt.Println()

	subnetCount := 1 << (mask2 - mask1)
	subnetNum := 0

	for subnetNum < subnetCount && subnetNum < 1000 {
		net := network | (uint32(subnetNum) << (32 - mask2))
		fmt.Printf(" %d.\n", subnetNum+1)
		if optHTML {
			fmt.Print("<table border=\"0\" cellspacing=\"0\" cellpadding=\"0\">\n")
		}
		printNet(net, mask2Uint, mask2, mask1)
		if optHTML {
			fmt.Print("</table>\n")
		}
		subnetNum++
	}

	if subnetNum >= 1000 {
		if optHTML {
			fmt.Print("... stopped at 1000 subnets ...<br>\n")
		} else {
			fmt.Println("... stopped at 1000 subnets ...")
		}
	}

	hostn := (network | (^mask2Uint)) - network - 1
	if hostn < 1 {
		hostn = 1
	}

	if optHTML {
		fmt.Printf("\nSubnets:   <font color=\"#0000ff\">%d</font><br>\n", subnetCount)
		fmt.Printf("Hosts:     <font color=\"#0000ff\">%d</font><br>\n", uint64(hostn)*uint64(subnetCount))
	} else {
		fmt.Printf("\nSubnets:   %s%d%s\n", setColor(quadsColor), subnetCount, setColor(normlColor))
		fmt.Printf("Hosts:     %s%d%s\n", setColor(quadsColor), uint64(hostn)*uint64(subnetCount), setColor(normlColor))
	}
}

func supernet(network uint32, mask1, mask2 int) {
	mask2Uint := cidrToMask(mask2)
	network = network & mask2Uint

	printLine("Netmask", mask2Uint, mask2Uint, cidrToMask(mask1), mask2, mask1, true)
	printLine("Wildcard", ^mask2Uint, mask2Uint, cidrToMask(mask1), mask2, mask1, false)

	fmt.Println()

	printNet(network, mask2Uint, mask2, mask1)
}

func splitNetwork(network uint32, mask1, mask2 int, sizes []int) {
	mask1Uint := cidrToMask(mask1)

	type netInfo struct {
		size int
		net  uint32
		mask int
	}

	var nets []netInfo
	neededAddresses := 0

	for _, size := range sizes {
		neededSize := round2PowerOf2(size + 2)
		nets = append(nets, netInfo{
			size: neededSize,
			net:  0,
			mask: size2BitCountMask(neededSize),
		})
		neededAddresses += neededSize
	}

	// Sort by size descending
	for k := 0; k < len(nets)-1; k++ {
		for j := k + 1; j < len(nets); j++ {
			if nets[k].size < nets[j].size {
				nets[k], nets[j] = nets[j], nets[k]
			}
		}
	}

	currentNet := network
	for i := range nets {
		nets[i].net = currentNet
		currentNet += uint32(nets[i].size)
	}

	for i, size := range sizes {
		fmt.Printf("%d. Requested size: %d hosts\n", i+1, size)
		printLine("Netmask", cidrToMask(nets[i].mask), cidrToMask(nets[i].mask), mask1Uint, nets[i].mask, mask2, false)
		printNet(nets[i].net, cidrToMask(nets[i].mask), nets[i].mask, mask2)
	}

	usedMask := size2BitCountMask(neededAddresses)
	if usedMask < mask1 {
		fmt.Println("Network is too small")
	}

	fmt.Printf("Needed size:  %d addresses.\n", neededAddresses)
	fmt.Printf("Used network: %s/%d\n", uint32ToIP(network).String(), usedMask)
	fmt.Println("Unused:")
	broadcast := network | (^mask1Uint)
	deaggregate(currentNet, broadcast)
}

func round2PowerOf2(n int) int {
	if n <= 0 {
		return 1
	}
	return 1 << bits.Len(uint(n-1))
}

func size2BitCountMask(size int) int {
	if size <= 0 {
		return 32
	}
	return 32 - bits.Len(uint(size-1))
}

func deaggregate(start, end uint32) {
	base := start
	for base <= end {
		step := 0
		for step < 32 {
			test := base | (uint32(1) << step)
			if test != base {
				break
			}
			mask := ^(uint32(1)<<(32-step) - 1)
			if (base | mask) > end {
				break
			}
			step++
		}
		fmt.Printf("%s/%d\n", uint32ToIP(base).String(), 32-step)
		base += uint32(1) << step
	}
}
