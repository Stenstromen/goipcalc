package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIP(n uint32) net.IP {
	return net.IP{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}

func cidrToMask(cidr int) uint32 {
	if cidr < 0 || cidr > 32 {
		return 0
	}
	return ^(uint32(1)<<(32-cidr) - 1)
}

func maskToCIDR(mask uint32) int {
	cidr := 0
	for i := 0; i < 32; i++ {
		if (mask & (uint32(1) << (31 - i))) != 0 {
			cidr++
		} else {
			break
		}
	}
	return cidr
}

func parseNetmask(arg string) (int, error) {
	// Remove leading slash if present
	arg = strings.TrimPrefix(arg, "/")

	// Try CIDR notation (e.g., "24" or "/24")
	if cidr, err := strconv.Atoi(arg); err == nil {
		if cidr >= 0 && cidr <= 32 {
			return cidr, nil
		}
		return 0, fmt.Errorf("invalid CIDR: %d", cidr)
	}

	// Try dotted decimal notation (e.g., "255.255.255.0")
	if ip := net.ParseIP(arg); ip != nil {
		ip = ip.To4()
		if ip != nil {
			mask := ipToUint32(ip)
			// Check if it's a valid netmask
			if isValidNetmask(mask) {
				return maskToCIDR(mask), nil
			}
			// Try wildcard mask
			mask = ^mask
			if isValidNetmask(mask) {
				return maskToCIDR(mask), nil
			}
		}
	}

	return 0, fmt.Errorf("invalid netmask: %s", arg)
}

func isValidNetmask(mask uint32) bool {
	sawZero := false
	for i := 0; i < 32; i++ {
		bit := (mask >> (31 - i)) & 1
		if bit == 0 {
			sawZero = true
		} else {
			if sawZero {
				return false
			}
		}
	}
	return true
}

func getClass(ip net.IP) string {
	ip = ip.To4()
	n := ipToUint32(ip)
	class := 1
	for class <= 5 {
		if (n & (uint32(1) << (32 - class))) == (uint32(1) << (32 - class)) {
			class++
		} else {
			break
		}
	}
	if class > 5 {
		return "invalid"
	}
	return string(rune(class + 64))
}

func getClassBits(ip net.IP) int {
	ip = ip.To4()
	n := ipToUint32(ip)
	class := 1
	for class <= 5 {
		if (n & (uint32(1) << (32 - class))) == (uint32(1) << (32 - class)) {
			class++
		} else {
			break
		}
	}
	if class > 5 {
		return 0
	}
	return classBits[class]
}
