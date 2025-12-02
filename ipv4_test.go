package main

import (
	"net"
	"testing"
)

func TestIPToUint32(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected uint32
	}{
		{"Zero IP", "0.0.0.0", 0},
		{"Max IP", "255.255.255.255", 0xFFFFFFFF},
		{"Localhost", "127.0.0.1", 0x7F000001},
		{"Private Class A", "10.0.0.1", 0x0A000001},
		{"Private Class B", "172.16.0.1", 0xAC100001},
		{"Private Class C", "192.168.0.1", 0xC0A80001},
		{"Public IP", "8.8.8.8", 0x08080808},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip).To4()
			result := ipToUint32(ip)
			if result != tt.expected {
				t.Errorf("ipToUint32(%s) = 0x%08X, want 0x%08X", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestUint32ToIP(t *testing.T) {
	tests := []struct {
		name     string
		value    uint32
		expected string
	}{
		{"Zero IP", 0, "0.0.0.0"},
		{"Max IP", 0xFFFFFFFF, "255.255.255.255"},
		{"Localhost", 0x7F000001, "127.0.0.1"},
		{"Private Class A", 0x0A000001, "10.0.0.1"},
		{"Private Class B", 0xAC100001, "172.16.0.1"},
		{"Private Class C", 0xC0A80001, "192.168.0.1"},
		{"Public IP", 0x08080808, "8.8.8.8"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := uint32ToIP(tt.value)
			if result.String() != tt.expected {
				t.Errorf("uint32ToIP(0x%08X) = %s, want %s", tt.value, result.String(), tt.expected)
			}
		})
	}
}

func TestIPRoundTrip(t *testing.T) {
	tests := []string{
		"0.0.0.0",
		"255.255.255.255",
		"127.0.0.1",
		"10.0.0.1",
		"172.16.0.1",
		"192.168.0.1",
		"8.8.8.8",
		"192.168.1.100",
	}

	for _, ipStr := range tests {
		t.Run(ipStr, func(t *testing.T) {
			ip := net.ParseIP(ipStr).To4()
			value := ipToUint32(ip)
			result := uint32ToIP(value)
			if !ip.Equal(result) {
				t.Errorf("Round trip failed: %s -> 0x%08X -> %s", ipStr, value, result.String())
			}
		})
	}
}

func TestCIDRToMask(t *testing.T) {
	tests := []struct {
		name     string
		cidr     int
		expected uint32
	}{
		{"CIDR 0", 0, 0x00000000},
		{"CIDR 8", 8, 0xFF000000},
		{"CIDR 16", 16, 0xFFFF0000},
		{"CIDR 24", 24, 0xFFFFFF00},
		{"CIDR 32", 32, 0xFFFFFFFF},
		{"CIDR 12", 12, 0xFFF00000},
		{"CIDR 20", 20, 0xFFFFF000},
		{"CIDR 28", 28, 0xFFFFFFF0},
		{"Invalid negative", -1, 0},
		{"Invalid too large", 33, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cidrToMask(tt.cidr)
			if result != tt.expected {
				t.Errorf("cidrToMask(%d) = 0x%08X, want 0x%08X", tt.cidr, result, tt.expected)
			}
		})
	}
}

func TestMaskToCIDR(t *testing.T) {
	tests := []struct {
		name     string
		mask     uint32
		expected int
	}{
		{"Mask 0", 0x00000000, 0},
		{"Mask /8", 0xFF000000, 8},
		{"Mask /16", 0xFFFF0000, 16},
		{"Mask /24", 0xFFFFFF00, 24},
		{"Mask /32", 0xFFFFFFFF, 32},
		{"Mask /12", 0xFFF00000, 12},
		{"Mask /20", 0xFFFFF000, 20},
		{"Mask /28", 0xFFFFFFF0, 28},
		{"Mask /30", 0xFFFFFFFC, 30},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := maskToCIDR(tt.mask)
			if result != tt.expected {
				t.Errorf("maskToCIDR(0x%08X) = %d, want %d", tt.mask, result, tt.expected)
			}
		})
	}
}

func TestCIDRMaskRoundTrip(t *testing.T) {
	for cidr := 0; cidr <= 32; cidr++ {
		t.Run(string(rune(cidr+'0')), func(t *testing.T) {
			mask := cidrToMask(cidr)
			result := maskToCIDR(mask)
			if result != cidr {
				t.Errorf("Round trip failed: CIDR %d -> mask 0x%08X -> CIDR %d", cidr, mask, result)
			}
		})
	}
}

func TestIsValidNetmask(t *testing.T) {
	tests := []struct {
		name     string
		mask     uint32
		expected bool
	}{
		{"Valid /0", 0x00000000, true},
		{"Valid /8", 0xFF000000, true},
		{"Valid /16", 0xFFFF0000, true},
		{"Valid /24", 0xFFFFFF00, true},
		{"Valid /32", 0xFFFFFFFF, true},
		{"Valid /12", 0xFFF00000, true},
		{"Valid /20", 0xFFFFF000, true},
		{"Valid /28", 0xFFFFFFF0, true},
		{"Invalid discontinuous", 0xFF00FF00, false},
		{"Invalid random", 0x12345678, false},
		{"Invalid middle zero", 0xFFFF00FF, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidNetmask(tt.mask)
			if result != tt.expected {
				t.Errorf("isValidNetmask(0x%08X) = %v, want %v", tt.mask, result, tt.expected)
			}
		})
	}
}

func TestParseNetmask(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
		wantErr  bool
	}{
		// CIDR notation
		{"CIDR /24", "24", 24, false},
		{"CIDR /24 with slash", "/24", 24, false},
		{"CIDR /8", "8", 8, false},
		{"CIDR /16", "16", 16, false},
		{"CIDR /32", "32", 32, false},
		{"CIDR /0", "0", 0, false},
		{"CIDR invalid negative", "-1", 0, true},
		{"CIDR invalid too large", "33", 0, true},

		// Dotted decimal notation
		{"Dotted /24", "255.255.255.0", 24, false},
		{"Dotted /16", "255.255.0.0", 16, false},
		{"Dotted /8", "255.0.0.0", 8, false},
		{"Dotted /32", "255.255.255.255", 32, false},
		{"Dotted /12", "255.240.0.0", 12, false},
		{"Dotted /20", "255.255.240.0", 20, false},
		{"Dotted /28", "255.255.255.240", 28, false},

		// Wildcard notation
		{"Wildcard /24", "0.0.0.255", 24, false},
		{"Wildcard /16", "0.0.255.255", 16, false},
		{"Wildcard /8", "0.255.255.255", 8, false},
		{"Wildcard /12", "0.15.255.255", 12, false},

		// Invalid cases
		{"Invalid string", "invalid", 0, true},
		{"Invalid IP", "256.256.256.256", 0, true},
		{"Invalid discontinuous", "255.0.255.0", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseNetmask(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseNetmask(%s) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && result != tt.expected {
				t.Errorf("parseNetmask(%s) = %d, want %d", tt.input, result, tt.expected)
			}
		})
	}
}

func TestGetClass(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected string
	}{
		{"Class A", "10.0.0.1", "A"},
		{"Class B", "172.16.0.1", "B"},
		{"Class C", "192.168.0.1", "C"},
		{"Class D", "224.0.0.1", "D"},
		{"Class E", "240.0.0.1", "E"},
		{"Public Class A", "1.1.1.1", "A"},
		{"Public Class B", "128.0.0.1", "B"},
		{"Public Class C", "192.0.0.1", "C"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip).To4()
			result := getClass(ip)
			if result != tt.expected {
				t.Errorf("getClass(%s) = %s, want %s", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestGetClassBits(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected int
	}{
		{"Class A", "10.0.0.1", 8},
		{"Class B", "172.16.0.1", 16},
		{"Class C", "192.168.0.1", 24},
		{"Class D", "224.0.0.1", 4},
		{"Class E", "240.0.0.1", 5},
		{"Public Class A", "1.1.1.1", 8},
		{"Public Class B", "128.0.0.1", 16},
		{"Public Class C", "192.0.0.1", 24},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip).To4()
			result := getClassBits(ip)
			if result != tt.expected {
				t.Errorf("getClassBits(%s) = %d, want %d", tt.ip, result, tt.expected)
			}
		})
	}
}

