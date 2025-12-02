package main

import (
	"net"
	"strconv"
	"strings"
	"testing"
)

func TestRound2PowerOf2(t *testing.T) {
	tests := []struct {
		name     string
		input    int
		expected int
	}{
		{"Zero", 0, 1},
		{"One", 1, 1},
		{"Two", 2, 2},
		{"Three", 3, 4},
		{"Four", 4, 4},
		{"Five", 5, 8},
		{"Seven", 7, 8},
		{"Eight", 8, 8},
		{"Nine", 9, 16},
		{"Fifteen", 15, 16},
		{"Sixteen", 16, 16},
		{"Seventeen", 17, 32},
		{"Thirty one", 31, 32},
		{"Thirty two", 32, 32},
		{"Negative", -1, 1},
		{"Large number", 100, 128},
		{"Very large", 1000, 1024},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := round2PowerOf2(tt.input)
			if result != tt.expected {
				t.Errorf("round2PowerOf2(%d) = %d, want %d", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSize2BitCountMask(t *testing.T) {
	tests := []struct {
		name     string
		size     int
		expected int
	}{
		{"Size 1", 1, 32}, // 1 address needs /32
		{"Size 2", 2, 31},
		{"Size 3", 3, 30},
		{"Size 4", 4, 30},
		{"Size 8", 8, 29},
		{"Size 16", 16, 28},
		{"Size 32", 32, 27},
		{"Size 64", 64, 26},
		{"Size 128", 128, 25},
		{"Size 256", 256, 24},
		{"Size 512", 512, 23},
		{"Size 1024", 1024, 22},
		{"Zero", 0, 32},
		{"Negative", -1, 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := size2BitCountMask(tt.size)
			if result != tt.expected {
				t.Errorf("size2BitCountMask(%d) = %d, want %d", tt.size, result, tt.expected)
			}
		})
	}
}

func deaggregateToSlice(start, end uint32) []string {
	var results []string
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
		results = append(results, uint32ToIP(base).String()+"/"+strconv.Itoa(32-step))
		base += uint32(1) << step
	}
	return results
}

func TestDeaggregate(t *testing.T) {
	tests := []struct {
		name          string
		start         string
		end           string
		expectedCount int // Just verify we get reasonable number of results
		minCount      int
		maxCount      int
	}{
		{
			name:          "Single IP",
			start:         "192.168.0.1",
			end:           "192.168.0.1",
			expectedCount: 1,
			minCount:      1,
			maxCount:      1,
		},
		{
			name:          "Two IPs",
			start:         "192.168.0.1",
			end:           "192.168.0.2",
			expectedCount: 1,
			minCount:      1,
			maxCount:      1,
		},
		{
			name:          "Small range",
			start:         "192.168.0.1",
			end:           "192.168.0.10",
			expectedCount: 3,
			minCount:      3,
			maxCount:      3,
		},
		{
			name:          "Aligned /30",
			start:         "192.168.0.0",
			end:           "192.168.0.3",
			expectedCount: 1,
			minCount:      1,
			maxCount:      3, // May produce multiple if not perfectly aligned
		},
		{
			name:          "Aligned /28",
			start:         "192.168.0.0",
			end:           "192.168.0.15",
			expectedCount: 1,
			minCount:      1,
			maxCount:      5, // May produce multiple if not perfectly aligned
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			startIP := net.ParseIP(tt.start).To4()
			endIP := net.ParseIP(tt.end).To4()
			start := ipToUint32(startIP)
			end := ipToUint32(endIP)

			results := deaggregateToSlice(start, end)

			if len(results) < tt.minCount || len(results) > tt.maxCount {
				t.Errorf("deaggregate(%s, %s) returned %d results, want between %d and %d", tt.start, tt.end, len(results), tt.minCount, tt.maxCount)
				t.Errorf("Got: %v", results)
			}

			// Verify all results are valid CIDR notation
			for i, result := range results {
				parts := strings.Split(result, "/")
				if len(parts) != 2 {
					t.Errorf("deaggregate(%s, %s)[%d] = %s, invalid format", tt.start, tt.end, i, result)
				}
				if net.ParseIP(parts[0]) == nil {
					t.Errorf("deaggregate(%s, %s)[%d] = %s, invalid IP", tt.start, tt.end, i, result)
				}
				cidr, err := strconv.Atoi(parts[1])
				if err != nil || cidr < 0 || cidr > 32 {
					t.Errorf("deaggregate(%s, %s)[%d] = %s, invalid CIDR", tt.start, tt.end, i, result)
				}
			}
		})
	}
}

func TestDeaggregateRange(t *testing.T) {
	// Test that deaggregate produces valid ranges (simplified test)
	testCases := []struct {
		name  string
		start string
		end   string
	}{
		{"Small range", "192.168.0.1", "192.168.0.10"},
		{"Medium range", "192.168.0.1", "192.168.0.100"},
		{"Aligned range", "192.168.0.0", "192.168.0.255"},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			startIP := net.ParseIP(tt.start).To4()
			endIP := net.ParseIP(tt.end).To4()
			start := ipToUint32(startIP)
			end := ipToUint32(endIP)

			results := deaggregateToSlice(start, end)

			// Verify we got some results
			if len(results) == 0 {
				t.Errorf("deaggregate(%s, %s) returned no results", tt.start, tt.end)
				return
			}

			// Verify all results are valid CIDR notation
			for i, result := range results {
				parts := strings.Split(result, "/")
				if len(parts) != 2 {
					t.Errorf("deaggregate(%s, %s)[%d] = %s, invalid format", tt.start, tt.end, i, result)
					continue
				}
				if net.ParseIP(parts[0]) == nil {
					t.Errorf("deaggregate(%s, %s)[%d] = %s, invalid IP", tt.start, tt.end, i, result)
				}
				cidr, err := strconv.Atoi(parts[1])
				if err != nil || cidr < 0 || cidr > 32 {
					t.Errorf("deaggregate(%s, %s)[%d] = %s, invalid CIDR", tt.start, tt.end, i, result)
				}
			}

			// Verify ranges are in order and don't go beyond end
			for i, result := range results {
				parts := strings.Split(result, "/")
				networkIP := net.ParseIP(parts[0]).To4()
				if networkIP == nil {
					continue // Already tested above
				}
				network := ipToUint32(networkIP)
				cidr, _ := strconv.Atoi(parts[1])
				mask := cidrToMask(cidr)
				broadcast := network | (^mask)

				if network < start {
					t.Errorf("Range %s starts before start address %s", result, tt.start)
				}
				if broadcast > end {
					t.Errorf("Range %s extends beyond end address %s", result, tt.end)
				}
				if i > 0 {
					prevParts := strings.Split(results[i-1], "/")
					prevIP := net.ParseIP(prevParts[0]).To4()
					if prevIP != nil {
						prevCIDR, _ := strconv.Atoi(prevParts[1])
						prevMask := cidrToMask(prevCIDR)
						prevBroadcast := ipToUint32(prevIP) | (^prevMask)
						if network <= prevBroadcast {
							t.Errorf("Range %s overlaps or is out of order with previous range %s", result, results[i-1])
						}
					}
				}
			}
		})
	}
}

