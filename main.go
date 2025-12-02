package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

const version = "v0.0.0"

var (
	optHTML           = false
	optColor          = false
	optPrintBits      = true
	optPrintOnlyClass = false
	optSplit          = false
	optDeaggregate    = false
	optSplitSizes     []int
)

var classBits = []int{0, 8, 16, 24, 4, 5, 5}

var rootCmd = &cobra.Command{
	Use:   "ipcalc [options] <ADDRESS>[[/]<NETMASK>] [NETMASK]",
	Short: "IP Calculator - Calculate network information from IP addresses and netmasks",
	Long: `ipcalc takes an IP address and netmask and calculates the resulting
broadcast, network, Cisco wildcard mask, and host range. By giving a
second netmask, you can design sub- and supernetworks. It is also
intended to be a teaching tool and presents the results as
easy-to-understand binary values.`,
	Example: `  ipcalc 192.168.0.1/24
  ipcalc 192.168.0.1/255.255.128.0
  ipcalc 192.168.0.1 255.255.128.0 255.255.192.0
  ipcalc 192.168.0.1 0.0.63.255
  ipcalc <ADDRESS1> - <ADDRESS2>  deaggregate address range
  ipcalc <ADDRESS>/<NETMASK> -s a b c  split network to subnets`,
	Run:     runIPCalc,
	Version: version,
}

var (
	flagColor    bool
	flagNoColor  bool
	flagNoBinary bool
)

func init() {
	rootCmd.Flags().BoolVar(&flagColor, "color", false, "Display ANSI color codes (default: auto-detect)")
	rootCmd.Flags().BoolVarP(&flagNoColor, "nocolor", "n", false, "Don't display ANSI color codes")
	rootCmd.Flags().BoolVarP(&flagNoBinary, "nobinary", "b", false, "Suppress the bitwise output")
	rootCmd.Flags().BoolVarP(&optPrintOnlyClass, "class", "c", false, "Just print bit-count-mask of given address")
	rootCmd.Flags().BoolVar(&optHTML, "html", false, "Display results as HTML (not finished in this version)")
	rootCmd.Flags().BoolVarP(&optDeaggregate, "range", "r", false, "Deaggregate address range")
	rootCmd.Flags().IntSliceVarP(&optSplitSizes, "split", "s", []int{}, "Split into networks of specified sizes")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runIPCalc(cmd *cobra.Command, args []string) {
	// Handle color flags
	if flagNoColor {
		optColor = false
	} else if flagColor {
		optColor = true
	} else {
		// Auto-detect color support
		if isTerminal(os.Stdout) {
			optColor = true
		}
	}

	// Disable color if TERM is dumb or inside Emacs
	if term := os.Getenv("TERM"); term == "dumb" || os.Getenv("INSIDE_EMACS") != "" {
		optColor = false
	}

	// Handle --nobinary flag (inverted logic)
	if flagNoBinary {
		optPrintBits = false
	}

	// Handle --split flag
	if len(optSplitSizes) > 0 {
		optSplit = true
	}

	if optHTML {
		printHTMLHeader()
	}

	if len(args) == 0 {
		cmd.Help()
		os.Exit(1)
	}

	// Detect ADDRESS1 - ADDRESS2 format (standalone "-" argument)
	if len(args) == 3 && args[1] == "-" {
		optDeaggregate = true
	}

	// Handle --range flag: Check for ADDRESS1 - ADDRESS2 format BEFORE parsing
	if optDeaggregate {
		// Check for ADDRESS1 - ADDRESS2 format
		if len(args) == 3 && args[1] == "-" {
			args = []string{args[0], args[2]}
		}
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "INVALID ADDRESS2\n")
			os.Exit(1)
		}
		// Parse addresses for deaggregate
		addressStr := args[0]
		address2Str := args[1]

		var address, address2 net.IP
		if ip := net.ParseIP(addressStr); ip != nil {
			if ip.To4() == nil {
				fmt.Fprintf(os.Stderr, "Deaggregate only supports IPv4\n")
				os.Exit(1)
			}
			address = ip.To4()
		} else {
			fmt.Fprintf(os.Stderr, "INVALID ADDRESS: %s\n", addressStr)
			os.Exit(1)
		}

		if ip := net.ParseIP(address2Str); ip != nil {
			if ip.To4() == nil {
				fmt.Fprintf(os.Stderr, "Deaggregate only supports IPv4\n")
				os.Exit(1)
			}
			address2 = ip.To4()
		} else {
			fmt.Fprintf(os.Stderr, "INVALID ADDRESS2: %s\n", address2Str)
			os.Exit(1)
		}

		deaggregate(ipToUint32(address), ipToUint32(address2))
		os.Exit(0)
	}

	// Parse address/netmask combinations
	var parsedArgs []string
	for _, arg := range args {
		if strings.Contains(arg, "/") {
			parts := strings.SplitN(arg, "/", 2)
			parsedArgs = append(parsedArgs, parts[0])
			if parts[1] != "" {
				parsedArgs = append(parsedArgs, parts[1])
			}
		} else {
			parsedArgs = append(parsedArgs, arg)
		}
	}

	addressStr := parsedArgs[0]
	var address net.IP
	var isIPv6 bool

	// Try parsing as IPv6 first
	if ip := net.ParseIP(addressStr); ip != nil {
		if ip.To4() == nil {
			isIPv6 = true
			address = ip
		} else {
			address = ip.To4()
		}
	} else {
		fmt.Fprintf(os.Stderr, "INVALID ADDRESS: %s\n", addressStr)
		os.Exit(1)
	}

	if optPrintOnlyClass {
		if isIPv6 {
			fmt.Println("N/A")
		} else {
			fmt.Println(getClassBits(address))
		}
		os.Exit(0)
	}

	if isIPv6 {
		mask1 := 64
		if len(args) > 1 {
			m, err := strconv.Atoi(args[1])
			if err != nil || m < 0 || m > 128 {
				fmt.Fprintf(os.Stderr, "INVALID MASK1\n")
				os.Exit(1)
			}
			mask1 = m
		}
		ipcalc6(address, mask1)
		os.Exit(0)
	}

	// IPv4 processing
	mask1 := 24
	if len(parsedArgs) > 1 {
		m, err := parseNetmask(parsedArgs[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "INVALID MASK1: %s\n", parsedArgs[1])
			os.Exit(1)
		}
		mask1 = m
	}

	mask2 := mask1
	if len(parsedArgs) > 2 {
		m, err := parseNetmask(parsedArgs[2])
		if err != nil {
			fmt.Fprintf(os.Stderr, "INVALID MASK2: %s\n", parsedArgs[2])
			os.Exit(1)
		}
		mask2 = m
	}

	if optHTML {
		fmt.Print("<table border=\"0\" cellspacing=\"0\" cellpadding=\"0\">\n")
	}

	addressUint := ipToUint32(address)
	mask1Uint := cidrToMask(mask1)
	_ = cidrToMask(mask2)

	printLine("Address", addressUint, mask1Uint, mask1Uint, mask1, mask2, true)
	printLine("Netmask", mask1Uint, mask1Uint, mask1Uint, mask1, mask2, false)
	printLine("Wildcard", ^mask1Uint, mask1Uint, mask1Uint, mask1, mask2, false)

	if optHTML {
		fmt.Print("<tr>\n<td colspan=\"3\"><tt>=></tt></td>\n</tr>\n")
	} else {
		fmt.Println("=>")
	}

	network := addressUint & mask1Uint
	printNet(network, mask1Uint, mask1, mask2)

	if optHTML {
		fmt.Print("</table>\n")
	}

	if optSplit {
		splitNetwork(network, mask1, mask2, optSplitSizes)
		os.Exit(0)
	}

	if mask1 < mask2 {
		fmt.Printf("Subnets after transition from /%d to /%d\n\n", mask1, mask2)
		subnets(network, mask1, mask2)
	}

	if mask1 > mask2 {
		fmt.Println("Supernet")
		supernet(network, mask1, mask2)
		if optHTML {
			fmt.Print("</table>\n")
		}
	}

	if optHTML {
		printHTMLFooter()
	}
}
