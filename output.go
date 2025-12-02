package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

const (
	colorReset   = "\033[0m"
	colorBlue    = "\033[34m"
	colorYellow  = "\033[33m"
	colorRed     = "\033[31m"
	colorMagenta = "\033[35m"
	colorGreen   = "\033[32m"
)

var (
	quadsColor = colorBlue
	normlColor = colorReset
	binryColor = colorYellow
	maskColor  = colorRed
	classColor = colorMagenta
	subntColor = colorGreen
)

func setColor(color string) string {
	if !optColor {
		return ""
	}
	return color
}

func printLine(label string, address uint32, mask1, mask2 uint32, cidr1, cidr2 int, htmlFillup bool) {
	additionalInfo := ""
	if label == "Netmask" {
		additionalInfo = fmt.Sprintf(" = %d", cidr1)
	}
	if label == "Network" {
		additionalInfo = fmt.Sprintf("/%d", cidr1)
	}

	ipStr := uint32ToIP(address).String() + additionalInfo

	if optHTML {
		fmt.Printf("<tr>\n<td><tt>%s:</tt></td>\n", label)
		if htmlFillup {
			fmt.Printf("<td><tt>%s", ipStr)
			for i := len(ipStr); i < 21; i++ {
				fmt.Print("&nbsp;")
			}
			fmt.Print("</tt></td>\n")
		} else {
			fmt.Printf("<td><tt>%-21s</tt></td>\n", ipStr)
		}
	} else {
		fmt.Printf("%-11s", label+":")
		fmt.Print(setColor(quadsColor))
		fmt.Printf("%-21s", ipStr)
		fmt.Print(setColor(normlColor))
	}

	if optPrintBits {
		printBinary(address, mask1, mask2, cidr1, cidr2, label == "Netmask", label == "Network" || (label == "Hostroute" && cidr1 == 32))
	}

	if optHTML {
		fmt.Print("</tr>\n")
	} else {
		fmt.Println()
	}
}

func printBinary(address, mask1, mask2 uint32, cidr1, cidr2 int, isNetmask, isNetwork bool) {
	var line strings.Builder
	bitColor := binryColor
	if isNetmask {
		bitColor = maskColor
	}

	classBitColorOn := isNetwork
	newBitColorOn := false

	for i := 1; i <= 32; i++ {
		bit := (address >> (32 - i)) & 1

		if classBitColorOn {
			line.WriteString(setColor(classColor))
		} else if newBitColorOn {
			line.WriteString(setColor(subntColor))
		} else {
			line.WriteString(setColor(bitColor))
		}

		if bit == 1 {
			line.WriteString("1")
		} else {
			line.WriteString("0")
		}

		if classBitColorOn && bit == 0 {
			classBitColorOn = false
			if newBitColorOn {
				line.WriteString(setColor(subntColor))
			} else {
				line.WriteString(setColor(bitColor))
			}
		}

		if i%8 == 0 && i < 32 {
			line.WriteString(setColor(normlColor))
			line.WriteString(".")
			if classBitColorOn {
				line.WriteString(setColor(classColor))
			} else if newBitColorOn {
				line.WriteString(setColor(subntColor))
			} else {
				line.WriteString(setColor(bitColor))
			}
		}

		if i == cidr1 {
			line.WriteString(" ")
		}

		if (i == cidr1 || i == cidr2) && cidr1 != cidr2 {
			if newBitColorOn {
				newBitColorOn = false
				if !classBitColorOn {
					line.WriteString(setColor(bitColor))
				}
			} else {
				newBitColorOn = true
				if !classBitColorOn {
					line.WriteString(setColor(subntColor))
				}
			}
		}
	}

	line.WriteString(setColor(normlColor))

	if optHTML {
		fmt.Printf("<td><tt>%s</tt></td>\n", line.String())
	} else {
		fmt.Print(" ")
		fmt.Print(line.String())
	}
}

func printNet(network, mask uint32, cidr1, cidr2 int) {
	broadcast := network | (^mask)
	hmin := network + 1
	hmax := broadcast - 1
	hostn := hmax - hmin + 1

	if cidr1 == 31 {
		hmax = broadcast
		hmin = network
		hostn = 2
	}
	if cidr1 == 32 {
		hostn = 1
	}

	if cidr1 == 32 {
		printLine("Hostroute", network, mask, mask, cidr1, cidr2, true)
	} else {
		printLine("Network", network, mask, mask, cidr1, cidr2, true)
		printLine("HostMin", hmin, mask, mask, cidr1, cidr2, false)
		printLine("HostMax", hmax, mask, mask, cidr1, cidr2, false)
		if cidr1 < 31 {
			printLine("Broadcast", broadcast, mask, mask, cidr1, cidr2, false)
		}
	}

	if optHTML {
		fmt.Print("<tr>\n<td valign=\"top\"><tt>Hosts/Net: </tt></td>\n")
		fmt.Printf("<td valign=\"top\"><tt>%s%-22s</tt></td>\n", setColor(quadsColor), fmt.Sprintf("%d", hostn))
		fmt.Print("<td>")
		fmt.Print(getDescription(network, mask, cidr1))
		fmt.Print("</td>\n</tr>\n")
	} else {
		fmt.Print("Hosts/Net: ")
		fmt.Print(setColor(quadsColor))
		fmt.Printf("%-22s", fmt.Sprintf("%d", hostn))
		fmt.Print(setColor(normlColor))
		fmt.Println(getDescription(network, mask, cidr1))
		fmt.Println()
	}
}

func getDescription(network, mask uint32, cidr int) string {
	var desc []string

	ip := uint32ToIP(network)
	class := getClass(ip)
	if optColor || optHTML {
		if optHTML {
			desc = append(desc, fmt.Sprintf("<font color=\"#009900\">Class %s</font>", class))
		} else {
			desc = append(desc, fmt.Sprintf("%sClass %s%s", setColor(classColor), class, setColor(normlColor)))
		}
	} else {
		desc = append(desc, fmt.Sprintf("Class %s", class))
	}

	netblockTxt, netblockURL := getNetblock(network, mask)
	if netblockTxt != "" {
		if optHTML {
			desc = append(desc, fmt.Sprintf("<a href=\"%s\">%s</a>", netblockURL, netblockTxt))
		} else {
			desc = append(desc, netblockTxt)
		}
	}

	if cidr == 31 {
		if optHTML {
			desc = append(desc, "<a href=\"http://www.ietf.org/rfc/rfc3021.txt\">PtP Link</a>")
		} else {
			desc = append(desc, "PtP Link RFC 3021")
		}
	}

	return strings.Join(desc, ", ")
}

func getNetblock(network, mask uint32) (string, string) {
	broadcast := network | (^mask)

	netblocks := map[string][]string{
		"192.168.0.0/16": {"Private Internet", "http://www.ietf.org/rfc/rfc1918.txt"},
		"172.16.0.0/12":  {"Private Internet", "http://www.ietf.org/rfc/rfc1918.txt"},
		"10.0.0.0/8":     {"Private Internet", "http://www.ietf.org/rfc/rfc1918.txt"},
		"169.254.0.0/16": {"APIPA", "http://www.ietf.org/rfc/rfc3330.txt"},
		"127.0.0.0/8":    {"Loopback", "http://www.ietf.org/rfc/rfc1700.txt"},
		"224.0.0.0/4":    {"Multicast", "http://www.ietf.org/rfc/rfc3171.txt"},
	}

	for blockStr, info := range netblocks {
		parts := strings.Split(blockStr, "/")
		blockIP := net.ParseIP(parts[0]).To4()
		blockMask, _ := strconv.Atoi(parts[1])
		blockStart := ipToUint32(blockIP)
		blockEnd := blockStart + (uint32(1) << (32 - blockMask)) - 1

		match := 0
		if network >= blockStart && network <= blockEnd {
			match++
		}
		if broadcast >= blockStart && broadcast <= blockEnd {
			match++
		}
		if blockStart > network && blockEnd < broadcast {
			match = 1
		}

		if match == 1 {
			return "In Part " + info[0], info[1]
		}
		if match == 2 {
			return info[0], info[1]
		}
	}

	return "", ""
}

func isTerminal(f *os.File) bool {
	stat, err := f.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}

func printHTMLHeader() {
	fmt.Print(`<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
<head>
<meta HTTP-EQUIV="content-type" CONTENT="text/html; charset=UTF-8">
<title>Bla</title>
</head>
<body>
`)
	fmt.Printf("<!-- Version %s -->\n", version)
}

func printHTMLFooter() {
	fmt.Print(`    <p>
      <a href="http://validator.w3.org/check/referer"><img border="0"
          src="http://www.w3.org/Icons/valid-html401"
          alt="Valid HTML 4.01!" height="31" width="88"></a>
    </p>
`)
}
