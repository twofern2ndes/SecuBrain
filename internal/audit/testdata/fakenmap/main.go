// Deterministic Nmap process double. It deliberately opens no sockets.
package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Println("Nmap fixture 0.3.0 (test executable)")
		return
	}
	args := os.Args[1:]
	if len(args) < 4 || args[len(args)-3] != "-oX" || args[len(args)-2] != "-" || args[len(args)-1] != "127.0.0.1" {
		fmt.Fprintln(os.Stderr, "unexpected argv or target")
		os.Exit(3)
	}
	udp := false
	for _, v := range args {
		if v == "-sU" {
			udp = true
		}
	}
	output := `<?xml version="1.0"?><nmaprun scanner="nmap"><host><status state="up" reason="user-set"/><address addr="127.0.0.1" addrtype="ipv4"/><hostnames><hostname name="localhost" type="user"/></hostnames><uptime seconds="2200"/><os><osmatch name="Linux 6.x" accuracy="93"/></os><ports><extraports state="filtered" count="98"/><port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="https" product="Fixture Web" version="1.2.3" extrainfo="test banner" conf="10" method="probed" tunnel="ssl"><cpe>cpe:/a:example:fixture_web:1.2.3</cpe></service><script id="http-title" output="Test &lt;script&gt; HTML &amp; synthetic"/></port><port protocol="tcp" portid="22"><state state="closed" reason="reset"/></port>`
	if udp {
		output += `<port protocol="udp" portid="53"><state state="open"/><service name="domain"/></port>`
	}
	output += `</ports></host></nmaprun>`
	if strings.Contains(strings.Join(args, " "), "--invalid") {
		os.Exit(2)
	}
	fmt.Print(output)
}
