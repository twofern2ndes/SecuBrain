// A deterministic fake executable used to integration-test the Nmap adapter.
// It never accesses the network and is not distributed as an Nmap replacement.
package main

import (
	"fmt"
	"os"
	"reflect"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Println("Nmap fixture 0.0.0 (test double)")
		return
	}
	args := os.Args[1:]
	expected := []string{"-sT", "-sV", "--version-light", "-Pn", "-F", "-T2", "--max-rate", "25", "--max-retries", "1", "--host-timeout", "80s", "--open", "-oX", "-", "127.0.0.1"}
	if !reflect.DeepEqual(args, expected) {
		fmt.Fprintln(os.Stderr, "unexpected arguments")
		os.Exit(3)
	}
	fmt.Print(`<?xml version="1.0"?><nmaprun><host><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" product="Fixture Web" version="1.2.3" tunnel="ssl"/></port><port protocol="tcp" portid="22"><state state="closed"/></port></ports></host></nmaprun>`)
}
