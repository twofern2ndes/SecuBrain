package main

import (
	"github.com/twofern2ndes/SecuBrain/internal/cli"
	"os"
)

func main() { os.Exit(cli.Run(os.Args[1:])) }
