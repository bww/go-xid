package main

import (
	"flag"
	"fmt"
	"os"
	"path"
	"strconv"

	"github.com/bww/go-xid/v1"
)

func main() {
	os.Exit(run())
}

func run() int {
	command := path.Base(os.Args[0])
	var err error

	cmdline := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	var (
		fSequence = cmdline.Bool("seq", false, "Generate a sequential identifier. This variant is good for sorting.")
		_         = cmdline.Bool("dst", true, "Generate a distributed identifier. This variant is good for partitioning.")
		fVerbose  = cmdline.Bool("verbose", false, "Be more verbose.")
	)
	cmdline.Parse(os.Args[1:])

	count := 1
	args := cmdline.Args()
	if l := len(args); l > 0 {
		s := args[l-1]
		count, err = strconv.Atoi(s)
		if err != nil {
			fmt.Printf("%s: not a valid count to generate: %s\n", command, s)
			return 1
		}
	}

	var gen *xid.Generator
	if *fSequence {
		gen = xid.NewGenerator(xid.Sequential)
	} else {
		gen = xid.NewGenerator(xid.Distributed)
	}
	for i := 0; i < count; i++ {
		if *fVerbose {
			fmt.Printf("#%d %v\n", i+1, xid.New())
		} else {
			fmt.Println(gen.New())
		}
	}
	return 0
}
