// NNCP -- Node to Node copy, utilities for store-and-forward data exchange
// Copyright (C) 2016-2025 Sergey Matveev <stargrave@stargrave.org>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 3 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Verify NNCP Rx/Tx packets checksum.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"go.cypherpunks.su/nncp/v8"
)

func usage() {
	fmt.Fprint(os.Stderr, "nncp-check -- verify Rx/Tx packets checksum\n\n")
	fmt.Fprintf(os.Stderr, "Usage: %s [-nock] [options]\nOptions:\n", os.Args[0])
	flag.PrintDefaults()
}

func main() {
	var (
		nock      = flag.Bool("nock", false, "Process .nock files")
		cycle     = flag.Uint("cycle", 0, "Repeat check after N seconds in infinite loop")
		cfgPath   = flag.String("cfg", nncp.DefaultCfgPath, "Path to configuration file")
		nodeRaw   = flag.String("node", "", "Process only that node")
		spoolPath = flag.String("spool", "", "Override path to spool")
		logPath   = flag.String("log", "", "Override path to logfile")
		quiet     = flag.Bool("quiet", false, "Print only errors")
		showPrgrs = flag.Bool("progress", false, "Force progress showing")
		omitPrgrs = flag.Bool("noprogress", false, "Omit progress showing")
		debug     = flag.Bool("debug", false, "Print debug messages")
		version   = flag.Bool("version", false, "Print version information")
		warranty  = flag.Bool("warranty", false, "Print warranty information")
	)
	log.SetFlags(log.Lshortfile)
	flag.Usage = usage
	flag.Parse()
	if *warranty {
		fmt.Println(nncp.Warranty)
		return
	}
	if *version {
		fmt.Println(nncp.VersionGet())
		return
	}

	ctx, err := nncp.CtxFromCmdline(
		*cfgPath,
		*spoolPath,
		*logPath,
		*quiet,
		*showPrgrs,
		*omitPrgrs,
		*debug,
	)
	if err != nil {
		log.Fatalln("Error during initialization:", err)
	}
	ctx.Umask()

	var nodeOnly *nncp.Node
	if *nodeRaw != "" {
		nodeOnly, err = ctx.FindNode(*nodeRaw)
		if err != nil {
			log.Fatalln("Invalid -node specified:", err)
		}
	}

Cycle:
	isBad := false
	for nodeId, node := range ctx.Neigh {
		if nodeOnly != nil && nodeId != *nodeOnly.Id {
			continue
		}
		if *nock {
			for job := range ctx.JobsNoCK(node.Id) {
				if _, err = ctx.CheckNoCK(node.Id, job.HshValue, nil); err != nil {
					pktName := nncp.Base32Codec.EncodeToString(job.HshValue[:])
					log.Println(filepath.Join(
						ctx.Spool,
						nodeId.String(),
						string(nncp.TRx),
						pktName+nncp.NoCKSuffix,
					), err)
					isBad = true
				}
			}
		} else if !ctx.Check(node.Id) {
			isBad = true
		}
	}
	if *cycle > 0 {
		time.Sleep(time.Duration(*cycle) * time.Second)
		goto Cycle
	}
	if isBad {
		os.Exit(1)
	}
}
