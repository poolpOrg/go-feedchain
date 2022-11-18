package main

import (
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/poolpOrg/feedchain/feedchain"
)

func main() {
	flag.Parse()

	if flag.NArg() != 1 {
		log.Fatal("need a path or URL to a raw feed")
	}

	origin := flag.Arg(0)

	var rd *feedchain.StreamReader
	var err error
	if strings.HasPrefix(origin, "http://") || strings.HasPrefix(origin, "https://") {
		rd, err = feedchain.NewReaderFromURL(origin)
	} else {
		rd, err = feedchain.NewReaderFromFile(origin)
	}
	if err != nil {
		log.Fatal(err)
	}
	defer rd.Close()

	for i := uint64(0); i < rd.Size(); i++ {
		block, err := rd.Offset(i)
		if err != nil {
			log.Fatal(err)
		}

		unixTimeUTC := time.UnixMilli(block.CreationTime).Format(time.RFC3339)
		fmt.Printf("[%s] (sha256:%s...%s): %s\n", unixTimeUTC, block.ID()[0:4], block.ID()[64-4:], block.Message)
	}

	//	fmt.Println(rd)
}
