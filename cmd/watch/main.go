package main

import (
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/user"
	"path"
	"time"

	"github.com/poolpOrg/feedchain/feedchain"
)

var WatchFeeds map[string]*FeedWatcher

type FeedWatcher struct {
	publicKey string
	source    string
	done      bool
}

type FeedSummary struct {
	PublicKey string `json:"public_key"`
	Origin    string `json:"origin"`
	Size      int    `json:"length"`
}

func NewFeedWatcher(publicKey string, source string) *FeedWatcher {
	return &FeedWatcher{publicKey: publicKey, source: source, done: false}
}

func (fw *FeedWatcher) Stop() {
	fw.done = true
}

func (fw *FeedWatcher) Run(beginOffset int) {
	refreshRate := time.Duration(0)
	lastFeedChecksum := ""
	lastBlockCtime := 0
	begin := time.Now().AddDate(0, 0, -beginOffset).UnixMilli()

	for {
		if fw.done {
			break
		}

		time.Sleep(refreshRate * time.Second)

		rd, err := feedchain.NewReaderFromURL(fw.source)
		if err != nil {
			fmt.Printf("[warning] could not obtain feed for %s, pausing source", fw.publicKey)
			refreshRate = 30
			continue
		}
		if rd.HeaderChecksum == lastFeedChecksum || len(rd.Index.Records) == 0 {
			if refreshRate < 30 {
				refreshRate += 1
			}
			continue
		}
		lastFeedChecksum = rd.HeaderChecksum

		for i := 0; i < len(rd.Index.Records); i++ {
			if rd.Index.Records[i].CreationTime < begin || rd.Index.Records[i].CreationTime <= int64(lastBlockCtime) {
				continue
			}
			block, err := rd.Offset(uint64(i))
			if err != nil {
				fmt.Printf("[warning] could not obtain block %d for %s, pausing source: %s\n", i, fw.publicKey, err)
				break
			}
			lastBlockCtime = int(block.CreationTime)

			unixTimeUTC := time.UnixMilli(block.CreationTime).Format(time.RFC3339)
			if rd.Metadata.Name != "" {
				fmt.Printf("[%s] @%s (%s...%s): %s\n", unixTimeUTC, rd.Metadata.Name, rd.ID()[0:4], rd.ID()[len(rd.ID())-4:], block.Message)
			} else {
				fmt.Printf("[%s] %s: %s\n", unixTimeUTC, rd.ID(), block.Message)
			}

		}

		rd.Close()

		time.Sleep(refreshRate * time.Second)
	}

}

func main() {
	var opt_node string
	var opt_begin int

	flag.StringVar(&opt_node, "node", "https://feeds.poolp.org", "set the default node for network operations")
	flag.IntVar(&opt_begin, "begin", 1, "display messages at most n days old")
	flag.Parse()

	userDefault, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}
	workdir := path.Join(userDefault.HomeDir, ".feedchain")
	os.MkdirAll(workdir, 0700)
	os.MkdirAll(path.Join(workdir, "keys"), 0700)

	WatchFeeds = make(map[string]*FeedWatcher)
	for {
		feeds := make(map[string]bool)
		fsys := os.DirFS(path.Join(workdir, "follows"))
		fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.Type().IsRegular() {
				feeds[d.Name()] = true
				if _, exists := WatchFeeds[d.Name()]; !exists {
					WatchFeeds[d.Name()] = NewFeedWatcher(d.Name(), p)
					go WatchFeeds[d.Name()].Run(opt_begin)

				}
			}
			return nil
		})

		for key, _ := range WatchFeeds {
			if _, exists := feeds[key]; !exists {
				WatchFeeds[key].Stop()
				delete(WatchFeeds, key)
			}
		}
		time.Sleep(1 * time.Second)
	}
}
