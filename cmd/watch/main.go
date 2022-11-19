package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/user"
	"path"
	"strings"
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

func addFollow(node string, workdir string, follow string) error {
	if !strings.Contains(follow, "/") {
		r, err := http.NewRequest("GET", node+"/lookup/"+follow, nil)
		if err != nil {
			panic(err)
		}
		client := &http.Client{}
		res, err := client.Do(r)
		if err != nil {
			panic(err)
		}
		defer res.Body.Close()

		var ret []FeedSummary
		err = json.NewDecoder(res.Body).Decode(&ret)
		if err != nil {
			return err
		}

		for _, record := range ret {
			rd, err := feedchain.NewReaderFromURL(node + "/" + record.PublicKey)
			if err != nil {
				return err
			}
			tmp := strings.Split(node, "://")
			origin := tmp[1]

			os.MkdirAll(path.Join(workdir, "follows", origin), 0700)
			fp, err := os.Create(path.Join(workdir, "follows", origin, rd.ID()))
			if err != nil {
				return err
			}
			fp.Close()
			rd.Close()
		}

	} else {
		rd, err := feedchain.NewReaderFromURL(follow)
		if err != nil {
			return err
		}
		tmp := strings.Split(follow, "/")
		origin := strings.Join(tmp[0:len(tmp)-1], "/")
		os.MkdirAll(path.Join(workdir, "follows", origin), 0700)
		fp, err := os.Create(path.Join(workdir, "follows", origin, rd.ID()))
		if err != nil {
			return err
		}
		fp.Close()
		rd.Close()
	}
	return nil
}

func removeFollow(workdir string, follow string) error {
	fsys := os.DirFS(path.Join(workdir, "follows"))
	fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			rd, err := feedchain.NewReaderFromURL(p)
			if err != nil {
				return err
			}
			if follow == rd.ID() || follow == rd.Metadata.Name {
				os.Remove(path.Join(workdir, "follows", p))
			}
			rd.Close()
		}
		return nil
	})
	return nil
}

func main() {
	var opt_node string
	var opt_begin int
	var opt_follow string
	var opt_unfollow string

	flag.StringVar(&opt_node, "node", "https://feeds.poolp.org", "set the default node for network operations")
	flag.IntVar(&opt_begin, "begin", 1, "display messages at most n days old")
	flag.StringVar(&opt_follow, "follow", "", "feed to follow")
	flag.StringVar(&opt_unfollow, "unfollow", "", "feed to unfollow")
	flag.Parse()

	userDefault, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}
	workdir := path.Join(userDefault.HomeDir, ".feedchain")
	os.MkdirAll(workdir, 0700)
	os.MkdirAll(path.Join(workdir, "keys"), 0700)

	if opt_follow != "" {
		addFollow(opt_node, workdir, opt_follow)
		os.Exit(0)
	}

	if opt_unfollow != "" {
		removeFollow(workdir, opt_unfollow)
		os.Exit(0)
	}

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
