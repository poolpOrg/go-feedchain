package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io/fs"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/user"
	"path"
	"strings"
	"time"

	"github.com/poolpOrg/feedchain/feedchain"
)

var Keys map[string][]byte
var OwnFeeds map[string]*feedchain.StreamWriter
var WatchFeeds map[string]string

type FeedWatcher struct {
	publicKey string
	source    string
}

func NewFeedWatcher(publicKey string, source string) *FeedWatcher {
	return &FeedWatcher{publicKey: publicKey, source: source}
}

func (fw *FeedWatcher) Run() {
	refreshRate := time.Duration(0)
	lastFeedChecksum := ""
	lastBlockCtime := 0
	//begin := time.Now().AddDate(0, 0, -1).UnixMilli()
	begin := time.Now().AddDate(0, 0, -7).UnixMilli()

	for {
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
				fmt.Printf("[%s] %s: %s\n", unixTimeUTC, rd.Metadata.Name, block.Message)
			} else {
				fmt.Printf("[%s] %s: %s\n", unixTimeUTC, rd.ID(), block.Message)
			}

		}

		rd.Close()

		time.Sleep(refreshRate * time.Second)
	}

}

func createFeedchain(workdir string) error {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	feed, err := feedchain.Init(priv)
	if err != nil {
		return err
	}

	err = os.WriteFile(path.Join(workdir, "keys", base64.RawURLEncoding.EncodeToString(priv)), []byte(""), 0700)
	if err != nil {
		return err
	}

	return feed.Commit(path.Join(workdir, feed.ID()))
}

func loadKeys(workdir string) error {
	Keys = make(map[string][]byte)
	files, err := ioutil.ReadDir(path.Join(workdir, "keys"))
	if err != nil {
		return err
	}
	for _, f := range files {
		priv, err := base64.RawURLEncoding.DecodeString(f.Name())
		if err != nil {
			return err
		}
		Keys[f.Name()] = priv
	}
	return nil
}

func keyForFeed(feedname string) ed25519.PrivateKey {
	var priv ed25519.PrivateKey
	for key, _ := range Keys {
		priv = Keys[key]
		if base64.RawURLEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)) == feedname {
			return priv
		}
	}
	return nil
}

func loadOwnFeeds(workdir string) error {
	OwnFeeds = make(map[string]*feedchain.StreamWriter)
	files, err := ioutil.ReadDir(path.Join(workdir))
	if err != nil {
		return err
	}
	for _, f := range files {
		if !f.IsDir() {
			priv := keyForFeed(f.Name())
			if priv == nil {
				continue
			}

			wr, err := feedchain.NewWriter(priv, path.Join(workdir, f.Name()))
			if err != nil {
				return err
			}
			OwnFeeds[f.Name()] = wr
		}
	}
	return nil
}

func loadWatchFeeds(workdir string) error {
	WatchFeeds = make(map[string]string)
	files, err := ioutil.ReadDir(path.Join(workdir))
	if err != nil {
		return err
	}
	for _, f := range files {
		if !f.IsDir() {
			WatchFeeds[f.Name()] = path.Join(workdir, f.Name())
		}
	}
	return nil
}

func loadWatchFeeds2(workdir string) error {
	WatchFeeds = make(map[string]string)
	fsys := os.DirFS(path.Join(workdir, "follows"))
	fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			WatchFeeds[d.Name()] = p
		}
		return nil
	})
	return nil
}

func addFollow(workdir string, follow string) error {
	if strings.Contains(follow, "@") {
		fmt.Println("trying to follow a user")
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
	}
	return nil
}

func main() {
	var opt_create bool
	var opt_write string
	var opt_publish bool
	var opt_node string
	var opt_follow string
	var opt_name string

	flag.BoolVar(&opt_create, "create", false, "create the feedchain")
	flag.StringVar(&opt_write, "write", "", "write a message to the feedchain")
	flag.BoolVar(&opt_publish, "publish", false, "publish the feedchain")
	flag.StringVar(&opt_node, "node", "https://feeds.poolp.org", "set the default node for network operations")
	flag.StringVar(&opt_follow, "follow", "", "feed to follow")
	flag.StringVar(&opt_name, "name", "", "update feed name")

	flag.Parse()

	userDefault, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}
	workdir := path.Join(userDefault.HomeDir, ".feedchain")
	os.MkdirAll(workdir, 0700)
	os.MkdirAll(path.Join(workdir, "keys"), 0700)

	if opt_create {
		err := createFeedchain(workdir)
		if err != nil {
			log.Fatal(err)
		}
	}

	err = loadKeys(workdir)
	if err != nil {
		log.Fatal(err)
	}
	err = loadOwnFeeds(workdir)
	if err != nil {
		log.Fatal(err)
	}
	/*
		err = loadWatchFeeds(workdir)
		if err != nil {
			log.Fatal(err)
		}
	*/
	err = loadWatchFeeds2(workdir)
	if err != nil {
		log.Fatal(err)
	}

	if opt_write != "" {
		if len(OwnFeeds) != 1 {
			log.Fatal("need to select a specific feed")
		}
		for _, feed := range OwnFeeds {
			feed.Append(opt_write)
			feed.Commit(path.Join(workdir, feed.ID()))
		}
		os.Exit(1)
	}

	if opt_write != "" {
		if len(OwnFeeds) != 1 {
			log.Fatal("need to select a specific feed")
		}
		for _, feed := range OwnFeeds {
			feed.Append(opt_write)
			feed.Commit(path.Join(workdir, feed.ID()))
		}
		os.Exit(1)
	}

	if opt_name != "" {
		if len(OwnFeeds) != 1 {
			log.Fatal("need to select a specific feed")
		}
		for _, feed := range OwnFeeds {
			feed.Metadata.Name = opt_name
			feed.Commit(path.Join(workdir, feed.ID()))
		}
		os.Exit(1)
	}

	if opt_publish {
		if len(OwnFeeds) != 1 {
			log.Fatal("need to select a specific feed")
		}
		for _, feed := range OwnFeeds {
			feedBytes, err := ioutil.ReadFile(path.Join(workdir, feed.ID()))
			if err != nil {
				log.Fatal(err)
			}
			r, err := http.NewRequest("POST", opt_node+"/"+feed.ID(), bytes.NewBuffer(feedBytes))
			if err != nil {
				panic(err)
			}
			client := &http.Client{}
			res, err := client.Do(r)
			if err != nil {
				panic(err)
			}
			defer res.Body.Close()
		}
		os.Exit(1)
	}

	if opt_follow != "" {
		addFollow(workdir, opt_follow)
		os.Exit(1)
	}

	for publicKey, feedSource := range WatchFeeds {
		go NewFeedWatcher(publicKey, feedSource).Run()
	}

	c := make(chan bool)
	<-c

}
