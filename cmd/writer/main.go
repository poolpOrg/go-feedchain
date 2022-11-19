package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/user"
	"path"
	"unicode"

	"github.com/poolpOrg/feedchain/feedchain"
)

var Keys map[string][]byte
var OwnFeeds map[string]*feedchain.StreamWriter

func checkName(name string) error {
	if len(name) > 16 || len(name) < 3 {
		return fmt.Errorf("invalid name length, should be 3 <= n <= 16")
	}
	for _, c := range name {
		if !unicode.IsLetter(c) && !unicode.IsDigit(c) {
			return fmt.Errorf("invalid name, must only contain letters and digits")
		}
	}
	return nil
}

func createFeedchain(workdir string, name string) error {
	err := checkName(name)
	if err != nil {
		return err
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	feed, err := feedchain.Init(priv)
	if err != nil {
		return err
	}
	feed.Metadata.Name = name

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

func main() {
	var opt_create bool
	var opt_write string
	var opt_publish bool
	var opt_node string
	var opt_name string
	var opt_newname string

	flag.StringVar(&opt_node, "node", "https://feeds.poolp.org", "set the default node for network operations")
	flag.StringVar(&opt_name, "name", "", "feed name")
	flag.StringVar(&opt_newname, "update-name", "", "update feed name")
	flag.BoolVar(&opt_create, "create", false, "create a feedchain")
	flag.StringVar(&opt_write, "write", "", "write a message to the feedchain")
	flag.BoolVar(&opt_publish, "publish", false, "publish the feedchain")

	flag.Parse()

	userDefault, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}
	workdir := path.Join(userDefault.HomeDir, ".feedchain")
	os.MkdirAll(workdir, 0700)
	os.MkdirAll(path.Join(workdir, "keys"), 0700)

	if opt_create {
		if opt_name == "" {
			log.Fatal("a name must be provided when creating a feed")
		}
		err := createFeedchain(workdir, opt_name)
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

	// add listing command
	//for n, _ := range OwnFeeds {
	//	fmt.Println(n, OwnFeeds[n].Metadata.Name)
	//}

	if len(Keys) == 0 {
		log.Fatal("no feedchain exists, try to -create one")
	}
	if len(Keys) != 1 && opt_name == "" {
		log.Fatal("multiple feeds exist, -name must be provided to select one")
	}

	var feedID string
	if opt_name != "" {
		for n, _ := range OwnFeeds {
			if opt_name == OwnFeeds[n].Metadata.Name {
				feedID = n
				break
			}
		}
		if feedID == "" {
			log.Fatal("could not find a feed with that name")
		}
	} else {
		for n, _ := range OwnFeeds {
			feedID = n
			break
		}
	}

	feed := OwnFeeds[feedID]
	dirty := false

	if opt_newname != "" {
		err := checkName(opt_newname)
		if err != nil {
			log.Fatal(err)
		}
		feed.Metadata.Name = opt_newname
		dirty = true
	}

	if opt_write != "" {
		feed.Append(opt_write)
		dirty = true
	}

	if dirty {
		feed.Commit(path.Join(workdir, feed.ID()))
	}

	if opt_publish {
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
}
