package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"io/fs"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/user"
	"path"
	"strings"

	"github.com/poolpOrg/feedchain/feedchain"
)

var Keys map[string][]byte
var OwnFeeds map[string]*feedchain.StreamWriter

type FeedSummary struct {
	PublicKey string `json:"public_key"`
	Origin    string `json:"origin"`
	Size      int    `json:"length"`
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
	var opt_create bool
	var opt_write string
	var opt_publish bool
	var opt_node string
	var opt_follow string
	var opt_unfollow string
	var opt_name string

	flag.BoolVar(&opt_create, "create", false, "create the feedchain")
	flag.StringVar(&opt_write, "write", "", "write a message to the feedchain")
	flag.BoolVar(&opt_publish, "publish", false, "publish the feedchain")
	flag.StringVar(&opt_node, "node", "https://feeds.poolp.org", "set the default node for network operations")
	flag.StringVar(&opt_follow, "follow", "", "feed to follow")
	flag.StringVar(&opt_unfollow, "unfollow", "", "feed to unfollow")
	flag.StringVar(&opt_name, "name", "", "update feed name")

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

}
