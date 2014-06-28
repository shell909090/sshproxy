package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"github.com/op/go-logging"
	stdlog "log"
	"os"
)

var log = logging.MustGetLogger("")

var (
	ErrIllegalUserName = errors.New("illegal username")
	ErrIllegalPubkey   = errors.New("illegal pubkey")
	ErrCINotFound      = errors.New("conn info not found")
	ErrHostKey         = errors.New("host key not match")
)

type Config struct {
	Logfile  string
	Loglevel string

	HostPrivateKeyFile string
	Listen             string
	DBFile             string
	LogDir             string
}

func LoadConfig() (cfg Config, err error) {
	var configfile string
	flag.StringVar(&configfile, "config",
		"/etc/sshproxy/config.json", "config file")
	flag.Parse()

	file, err := os.Open(configfile)
	if err != nil {
		return
	}
	defer file.Close()

	dec := json.NewDecoder(file)
	err = dec.Decode(&cfg)
	if err != nil {
		return
	}
	return
}

func SetLogging(cfg Config) (err error) {
	var file *os.File
	file = os.Stdout

	if cfg.Logfile != "" {
		file, err = os.OpenFile(cfg.Logfile,
			os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			log.Error("%s", err.Error())
			return err
		}
	}
	logBackend := logging.NewLogBackend(file, "",
		stdlog.LstdFlags|stdlog.Lmicroseconds|stdlog.Lshortfile)
	logging.SetBackend(logBackend)

	logging.SetFormatter(logging.MustStringFormatter("%{level}: %{message}"))

	lv, err := logging.LogLevel(cfg.Loglevel)
	if err != nil {
		panic(err.Error())
	}
	logging.SetLevel(lv, "")

	return
}

func main() {
	cfg, err := LoadConfig()
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	err = SetLogging(cfg)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	srv, err := CreateServer(cfg.DBFile, cfg.LogDir)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	srv.MainLoop(cfg.HostPrivateKeyFile, cfg.Listen)
}
