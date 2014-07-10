package sshproxy

import (
	"bytes"
	"code.google.com/p/go.crypto/ssh"
	"encoding/binary"
	"errors"
	"github.com/op/go-logging"
	"io"
	"net"
	"sync"
	"time"
)

var (
	ErrDataBase             = errors.New("database error")
	ErrScpStreamIllegal     = errors.New("scp stream illegal")
	ErrChanTypeNotSupported = errors.New("channel type not support")
	ErrIllegalUserName      = errors.New("illegal username")
	ErrIllegalPubkey        = errors.New("illegal pubkey")
	ErrSCSNotFound          = errors.New("ssh conn server not found")
	ErrHostKey              = errors.New("host key not match")
	ErrNoPerms              = errors.New("no perms")
	ErrFailedTooMany        = errors.New("banned because failed too many times")
)

var (
	CONN_PROTECT = 300 * time.Second
	MAX_FAILED   = 3
)

var log = logging.MustGetLogger("")

func CheckHostKey(HostKey string) (checkHostKey func(string, net.Addr, ssh.PublicKey) error) {
	var err error
	var public ssh.PublicKey
	var publices []ssh.PublicKey
	rest := []byte(HostKey)
	for {
		public, _, _, rest, err = ssh.ParseAuthorizedKey(rest)
		if err != nil {
			err = nil
			break
		}
		publices = append(publices, public)
	}

	checkHostKey = func(hostname string, remote net.Addr, key ssh.PublicKey) (err error) {
		hostkey := key.Marshal()
		log.Debug("remote hostkey: %s, type: %s", hostname, key.Type())

		for _, public := range publices {
			if key.Type() == public.Type() && bytes.Compare(hostkey, public.Marshal()) == 0 {
				log.Info("host key match: %s", hostname)
				return nil
			}
		}
		log.Info("host key not match: %s", hostname)
		return ErrHostKey
	}
	return
}

func MultiCopyClose(s io.Reader, ds ...io.WriteCloser) (err error) {
	var ws []io.Writer
	for _, d := range ds {
		ws = append(ws, d.(io.Writer))
		defer d.Close()
	}
	_, err = io.Copy(io.MultiWriter(ws...), s)
	if err != nil && err != io.EOF {
		log.Error("%s", err.Error())
	}
	return
}

func ReadPayloadString(payload []byte) (s string, rest []byte, err error) {
	size := binary.BigEndian.Uint32(payload[:4])
	s = string(payload[4 : 4+size])
	rest = payload[4+size:]
	return
}

func ReadPayloadUint32(payload []byte) (i uint32, rest []byte, err error) {
	i = binary.BigEndian.Uint32(payload[:4])
	rest = payload[4:]
	return
}

func ReadPayloads(payload []byte) (strs []string, err error) {
	var s string
	for len(payload) >= 4 {
		s, payload, err = ReadPayloadString(payload)
		if err != nil {
			return
		}
		strs = append(strs, s)
	}
	return
}

func getTcpInfo(d []byte) (srcip string, srcport uint32, dstip string, dstport uint32, err error) {
	srcip, d, err = ReadPayloadString(d)
	if err != nil {
		return
	}
	srcport, d, err = ReadPayloadUint32(d)
	if err != nil {
		return
	}
	dstip, d, err = ReadPayloadString(d)
	if err != nil {
		return
	}
	dstport, d, err = ReadPayloadUint32(d)
	if err != nil {
		return
	}
	return
}

type DebugStream struct {
	Name string
}

func (ds *DebugStream) Write(p []byte) (n int, err error) {
	log.Debug("%s write(%d): %v", ds.Name, len(p), p)
	return len(p), nil
}

func (ds *DebugStream) Close() error {
	return nil
}

type SshConnServer interface {
	Serve(*ssh.ServerConn, <-chan ssh.NewChannel, <-chan *ssh.Request) error
}

type Counter struct {
	mu sync.Mutex
	cm map[string]int
	d  time.Duration
}

func CreateCounter(d time.Duration) (c *Counter) {
	return &Counter{
		cm: make(map[string]int, 0),
		d:  d,
	}
}

func (c *Counter) Add(s string, n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	i, ok := c.cm[s]
	if !ok {
		i = 0
	}
	i += n
	c.cm[s] = i
	time.AfterFunc(c.d, func() { c.Remove(s, n) })
}

func (c *Counter) Remove(s string, n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	i, ok := c.cm[s]
	if !ok {
		return
	}
	i -= n
	if i <= 0 {
		delete(c.cm, s)
	} else {
		c.cm[s] = i
	}
}

func (c *Counter) Number(s string) (i int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	i, ok := c.cm[s]
	if !ok {
		return 0
	}
	return
}

type AccountInfo struct {
	Hostid    int
	Hostname  string
	Port      int
	HostKey   string
	Accountid int
	Account   string
	Key       string
	Password  string
}

func (ai *AccountInfo) ClientConfig() (config *ssh.ClientConfig, err error) {
	config = &ssh.ClientConfig{
		User:            ai.Account,
		HostKeyCallback: CheckHostKey(ai.HostKey),
	}

	if ai.Key != "" {
		private, err := ssh.ParsePrivateKey([]byte(ai.Key))
		if err != nil {
			log.Error("failed to parse keyfile: %s", err.Error())
			return nil, err
		}
		config.Auth = append(config.Auth, ssh.PublicKeys(private))
	}
	if ai.Password != "" {
		config.Auth = append(config.Auth, ssh.Password(ai.Password))
	}

	return
}
