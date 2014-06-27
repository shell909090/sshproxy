package main

import (
	"bytes"
	"code.google.com/p/go.crypto/ssh"
	"io"
	"io/ioutil"
	"net"
)

func LoadPrivateKey(filename string) (private ssh.Signer, err error) {
	log.Info("load private key: %s", filename)

	privateBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Error("failed to load keyfile: %s", err.Error())
		return
	}
	private, err = ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Error("failed to parse keyfile: %s", err.Error())
		return
	}
	return
}

// func LoadAuthorizedKey(filename string) (publices []ssh.PublicKey, err error) {
// 	log.Info("load authorized key: %s", filename)

// 	publicBytes, err := ioutil.ReadFile(filename)
// 	if err != nil {
// 		log.Error("failed to load pubkeyfile: %s", err.Error())
// 		return
// 	}
// 	rest := publicBytes
// 	for {
// 		var public ssh.PublicKey
// 		public, _, _, rest, err = ssh.ParseAuthorizedKey(rest)
// 		if err != nil {
// 			err = nil
// 			break
// 		}
// 		publices = append(publices, public)
// 	}
// 	return
// }

func CopyChan(d io.WriteCloser, s io.ReadCloser) {
	defer s.Close()
	defer d.Close()
	_, err := io.Copy(d, s)

	switch err {
	case io.EOF:
	case nil:
	default:
		log.Error("%s", err.Error())
	}
	return
}

type ConnInfo struct {
	realname string
	username string
	host     string
	hostname string
	port     int
	hostkeys string
}

func (ci *ConnInfo) checkHostKey(hostname string, remote net.Addr, key ssh.PublicKey) (err error) {
	log.Debug("check hostkey: %s", hostname)

	hostkey := key.Marshal()
	log.Info("remote hostkey: %s", key.Type())

	rest := []byte(ci.hostkeys)
	for {
		var public ssh.PublicKey
		public, _, _, rest, err = ssh.ParseAuthorizedKey(rest)
		if err != nil {
			err = nil
			break
		}
		if key.Type() == public.Type() && bytes.Compare(hostkey, public.Marshal()) == 0 {
			log.Info("host key match: %s", hostname)
			return nil
		}
	}

	log.Info("host key not match: %s", hostname)
	return ErrHostKey
}
