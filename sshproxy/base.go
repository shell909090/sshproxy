package sshproxy

import (
	"code.google.com/p/go.crypto/ssh"
	"encoding/binary"
	"errors"
	"github.com/op/go-logging"
	"io"
	"io/ioutil"
)

var (
	ErrScpStreamIllegal     = errors.New("scp stream illegal")
	ErrChanTypeNotSupported = errors.New("channel type not support")
	ErrIllegalUserName      = errors.New("illegal username")
	ErrIllegalPubkey        = errors.New("illegal pubkey")
	ErrCINotFound           = errors.New("conn info not found")
	ErrHostKey              = errors.New("host key not match")
)

var log = logging.MustGetLogger("")

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

type MultiWriteCloser struct {
	a io.WriteCloser
	b []io.WriteCloser
}

func CreateMultiWriteCloser(a io.WriteCloser, bs ...io.WriteCloser) (mwc *MultiWriteCloser) {
	mwc = &MultiWriteCloser{a: a, b: make([]io.WriteCloser, 0)}
	for _, b := range bs {
		mwc.b = append(mwc.b, b.(io.WriteCloser))
	}
	return
}

func (mwc *MultiWriteCloser) Write(p []byte) (n int, err error) {
	log.Debug("write out: %d.", len(p))
	for _, b := range mwc.b {
		defer b.Write(p)
	}
	return mwc.a.Write(p)
}

func (mwc *MultiWriteCloser) Close() (err error) {
	for _, b := range mwc.b {
		defer b.Close()
	}
	return mwc.a.Close()
}
