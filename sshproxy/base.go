package sshproxy

import (
	"bytes"
	"code.google.com/p/go.crypto/ssh"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

var (
	ErrScpStreamIllegal     = errors.New("scp stream illegal")
	ErrChanTypeNotSupported = errorw.New("channel type not support")
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

func ReadPayloadInt32(payload []byte) (i int32, rest []byte, err error) {
	i := binary.BigEndian.Int32(payload[:4])
	rest = payload[4+size:]
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

type ABWriteCloser struct {
	a io.WriteCloser
	b []io.WriteCloser
}

func CreateABWriteCloser(a io.WriteCloser, bs ...io.WriteCloser) (abc *ABWriteCloser) {
	abc = &ABWriteCloser{a: a, b: make([]io.WriteCloser, 0)}
	for _, b := range bs {
		abc.b = append(abc.b, b.(io.WriteCloser))
	}
	return
}

func (abc *ABWriteCloser) Write(p []byte) (n int, err error) {
	log.Debug("write out: %d.", len(p))
	for _, b := range abc.b {
		defer b.Write(p)
	}
	return abc.a.Write(p)
}

func (abc *ABWriteCloser) Close() (err error) {
	for _, b := range abc.b {
		defer b.Close()
	}
	return abc.a.Close()
}
