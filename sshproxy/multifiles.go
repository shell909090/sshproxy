package sshproxy

import (
	"io"
)

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
