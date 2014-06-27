package main

import (
	"fmt"
	"io"
	"os"
)

type WriteLogger struct {
	io.WriteCloser
	raw io.WriteCloser
}

func (srv *Server) CreateLogger(w io.WriteCloser, ci *ConnInfo) (wl *WriteLogger, err error) {
	res, err := srv.stmtInsertRecord.Exec(ci.realname, ci.username, ci.host)
	if err != nil {
		log.Error("%s", err.Error())
		return
	}

	id, err := res.LastInsertId()
	if err != nil {
		log.Error("%s", err.Error())
		return
	}

	filepath := fmt.Sprintf("%s/%d.raw", srv.Config.LogDir, id)
	fraw, err := os.OpenFile(filepath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	if err != nil {
		log.Error("%s", err.Error())
		return
	}

	// fcmd, err := os.OpenFile(filepath+".cmd", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	// if err != nil {
	// 	log.Error("%s", err.Error())
	// 	return
	// }

	wl = &WriteLogger{
		WriteCloser: w,
		raw:         fraw,
	}
	return
}

func (wl *WriteLogger) Write(p []byte) (n int, err error) {
	defer wl.raw.Write(p)
	return wl.WriteCloser.Write(p)
}

func (wl *WriteLogger) Close() (err error) {
	defer wl.raw.Close()
	return wl.WriteCloser.Close()
}
