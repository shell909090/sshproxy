package sshproxy

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
