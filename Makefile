### Makefile --- 

## Author: shell@debws0.lan
## Version: $Id: Makefile,v 0.0 2014/06/12 06:58:21 shell Exp $
## Keywords: 
## X-URL: 

TARGET=bin/sshproxy ssh.db

build: $(TARGET)

clean:
	rm -f $(TARGET)

run: build
	bin/sshproxy -config config.json

bin/sshproxy:
	mkdir -p bin
	go build -o $@ github.com/shell909090/sshproxy/main
	strip $@

ssh.db:
	sqlite3 $@ < db/ssh.sql
	python db/pubkey.py $@ shell < db/shell.pub
	python db/hosts.py $@ localhost localhost
	python db/prikey.py $@ shell@localhost ~/.ssh/id_rsa

### Makefile ends here
