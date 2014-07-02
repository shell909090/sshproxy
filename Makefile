### Makefile --- 

## Author: shell@debws0.lan
## Version: $Id: Makefile,v 0.0 2014/06/12 06:58:21 shell Exp $
## Keywords: 
## X-URL: 

TARGET=bin/sshproxy

build: $(TARGET)

clean:
	rm -f $(TARGET)

cleandb:
	rm -f ssh.db
	rm -rf logs

run: build ssh.db
	bin/sshproxy -config config.json

runweb:
	cd web; python main.py

bin/sshproxy:
	mkdir -p bin
	go build -o $@ github.com/shell909090/sshproxy/main
	strip $@

ssh.db:
	mkdir -p logs
	sqlite3 $@ < db/ssh.sql
	python db/pubkey.py $@ shell < db/shell.pub
	python db/prikey.py $@ shell@localhost < ~/.ssh/id_rsa
	python db/hosts.py -a 1 $@ localhost localhost

### Makefile ends here
