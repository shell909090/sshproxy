### Makefile --- 

## Author: shell@debws0.lan
## Version: $Id: Makefile,v 0.0 2014/06/12 06:58:21 shell Exp $
## Keywords: 
## X-URL: 

TARGET=bin/sshproxy

build: $(TARGET)

bin/sshproxy:
	mkdir -p bin
	go build -o $@ github.com/shell909090/sshproxy/main
	strip $@

run: build ssh.db
	bin/sshproxy -config config.json

runweb:
	cd web; python main.py

clean:
	rm -f $(TARGET)

ssh.db:
	mkdir -p logs
	cd web; python db.py -b
	cd web; python db.py -x shell 123 ~/.ssh/authorized_keys

cleandb:
	rm -f ssh.db
	rm -rf logs

### Makefile ends here
