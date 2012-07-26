all:
	mkdir -p bin
	gcc -lcrypto -o bin/rpg -s recursivepassgen.c

install:
	install -C bin/rpg /usr/local/bin