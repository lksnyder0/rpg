all:
	mkdir -p bin
	gcc -lcrypto -o bin/rpg recursivepassgen.c
