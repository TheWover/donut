donut:
	gcc -Wall -fpack-struct=8 -DDONUT_EXE -I include donut.c hash.c encrypt.c format.c loader/clib.c -odonut
	gcc -Wall -c -fpack-struct=8 -fPIC -I include donut.c hash.c encrypt.c format.c loader/clib.c
	ar rcs lib/libdonut.a donut.o hash.o encrypt.o format.o clib.o
	gcc -Wall -shared -o lib/libdonut.so donut.o hash.o encrypt.o format.o clib.o
debug:
	gcc -ggdb -Wall -Wno-format -fpack-struct=8 -DDEBUG -DDONUT_EXE -I include donut.c hash.c encrypt.c format.c loader/clib.c -odonut
hash:
	gcc -Wall -Wno-format -fpack-struct=8 -DTEST -I include hash.c format.c loader/clib.c -ohash
clean:
	rm *.o hash donut lib/libdonut.a lib/libdonut.so
