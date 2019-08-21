donut:
	gcc -Wall -fpack-struct=8 -DDONUT_EXE -I include donut.c hash.c encrypt.c payload/clib.c -odonut
	gcc -Wall -c -fpack-struct=8 -fPIC -I include donut.c hash.c encrypt.c payload/clib.c
	ar rcs lib/libdonut.a donut.o hash.o encrypt.o clib.o
	gcc -Wall -shared -o lib/libdonut.so donut.o hash.o encrypt.o clib.o
debug:
	gcc -Wall -Wno-format -fpack-struct=8 -DDEBUG -DDONUT_EXE -I include donut.c hash.c encrypt.c payload/clib.c -odonut
clean:
	rm *.o donut lib/libdonut.a lib/libdonut.so
