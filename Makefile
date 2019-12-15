donut:
	gcc -Wunused-function -Wall -fpack-struct=8 -DDONUT_EXE -I include donut.c hash.c encrypt.c format.c loader/clib.c -odonut lib/aplib64.a
	gcc -Wunused-function -Wall -c -fpack-struct=8 -fPIC -I include donut.c hash.c encrypt.c format.c loader/clib.c 
	ar rcs lib/libdonut.a donut.o hash.o encrypt.o format.o clib.o lib/aplib64.a
	gcc -Wall -shared -o lib/libdonut.so donut.o hash.o encrypt.o format.o clib.o lib/aplib64.a
debug:
	gcc -Wunused-function -ggdb -Wall -Wno-format -fpack-struct=8 -DDEBUG -DDONUT_EXE -I include donut.c hash.c encrypt.c format.c loader/clib.c lib/aplib64.a -odonut
hash:
	gcc -Wall -Wno-format -fpack-struct=8 -DTEST -I include hash.c format.c loader/clib.c -ohash
clean:
	rm -f donut.o hash.o encrypt.o format.o clib.o hash encrypt donut hash.exe encrypt.exe donut.exe lib/libdonut.a lib/libdonut.so
