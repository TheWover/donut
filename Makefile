donut: clean
	gcc -Wunused-function -Wall -fpack-struct=8 -DDONUT_EXE -I include donut.c hash.c encrypt.c format.c loader/clib.c -odonut lib/aplib64.a
	gcc -Wunused-function -Wall -c -fpack-struct=8 -fPIC -I include donut.c hash.c encrypt.c format.c loader/clib.c 
	ar rcs lib/libdonut.a donut.o hash.o encrypt.o format.o clib.o lib/aplib64.a
	gcc -Wall -shared -o lib/libdonut.so donut.o hash.o encrypt.o format.o clib.o lib/aplib64.a
debug: clean
	gcc -Wunused-function -ggdb -Wall -Wno-format -fpack-struct=8 -DDEBUG -DDONUT_EXE -I include donut.c hash.c encrypt.c format.c loader/clib.c lib/aplib64.a -odonut
hash:
	gcc -Wall -Wno-format -fpack-struct=8 -DTEST -I include hash.c loader/clib.c -ohash
encrypt:
	gcc -Wall -Wno-format -fpack-struct=8 -DTEST -I include encrypt.c loader/clib.c -oencrypt
clean:
	rm -f loader.exe exe2h.exe exe2h loader32.exe loader64.exe donut.o hash.o encrypt.o format.o clib.o hash encrypt donut hash.exe encrypt.exe donut.exe lib/libdonut.a lib/libdonut.so inject32.exe inject64.exe
