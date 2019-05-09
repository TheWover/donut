donut:
	gcc -Wall -fpack-struct=8 -DDONUT_EXE -I include donut.c hash.c encrypt.c -odonut
	gcc -Wall -c -fpack-struct=8 -fPIC -I include donut.c hash.c encrypt.c
	ar rcs lib/libdonut.a donut.o hash.o encrypt.o
	gcc -Wall -shared -o lib/libdonut.so donut.o hash.o encrypt.o
debug:
	gcc -Wall -Wno-format -fpack-struct=8 -DDEBUG -DDONUT_EXE -I include donut.c hash.c encrypt.c -odonut
clean:
	rm *.o donut lib/libdonut.a lib/libdonut.so
