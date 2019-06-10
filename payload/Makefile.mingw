x64:
	x86_64-w64-mingw32-gcc -DBYPASS_AMSI_A -DBYPASS_WLDP_A -fno-toplevel-reorder -fpack-struct=8 -fPIC -O0 -nostdlib payload.c clib.c ../hash.c ../encrypt.c -I ../include -opayload.exe
	exe2h/exe2h payload.exe
x86:
	i686-w64-mingw32-gcc -DBYPASS_AMSI_A -DBYPASS_WLDP_A -fno-toplevel-reorder -fpack-struct=8 -fPIC -O0 -nostdlib payload.c clib.c ../hash.c ../encrypt.c -I ../include -opayload.exe
	exe2h/exe2h payload.exe
debug_x64:
	x86_64-w64-mingw32-gcc -DCLIB -DBYPASS_AMSI_A -DBYPASS_WLDP_A -Wno-format -fpack-struct=8 -DDEBUG -I ../include payload.c ../hash.c ../encrypt.c clib.c -opayload.exe
debug_x86:
	i686-w64-mingw32-gcc -DCLIB -DBYPASS_AMSI_A -DBYPASS_WLDP_A -Wno-format -fpack-struct=8 -DDEBUG -I ../include payload.c ../hash.c ../encrypt.c clib.c -opayload.exe
clean:
	rm *.o payload.exe
