x86:
	cl -c -nologo -Os -O1 -Gm- -GR- -Gr -EHa -Oi- -GS- payload.c maru.c encrypt.c clib.c
	link /order:@order32.txt /entry:ThreadProc /fixed payload.obj maru.obj encrypt.obj clib.obj -subsystem:console -nodefaultlib
	xbin payload.exe .text
	disasm payload.exe32.bin > payload_x86.h
	cl donut.c builder.c maru.c encrypt.c
	cl /DDLL /LD builder.c maru.c encrypt.c
x64:
	cl -c -nologo -Os -O1 -Gm- -GR- -Gr -EHa -Oi- -GS- payload.c maru.c encrypt.c clib.c
	link /order:@order64.txt /entry:ThreadProc /fixed payload.obj maru.obj encrypt.obj clib.obj -subsystem:console -nodefaultlib
	xbin payload.exe .text
	disasm -m64 payload.exe64.bin > payload_amd64.h
	cl donut.c builder.c maru.c encrypt.c
	cl /DDLL /LD builder.c maru.c encrypt.c
clean:
	del *.obj *.bin donut.exe builder.exp builder.lib builder.dll