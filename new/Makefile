x86:
	cl -c -nologo -Os -O1 -Gm- -GR- -Gr -EHa -Oi- -GS- payload.c hash.c encrypt.c clib.c
	link -nologo -order:@order32.txt -entry:ThreadProc -fixed payload.obj hash.obj encrypt.obj clib.obj -subsystem:console -nodefaultlib
	xbin payload.exe .text
	cl -nologo -DDONUT_EXE donut.c hash.c encrypt.c
	cl -nologo -DDLL -LD donut.c hash.c encrypt.c
x64:
	cl -c -nologo -Os -O1 -Gm- -GR- -Gr -EHa -Oi- -GS- payload.c hash.c encrypt.c clib.c
	link /order:@order64.txt /entry:ThreadProc /fixed payload.obj hash.obj encrypt.obj clib.obj -subsystem:console -nodefaultlib
	xbin payload.exe .text
	cl -nologo -DDONUT_EXE donut.c hash.c encrypt.c
	cl -nologo -DDLL -LD donut.c hash.c encrypt.c
clean:
	del *.obj *.bin donut.exe donut.exp donut.lib donut.dll