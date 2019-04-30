x64:
	cl -Zp8 -c -nologo -Os -O1 -Gm- -GR- -Gr -EHa -Oi -GS- -I ..\include payload.c ..\hash.c ..\encrypt.c
	link -nologo -order:@order64.txt -entry:ThreadProc -fixed -subsystem:console -nodefaultlib payload.obj hash.obj encrypt.obj
	xbin payload.exe .text
x86:
	cl -Zp8 -c -nologo -Os -O1 -Gm- -GR- -Gr -EHa -Oi -GS- -I ..\include payload.c ..\hash.c ..\encrypt.c
	link -nologo -order:@order32.txt -entry:ThreadProc -fixed -subsystem:console -nodefaultlib payload.obj hash.obj encrypt.obj
	xbin payload.exe .text
debug:
  cl -nologo -Zp8 -DDEBUG -I ..\include payload.c ..\hash.c ..\encrypt.c
clean:
	del *.obj *.bin
