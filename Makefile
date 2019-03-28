donut:
	cl -DPIC -DNOEKEON -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- donut.c
	link /order:@order.txt /entry:ThreadProc /base:0 donut.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
	xbin donut.exe .text
	cl -DNOEKEON donut.c
        cl /MD inject.c
clean:
	del *.obj *.bin