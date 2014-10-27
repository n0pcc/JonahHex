Link to a repository with the binaries/solutions for hack.lu 2014:
https://github.com/ctfs/write-ups/tree/master/hack-lu-ctf-2014#readme


To build JonahHex VisualStudio 2012 and Python 2.7 with pefile was used.

Building from the bin\ directory:

1.	cl ..\src\JonahHex.c ..\src\import.c ..\src\des\des.c /c /Od /GS-
	link /NODEFAULTLIB /ENTRY:main JonahHex.obj import.obj des.obj user32.lib kernel32.lib msvcrt.lib

2.	Run keyCalculator.py and write the displayed values to ..\src\des_patcher\main.c

3.	cd desCalculator
	cl ..\..\src\desCalculator\desCalculator.c ..\..\src\desCalculator\des.c
	desCalculator.exe
	cd ..
	Write the new values to patcher.py (line 24/25).

4.	Check in a debugger/hex editor if the offsets for the jumps, which are going
	to be patched, are still correct. If they're not, change the offsets in code.
	JonahHex.exe has to be rebuild in that case, or change them via debugger/hex
	editor.
	Also the offsets have to be adjusted in patcher.py.

5. Run patcher.py - done.